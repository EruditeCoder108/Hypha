#ifndef HYPHA_NODE_PEER_H
#define HYPHA_NODE_PEER_H

constexpr uint32_t kNodePeerScanIntervalMs = 8000;
constexpr uint32_t kNodePeerPhoneIdleMs = 3000;
constexpr uint32_t kNodePeerRepeatCooldownMs = 12000;
constexpr uint32_t kNodePeerConnectTimeoutMs = 6000;

struct NodePeerCrypto {
  std::array<uint8_t, kAesKeyBytes> sendKey{};
  std::array<uint8_t, kAesKeyBytes> receiveKey{};
  std::array<uint8_t, kAdvertisementTokenBytes> token{};
  std::array<uint8_t, kP256PublicBytes> serverIdentity{};
  uint64_t nextSendSequence = 0;
  uint64_t expectedReceiveSequence = 0;
  bool ready = false;
};

BLEScan* nodePeerScanner = nullptr;
BLEClient* nodePeerClient = nullptr;
BLERemoteCharacteristic* nodePeerRemote = nullptr;
BLEAdvertisedDevice* nodePeerTarget = nullptr;
bool nodePeerReadyState = false;
bool nodePeerBusyState = false;
bool nodePeerForced = false;
uint32_t nodePeerLastAttemptMs = 0;
uint32_t nodePeerLastAddressAtMs = 0;
uint32_t nodePeerSuccessCount = 0;
uint32_t nodePeerFailureCount = 0;
String nodePeerLastAddress;

void resetNodePeerCrypto(NodePeerCrypto* crypto) {
  crypto->sendKey.fill(0);
  crypto->receiveKey.fill(0);
  crypto->token.fill(0);
  crypto->serverIdentity.fill(0);
  crypto->nextSendSequence = 0;
  crypto->expectedReceiveSequence = 0;
  crypto->ready = false;
}

std::vector<uint8_t> nodePeerRecordAad(
    const std::array<uint8_t, kAdvertisementTokenBytes>& token,
    uint64_t sequence) {
  std::vector<uint8_t> aad;
  aad.insert(aad.end(), kRecordDomain,
             kRecordDomain + sizeof(kRecordDomain) - 1);
  aad.insert(aad.end(), token.begin(), token.end());
  const size_t sequenceOffset = aad.size();
  aad.resize(aad.size() + kSequenceBytes);
  putU64(aad.data() + sequenceOffset, sequence);
  return aad;
}

bool encryptNodePeerRecord(NodePeerCrypto* crypto,
                           const std::vector<uint8_t>& plaintext,
                           std::vector<uint8_t>* encoded) {
  if (!crypto->ready || plaintext.empty() ||
      plaintext.size() > kMaximumSyncBytes ||
      crypto->nextSendSequence == UINT64_MAX) {
    return false;
  }
  const uint64_t sequence = crypto->nextSendSequence;
  encoded->assign(kSequenceBytes + plaintext.size() + kGcmTagBytes, 0);
  putU64(encoded->data(), sequence);
  uint8_t nonce[kGcmNonceBytes] = {};
  buildRecordNonce(kClientNoncePrefix, sequence, nonce);
  const std::vector<uint8_t> aad = nodePeerRecordAad(crypto->token, sequence);
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  const bool success = mbedtls_gcm_setkey(
                           &gcm, MBEDTLS_CIPHER_ID_AES,
                           crypto->sendKey.data(), kAesKeyBytes * 8) == 0 &&
      mbedtls_gcm_crypt_and_tag(
          &gcm, MBEDTLS_GCM_ENCRYPT, plaintext.size(), nonce, sizeof(nonce),
          aad.data(), aad.size(), plaintext.data(),
          encoded->data() + kSequenceBytes, kGcmTagBytes,
          encoded->data() + kSequenceBytes + plaintext.size()) == 0;
  mbedtls_gcm_free(&gcm);
  if (success) {
    ++crypto->nextSendSequence;
  } else {
    encoded->clear();
    resetNodePeerCrypto(crypto);
  }
  return success;
}

bool decryptNodePeerRecord(NodePeerCrypto* crypto,
                           const std::vector<uint8_t>& encoded,
                           std::vector<uint8_t>* plaintext) {
  if (!crypto->ready || encoded.size() <= kSequenceBytes + kGcmTagBytes) {
    return false;
  }
  const uint64_t sequence = readU64(encoded.data());
  if (sequence != crypto->expectedReceiveSequence) return false;
  const size_t ciphertextBytes = encoded.size() - kSequenceBytes - kGcmTagBytes;
  plaintext->assign(ciphertextBytes, 0);
  uint8_t nonce[kGcmNonceBytes] = {};
  buildRecordNonce(kNodeNoncePrefix, sequence, nonce);
  const std::vector<uint8_t> aad = nodePeerRecordAad(crypto->token, sequence);
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  const bool success = mbedtls_gcm_setkey(
                           &gcm, MBEDTLS_CIPHER_ID_AES,
                           crypto->receiveKey.data(), kAesKeyBytes * 8) == 0 &&
      mbedtls_gcm_auth_decrypt(
          &gcm, ciphertextBytes, nonce, sizeof(nonce), aad.data(), aad.size(),
          encoded.data() + encoded.size() - kGcmTagBytes, kGcmTagBytes,
          encoded.data() + kSequenceBytes, plaintext->data()) == 0;
  mbedtls_gcm_free(&gcm);
  if (success) {
    ++crypto->expectedReceiveSequence;
  } else {
    plaintext->clear();
    resetNodePeerCrypto(crypto);
  }
  return success;
}

bool writeNodePeerTransfer(BLERemoteCharacteristic* remote, uint16_t mtu,
                           uint8_t type, const std::vector<uint8_t>& payload,
                           uint8_t* responseKind,
                           std::vector<uint8_t>* responsePayload) {
  if (remote == nullptr || responseKind == nullptr ||
      payload.empty() || payload.size() > kMaximumTransferBytes) {
    return false;
  }
  uint8_t start[kStartFrameBytes] = {};
  memcpy(start, kFrameStartMagic, sizeof(kFrameStartMagic));
  start[4] = type;
  putU16(start + 6, static_cast<uint16_t>(payload.size()));
  putU32(start + 8, crc32(payload.data(), payload.size()));
  if (!remote->writeValue(start, sizeof(start), true)) return false;

  const size_t valueBytes = std::max<size_t>(20, mtu > 3 ? mtu - 3 : 20);
  if (valueBytes <= kDataHeaderBytes) return false;
  const size_t chunkLimit = valueBytes - kDataHeaderBytes;
  size_t offset = 0;
  uint16_t sequence = 0;
  while (offset < payload.size()) {
    const size_t chunkBytes = std::min(chunkLimit, payload.size() - offset);
    std::vector<uint8_t> frame(kDataHeaderBytes + chunkBytes, 0);
    memcpy(frame.data(), kFrameDataMagic, sizeof(kFrameDataMagic));
    putU16(frame.data() + 4, sequence);
    memcpy(frame.data() + kDataHeaderBytes, payload.data() + offset, chunkBytes);
    if (!remote->writeValue(frame.data(), frame.size(), true)) return false;
    offset += chunkBytes;
    ++sequence;
  }

  delay(8);
  responsePayload->clear();
  uint16_t expectedSequence = 0;
  uint16_t expectedBytes = 0;
  uint32_t expectedCrc = 0;
  bool initialized = false;
  while (true) {
    const String value = remote->readValue();
    const size_t bytes = value.length();
    if (bytes < kResponseHeaderBytes) return false;
    const uint8_t* frame = reinterpret_cast<const uint8_t*>(value.c_str());
    if (memcmp(frame, kFrameResponseMagic, sizeof(kFrameResponseMagic)) != 0 ||
        frame[5] > 1 || readU16(frame + 6) != expectedSequence) {
      return false;
    }
    const uint16_t totalBytes = readU16(frame + 8);
    const uint32_t totalCrc = readU32(frame + 10);
    if (!initialized) {
      *responseKind = frame[4];
      expectedBytes = totalBytes;
      expectedCrc = totalCrc;
      if (expectedBytes == 0 || expectedBytes > kMaximumTransferBytes) return false;
      responsePayload->reserve(expectedBytes);
      initialized = true;
    } else if (frame[4] != *responseKind || totalBytes != expectedBytes ||
               totalCrc != expectedCrc) {
      return false;
    }
    const size_t chunkBytes = bytes - kResponseHeaderBytes;
    if (chunkBytes > expectedBytes - responsePayload->size()) return false;
    responsePayload->insert(responsePayload->end(),
                            frame + kResponseHeaderBytes, frame + bytes);
    ++expectedSequence;
    if (frame[5] == 1) {
      return responsePayload->size() == expectedBytes &&
          crc32(responsePayload->data(), responsePayload->size()) == expectedCrc;
    }
    if (responsePayload->size() >= expectedBytes) return false;
  }
}

bool exchangeNodePeerSecure(BLERemoteCharacteristic* remote, uint16_t mtu,
                            NodePeerCrypto* crypto,
                            const std::vector<uint8_t>& plaintext,
                            std::vector<uint8_t>* responsePlaintext) {
  std::vector<uint8_t> encrypted;
  if (!encryptNodePeerRecord(crypto, plaintext, &encrypted)) return false;
  uint8_t responseKind = 0;
  std::vector<uint8_t> response;
  if (!writeNodePeerTransfer(remote, mtu, kTransferSecure, encrypted,
                             &responseKind, &response) ||
      responseKind != kResponseSecure) {
    return false;
  }
  return decryptNodePeerRecord(crypto, response, responsePlaintext);
}

bool establishNodePeerSession(BLERemoteCharacteristic* remote, uint16_t mtu,
                              const uint8_t peerToken[kAdvertisementTokenBytes],
                              NodePeerCrypto* crypto) {
  resetNodePeerCrypto(crypto);
  memcpy(crypto->token.data(), peerToken, crypto->token.size());

  mbedtls_ecp_keypair ephemeral;
  mbedtls_ecp_keypair_init(&ephemeral);
  uint8_t clientNonce[kNonceBytes] = {};
  uint8_t clientPublic[kP256PublicBytes] = {};
  esp_fill_random(clientNonce, sizeof(clientNonce));
  bool success = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &ephemeral,
                                     hardwareRandom, nullptr) == 0 &&
      exportPublicKey(ephemeral, clientPublic);
  std::vector<uint8_t> hello;
  hello.insert(hello.end(), kHelloMagic, kHelloMagic + sizeof(kHelloMagic));
  hello.insert(hello.end(), peerToken, peerToken + kAdvertisementTokenBytes);
  hello.insert(hello.end(), clientNonce, clientNonce + sizeof(clientNonce));
  hello.insert(hello.end(), clientPublic, clientPublic + sizeof(clientPublic));
  uint8_t responseKind = 0;
  std::vector<uint8_t> response;
  success = success && writeNodePeerTransfer(
      remote, mtu, kTransferHello, hello, &responseKind, &response) &&
      responseKind == kResponseHello;

  const size_t fixedResponseBytes = sizeof(kHelloResponseMagic) +
      kAdvertisementTokenBytes + kNonceBytes + kP256PublicBytes * 2 + 2;
  success = success && response.size() > fixedResponseBytes &&
      memcmp(response.data(), kHelloResponseMagic,
             sizeof(kHelloResponseMagic)) == 0;
  const uint8_t* returnedToken = success
      ? response.data() + sizeof(kHelloResponseMagic) : nullptr;
  success = success && fixedEquals(returnedToken, peerToken,
                                   kAdvertisementTokenBytes);
  const uint8_t* nodeNonce = success
      ? returnedToken + kAdvertisementTokenBytes : nullptr;
  const uint8_t* nodePublic = success ? nodeNonce + kNonceBytes : nullptr;
  const uint8_t* nodeIdentity = success
      ? nodePublic + kP256PublicBytes : nullptr;
  const size_t signatureBytes = success
      ? readU16(nodeIdentity + kP256PublicBytes) : 0;
  success = success && signatureBytes > 0 && signatureBytes <= 80 &&
      fixedResponseBytes + signatureBytes == response.size();

  std::vector<uint8_t> transcript;
  if (success) {
    transcript.insert(transcript.end(), kHandshakeDomain,
                      kHandshakeDomain + sizeof(kHandshakeDomain) - 1);
    transcript.insert(transcript.end(), peerToken,
                      peerToken + kAdvertisementTokenBytes);
    transcript.insert(transcript.end(), clientNonce,
                      clientNonce + sizeof(clientNonce));
    transcript.insert(transcript.end(), nodeNonce, nodeNonce + kNonceBytes);
    transcript.insert(transcript.end(), clientPublic,
                      clientPublic + sizeof(clientPublic));
    transcript.insert(transcript.end(), nodePublic,
                      nodePublic + kP256PublicBytes);
    transcript.insert(transcript.end(), nodeIdentity,
                      nodeIdentity + kP256PublicBytes);
    success = verifyTranscript(
        nodeIdentity, transcript, nodeIdentity + kP256PublicBytes + 2,
        signatureBytes);
  }

  mbedtls_ecp_point nodePoint;
  mbedtls_ecp_point_init(&nodePoint);
  mbedtls_mpi shared;
  mbedtls_mpi_init(&shared);
  uint8_t sharedBytes[32] = {};
  if (success) {
    success = mbedtls_ecp_point_read_binary(
                  &ephemeral.MBEDTLS_PRIVATE(grp), &nodePoint,
                  nodePublic, kP256PublicBytes) == 0 &&
        mbedtls_ecp_check_pubkey(
            &ephemeral.MBEDTLS_PRIVATE(grp), &nodePoint) == 0 &&
        mbedtls_ecdh_compute_shared(
            &ephemeral.MBEDTLS_PRIVATE(grp), &shared, &nodePoint,
            &ephemeral.MBEDTLS_PRIVATE(d), hardwareRandom, nullptr) == 0 &&
        mbedtls_mpi_write_binary(&shared, sharedBytes,
                                 sizeof(sharedBytes)) == 0;
  }
  uint8_t salt[kNonceBytes * 2] = {};
  if (success) {
    memcpy(salt, clientNonce, kNonceBytes);
    memcpy(salt + kNonceBytes, nodeNonce, kNonceBytes);
  }
  std::vector<uint8_t> info;
  info.insert(info.end(), kSessionDomain,
              kSessionDomain + sizeof(kSessionDomain) - 1);
  info.insert(info.end(), peerToken, peerToken + kAdvertisementTokenBytes);
  uint8_t keys[kSessionKeyBytes] = {};
  const mbedtls_md_info_t* sha256 =
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  success = success && sha256 != nullptr &&
      mbedtls_hkdf(sha256, salt, sizeof(salt), sharedBytes,
                   sizeof(sharedBytes), info.data(), info.size(),
                   keys, sizeof(keys)) == 0;
  if (success) {
    memcpy(crypto->sendKey.data(), keys, kAesKeyBytes);
    memcpy(crypto->receiveKey.data(), keys + kAesKeyBytes, kAesKeyBytes);
    memcpy(crypto->serverIdentity.data(), nodeIdentity, kP256PublicBytes);
    crypto->ready = true;
  }
  memset(keys, 0, sizeof(keys));
  memset(sharedBytes, 0, sizeof(sharedBytes));
  memset(clientNonce, 0, sizeof(clientNonce));
  mbedtls_mpi_free(&shared);
  mbedtls_ecp_point_free(&nodePoint);
  mbedtls_ecp_keypair_free(&ephemeral);
  if (!success) resetNodePeerCrypto(crypto);
  return success;
}

bool mutuallyAuthenticateNodePeer(BLERemoteCharacteristic* remote,
                                  uint16_t mtu, NodePeerCrypto* crypto) {
  std::vector<uint8_t> response;
  const std::vector<uint8_t> finish(kFinishMagic,
                                    kFinishMagic + sizeof(kFinishMagic));
  if (!exchangeNodePeerSecure(remote, mtu, crypto, finish, &response) ||
      response.size() != sizeof(kWelcomeMagic) ||
      memcmp(response.data(), kWelcomeMagic, sizeof(kWelcomeMagic)) != 0) {
    return false;
  }

  uint8_t identityPublic[kP256PublicBytes] = {};
  if (!exportPublicKey(identityKey, identityPublic)) return false;
  std::vector<uint8_t> transcript;
  transcript.insert(transcript.end(), kNodeAuthDomain,
                    kNodeAuthDomain + sizeof(kNodeAuthDomain) - 1);
  transcript.insert(transcript.end(), crypto->token.begin(), crypto->token.end());
  transcript.insert(transcript.end(), crypto->serverIdentity.begin(),
                    crypto->serverIdentity.end());
  transcript.insert(transcript.end(), identityPublic,
                    identityPublic + sizeof(identityPublic));
  std::vector<uint8_t> signature;
  if (!signTranscript(identityKey, transcript, &signature)) return false;
  std::vector<uint8_t> authentication;
  authentication.insert(authentication.end(), kNodeAuthMagic,
                        kNodeAuthMagic + sizeof(kNodeAuthMagic));
  authentication.insert(authentication.end(), identityPublic,
                        identityPublic + sizeof(identityPublic));
  const size_t signatureOffset = authentication.size();
  authentication.resize(authentication.size() + 2);
  putU16(authentication.data() + signatureOffset,
         static_cast<uint16_t>(signature.size()));
  authentication.insert(authentication.end(), signature.begin(), signature.end());
  response.clear();
  return exchangeNodePeerSecure(remote, mtu, crypto, authentication, &response) &&
      response.size() == sizeof(kNodeAuthOkMagic) &&
      memcmp(response.data(), kNodeAuthOkMagic,
             sizeof(kNodeAuthOkMagic)) == 0;
}

std::vector<ObjectId> nodePeerInventory() {
  std::vector<ObjectId> inventory;
  File directory = LittleFS.open(kStoreDirectory);
  if (!directory || !directory.isDirectory()) {
    if (directory) directory.close();
    return inventory;
  }
  File entry = directory.openNextFile();
  while (entry && inventory.size() < kMaximumRecords) {
    ObjectId id{};
    if (!entry.isDirectory() && parseObjectIdFromName(entry.name(), &id)) {
      inventory.push_back(id);
    }
    entry.close();
    entry = directory.openNextFile();
  }
  if (entry) entry.close();
  directory.close();
  std::sort(inventory.begin(), inventory.end());
  return inventory;
}

bool synchronizeNodePeer(BLERemoteCharacteristic* remote, uint16_t mtu,
                         NodePeerCrypto* crypto) {
  const std::vector<ObjectId> inventory = nodePeerInventory();
  pendingOffers.clear();
  const std::vector<uint8_t> request =
      encodeExchange(kRmsRequestMagic, inventory, {});
  std::vector<uint8_t> responsePlaintext;
  if (!exchangeNodePeerSecure(remote, mtu, crypto, request,
                              &responsePlaintext)) {
    pendingOffers.clear();
    return false;
  }
  ExchangeView response;
  if (!decodeExchange(responsePlaintext, kRmsResponseMagic, &response) ||
      !response.primaryIds.empty() || !response.secondaryEnvelopes.empty()) {
    return false;
  }

  std::vector<ObjectId> acceptedRemote;
  for (const std::vector<uint8_t>& offered : response.primaryEnvelopes) {
    ObjectId id{};
    if (!validateEnvelope(offered.data(), offered.size(), &id)) continue;
    const StoreOutcome outcome = storeEnvelope(offered.data(), offered.size());
    if (outcome == StoreOutcome::kCommitted ||
        outcome == StoreOutcome::kDuplicate) {
      acceptedRemote.push_back(id);
    }
  }
  planNodeOffers(response.secondaryIds);
  const std::vector<uint8_t> ack =
      encodeExchange(kRmsAckMagic, acceptedRemote, pendingOffers);
  responsePlaintext.clear();
  if (!exchangeNodePeerSecure(remote, mtu, crypto, ack, &responsePlaintext)) {
    pendingOffers.clear();
    return false;
  }
  ExchangeView completion;
  if (!decodeExchange(responsePlaintext, kRmsCompletionMagic, &completion) ||
      !completion.primaryEnvelopes.empty() ||
      !completion.secondaryIds.empty() ||
      !completion.secondaryEnvelopes.empty()) {
    pendingOffers.clear();
    return false;
  }
  for (const ObjectId& accepted : completion.primaryIds) {
    const auto offer = std::find_if(
        pendingOffers.begin(), pendingOffers.end(),
        [&](const PendingOffer& candidate) { return candidate.id == accepted; });
    if (offer == pendingOffers.end() ||
        !replaceEnvelope(offer->id, offer->retainedWire)) {
      pendingOffers.clear();
      return false;
    }
  }
  pendingOffers.clear();
  const std::vector<uint8_t> finalAck =
      encodeExchange(kRmsFinalAckMagic, {}, {});
  responsePlaintext.clear();
  return exchangeNodePeerSecure(remote, mtu, crypto, finalAck,
                                &responsePlaintext) &&
      responsePlaintext.size() == sizeof(kDoneMagic) &&
      memcmp(responsePlaintext.data(), kDoneMagic,
             sizeof(kDoneMagic)) == 0;
}

bool extractNodePeerToken(BLEAdvertisedDevice& device,
                          uint8_t token[kAdvertisementTokenBytes]) {
  if (!device.haveManufacturerData() || !device.isConnectable()) return false;
  const String manufacturer = device.getManufacturerData();
  const uint8_t* bytes =
      reinterpret_cast<const uint8_t*>(manufacturer.c_str());
  size_t offset = 0;
  if (manufacturer.length() == 2 + sizeof(kAdvertisementPrefix) +
                                   kAdvertisementTokenBytes &&
      bytes[0] == 0xff && bytes[1] == 0xff) {
    offset = 2;
  } else if (manufacturer.length() != sizeof(kAdvertisementPrefix) +
                                      kAdvertisementTokenBytes) {
    return false;
  }
  if (memcmp(bytes + offset, kAdvertisementPrefix,
             sizeof(kAdvertisementPrefix)) != 0) {
    return false;
  }
  memcpy(token, bytes + offset + sizeof(kAdvertisementPrefix),
         kAdvertisementTokenBytes);
  return !fixedEquals(token, advertisementToken.data(),
                      kAdvertisementTokenBytes);
}

class NodePeerAdvertisedCallbacks final : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice device) override {
    if (nodePeerTarget != nullptr || serverClientConnected ||
        !nodePeerBusyState) {
      return;
    }
    uint8_t peerToken[kAdvertisementTokenBytes] = {};
    if (!extractNodePeerToken(device, peerToken) ||
        memcmp(advertisementToken.data(), peerToken,
               kAdvertisementTokenBytes) >= 0) {
      return;
    }
    const String address = device.getAddress().toString();
    const uint32_t now = millis();
    if (address == nodePeerLastAddress &&
        now - nodePeerLastAddressAtMs < kNodePeerRepeatCooldownMs) {
      return;
    }
    nodePeerTarget = new BLEAdvertisedDevice(device);
    nodePeerScanner->stop();
  }
};

class NodePeerClientCallbacks final : public BLEClientCallbacks {
  void onConnect(BLEClient*) override {}
  void onDisconnect(BLEClient*) override { nodePeerRemote = nullptr; }
};

NodePeerAdvertisedCallbacks nodePeerAdvertisedCallbacks;
NodePeerClientCallbacks nodePeerClientCallbacks;

bool runNodePeerSync(BLEAdvertisedDevice* target) {
  if (!storageReady || !identityReady || !venueRelayAllowed()) return false;
  uint8_t peerToken[kAdvertisementTokenBytes] = {};
  if (target == nullptr || !extractNodePeerToken(*target, peerToken)) return false;
  if (nodePeerClient == nullptr) {
    nodePeerClient = BLEDevice::createClient();
    if (nodePeerClient == nullptr) return false;
    nodePeerClient->setClientCallbacks(&nodePeerClientCallbacks);
  }
  if (!nodePeerClient->connectTimeout(target, kNodePeerConnectTimeoutMs)) {
    return false;
  }
  nodePeerClient->setMTU(247);
  BLERemoteService* service =
      nodePeerClient->getService(BLEUUID(kServiceUuid));
  nodePeerRemote = service == nullptr
      ? nullptr
      : service->getCharacteristic(BLEUUID(kTransferCharacteristicUuid));
  bool success = nodePeerRemote != nullptr && nodePeerRemote->canRead() &&
      nodePeerRemote->canWrite();
  NodePeerCrypto crypto;
  const uint16_t mtu = std::max<uint16_t>(23, nodePeerClient->getMTU());
  success = success && establishNodePeerSession(
      nodePeerRemote, mtu, peerToken, &crypto);
  success = success && venueAllowsNodeIdentity(crypto.serverIdentity.data());
  success = success && mutuallyAuthenticateNodePeer(
      nodePeerRemote, mtu, &crypto);
  success = success && synchronizeNodePeer(nodePeerRemote, mtu, &crypto);
  resetNodePeerCrypto(&crypto);
  pendingOffers.clear();
  if (nodePeerClient->isConnected()) nodePeerClient->disconnect();
  nodePeerRemote = nullptr;
  return success;
}

void startNodePeerRelay() {
  nodePeerScanner = BLEDevice::getScan();
  if (nodePeerScanner == nullptr) return;
  nodePeerScanner->setAdvertisedDeviceCallbacks(
      &nodePeerAdvertisedCallbacks, false, true);
  nodePeerScanner->setActiveScan(true);
  nodePeerScanner->setInterval(400);
  nodePeerScanner->setWindow(160);
  nodePeerReadyState = true;
  nodePeerLastAttemptMs = millis();
}

void pollNodePeerRelay() {
  if (!storageReady || !identityReady || !venueRelayAllowed() ||
      !nodePeerReadyState || nodePeerBusyState || serverClientConnected ||
      sessionReady || inboundActive || !pendingOffers.empty()) {
    return;
  }
  const uint32_t now = millis();
  if (!nodePeerForced &&
      (now - nodePeerLastAttemptMs < kNodePeerScanIntervalMs ||
       now - lastServerActivityMs < kNodePeerPhoneIdleMs)) {
    return;
  }
  nodePeerForced = false;
  nodePeerBusyState = true;
  nodePeerLastAttemptMs = now;
  if (nodePeerTarget != nullptr) {
    delete nodePeerTarget;
    nodePeerTarget = nullptr;
  }
  nodePeerScanner->start(1, false);
  nodePeerScanner->clearResults();
  if (nodePeerTarget != nullptr && !serverClientConnected) {
    nodePeerLastAddress = nodePeerTarget->getAddress().toString();
    nodePeerLastAddressAtMs = millis();
    BLEDevice::getAdvertising()->stop();
    const bool success = runNodePeerSync(nodePeerTarget);
    if (success) {
      ++nodePeerSuccessCount;
    } else {
      ++nodePeerFailureCount;
    }
    if (!serverAdvertisingBackoff) BLEDevice::getAdvertising()->start();
    delete nodePeerTarget;
    nodePeerTarget = nullptr;
  }
  nodePeerBusyState = false;
}

bool nodePeerRelayReady() { return nodePeerReadyState; }
bool nodePeerRelayBusy() { return nodePeerBusyState; }
uint32_t nodePeerSyncSuccesses() { return nodePeerSuccessCount; }
uint32_t nodePeerSyncFailures() { return nodePeerFailureCount; }
void requestNodePeerSync() { nodePeerForced = true; }

#endif  // HYPHA_NODE_PEER_H
