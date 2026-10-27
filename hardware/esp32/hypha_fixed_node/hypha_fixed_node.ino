#include <Arduino.h>
#include <BLE2902.h>
#include <BLEAdvertising.h>
#include <BLEClient.h>
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <FS.h>
#include <LittleFS.h>
#include <Preferences.h>
#include <esp_system.h>
#include <esp_task_wdt.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "hypha_ble_session_guard.h"
#include "hypha_venue_inventory.h"

namespace {

constexpr uint32_t kSerialBaud = 115200;
constexpr char kServiceUuid[] = "7e57d014-2b97-4d12-9f65-53a4c7a36c81";
constexpr char kTransferCharacteristicUuid[] = "7e57d015-2b97-4d12-9f65-53a4c7a36c81";
constexpr uint8_t kAdvertisementPrefix[] = {'H', 'N', 0x01};
constexpr size_t kAdvertisementTokenBytes = 8;
constexpr size_t kObjectIdBytes = 16;
constexpr size_t kDigestBytes = 32;
// A maximum-size typed reply produces a 4,196-byte opaque RLY1 envelope.
// Keep modest framing headroom while remaining tightly bounded for ESP RAM.
constexpr size_t kMaximumRecordBytes = 4352;
constexpr size_t kMaximumRecords = 192;
constexpr size_t kReservedControlRecords = 24;
constexpr size_t kMaximumTransferBytes = 16 * 1024;
constexpr size_t kMaximumSyncBytes = 12 * 1024;
constexpr size_t kMaximumOffersPerSync = 12;
constexpr size_t kMaximumControlOffersPerSync = 8;
constexpr char kStoreDirectory[] = "/mesh";
constexpr char kVenueInventorySlot0[] = "/venue0.hvi";
constexpr char kVenueInventorySlot1[] = "/venue1.hvi";
constexpr char kVenuePreferencesNamespace[] = "hypha-venue";
constexpr char kVenueAnchorKey[] = "anchor";
constexpr uint8_t kVenueAnchorMagic[] = {'H', 'V', 'A', '1'};
constexpr size_t kVenueAnchorBytes = 97;
constexpr uint8_t kStoreMagic[] = {'H', 'N', 'M', '1'};
constexpr size_t kStoreHeaderBytes = sizeof(kStoreMagic) + 2 + kDigestBytes;
constexpr uint8_t kRlyMagic[] = {'R', 'L', 'Y', '1'};
constexpr uint8_t kRmsRequestMagic[] = {'R', 'M', 'S', '2'};
constexpr uint8_t kRmsResponseMagic[] = {'R', 'M', 'R', '2'};
constexpr uint8_t kRmsAckMagic[] = {'R', 'M', 'A', '2'};
constexpr uint8_t kRmsCompletionMagic[] = {'R', 'M', 'C', '2'};
constexpr uint8_t kRmsFinalAckMagic[] = {'R', 'M', 'F', '2'};
constexpr size_t kRlyHeaderBytes = 64;
constexpr size_t kRlyIdOffset = 8;
constexpr size_t kRlyLifetimeOffset = 40;
constexpr size_t kRlyAgeOffset = 48;
constexpr size_t kRlyHopLimitOffset = 56;
constexpr size_t kRlyHopsTakenOffset = 57;
constexpr size_t kRlyCopyBudgetOffset = 58;
constexpr size_t kRlyCiphertextLengthOffset = 60;
constexpr uint64_t kMaximumLifetimeMs = 30ULL * 24ULL * 60ULL * 60ULL * 1000ULL;
constexpr uint8_t kControlPriority = 0;
constexpr size_t kExchangeHeaderBytes = 14;
constexpr size_t kMaximumExchangeIds = 512;
constexpr size_t kMaximumExchangeEnvelopes = 48;
constexpr uint8_t kExchangeVersion = 2;

constexpr uint8_t kFrameStartMagic[] = {'H', 'N', 'F', '1'};
constexpr uint8_t kFrameDataMagic[] = {'H', 'N', 'D', '1'};
constexpr uint8_t kFrameResponseMagic[] = {'H', 'N', 'R', '1'};
constexpr size_t kStartFrameBytes = 12;
constexpr size_t kDataHeaderBytes = 8;
constexpr size_t kResponseHeaderBytes = 14;
constexpr uint8_t kTransferHello = 1;
constexpr uint8_t kTransferSecure = 2;
constexpr uint8_t kResponseHello = 1;
constexpr uint8_t kResponseSecure = 2;
constexpr uint8_t kResponseError = 0x7f;

constexpr uint8_t kHelloMagic[] = {'H', 'N', 'H', '1'};
constexpr uint8_t kHelloResponseMagic[] = {'H', 'N', 'S', '1'};
constexpr uint8_t kFinishMagic[] = {'H', 'N', 'F', '1'};
constexpr uint8_t kWelcomeMagic[] = {'H', 'N', 'W', '1'};
constexpr uint8_t kDoneMagic[] = {'H', 'N', 'O', '1'};
constexpr uint8_t kNodeAuthMagic[] = {'H', 'N', 'A', '1'};
constexpr uint8_t kNodeAuthOkMagic[] = {'H', 'N', 'X', '1'};
constexpr size_t kNonceBytes = 16;
constexpr size_t kP256PublicBytes = 65;
constexpr size_t kAesKeyBytes = 32;
constexpr size_t kSessionKeyBytes = kAesKeyBytes * 2;
constexpr size_t kGcmTagBytes = 16;
constexpr size_t kGcmNonceBytes = 12;
constexpr size_t kSequenceBytes = 8;
constexpr uint8_t kClientNoncePrefix[] = {'C', '2', 'N', 0x01};
constexpr uint8_t kNodeNoncePrefix[] = {'N', '2', 'C', 0x01};
constexpr char kHandshakeDomain[] = "Hypha fixed node handshake v1\0";
constexpr char kSessionDomain[] = "Hypha fixed node session v1\0";
constexpr char kRecordDomain[] = "Hypha fixed node record v1\0";
constexpr char kNodeAuthDomain[] = "Hypha fixed node mutual auth v1\0";

using ObjectId = std::array<uint8_t, kObjectIdBytes>;

struct StoredRecord {
  ObjectId id{};
  std::vector<uint8_t> wire;
};

struct PendingOffer {
  ObjectId id{};
  std::vector<uint8_t> retainedWire;
  std::vector<uint8_t> forwardedWire;
};

struct OfferCandidate {
  ObjectId id;
  uint8_t priority;
  uint64_t age;
};

struct VenueAnchor {
  uint8_t slot = 0;
  uint64_t version = 0;
  std::array<uint8_t, HyphaVenueInventory::kVenueIdBytes> venueId{};
  std::array<uint8_t, HyphaVenueInventory::kP256PublicBytes> authority{};
};

enum class StoreOutcome {
  kCommitted,
  kDuplicate,
  kConflict,
  kFull,
  kFailed,
};

std::array<uint8_t, kAdvertisementTokenBytes> advertisementToken{};
mbedtls_ecp_keypair identityKey;
bool identityReady = false;
bool storageReady = false;
BLECharacteristic* transferCharacteristic = nullptr;
BLEServer* bleServer = nullptr;
uint16_t negotiatedMtu = 23;

std::vector<uint8_t> inboundPayload;
uint8_t inboundType = 0;
uint32_t inboundCrc = 0;
uint16_t inboundNextSequence = 0;
size_t inboundExpectedBytes = 0;
bool inboundActive = false;
std::vector<uint8_t> outboundPayload;
uint8_t outboundKind = kResponseError;
uint32_t outboundCrc = 0;
size_t outboundOffset = 0;
uint16_t outboundNextSequence = 0;
std::vector<PendingOffer> pendingOffers;

std::array<uint8_t, kAesKeyBytes> clientToNodeKey{};
std::array<uint8_t, kAesKeyBytes> nodeToClientKey{};
uint64_t expectedClientSequence = 0;
uint64_t nextNodeSequence = 0;
bool sessionReady = false;
bool nodePeerAuthenticated = false;
volatile bool serverClientConnected = false;
volatile bool serverDisconnectPending = false;
volatile bool serverGuardAuthenticated = false;
volatile bool serverProtocolViolation = false;
volatile bool serverAdvertisingBackoff = false;
volatile uint16_t serverConnectionId = 0;
volatile uint32_t serverConnectedAtMs = 0;
volatile uint32_t lastServerActivityMs = 0;
volatile uint32_t serverDeclaredBytes = 0;
volatile uint32_t serverTransferStarts = 0;
volatile uint32_t serverHelloStarts = 0;
volatile uint32_t serverWrites = 0;
volatile uint32_t serverReads = 0;
HyphaBleSessionGuard::DisconnectReason lastServerGuardReason =
    HyphaBleSessionGuard::DisconnectReason::kNone;
uint32_t serverGuardDisconnectCount = 0;
uint32_t serverGuardBackoffCount = 0;
uint32_t serverGuardBackoffUntilMs = 0;
std::array<uint32_t,
           HyphaBleSessionGuard::kFailuresBeforeBackoff>
    serverGuardFailureTimes{};
uint8_t serverGuardFailuresInWindow = 0;
uint32_t serverResourceWindowStartedMs = 0;
volatile uint32_t serverConnectionsInWindow = 0;
volatile uint32_t serverDeclaredBytesInWindow = 0;
volatile uint32_t serverWritesInWindow = 0;
volatile uint32_t serverReadsInWindow = 0;
// One reconnecting radio is isolated inside its own window so it can neither consume the
// aggregate allowance nor push legitimate phones into global advertising backoff.
HyphaBleSessionGuard::PeerConnectionWindows serverPeerWindows{};
volatile bool serverPeerLimited = false;
uint32_t serverPeerIsolationCount = 0;
constexpr uint32_t kLoopWatchdogMs = 60U * 1000U;

bool venueManaged = false;
bool venuePolicyReady = false;
VenueAnchor venueAnchor;
std::vector<uint8_t> venueInventoryWire;
std::vector<uint8_t> venueInventoryStaging;
size_t venueInventoryExpectedBytes = 0;

bool nodePeerRelayBusy();

char serialCommand[97] = {};
size_t serialCommandBytes = 0;
bool serialOverflow = false;

uint16_t readU16(const uint8_t* source) {
  return (static_cast<uint16_t>(source[0]) << 8) | source[1];
}

uint32_t readU32(const uint8_t* source) {
  return (static_cast<uint32_t>(source[0]) << 24) |
         (static_cast<uint32_t>(source[1]) << 16) |
         (static_cast<uint32_t>(source[2]) << 8) | source[3];
}

uint64_t readU64(const uint8_t* source) {
  uint64_t value = 0;
  for (size_t index = 0; index < 8; ++index) {
    value = (value << 8) | source[index];
  }
  return value;
}

void putU16(uint8_t* target, uint16_t value) {
  target[0] = static_cast<uint8_t>(value >> 8);
  target[1] = static_cast<uint8_t>(value);
}

void putU32(uint8_t* target, uint32_t value) {
  target[0] = static_cast<uint8_t>(value >> 24);
  target[1] = static_cast<uint8_t>(value >> 16);
  target[2] = static_cast<uint8_t>(value >> 8);
  target[3] = static_cast<uint8_t>(value);
}

void putU64(uint8_t* target, uint64_t value) {
  for (size_t index = 0; index < 8; ++index) {
    target[7 - index] = static_cast<uint8_t>(value);
    value >>= 8;
  }
}

uint32_t crc32(const uint8_t* bytes, size_t length) {
  uint32_t value = 0xffffffffU;
  for (size_t index = 0; index < length; ++index) {
    value ^= bytes[index];
    for (uint8_t bit = 0; bit < 8; ++bit) {
      value = (value >> 1) ^ (0xedb88320U &
              static_cast<uint32_t>(-static_cast<int32_t>(value & 1U)));
    }
  }
  return value ^ 0xffffffffU;
}

bool monotonicDeadlinePending(uint32_t nowMs, uint32_t deadlineMs) {
  return static_cast<int32_t>(deadlineMs - nowMs) > 0;
}

const char* serverGuardReasonName(
    HyphaBleSessionGuard::DisconnectReason reason) {
  switch (reason) {
    case HyphaBleSessionGuard::DisconnectReason::kNone:
      return "none";
    case HyphaBleSessionGuard::DisconnectReason::kProtocolViolation:
      return "protocol";
    case HyphaBleSessionGuard::DisconnectReason::kHandshakeLimit:
      return "handshakes";
    case HyphaBleSessionGuard::DisconnectReason::kTransferLimit:
      return "transfers";
    case HyphaBleSessionGuard::DisconnectReason::kDeclaredByteLimit:
      return "bytes";
    case HyphaBleSessionGuard::DisconnectReason::kWriteLimit:
      return "writes";
    case HyphaBleSessionGuard::DisconnectReason::kReadLimit:
      return "reads";
    case HyphaBleSessionGuard::DisconnectReason::kPeerConnectionWindowLimit:
      return "peer_connection_window";
    case HyphaBleSessionGuard::DisconnectReason::kConnectionWindowLimit:
      return "window_connections";
    case HyphaBleSessionGuard::DisconnectReason::kDeclaredByteWindowLimit:
      return "window_bytes";
    case HyphaBleSessionGuard::DisconnectReason::kWriteWindowLimit:
      return "window_writes";
    case HyphaBleSessionGuard::DisconnectReason::kReadWindowLimit:
      return "window_reads";
    case HyphaBleSessionGuard::DisconnectReason::kAuthenticationDeadline:
      return "auth_timeout";
    case HyphaBleSessionGuard::DisconnectReason::kConnectionLifetime:
      return "lifetime";
    case HyphaBleSessionGuard::DisconnectReason::kAuthenticatedIdle:
      return "idle";
  }
  return "unknown";
}

void refreshServerResourceWindow(uint32_t nowMs) {
  if (HyphaBleSessionGuard::elapsed(
          nowMs, serverResourceWindowStartedMs) <
      HyphaBleSessionGuard::kResourceWindowMs) {
    return;
  }
  serverResourceWindowStartedMs = nowMs;
  serverConnectionsInWindow = 0;
  serverDeclaredBytesInWindow = 0;
  serverWritesInWindow = 0;
  serverReadsInWindow = 0;
}

HyphaBleSessionGuard::WindowSnapshot serverGuardWindowSnapshot() {
  return HyphaBleSessionGuard::WindowSnapshot{
      serverConnectionsInWindow,
      serverDeclaredBytesInWindow,
      serverWritesInWindow,
      serverReadsInWindow,
  };
}

HyphaBleSessionGuard::Snapshot serverGuardSnapshot() {
  return HyphaBleSessionGuard::Snapshot{
      serverClientConnected,
      serverGuardAuthenticated,
      serverProtocolViolation,
      serverConnectedAtMs,
      lastServerActivityMs,
      serverDeclaredBytes,
      serverTransferStarts,
      serverHelloStarts,
      serverWrites,
      serverReads,
  };
}

void resetServerGuardConnection(uint32_t nowMs) {
  serverDisconnectPending = false;
  serverGuardAuthenticated = false;
  serverProtocolViolation = false;
  serverConnectedAtMs = nowMs;
  lastServerActivityMs = nowMs;
  serverDeclaredBytes = 0;
  serverTransferStarts = 0;
  serverHelloStarts = 0;
  serverWrites = 0;
  serverReads = 0;
}

void recordServerGuardFailure(uint32_t nowMs) {
  uint8_t retained = 0;
  for (uint8_t index = 0; index < serverGuardFailuresInWindow; ++index) {
    if (HyphaBleSessionGuard::elapsed(
            nowMs, serverGuardFailureTimes[index]) <
        HyphaBleSessionGuard::kFailureWindowMs) {
      serverGuardFailureTimes[retained++] =
          serverGuardFailureTimes[index];
    }
  }
  serverGuardFailuresInWindow = retained;
  serverGuardFailureTimes[serverGuardFailuresInWindow++] = nowMs;
  if (!HyphaBleSessionGuard::shouldBackoff(
          serverGuardFailuresInWindow)) {
    return;
  }
  serverGuardFailuresInWindow = 0;
  serverGuardBackoffUntilMs = nowMs + HyphaBleSessionGuard::kBackoffMs;
  serverAdvertisingBackoff = true;
  ++serverGuardBackoffCount;
  BLEDevice::getAdvertising()->stop();
}

void recordSuccessfulServerExchange() {
  serverGuardFailuresInWindow = 0;
}

bool fixedEquals(const uint8_t* left, const uint8_t* right, size_t bytes) {
  uint8_t difference = 0;
  for (size_t index = 0; index < bytes; ++index) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

int hardwareRandom(void*, unsigned char* output, size_t bytes) {
  esp_fill_random(output, bytes);
  return 0;
}

void bytesToHex(const uint8_t* source, size_t bytes, char* target) {
  static constexpr char kHex[] = "0123456789abcdef";
  for (size_t index = 0; index < bytes; ++index) {
    target[index * 2] = kHex[source[index] >> 4];
    target[index * 2 + 1] = kHex[source[index] & 0x0f];
  }
  target[bytes * 2] = '\0';
}

bool hasSuffix(const char* value, const char* suffix) {
  const size_t valueBytes = strlen(value);
  const size_t suffixBytes = strlen(suffix);
  return valueBytes >= suffixBytes &&
         strcmp(value + valueBytes - suffixBytes, suffix) == 0;
}

bool makeRecordPath(const ObjectId& id, const char* suffix,
                    char* target, size_t targetBytes) {
  char idHex[kObjectIdBytes * 2 + 1] = {};
  bytesToHex(id.data(), id.size(), idHex);
  const int written = snprintf(target, targetBytes, "%s/%s%s",
                               kStoreDirectory, idHex, suffix);
  return written > 0 && static_cast<size_t>(written) < targetBytes;
}

bool digest(const uint8_t* bytes, size_t length, uint8_t output[kDigestBytes]) {
  return mbedtls_sha256(bytes, length, output, 0) == 0;
}

bool readExact(File& file, uint8_t* target, size_t bytes) {
  return file.read(target, bytes) == bytes;
}

bool sameOpaquePayload(const std::vector<uint8_t>& left,
                       const std::vector<uint8_t>& right) {
  if (left.size() != right.size() || left.size() <= kRlyHeaderBytes) return false;
  return memcmp(left.data(), right.data(), kRlyAgeOffset) == 0 &&
         left[kRlyHopLimitOffset] == right[kRlyHopLimitOffset] &&
         memcmp(left.data() + kRlyCiphertextLengthOffset,
                right.data() + kRlyCiphertextLengthOffset,
                left.size() - kRlyCiphertextLengthOffset) == 0;
}

bool validateEnvelope(const uint8_t* wire, size_t bytes, ObjectId* id = nullptr) {
  if (bytes <= kRlyHeaderBytes || bytes > kMaximumRecordBytes ||
      memcmp(wire, kRlyMagic, sizeof(kRlyMagic)) != 0 || wire[4] != 1 ||
      wire[5] > 5 || wire[6] != 0 || wire[7] != 0) {
    return false;
  }
  const uint64_t lifetime = readU64(wire + kRlyLifetimeOffset);
  const uint64_t age = readU64(wire + kRlyAgeOffset);
  const uint8_t hopLimit = wire[kRlyHopLimitOffset];
  const uint8_t hopsTaken = wire[kRlyHopsTakenOffset];
  const uint16_t copyBudget = readU16(wire + kRlyCopyBudgetOffset);
  const uint32_t ciphertextBytes = readU32(wire + kRlyCiphertextLengthOffset);
  if (lifetime == 0 || lifetime > kMaximumLifetimeMs || age > lifetime ||
      hopLimit == 0 || hopsTaken > hopLimit || copyBudget == 0 || copyBudget > 64 ||
      ciphertextBytes == 0 || ciphertextBytes != bytes - kRlyHeaderBytes) {
    return false;
  }
  if (id != nullptr) {
    memcpy(id->data(), wire + kRlyIdOffset, id->size());
  }
  return true;
}

bool readRecordPath(const char* path, const ObjectId& id, StoredRecord* record) {
  if (!LittleFS.exists(path)) return false;
  File file = LittleFS.open(path, FILE_READ);
  if (!file || file.isDirectory()) {
    if (file) file.close();
    return false;
  }
  uint8_t magic[sizeof(kStoreMagic)] = {};
  uint8_t encodedLength[2] = {};
  uint8_t storedDigest[kDigestBytes] = {};
  bool valid = readExact(file, magic, sizeof(magic)) &&
               readExact(file, encodedLength, sizeof(encodedLength)) &&
               readExact(file, storedDigest, sizeof(storedDigest));
  const size_t payloadBytes = readU16(encodedLength);
  valid = valid && memcmp(magic, kStoreMagic, sizeof(magic)) == 0 &&
          payloadBytes > kRlyHeaderBytes && payloadBytes <= kMaximumRecordBytes &&
          file.size() == kStoreHeaderBytes + payloadBytes;
  if (!valid) {
    file.close();
    return false;
  }
  std::vector<uint8_t> payload(payloadBytes);
  valid = readExact(file, payload.data(), payload.size());
  file.close();
  uint8_t calculatedDigest[kDigestBytes] = {};
  ObjectId wireId{};
  valid = valid && digest(payload.data(), payload.size(), calculatedDigest) &&
          fixedEquals(storedDigest, calculatedDigest, sizeof(storedDigest)) &&
          validateEnvelope(payload.data(), payload.size(), &wireId) && wireId == id;
  if (!valid) return false;
  record->id = id;
  record->wire = std::move(payload);
  return true;
}

bool readRecord(const ObjectId& id, StoredRecord* record) {
  char path[64] = {};
  return makeRecordPath(id, ".obj", path, sizeof(path)) &&
      readRecordPath(path, id, record);
}

bool writeTemporaryRecord(const char* path, const uint8_t* wire, size_t bytes) {
  uint8_t payloadDigest[kDigestBytes] = {};
  if (!digest(wire, bytes, payloadDigest)) return false;
  if (LittleFS.exists(path) && !LittleFS.remove(path)) return false;
  File file = LittleFS.open(path, FILE_WRITE);
  uint8_t encodedLength[2] = {};
  putU16(encodedLength, static_cast<uint16_t>(bytes));
  const bool wrote = file &&
      file.write(kStoreMagic, sizeof(kStoreMagic)) == sizeof(kStoreMagic) &&
      file.write(encodedLength, sizeof(encodedLength)) == sizeof(encodedLength) &&
      file.write(payloadDigest, sizeof(payloadDigest)) == sizeof(payloadDigest) &&
      file.write(wire, bytes) == bytes;
  if (file) {
    file.flush();
    file.close();
  }
  return wrote;
}

size_t recordCount() {
  size_t count = 0;
  File directory = LittleFS.open(kStoreDirectory);
  if (!directory || !directory.isDirectory()) {
    if (directory) directory.close();
    return 0;
  }
  File entry = directory.openNextFile();
  while (entry) {
    if (!entry.isDirectory() && hasSuffix(entry.name(), ".obj")) ++count;
    entry.close();
    entry = directory.openNextFile();
  }
  directory.close();
  return count;
}

bool parseObjectIdFromName(const char* name, ObjectId* id);

bool selectControlEvictionCandidate(ObjectId* selected) {
  if (selected == nullptr) return false;
  bool found = false;
  uint8_t selectedPriority = kControlPriority;
  uint64_t selectedAge = 0;
  File directory = LittleFS.open(kStoreDirectory);
  if (!directory || !directory.isDirectory()) {
    if (directory) directory.close();
    return false;
  }
  File entry = directory.openNextFile();
  while (entry) {
    ObjectId id{};
    const bool candidate = !entry.isDirectory() &&
        parseObjectIdFromName(entry.name(), &id);
    entry.close();
    if (candidate) {
      StoredRecord record;
      if (readRecord(id, &record)) {
        const uint8_t priority = record.wire[5];
        const uint64_t age = readU64(record.wire.data() + kRlyAgeOffset);
        if (priority > kControlPriority &&
            (!found || priority > selectedPriority ||
             (priority == selectedPriority && age > selectedAge) ||
             (priority == selectedPriority && age == selectedAge && id < *selected))) {
          *selected = id;
          selectedPriority = priority;
          selectedAge = age;
          found = true;
        }
      }
    }
    entry = directory.openNextFile();
  }
  directory.close();
  return found;
}

bool clearStoredRecords(size_t* removedRecords) {
  if (!storageReady || removedRecords == nullptr) return false;
  *removedRecords = 0;
  File directory = LittleFS.open(kStoreDirectory);
  if (!directory || !directory.isDirectory()) {
    if (directory) directory.close();
    return false;
  }
  std::vector<String> names;
  File entry = directory.openNextFile();
  while (entry) {
    const String name(entry.name());
    if (!entry.isDirectory() &&
        (name.endsWith(".obj") || name.endsWith(".tmp") ||
         name.endsWith(".bak"))) {
      names.push_back(name);
    }
    entry.close();
    entry = directory.openNextFile();
  }
  directory.close();

  bool removedAll = true;
  for (const String& name : names) {
    const bool durableRecord = name.endsWith(".obj");
    const int separator = name.lastIndexOf('/');
    const String baseName = separator >= 0 ? name.substring(separator + 1) : name;
    const String path = String(kStoreDirectory) + "/" + baseName;
    if (LittleFS.remove(path)) {
      if (durableRecord) ++(*removedRecords);
    } else {
      removedAll = false;
    }
  }
  return removedAll && recordCount() == 0;
}

StoreOutcome storeEnvelope(const uint8_t* wire, size_t bytes) {
  if (!storageReady) return StoreOutcome::kFailed;
  ObjectId id{};
  if (!validateEnvelope(wire, bytes, &id)) return StoreOutcome::kFailed;
  StoredRecord existing;
  if (readRecord(id, &existing)) {
    const std::vector<uint8_t> offered(wire, wire + bytes);
    return sameOpaquePayload(existing.wire, offered)
        ? StoreOutcome::kDuplicate
        : StoreOutcome::kConflict;
  }
  const uint8_t priority = wire[5];
  const size_t storedRecords = recordCount();
  ObjectId evictionId{};
  bool evictForControl = false;
  if (priority == kControlPriority) {
    if (storedRecords >= kMaximumRecords) {
      evictForControl = selectControlEvictionCandidate(&evictionId);
      if (!evictForControl) return StoreOutcome::kFull;
    }
  } else if (storedRecords >= kMaximumRecords - kReservedControlRecords) {
    return StoreOutcome::kFull;
  }
  char temporaryPath[64] = {};
  char finalPath[64] = {};
  char evictionPath[64] = {};
  char evictionBackupPath[64] = {};
  if (!makeRecordPath(id, ".tmp", temporaryPath, sizeof(temporaryPath)) ||
      !makeRecordPath(id, ".obj", finalPath, sizeof(finalPath)) ||
      !writeTemporaryRecord(temporaryPath, wire, bytes)) {
    LittleFS.remove(temporaryPath);
    return StoreOutcome::kFailed;
  }
  if (evictForControl) {
    if (!makeRecordPath(evictionId, ".obj", evictionPath, sizeof(evictionPath)) ||
        !makeRecordPath(evictionId, ".bak", evictionBackupPath,
                        sizeof(evictionBackupPath)) ||
        (LittleFS.exists(evictionBackupPath) &&
         !LittleFS.remove(evictionBackupPath)) ||
        !LittleFS.rename(evictionPath, evictionBackupPath)) {
      LittleFS.remove(temporaryPath);
      return StoreOutcome::kFailed;
    }
  }
  if (!LittleFS.rename(temporaryPath, finalPath)) {
    if (evictForControl) LittleFS.rename(evictionBackupPath, evictionPath);
    LittleFS.remove(temporaryPath);
    return StoreOutcome::kFailed;
  }
  StoredRecord committed;
  if (!readRecord(id, &committed) || committed.wire.size() != bytes ||
      memcmp(committed.wire.data(), wire, bytes) != 0) {
    LittleFS.remove(finalPath);
    if (evictForControl) LittleFS.rename(evictionBackupPath, evictionPath);
    return StoreOutcome::kFailed;
  }
  if (evictForControl && !LittleFS.remove(evictionBackupPath)) {
    LittleFS.remove(finalPath);
    LittleFS.rename(evictionBackupPath, evictionPath);
    return StoreOutcome::kFailed;
  }
  return StoreOutcome::kCommitted;
}

bool replaceEnvelope(const ObjectId& id, const std::vector<uint8_t>& wire) {
  ObjectId wireId{};
  if (!validateEnvelope(wire.data(), wire.size(), &wireId) || wireId != id) return false;
  char temporaryPath[64] = {};
  char finalPath[64] = {};
  char backupPath[64] = {};
  if (!makeRecordPath(id, ".tmp", temporaryPath, sizeof(temporaryPath)) ||
      !makeRecordPath(id, ".obj", finalPath, sizeof(finalPath)) ||
      !makeRecordPath(id, ".bak", backupPath, sizeof(backupPath)) ||
      !writeTemporaryRecord(temporaryPath, wire.data(), wire.size())) {
    return false;
  }
  if (LittleFS.exists(backupPath) && !LittleFS.remove(backupPath)) {
    LittleFS.remove(temporaryPath);
    return false;
  }
  if (!LittleFS.rename(finalPath, backupPath)) {
    LittleFS.remove(temporaryPath);
    return false;
  }
  if (!LittleFS.rename(temporaryPath, finalPath)) {
    LittleFS.rename(backupPath, finalPath);
    LittleFS.remove(temporaryPath);
    return false;
  }
  StoredRecord committed;
  if (!readRecord(id, &committed) || committed.wire != wire) {
    LittleFS.remove(finalPath);
    LittleFS.rename(backupPath, finalPath);
    return false;
  }
  return LittleFS.remove(backupPath);
}

bool recoveryObjectId(const char* name, const char* suffix, ObjectId* id) {
  const char* base = strrchr(name, '/');
  base = base == nullptr ? name : base + 1;
  if (strlen(base) != kObjectIdBytes * 2 + 4 || !hasSuffix(base, suffix)) return false;
  char objectName[kObjectIdBytes * 2 + 5] = {};
  memcpy(objectName, base, kObjectIdBytes * 2);
  memcpy(objectName + kObjectIdBytes * 2, ".obj", 5);
  return parseObjectIdFromName(objectName, id);
}

bool recoverStoreFiles() {
  File directory = LittleFS.open(kStoreDirectory);
  if (!directory || !directory.isDirectory()) {
    if (directory) directory.close();
    return false;
  }
  std::vector<String> names;
  File entry = directory.openNextFile();
  while (entry) {
    if (!entry.isDirectory()) names.emplace_back(entry.name());
    entry.close();
    entry = directory.openNextFile();
  }
  directory.close();
  // Resolve durable backups before discarding uncommitted temporary files. File::name()
  // is a basename on the pinned core; reconstruct every path from a validated object ID.
  for (const String& name : names) {
    ObjectId id{};
    if (!recoveryObjectId(name.c_str(), ".bak", &id)) continue;
    char backupPath[64] = {};
    char finalPath[64] = {};
    if (!makeRecordPath(id, ".bak", backupPath, sizeof(backupPath)) ||
        !makeRecordPath(id, ".obj", finalPath, sizeof(finalPath))) return false;
    StoredRecord committed;
    if (readRecord(id, &committed)) {
      if (!LittleFS.remove(backupPath)) return false;
    } else {
      StoredRecord backup;
      if (!readRecordPath(backupPath, id, &backup) ||
          (LittleFS.exists(finalPath) && !LittleFS.remove(finalPath)) ||
          !LittleFS.rename(backupPath, finalPath)) return false;
      StoredRecord restored;
      if (!readRecord(id, &restored) || restored.wire != backup.wire) return false;
    }
  }
  for (const String& name : names) {
    ObjectId id{};
    if (!recoveryObjectId(name.c_str(), ".tmp", &id)) continue;
    char path[64] = {};
    if (!makeRecordPath(id, ".tmp", path, sizeof(path)) ||
        (LittleFS.exists(path) && !LittleFS.remove(path))) return false;
  }
  // An interrupted pressure eviction can leave both the victim backup and a newly
  // published record. Preserve them, but do not advertise ready custody above quota.
  return recordCount() <= kMaximumRecords;
}

bool initializeStorage() {
  Preferences preferences;
  if (!preferences.begin("hypha-node", false)) return false;
  const bool wasInitialized = preferences.getBool("fs-init", false);
  if (!LittleFS.begin(false)) {
    if (wasInitialized || !LittleFS.format() || !LittleFS.begin(false)) {
      preferences.end();
      return false;
    }
  }
  if (!wasInitialized && !preferences.putBool("fs-init", true)) {
    preferences.end();
    LittleFS.end();
    return false;
  }
  preferences.end();
  if (!LittleFS.exists(kStoreDirectory) && !LittleFS.mkdir(kStoreDirectory)) {
    LittleFS.end();
    return false;
  }
  return recoverStoreFiles();
}

bool exportPublicKey(const mbedtls_ecp_keypair& key,
                     uint8_t output[kP256PublicBytes]) {
  size_t written = 0;
  return mbedtls_ecp_point_write_binary(
      &key.MBEDTLS_PRIVATE(grp), &key.MBEDTLS_PRIVATE(Q),
      MBEDTLS_ECP_PF_UNCOMPRESSED, &written, output, kP256PublicBytes) == 0 &&
      written == kP256PublicBytes;
}

bool signTranscript(const mbedtls_ecp_keypair& key,
                    const std::vector<uint8_t>& transcript,
                    std::vector<uint8_t>* signature) {
  uint8_t transcriptHash[kDigestBytes] = {};
  if (!digest(transcript.data(), transcript.size(), transcriptHash)) return false;
  mbedtls_ecdsa_context signer;
  mbedtls_ecdsa_init(&signer);
  uint8_t encoded[MBEDTLS_ECDSA_MAX_LEN] = {};
  size_t encodedBytes = 0;
  const bool success = mbedtls_ecdsa_from_keypair(&signer, &key) == 0 &&
      mbedtls_ecdsa_write_signature(
          &signer, MBEDTLS_MD_SHA256, transcriptHash, sizeof(transcriptHash),
          encoded, sizeof(encoded), &encodedBytes, hardwareRandom, nullptr) == 0;
  mbedtls_ecdsa_free(&signer);
  memset(transcriptHash, 0, sizeof(transcriptHash));
  if (!success || encodedBytes == 0 || encodedBytes > 80) return false;
  signature->assign(encoded, encoded + encodedBytes);
  memset(encoded, 0, sizeof(encoded));
  return true;
}

bool verifyTranscript(const uint8_t publicKey[kP256PublicBytes],
                      const std::vector<uint8_t>& transcript,
                      const uint8_t* signature, size_t signatureBytes) {
  if (signature == nullptr || signatureBytes == 0 || signatureBytes > 80) return false;
  uint8_t transcriptHash[kDigestBytes] = {};
  if (!digest(transcript.data(), transcript.size(), transcriptHash)) return false;
  mbedtls_ecp_keypair verifierKey;
  mbedtls_ecp_keypair_init(&verifierKey);
  mbedtls_ecdsa_context verifier;
  mbedtls_ecdsa_init(&verifier);
  bool success = mbedtls_ecp_group_load(
                     &verifierKey.MBEDTLS_PRIVATE(grp),
                     MBEDTLS_ECP_DP_SECP256R1) == 0 &&
      mbedtls_ecp_point_read_binary(
          &verifierKey.MBEDTLS_PRIVATE(grp), &verifierKey.MBEDTLS_PRIVATE(Q),
          publicKey, kP256PublicBytes) == 0 &&
      mbedtls_ecp_check_pubkey(
          &verifierKey.MBEDTLS_PRIVATE(grp),
          &verifierKey.MBEDTLS_PRIVATE(Q)) == 0 &&
      mbedtls_ecdsa_from_keypair(&verifier, &verifierKey) == 0 &&
      mbedtls_ecdsa_read_signature(
          &verifier, transcriptHash, sizeof(transcriptHash),
          signature, signatureBytes) == 0;
  mbedtls_ecdsa_free(&verifier);
  mbedtls_ecp_keypair_free(&verifierKey);
  memset(transcriptHash, 0, sizeof(transcriptHash));
  return success;
}

bool validP256PublicKey(const uint8_t publicKey[kP256PublicBytes]) {
  if (publicKey == nullptr || publicKey[0] != 0x04) return false;
  mbedtls_ecp_group group;
  mbedtls_ecp_group_init(&group);
  mbedtls_ecp_point point;
  mbedtls_ecp_point_init(&point);
  const bool valid = mbedtls_ecp_group_load(
                         &group, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
      mbedtls_ecp_point_read_binary(
          &group, &point, publicKey,
          HyphaVenueInventory::kP256PublicBytes) == 0 &&
      mbedtls_ecp_check_pubkey(&group, &point) == 0;
  mbedtls_ecp_point_free(&point);
  mbedtls_ecp_group_free(&group);
  return valid;
}

bool verifyVenueInventory(const std::vector<uint8_t>& encoded,
                          HyphaVenueInventory::View* parsed) {
  HyphaVenueInventory::View view;
  if (!HyphaVenueInventory::structurallyValid(
          encoded.data(), encoded.size(), &view) ||
      !validP256PublicKey(view.authorityPublicKey)) {
    return false;
  }
  for (uint16_t index = 0; index < view.entryCount; ++index) {
    if (!validP256PublicKey(
            view.entries + index * HyphaVenueInventory::kEntryBytes)) {
      return false;
    }
  }
  std::vector<uint8_t> transcript;
  transcript.reserve(sizeof(HyphaVenueInventory::kSignatureDomain) - 1 +
                     view.unsignedBytes);
  transcript.insert(
      transcript.end(), HyphaVenueInventory::kSignatureDomain,
      HyphaVenueInventory::kSignatureDomain +
          sizeof(HyphaVenueInventory::kSignatureDomain) - 1);
  transcript.insert(transcript.end(), encoded.begin(),
                    encoded.begin() + view.unsignedBytes);
  if (!verifyTranscript(view.authorityPublicKey, transcript, view.signature,
                        view.signatureBytes)) {
    return false;
  }
  if (parsed != nullptr) *parsed = view;
  return true;
}

bool currentIdentityIsActive(const HyphaVenueInventory::View& inventory) {
  uint8_t localIdentity[kP256PublicBytes] = {};
  return identityReady && exportPublicKey(identityKey, localIdentity) &&
      HyphaVenueInventory::statusFor(inventory, localIdentity) ==
          HyphaVenueInventory::kStatusActive;
}

bool sameFixedBytes(const uint8_t* left, const uint8_t* right, size_t bytes) {
  return left != nullptr && right != nullptr && fixedEquals(left, right, bytes);
}

const char* venueInventoryPath(uint8_t slot) {
  return slot == 0 ? kVenueInventorySlot0 : kVenueInventorySlot1;
}

bool readBoundedFile(const char* path, size_t maximumBytes,
                     std::vector<uint8_t>* output) {
  output->clear();
  File file = LittleFS.open(path, FILE_READ);
  if (!file || file.isDirectory() || file.size() == 0 ||
      file.size() > maximumBytes) {
    if (file) file.close();
    return false;
  }
  output->resize(file.size());
  const bool read = file.read(output->data(), output->size()) == output->size();
  file.close();
  if (!read) output->clear();
  return read;
}

bool writeBoundedFile(const char* path, const std::vector<uint8_t>& encoded) {
  if (LittleFS.exists(path) && !LittleFS.remove(path)) return false;
  File file = LittleFS.open(path, FILE_WRITE);
  const bool wrote = file &&
      file.write(encoded.data(), encoded.size()) == encoded.size();
  if (file) {
    file.flush();
    file.close();
  }
  if (!wrote) {
    LittleFS.remove(path);
    return false;
  }
  std::vector<uint8_t> verified;
  const bool matches = readBoundedFile(
      path, HyphaVenueInventory::kMaximumWireBytes, &verified) &&
      verified == encoded;
  if (!matches) LittleFS.remove(path);
  return matches;
}

void encodeVenueAnchor(const VenueAnchor& anchor,
                       uint8_t encoded[kVenueAnchorBytes]) {
  memset(encoded, 0, kVenueAnchorBytes);
  memcpy(encoded, kVenueAnchorMagic, sizeof(kVenueAnchorMagic));
  encoded[4] = anchor.slot;
  putU64(encoded + 8, anchor.version);
  memcpy(encoded + 16, anchor.venueId.data(), anchor.venueId.size());
  memcpy(encoded + 32, anchor.authority.data(), anchor.authority.size());
}

bool decodeVenueAnchor(const uint8_t encoded[kVenueAnchorBytes],
                       VenueAnchor* anchor) {
  if (memcmp(encoded, kVenueAnchorMagic, sizeof(kVenueAnchorMagic)) != 0 ||
      encoded[4] > 1 || encoded[5] != 0 || encoded[6] != 0 ||
      encoded[7] != 0) {
    return false;
  }
  const uint64_t version = readU64(encoded + 8);
  bool venueNonZero = false;
  for (size_t index = 0; index < HyphaVenueInventory::kVenueIdBytes; ++index) {
    venueNonZero = venueNonZero || encoded[16 + index] != 0;
  }
  if (version == 0 || version > INT64_MAX || !venueNonZero ||
      !validP256PublicKey(encoded + 32)) {
    return false;
  }
  anchor->slot = encoded[4];
  anchor->version = version;
  memcpy(anchor->venueId.data(), encoded + 16, anchor->venueId.size());
  memcpy(anchor->authority.data(), encoded + 32, anchor->authority.size());
  return true;
}

bool storeVenueAnchor(const VenueAnchor& anchor) {
  uint8_t encoded[kVenueAnchorBytes] = {};
  encodeVenueAnchor(anchor, encoded);
  Preferences preferences;
  if (!preferences.begin(kVenuePreferencesNamespace, false)) return false;
  const bool stored = preferences.putBytes(
      kVenueAnchorKey, encoded, sizeof(encoded)) == sizeof(encoded);
  preferences.end();
  return stored;
}

bool loadVenuePolicy() {
  venueManaged = false;
  venuePolicyReady = false;
  venueAnchor = VenueAnchor{};
  venueInventoryWire.clear();
  Preferences preferences;
  if (!preferences.begin(kVenuePreferencesNamespace, false)) {
    venueManaged = true;
    return false;
  }
  const size_t anchorBytes = preferences.getBytesLength(kVenueAnchorKey);
  if (anchorBytes == 0) {
    preferences.end();
    return true;
  }
  venueManaged = true;
  uint8_t encodedAnchor[kVenueAnchorBytes] = {};
  const bool loadedAnchor = anchorBytes == sizeof(encodedAnchor) &&
      preferences.getBytes(kVenueAnchorKey, encodedAnchor,
                           sizeof(encodedAnchor)) == sizeof(encodedAnchor) &&
      decodeVenueAnchor(encodedAnchor, &venueAnchor);
  preferences.end();
  if (!loadedAnchor || !storageReady ||
      !readBoundedFile(venueInventoryPath(venueAnchor.slot),
                       HyphaVenueInventory::kMaximumWireBytes,
                       &venueInventoryWire)) {
    venueInventoryWire.clear();
    return false;
  }
  HyphaVenueInventory::View inventory;
  const bool ready = verifyVenueInventory(venueInventoryWire, &inventory) &&
      inventory.version == venueAnchor.version &&
      sameFixedBytes(inventory.venueId, venueAnchor.venueId.data(),
                     venueAnchor.venueId.size()) &&
      sameFixedBytes(inventory.authorityPublicKey, venueAnchor.authority.data(),
                     venueAnchor.authority.size()) &&
      currentIdentityIsActive(inventory);
  venuePolicyReady = ready;
  if (!ready) venueInventoryWire.clear();
  return ready;
}

bool venueRelayAllowed() { return !venueManaged || venuePolicyReady; }

bool venueAllowsNodeIdentity(const uint8_t* publicKey) {
  if (!venueManaged) return true;
  if (!venuePolicyReady) return false;
  HyphaVenueInventory::View inventory;
  return HyphaVenueInventory::structurallyValid(
             venueInventoryWire.data(), venueInventoryWire.size(), &inventory) &&
      HyphaVenueInventory::statusFor(inventory, publicKey) ==
          HyphaVenueInventory::kStatusActive;
}

bool installVenueInventory(const std::vector<uint8_t>& encoded) {
  if (!storageReady || serverClientConnected || sessionReady || inboundActive ||
      !pendingOffers.empty() || nodePeerRelayBusy()) {
    return false;
  }
  HyphaVenueInventory::View inventory;
  if (!verifyVenueInventory(encoded, &inventory) ||
      !currentIdentityIsActive(inventory)) {
    return false;
  }
  const bool sameVenue = !venueManaged ||
      sameFixedBytes(inventory.venueId, venueAnchor.venueId.data(),
                     venueAnchor.venueId.size());
  const bool sameAuthority = !venueManaged ||
      sameFixedBytes(inventory.authorityPublicKey, venueAnchor.authority.data(),
                     venueAnchor.authority.size());
  if (!HyphaVenueInventory::installVersionAllowed(
          venueManaged, venuePolicyReady, venueAnchor.version, sameVenue,
          sameAuthority, inventory.version)) {
    return false;
  }
  VenueAnchor next;
  next.slot = venueManaged ? venueAnchor.slot ^ 1 : 0;
  next.version = inventory.version;
  memcpy(next.venueId.data(), inventory.venueId, next.venueId.size());
  memcpy(next.authority.data(), inventory.authorityPublicKey,
         next.authority.size());
  const char* nextPath = venueInventoryPath(next.slot);
  if (!writeBoundedFile(nextPath, encoded) || !storeVenueAnchor(next)) {
    LittleFS.remove(nextPath);
    return false;
  }
  venueAnchor = next;
  venueInventoryWire = encoded;
  venueManaged = true;
  venuePolicyReady = true;
  return true;
}

bool resetVenuePolicyToLab() {
  if (serverClientConnected || sessionReady || inboundActive ||
      !pendingOffers.empty() ||
      nodePeerRelayBusy()) {
    return false;
  }
  Preferences preferences;
  if (!preferences.begin(kVenuePreferencesNamespace, false)) return false;
  const bool removed = preferences.remove(kVenueAnchorKey) ||
      preferences.getBytesLength(kVenueAnchorKey) == 0;
  preferences.end();
  if (!removed) return false;
  LittleFS.remove(kVenueInventorySlot0);
  LittleFS.remove(kVenueInventorySlot1);
  venueManaged = false;
  venuePolicyReady = false;
  venueAnchor = VenueAnchor{};
  venueInventoryWire.clear();
  venueInventoryStaging.clear();
  venueInventoryExpectedBytes = 0;
  return true;
}

bool initializeIdentity() {
  mbedtls_ecp_keypair_init(&identityKey);
  if (mbedtls_ecp_group_load(&identityKey.MBEDTLS_PRIVATE(grp),
                             MBEDTLS_ECP_DP_SECP256R1) != 0) {
    return false;
  }
  Preferences preferences;
  if (!preferences.begin("hypha-id", false)) return false;
  uint8_t privateBytes[32] = {};
  const size_t storedBytes = preferences.getBytesLength("p256-d");
  bool ready = false;
  if (storedBytes == sizeof(privateBytes) &&
      preferences.getBytes("p256-d", privateBytes, sizeof(privateBytes)) ==
          sizeof(privateBytes)) {
    ready = mbedtls_mpi_read_binary(&identityKey.MBEDTLS_PRIVATE(d),
                                    privateBytes, sizeof(privateBytes)) == 0 &&
            mbedtls_ecp_check_privkey(&identityKey.MBEDTLS_PRIVATE(grp),
                                     &identityKey.MBEDTLS_PRIVATE(d)) == 0 &&
            mbedtls_ecp_mul(&identityKey.MBEDTLS_PRIVATE(grp),
                            &identityKey.MBEDTLS_PRIVATE(Q),
                            &identityKey.MBEDTLS_PRIVATE(d),
                            &identityKey.MBEDTLS_PRIVATE(grp).G,
                            hardwareRandom, nullptr) == 0;
  } else {
    ready = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &identityKey,
                                hardwareRandom, nullptr) == 0 &&
            mbedtls_mpi_write_binary(&identityKey.MBEDTLS_PRIVATE(d), privateBytes,
                                     sizeof(privateBytes)) == 0 &&
            preferences.putBytes("p256-d", privateBytes, sizeof(privateBytes)) ==
                sizeof(privateBytes);
  }
  memset(privateBytes, 0, sizeof(privateBytes));
  preferences.end();
  uint8_t publicKey[kP256PublicBytes] = {};
  return ready && exportPublicKey(identityKey, publicKey);
}

void resetSession() {
  clientToNodeKey.fill(0);
  nodeToClientKey.fill(0);
  expectedClientSequence = 0;
  nextNodeSequence = 0;
  sessionReady = false;
  nodePeerAuthenticated = false;
  pendingOffers.clear();
}

bool authenticateNodePeer(const std::vector<uint8_t>& authentication) {
  const size_t fixedBytes = sizeof(kNodeAuthMagic) + kP256PublicBytes + 2;
  if (!identityReady || authentication.size() <= fixedBytes ||
      memcmp(authentication.data(), kNodeAuthMagic,
             sizeof(kNodeAuthMagic)) != 0) {
    return false;
  }
  const uint8_t* peerIdentity = authentication.data() + sizeof(kNodeAuthMagic);
  const size_t signatureBytes = readU16(peerIdentity + kP256PublicBytes);
  if (signatureBytes == 0 || signatureBytes > 80 ||
      fixedBytes + signatureBytes != authentication.size()) {
    return false;
  }
  uint8_t serverIdentity[kP256PublicBytes] = {};
  if (!exportPublicKey(identityKey, serverIdentity)) return false;
  std::vector<uint8_t> transcript;
  transcript.insert(transcript.end(), kNodeAuthDomain,
                    kNodeAuthDomain + sizeof(kNodeAuthDomain) - 1);
  transcript.insert(transcript.end(), advertisementToken.begin(),
                    advertisementToken.end());
  transcript.insert(transcript.end(), serverIdentity,
                    serverIdentity + sizeof(serverIdentity));
  transcript.insert(transcript.end(), peerIdentity,
                    peerIdentity + kP256PublicBytes);
  return verifyTranscript(
             peerIdentity, transcript, peerIdentity + kP256PublicBytes + 2,
             signatureBytes) &&
      venueAllowsNodeIdentity(peerIdentity);
}

bool startSession(const std::vector<uint8_t>& hello,
                  std::vector<uint8_t>* response) {
  constexpr size_t kHelloBytes = sizeof(kHelloMagic) + kAdvertisementTokenBytes +
                                 kNonceBytes + kP256PublicBytes;
  if (!identityReady || hello.size() != kHelloBytes ||
      memcmp(hello.data(), kHelloMagic, sizeof(kHelloMagic)) != 0 ||
      !fixedEquals(hello.data() + sizeof(kHelloMagic), advertisementToken.data(),
                   advertisementToken.size())) {
    return false;
  }
  const uint8_t* clientNonce = hello.data() + sizeof(kHelloMagic) +
                               kAdvertisementTokenBytes;
  const uint8_t* clientPublic = clientNonce + kNonceBytes;

  mbedtls_ecp_keypair ephemeral;
  mbedtls_ecp_keypair_init(&ephemeral);
  mbedtls_ecp_point clientPoint;
  mbedtls_ecp_point_init(&clientPoint);
  mbedtls_mpi shared;
  mbedtls_mpi_init(&shared);
  bool success = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &ephemeral,
                                     hardwareRandom, nullptr) == 0 &&
      mbedtls_ecp_point_read_binary(&ephemeral.MBEDTLS_PRIVATE(grp), &clientPoint,
                                    clientPublic, kP256PublicBytes) == 0 &&
      mbedtls_ecp_check_pubkey(&ephemeral.MBEDTLS_PRIVATE(grp), &clientPoint) == 0 &&
      mbedtls_ecdh_compute_shared(&ephemeral.MBEDTLS_PRIVATE(grp), &shared,
          &clientPoint, &ephemeral.MBEDTLS_PRIVATE(d), hardwareRandom, nullptr) == 0;
  uint8_t sharedBytes[32] = {};
  uint8_t nodePublic[kP256PublicBytes] = {};
  uint8_t identityPublic[kP256PublicBytes] = {};
  uint8_t nodeNonce[kNonceBytes] = {};
  esp_fill_random(nodeNonce, sizeof(nodeNonce));
  success = success &&
      mbedtls_mpi_write_binary(&shared, sharedBytes, sizeof(sharedBytes)) == 0 &&
      exportPublicKey(ephemeral, nodePublic) && exportPublicKey(identityKey, identityPublic);

  std::vector<uint8_t> transcript;
  transcript.insert(transcript.end(), kHandshakeDomain,
                    kHandshakeDomain + sizeof(kHandshakeDomain) - 1);
  transcript.insert(transcript.end(), advertisementToken.begin(), advertisementToken.end());
  transcript.insert(transcript.end(), clientNonce, clientNonce + kNonceBytes);
  transcript.insert(transcript.end(), nodeNonce, nodeNonce + sizeof(nodeNonce));
  transcript.insert(transcript.end(), clientPublic, clientPublic + kP256PublicBytes);
  transcript.insert(transcript.end(), nodePublic, nodePublic + sizeof(nodePublic));
  transcript.insert(transcript.end(), identityPublic,
                    identityPublic + sizeof(identityPublic));
  uint8_t transcriptHash[32] = {};
  success = success && digest(transcript.data(), transcript.size(), transcriptHash);

  mbedtls_ecdsa_context signer;
  mbedtls_ecdsa_init(&signer);
  uint8_t signature[MBEDTLS_ECDSA_MAX_LEN] = {};
  size_t signatureBytes = 0;
  success = success && mbedtls_ecdsa_from_keypair(&signer, &identityKey) == 0 &&
      mbedtls_ecdsa_write_signature(&signer, MBEDTLS_MD_SHA256,
          transcriptHash, sizeof(transcriptHash), signature, sizeof(signature),
          &signatureBytes, hardwareRandom, nullptr) == 0;

  uint8_t salt[kNonceBytes * 2] = {};
  memcpy(salt, clientNonce, kNonceBytes);
  memcpy(salt + kNonceBytes, nodeNonce, kNonceBytes);
  std::vector<uint8_t> info;
  info.insert(info.end(), kSessionDomain, kSessionDomain + sizeof(kSessionDomain) - 1);
  info.insert(info.end(), advertisementToken.begin(), advertisementToken.end());
  uint8_t sessionKeys[kSessionKeyBytes] = {};
  const mbedtls_md_info_t* sha256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  success = success && sha256 != nullptr &&
      mbedtls_hkdf(sha256, salt, sizeof(salt), sharedBytes, sizeof(sharedBytes),
                   info.data(), info.size(), sessionKeys, sizeof(sessionKeys)) == 0;
  if (success) {
    memcpy(clientToNodeKey.data(), sessionKeys, kAesKeyBytes);
    memcpy(nodeToClientKey.data(), sessionKeys + kAesKeyBytes, kAesKeyBytes);
    expectedClientSequence = 0;
    nextNodeSequence = 0;
    sessionReady = true;
    response->clear();
    response->insert(response->end(), kHelloResponseMagic,
                     kHelloResponseMagic + sizeof(kHelloResponseMagic));
    response->insert(response->end(), advertisementToken.begin(), advertisementToken.end());
    response->insert(response->end(), nodeNonce, nodeNonce + sizeof(nodeNonce));
    response->insert(response->end(), nodePublic, nodePublic + sizeof(nodePublic));
    response->insert(response->end(), identityPublic,
                     identityPublic + sizeof(identityPublic));
    const size_t lengthOffset = response->size();
    response->resize(response->size() + 2);
    putU16(response->data() + lengthOffset, static_cast<uint16_t>(signatureBytes));
    response->insert(response->end(), signature, signature + signatureBytes);
  } else {
    resetSession();
  }
  memset(sharedBytes, 0, sizeof(sharedBytes));
  memset(sessionKeys, 0, sizeof(sessionKeys));
  memset(transcriptHash, 0, sizeof(transcriptHash));
  mbedtls_ecdsa_free(&signer);
  mbedtls_mpi_free(&shared);
  mbedtls_ecp_point_free(&clientPoint);
  mbedtls_ecp_keypair_free(&ephemeral);
  return success;
}

void buildRecordNonce(const uint8_t prefix[4], uint64_t sequence,
                      uint8_t nonce[kGcmNonceBytes]) {
  memcpy(nonce, prefix, 4);
  putU64(nonce + 4, sequence);
}

std::vector<uint8_t> buildRecordAad(uint64_t sequence) {
  std::vector<uint8_t> aad;
  aad.insert(aad.end(), kRecordDomain, kRecordDomain + sizeof(kRecordDomain) - 1);
  aad.insert(aad.end(), advertisementToken.begin(), advertisementToken.end());
  const size_t sequenceOffset = aad.size();
  aad.resize(aad.size() + kSequenceBytes);
  putU64(aad.data() + sequenceOffset, sequence);
  return aad;
}

bool decryptClientRecord(const std::vector<uint8_t>& encoded,
                         std::vector<uint8_t>* plaintext) {
  if (!sessionReady || encoded.size() <= kSequenceBytes + kGcmTagBytes) return false;
  const uint64_t sequence = readU64(encoded.data());
  if (sequence != expectedClientSequence) return false;
  const size_t ciphertextBytes = encoded.size() - kSequenceBytes - kGcmTagBytes;
  plaintext->assign(ciphertextBytes, 0);
  uint8_t nonce[kGcmNonceBytes] = {};
  buildRecordNonce(kClientNoncePrefix, sequence, nonce);
  const std::vector<uint8_t> aad = buildRecordAad(sequence);
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  const bool success = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES,
      clientToNodeKey.data(), kAesKeyBytes * 8) == 0 &&
      mbedtls_gcm_auth_decrypt(&gcm, ciphertextBytes, nonce, sizeof(nonce),
          aad.data(), aad.size(), encoded.data() + encoded.size() - kGcmTagBytes,
          kGcmTagBytes, encoded.data() + kSequenceBytes, plaintext->data()) == 0;
  mbedtls_gcm_free(&gcm);
  if (success) {
    ++expectedClientSequence;
  } else {
    plaintext->clear();
    resetSession();
  }
  return success;
}

bool encryptNodeRecord(const std::vector<uint8_t>& plaintext,
                       std::vector<uint8_t>* encoded) {
  if (!sessionReady || plaintext.empty() || plaintext.size() > kMaximumSyncBytes) return false;
  const uint64_t sequence = nextNodeSequence;
  encoded->assign(kSequenceBytes + plaintext.size() + kGcmTagBytes, 0);
  putU64(encoded->data(), sequence);
  uint8_t nonce[kGcmNonceBytes] = {};
  buildRecordNonce(kNodeNoncePrefix, sequence, nonce);
  const std::vector<uint8_t> aad = buildRecordAad(sequence);
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  const bool success = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES,
      nodeToClientKey.data(), kAesKeyBytes * 8) == 0 &&
      mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plaintext.size(),
          nonce, sizeof(nonce), aad.data(), aad.size(), plaintext.data(),
          encoded->data() + kSequenceBytes, kGcmTagBytes,
          encoded->data() + kSequenceBytes + plaintext.size()) == 0;
  mbedtls_gcm_free(&gcm);
  if (success) {
    ++nextNodeSequence;
  } else {
    encoded->clear();
    resetSession();
  }
  return success;
}

struct ExchangeView {
  std::vector<ObjectId> primaryIds;
  std::vector<std::vector<uint8_t>> primaryEnvelopes;
  std::vector<ObjectId> secondaryIds;
  std::vector<std::vector<uint8_t>> secondaryEnvelopes;
};

bool idExists(const std::vector<ObjectId>& ids, const ObjectId& wanted) {
  return std::find(ids.begin(), ids.end(), wanted) != ids.end();
}

bool decodeExchange(const std::vector<uint8_t>& encoded, const uint8_t magic[4],
                    ExchangeView* exchange) {
  if (encoded.size() < kExchangeHeaderBytes || encoded.size() > kMaximumSyncBytes ||
      memcmp(encoded.data(), magic, 4) != 0 || encoded[4] != kExchangeVersion ||
      encoded[5] != 0) {
    return false;
  }
  const size_t primaryIdCount = readU16(encoded.data() + 6);
  const size_t primaryEnvelopeCount = readU16(encoded.data() + 8);
  const size_t secondaryIdCount = readU16(encoded.data() + 10);
  const size_t secondaryEnvelopeCount = readU16(encoded.data() + 12);
  if (primaryIdCount > kMaximumExchangeIds || secondaryIdCount > kMaximumExchangeIds ||
      primaryEnvelopeCount > kMaximumExchangeEnvelopes ||
      secondaryEnvelopeCount > 128) {
    return false;
  }
  size_t offset = kExchangeHeaderBytes;
  auto takeIds = [&](size_t count, std::vector<ObjectId>* ids) {
    if (count > (encoded.size() - offset) / kObjectIdBytes) return false;
    ids->clear();
    for (size_t index = 0; index < count; ++index) {
      ObjectId id{};
      memcpy(id.data(), encoded.data() + offset, id.size());
      offset += id.size();
      if (idExists(*ids, id)) return false;
      ids->push_back(id);
    }
    return true;
  };
  auto takeEnvelopes = [&](size_t count, std::vector<std::vector<uint8_t>>* envelopes) {
    envelopes->clear();
    for (size_t index = 0; index < count; ++index) {
      if (encoded.size() - offset < 4) return false;
      const size_t bytes = readU32(encoded.data() + offset);
      offset += 4;
      if (bytes <= kRlyHeaderBytes || bytes > kMaximumRecordBytes ||
          bytes > encoded.size() - offset) {
        return false;
      }
      std::vector<uint8_t> envelope(encoded.begin() + offset,
                                    encoded.begin() + offset + bytes);
      if (!validateEnvelope(envelope.data(), envelope.size())) return false;
      envelopes->push_back(std::move(envelope));
      offset += bytes;
    }
    return true;
  };
  return takeIds(primaryIdCount, &exchange->primaryIds) &&
      takeEnvelopes(primaryEnvelopeCount, &exchange->primaryEnvelopes) &&
      takeIds(secondaryIdCount, &exchange->secondaryIds) &&
      takeEnvelopes(secondaryEnvelopeCount, &exchange->secondaryEnvelopes) &&
      offset == encoded.size();
}

void appendIds(std::vector<uint8_t>* target, const std::vector<ObjectId>& ids) {
  for (const ObjectId& id : ids) {
    target->insert(target->end(), id.begin(), id.end());
  }
}

void appendEnvelopes(std::vector<uint8_t>* target,
                     const std::vector<PendingOffer>& offers) {
  for (const PendingOffer& offer : offers) {
    const size_t offset = target->size();
    target->resize(offset + 4);
    putU32(target->data() + offset,
           static_cast<uint32_t>(offer.forwardedWire.size()));
    target->insert(target->end(), offer.forwardedWire.begin(),
                   offer.forwardedWire.end());
  }
}

std::vector<uint8_t> encodeExchange(const uint8_t magic[4],
                                    const std::vector<ObjectId>& primaryIds,
                                    const std::vector<PendingOffer>& offers,
                                    const std::vector<ObjectId>& secondaryIds = {}) {
  std::vector<uint8_t> encoded(kExchangeHeaderBytes, 0);
  memcpy(encoded.data(), magic, 4);
  encoded[4] = kExchangeVersion;
  putU16(encoded.data() + 6, static_cast<uint16_t>(primaryIds.size()));
  putU16(encoded.data() + 8, static_cast<uint16_t>(offers.size()));
  putU16(encoded.data() + 10, static_cast<uint16_t>(secondaryIds.size()));
  appendIds(&encoded, primaryIds);
  appendEnvelopes(&encoded, offers);
  appendIds(&encoded, secondaryIds);
  return encoded;
}

bool parseObjectIdFromName(const char* name, ObjectId* id) {
  const char* base = strrchr(name, '/');
  base = base == nullptr ? name : base + 1;
  if (strlen(base) != kObjectIdBytes * 2 + 4 || !hasSuffix(base, ".obj")) return false;
  for (size_t index = 0; index < id->size(); ++index) {
    const char highChar = static_cast<char>(tolower(base[index * 2]));
    const char lowChar = static_cast<char>(tolower(base[index * 2 + 1]));
    const int high = highChar >= '0' && highChar <= '9' ? highChar - '0' :
                     highChar >= 'a' && highChar <= 'f' ? highChar - 'a' + 10 : -1;
    const int low = lowChar >= '0' && lowChar <= '9' ? lowChar - '0' :
                    lowChar >= 'a' && lowChar <= 'f' ? lowChar - 'a' + 10 : -1;
    if (high < 0 || low < 0) return false;
    (*id)[index] = static_cast<uint8_t>((high << 4) | low);
  }
  return true;
}

void planNodeOffers(const std::vector<ObjectId>& phoneInventory) {
  pendingOffers.clear();
  if (!storageReady) return;
  std::vector<OfferCandidate> candidates;
  File directory = LittleFS.open(kStoreDirectory);
  if (!directory || !directory.isDirectory()) {
    if (directory) directory.close();
    return;
  }
  File entry = directory.openNextFile();
  while (entry) {
    ObjectId id{};
    const bool candidate = !entry.isDirectory() &&
        parseObjectIdFromName(entry.name(), &id) && !idExists(phoneInventory, id);
    entry.close();
    if (candidate) {
      StoredRecord record;
      if (readRecord(id, &record)) {
        const uint8_t hopsTaken = record.wire[kRlyHopsTakenOffset];
        const uint8_t hopLimit = record.wire[kRlyHopLimitOffset];
        const uint16_t copies = readU16(record.wire.data() + kRlyCopyBudgetOffset);
        if (copies > 1 && hopsTaken < hopLimit) {
          candidates.push_back(OfferCandidate{
              id,
              record.wire[5],
              readU64(record.wire.data() + kRlyAgeOffset),
          });
        }
      }
    }
    entry = directory.openNextFile();
  }
  if (entry) entry.close();
  directory.close();
  std::sort(candidates.begin(), candidates.end(),
            [](const OfferCandidate& left, const OfferCandidate& right) {
              if (left.priority != right.priority) {
                return left.priority < right.priority;
              }
              if (left.age != right.age) return left.age > right.age;
              return left.id < right.id;
            });
  std::vector<OfferCandidate> orderedCandidates;
  orderedCandidates.reserve(candidates.size());
  size_t admittedControl = 0;
  for (const OfferCandidate& candidate : candidates) {
    if (candidate.priority == kControlPriority &&
        admittedControl < kMaximumControlOffersPerSync) {
      orderedCandidates.push_back(candidate);
      ++admittedControl;
    }
  }
  for (const OfferCandidate& candidate : candidates) {
    if (candidate.priority != kControlPriority) {
      orderedCandidates.push_back(candidate);
    }
  }
  if (admittedControl < candidates.size()) {
    size_t skippedControl = 0;
    for (const OfferCandidate& candidate : candidates) {
      if (candidate.priority != kControlPriority) continue;
      if (skippedControl++ < admittedControl) continue;
      orderedCandidates.push_back(candidate);
    }
  }
  size_t responseBytes = kExchangeHeaderBytes;
  for (const OfferCandidate& candidate : orderedCandidates) {
    if (pendingOffers.size() >= kMaximumOffersPerSync) break;
    StoredRecord record;
    if (!readRecord(candidate.id, &record)) continue;
    const uint8_t hopsTaken = record.wire[kRlyHopsTakenOffset];
    const uint8_t hopLimit = record.wire[kRlyHopLimitOffset];
    const uint16_t copies = readU16(record.wire.data() + kRlyCopyBudgetOffset);
    if (copies <= 1 || hopsTaken >= hopLimit) continue;
    const uint16_t transferred = copies / 2;
    const uint16_t retained = copies - transferred;
    PendingOffer offer;
    offer.id = candidate.id;
    offer.forwardedWire = record.wire;
    offer.forwardedWire[kRlyHopsTakenOffset] = hopsTaken + 1;
    putU16(offer.forwardedWire.data() + kRlyCopyBudgetOffset, transferred);
    offer.retainedWire = record.wire;
    putU16(offer.retainedWire.data() + kRlyCopyBudgetOffset, retained);
    const size_t encodedBytes = 4 + offer.forwardedWire.size();
    if (responseBytes + encodedBytes <= kMaximumSyncBytes) {
      responseBytes += encodedBytes;
      pendingOffers.push_back(std::move(offer));
    }
  }
}

std::vector<ObjectId> nodePeerInventory();

bool processMeshRequest(const std::vector<uint8_t>& request,
                        std::vector<uint8_t>* response) {
  ExchangeView decoded;
  if (!storageReady || !venueRelayAllowed() ||
      !decodeExchange(request, kRmsRequestMagic, &decoded) ||
      !decoded.secondaryIds.empty() ||
      (nodePeerAuthenticated && !decoded.primaryEnvelopes.empty())) {
    return false;
  }
  std::vector<ObjectId> accepted;
  for (const std::vector<uint8_t>& offered : decoded.primaryEnvelopes) {
    ObjectId id{};
    validateEnvelope(offered.data(), offered.size(), &id);
    const StoreOutcome outcome = storeEnvelope(offered.data(), offered.size());
    if (outcome == StoreOutcome::kCommitted || outcome == StoreOutcome::kDuplicate) {
      accepted.push_back(id);
    }
  }
  std::vector<ObjectId> effectivePeerInventory = decoded.primaryIds;
  for (const ObjectId& acceptedId : accepted) {
    if (!idExists(effectivePeerInventory, acceptedId)) {
      effectivePeerInventory.push_back(acceptedId);
    }
  }
  planNodeOffers(effectivePeerInventory);
  *response = encodeExchange(
      kRmsResponseMagic, accepted, pendingOffers,
      nodePeerAuthenticated ? nodePeerInventory() : std::vector<ObjectId>{});
  return response->size() <= kMaximumSyncBytes;
}

bool processMeshAck(const std::vector<uint8_t>& ack,
                    std::vector<uint8_t>* completion) {
  ExchangeView decoded;
  if (!venueRelayAllowed() || !decodeExchange(ack, kRmsAckMagic, &decoded) ||
      (!nodePeerAuthenticated && !decoded.primaryEnvelopes.empty()) ||
      !decoded.secondaryIds.empty() ||
      !decoded.secondaryEnvelopes.empty()) {
    return false;
  }
  for (const PendingOffer& offer : pendingOffers) {
    if (idExists(decoded.primaryIds, offer.id) &&
        !replaceEnvelope(offer.id, offer.retainedWire)) {
      return false;
    }
  }
  std::vector<ObjectId> acceptedNodeOffers;
  if (nodePeerAuthenticated) {
    for (const std::vector<uint8_t>& offered : decoded.primaryEnvelopes) {
      ObjectId id{};
      if (!validateEnvelope(offered.data(), offered.size(), &id)) continue;
      const StoreOutcome outcome = storeEnvelope(offered.data(), offered.size());
      if (outcome == StoreOutcome::kCommitted ||
          outcome == StoreOutcome::kDuplicate) {
        acceptedNodeOffers.push_back(id);
      }
    }
  }
  pendingOffers.clear();
  *completion = encodeExchange(kRmsCompletionMagic, acceptedNodeOffers, {});
  return true;
}

bool processFinalAck(const std::vector<uint8_t>& finalAck,
                     std::vector<uint8_t>* done) {
  ExchangeView decoded;
  if (!venueRelayAllowed() ||
      !decodeExchange(finalAck, kRmsFinalAckMagic, &decoded) ||
      !decoded.primaryIds.empty() || !decoded.primaryEnvelopes.empty() ||
      !decoded.secondaryIds.empty() || !decoded.secondaryEnvelopes.empty()) {
    return false;
  }
  done->assign(kDoneMagic, kDoneMagic + sizeof(kDoneMagic));
  return true;
}

void setOutbound(uint8_t kind, const std::vector<uint8_t>& payload) {
  outboundKind = kind;
  outboundPayload = payload;
  outboundCrc = crc32(outboundPayload.data(), outboundPayload.size());
  outboundOffset = 0;
  outboundNextSequence = 0;
}

void setErrorResponse() {
  const std::vector<uint8_t> error = {'H', 'N', 'E', '1'};
  setOutbound(kResponseError, error);
}

void processCompletedTransfer() {
  if (crc32(inboundPayload.data(), inboundPayload.size()) != inboundCrc) {
    serverProtocolViolation = true;
    setErrorResponse();
    return;
  }
  if (inboundType == kTransferHello) {
    resetSession();
    std::vector<uint8_t> response;
    if (startSession(inboundPayload, &response)) {
      setOutbound(kResponseHello, response);
    } else {
      serverProtocolViolation = true;
      setErrorResponse();
    }
    return;
  }
  if (inboundType != kTransferSecure || !sessionReady) {
    serverProtocolViolation = true;
    setErrorResponse();
    return;
  }
  std::vector<uint8_t> plaintext;
  if (!decryptClientRecord(inboundPayload, &plaintext)) {
    serverProtocolViolation = true;
    setErrorResponse();
    return;
  }
  std::vector<uint8_t> responsePlaintext;
  bool accepted = false;
  if (plaintext.size() == sizeof(kFinishMagic) &&
      memcmp(plaintext.data(), kFinishMagic, sizeof(kFinishMagic)) == 0) {
    responsePlaintext.assign(kWelcomeMagic, kWelcomeMagic + sizeof(kWelcomeMagic));
    serverGuardAuthenticated = true;
    accepted = true;
  } else if (plaintext.size() > sizeof(kNodeAuthMagic) &&
             memcmp(plaintext.data(), kNodeAuthMagic,
                    sizeof(kNodeAuthMagic)) == 0) {
    nodePeerAuthenticated = authenticateNodePeer(plaintext);
    if (nodePeerAuthenticated) {
      responsePlaintext.assign(kNodeAuthOkMagic,
                               kNodeAuthOkMagic + sizeof(kNodeAuthOkMagic));
      accepted = true;
    }
  } else if (plaintext.size() >= 4 &&
             memcmp(plaintext.data(), kRmsRequestMagic, 4) == 0) {
    accepted = processMeshRequest(plaintext, &responsePlaintext);
  } else if (plaintext.size() >= 4 &&
             memcmp(plaintext.data(), kRmsAckMagic, 4) == 0) {
    accepted = processMeshAck(plaintext, &responsePlaintext);
  } else if (plaintext.size() >= 4 &&
             memcmp(plaintext.data(), kRmsFinalAckMagic, 4) == 0) {
    accepted = processFinalAck(plaintext, &responsePlaintext);
  }
  std::vector<uint8_t> encrypted;
  if (accepted && encryptNodeRecord(responsePlaintext, &encrypted)) {
    if (responsePlaintext.size() == sizeof(kDoneMagic) &&
        memcmp(responsePlaintext.data(), kDoneMagic,
               sizeof(kDoneMagic)) == 0) {
      recordSuccessfulServerExchange();
    }
    setOutbound(kResponseSecure, encrypted);
  } else {
    serverProtocolViolation = true;
    setErrorResponse();
  }
}

void handleStartFrame(const uint8_t* frame, size_t bytes) {
  if (bytes != kStartFrameBytes || memcmp(frame, kFrameStartMagic, 4) != 0 ||
      frame[5] != 0) {
    serverProtocolViolation = true;
    setErrorResponse();
    return;
  }
  const uint8_t type = frame[4];
  const size_t payloadBytes = readU16(frame + 6);
  if ((type != kTransferHello && type != kTransferSecure) || payloadBytes == 0 ||
      payloadBytes > kMaximumTransferBytes) {
    serverProtocolViolation = true;
    setErrorResponse();
    return;
  }
  serverTransferStarts = serverTransferStarts + 1;
  if (type == kTransferHello) {
    serverHelloStarts = serverHelloStarts + 1;
  }
  serverDeclaredBytes += static_cast<uint32_t>(payloadBytes);
  serverDeclaredBytesInWindow += static_cast<uint32_t>(payloadBytes);
  const HyphaBleSessionGuard::DisconnectReason budgetReason =
      HyphaBleSessionGuard::evaluate(serverGuardSnapshot(), millis());
  if (budgetReason ==
          HyphaBleSessionGuard::DisconnectReason::kHandshakeLimit ||
      budgetReason ==
          HyphaBleSessionGuard::DisconnectReason::kTransferLimit ||
      budgetReason ==
          HyphaBleSessionGuard::DisconnectReason::kDeclaredByteLimit) {
    setErrorResponse();
    return;
  }
  inboundType = type;
  inboundCrc = readU32(frame + 8);
  inboundPayload.clear();
  inboundPayload.reserve(payloadBytes);
  inboundExpectedBytes = payloadBytes;
  inboundNextSequence = 0;
  inboundActive = true;
  outboundPayload.clear();
}

void handleDataFrame(const uint8_t* frame, size_t bytes) {
  if (!inboundActive || bytes <= kDataHeaderBytes ||
      memcmp(frame, kFrameDataMagic, 4) != 0 ||
      readU16(frame + 4) != inboundNextSequence || frame[6] != 0 || frame[7] != 0) {
    inboundActive = false;
    serverProtocolViolation = true;
    setErrorResponse();
    return;
  }
  const size_t chunkBytes = bytes - kDataHeaderBytes;
  if (chunkBytes > inboundExpectedBytes - inboundPayload.size()) {
    inboundActive = false;
    serverProtocolViolation = true;
    setErrorResponse();
    return;
  }
  inboundPayload.insert(inboundPayload.end(), frame + kDataHeaderBytes,
                        frame + bytes);
  ++inboundNextSequence;
  if (inboundPayload.size() == inboundExpectedBytes) {
    inboundActive = false;
    processCompletedTransfer();
  }
}

class TransferCallbacks final : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic* characteristic) override {
    lastServerActivityMs = millis();
    serverWrites = serverWrites + 1;
    serverWritesInWindow = serverWritesInWindow + 1;
    if (serverWrites > HyphaBleSessionGuard::kMaximumWrites) {
      setErrorResponse();
      return;
    }
    const String value = characteristic->getValue();
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(value.c_str());
    if (value.length() >= 4 && memcmp(bytes, kFrameStartMagic, 4) == 0) {
      handleStartFrame(bytes, value.length());
    } else if (value.length() >= 4 && memcmp(bytes, kFrameDataMagic, 4) == 0) {
      handleDataFrame(bytes, value.length());
    } else {
      serverProtocolViolation = true;
      setErrorResponse();
    }
  }

  void onRead(BLECharacteristic* characteristic) override {
    lastServerActivityMs = millis();
    serverReads = serverReads + 1;
    serverReadsInWindow = serverReadsInWindow + 1;
    if (serverReads > HyphaBleSessionGuard::kMaximumReads) {
      const uint8_t unavailable[] = {'H', 'N', 'E', '1'};
      characteristic->setValue(unavailable, sizeof(unavailable));
      return;
    }
    if (outboundPayload.empty() || outboundOffset > outboundPayload.size()) {
      serverProtocolViolation = true;
      const uint8_t unavailable[] = {'H', 'N', 'E', '1'};
      characteristic->setValue(unavailable, sizeof(unavailable));
      return;
    }
    const size_t maximumFrameBytes = std::max<size_t>(negotiatedMtu, 23) - 1;
    const size_t maximumChunkBytes = maximumFrameBytes - kResponseHeaderBytes;
    const size_t chunkBytes = std::min(maximumChunkBytes,
                                       outboundPayload.size() - outboundOffset);
    std::vector<uint8_t> frame(kResponseHeaderBytes + chunkBytes, 0);
    memcpy(frame.data(), kFrameResponseMagic, 4);
    frame[4] = outboundKind;
    frame[5] = outboundOffset + chunkBytes == outboundPayload.size() ? 1 : 0;
    putU16(frame.data() + 6, outboundNextSequence);
    putU16(frame.data() + 8, static_cast<uint16_t>(outboundPayload.size()));
    putU32(frame.data() + 10, outboundCrc);
    memcpy(frame.data() + kResponseHeaderBytes,
           outboundPayload.data() + outboundOffset, chunkBytes);
    characteristic->setValue(frame.data(), frame.size());
    outboundOffset += chunkBytes;
    ++outboundNextSequence;
    if (outboundOffset == outboundPayload.size()) {
      outboundPayload.clear();
      outboundOffset = 0;
    }
  }
};

class NodeServerCallbacks final : public BLEServerCallbacks {
  void onConnect(BLEServer* server) override {
    const uint32_t now = millis();
    serverClientConnected = true;
    serverConnectionId = server == nullptr ? 0 : server->getConnId();
    refreshServerResourceWindow(now);
    serverConnectionsInWindow = serverConnectionsInWindow + 1;
    resetServerGuardConnection(now);
    serverPeerLimited = false;
    negotiatedMtu = 23;
    inboundActive = false;
    outboundPayload.clear();
    resetSession();
  }

  // Called by the BLE library immediately after onConnect(BLEServer*).
  void onConnect(BLEServer*, esp_ble_gatts_cb_param_t* parameters) override {
    if (parameters == nullptr) return;
    HyphaBleSessionGuard::PeerAddress address{};
    memcpy(address.data(), parameters->connect.remote_bda, address.size());
    const HyphaBleSessionGuard::PeerConnectionDecision decision =
        HyphaBleSessionGuard::recordPeerConnection(
            serverPeerWindows, address, millis());
    if (!decision.countsTowardAggregate && serverConnectionsInWindow > 0) {
      serverConnectionsInWindow = serverConnectionsInWindow - 1;
    }
    serverPeerLimited = decision.peerLimited;
  }

  void onDisconnect(BLEServer* server) override {
    serverClientConnected = false;
    serverDisconnectPending = false;
    serverGuardAuthenticated = false;
    serverProtocolViolation = false;
    lastServerActivityMs = millis();
    inboundActive = false;
    outboundPayload.clear();
    resetSession();
    if (!serverAdvertisingBackoff) server->startAdvertising();
  }

  void onMtuChanged(BLEServer*, esp_ble_gatts_cb_param_t* parameters) override {
    if (parameters != nullptr) negotiatedMtu = std::max<uint16_t>(23, parameters->mtu.mtu);
  }
};

TransferCallbacks transferCallbacks;
NodeServerCallbacks serverCallbacks;

void startBle() {
  esp_fill_random(advertisementToken.data(), advertisementToken.size());
  BLEDevice::init("");
  BLEDevice::setMTU(247);
  bleServer = BLEDevice::createServer();
  bleServer->setCallbacks(&serverCallbacks);
  BLEService* service = bleServer->createService(kServiceUuid);
  transferCharacteristic = service->createCharacteristic(
      kTransferCharacteristicUuid,
      BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_WRITE);
  transferCharacteristic->setCallbacks(&transferCallbacks);
  service->start();

  uint8_t manufacturer[2 + sizeof(kAdvertisementPrefix) + kAdvertisementTokenBytes] = {};
  manufacturer[0] = 0xff;
  manufacturer[1] = 0xff;
  memcpy(manufacturer + 2, kAdvertisementPrefix, sizeof(kAdvertisementPrefix));
  memcpy(manufacturer + 2 + sizeof(kAdvertisementPrefix),
         advertisementToken.data(), advertisementToken.size());
  BLEAdvertisementData advertisement;
  advertisement.setFlags(ESP_BLE_ADV_FLAG_GEN_DISC | ESP_BLE_ADV_FLAG_BREDR_NOT_SPT);
  advertisement.setManufacturerData(String(
      reinterpret_cast<const char*>(manufacturer), sizeof(manufacturer)));
  BLEAdvertising* advertising = BLEDevice::getAdvertising();
  advertising->setAdvertisementData(advertisement);
  advertising->setScanResponse(false);
  advertising->setMinPreferred(0x06);
  advertising->setMaxPreferred(0x12);
  advertising->start();
}

void pollServerConnectionGuard() {
  if (!serverClientConnected || serverDisconnectPending || bleServer == nullptr) {
    return;
  }
  const uint32_t now = millis();
  if (serverPeerLimited) {
    // Per-radio isolation is not a node-wide failure: no global backoff is recorded.
    serverDisconnectPending = true;
    serverPeerLimited = false;
    lastServerGuardReason =
        HyphaBleSessionGuard::DisconnectReason::kPeerConnectionWindowLimit;
    ++serverPeerIsolationCount;
    Serial.println("BLE_GUARD disconnect reason=peer_connection_window");
    bleServer->disconnect(serverConnectionId);
    return;
  }
  refreshServerResourceWindow(now);
  HyphaBleSessionGuard::DisconnectReason reason =
      HyphaBleSessionGuard::evaluate(serverGuardSnapshot(), now);
  if (reason == HyphaBleSessionGuard::DisconnectReason::kNone) {
    reason = HyphaBleSessionGuard::evaluateWindow(
        serverGuardWindowSnapshot());
  }
  if (reason == HyphaBleSessionGuard::DisconnectReason::kNone) return;
  serverDisconnectPending = true;
  lastServerGuardReason = reason;
  ++serverGuardDisconnectCount;
  recordServerGuardFailure(now);
  Serial.printf("BLE_GUARD disconnect reason=%s\n",
                serverGuardReasonName(reason));
  bleServer->disconnect(serverConnectionId);
}

void pollServerAdvertisingBackoff() {
  if (!serverAdvertisingBackoff || serverClientConnected ||
      monotonicDeadlinePending(millis(), serverGuardBackoffUntilMs)) {
    return;
  }
  serverAdvertisingBackoff = false;
  BLEDevice::getAdvertising()->start();
}

#include "hypha_node_peer.h"

const char* venueModeName() { return venueManaged ? "managed" : "lab"; }

const char* venuePolicyName() {
  if (!venueManaged) return "lab";
  return venuePolicyReady ? "ready" : "unavailable";
}

void printVenueStatus() {
  Serial.printf(
      "VENUE_STATUS mode=%s policy=%s version=%llu entries=%u staged=%lu/%lu\n",
      venueModeName(), venuePolicyName(),
      static_cast<unsigned long long>(venueAnchor.version),
      venuePolicyReady
          ? HyphaVenueInventory::readU16(venueInventoryWire.data() + 97)
          : 0,
      static_cast<unsigned long>(venueInventoryStaging.size()),
      static_cast<unsigned long>(venueInventoryExpectedBytes));
}

void printNodeIdentity() {
  uint8_t publicKey[kP256PublicBytes] = {};
  if (!identityReady || !exportPublicKey(identityKey, publicKey)) {
    Serial.println("ERROR identity_unavailable");
    return;
  }
  char encoded[kP256PublicBytes * 2 + 1] = {};
  bytesToHex(publicKey, sizeof(publicKey), encoded);
  Serial.printf("NODE_IDENTITY_P256 %s\n", encoded);
}

bool parseVenueLength(const char* encoded, size_t* length) {
  if (encoded == nullptr || *encoded == '\0') return false;
  char* end = nullptr;
  const unsigned long parsed = strtoul(encoded, &end, 10);
  if (end == encoded || *end != '\0' || parsed == 0 ||
      parsed > HyphaVenueInventory::kMaximumWireBytes) {
    return false;
  }
  *length = static_cast<size_t>(parsed);
  return true;
}

int hexNibble(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  value = static_cast<char>(tolower(static_cast<unsigned char>(value)));
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  return -1;
}

bool appendVenueChunk(const char* encoded) {
  if (venueInventoryExpectedBytes == 0 || encoded == nullptr) return false;
  const size_t characters = strlen(encoded);
  if (characters == 0 || characters > 64 || characters % 2 != 0) return false;
  const size_t bytes = characters / 2;
  if (venueInventoryStaging.size() + bytes > venueInventoryExpectedBytes) {
    return false;
  }
  const size_t offset = venueInventoryStaging.size();
  venueInventoryStaging.resize(offset + bytes);
  for (size_t index = 0; index < bytes; ++index) {
    const int high = hexNibble(encoded[index * 2]);
    const int low = hexNibble(encoded[index * 2 + 1]);
    if (high < 0 || low < 0) {
      venueInventoryStaging.resize(offset);
      return false;
    }
    venueInventoryStaging[offset + index] =
        static_cast<uint8_t>((high << 4) | low);
  }
  return true;
}

void printStatus() {
  Serial.printf(
      "STATUS firmware=hypha-fixed-node/1 storage=%s identity=%s records=%lu "
      "limit=%lu control_reserve=%lu venue=%s venue_policy=%s venue_version=%llu "
      "ble=ready node_relay=%s node_syncs=%lu "
      "node_failures=%lu ble_guard=ready ble_guard_disconnects=%lu "
      "ble_guard_backoffs=%lu ble_guard_peer_isolations=%lu ble_guard_last=%s "
      "free_heap=%lu min_free_heap=%lu reset_reason=%d uptime_ms=%lu\n",
      storageReady ? "ready" : "unavailable",
      identityReady ? "ready" : "unavailable",
      static_cast<unsigned long>(storageReady ? recordCount() : 0),
      static_cast<unsigned long>(kMaximumRecords),
      static_cast<unsigned long>(kReservedControlRecords),
      venueModeName(), venuePolicyName(),
      static_cast<unsigned long long>(venueAnchor.version),
      nodePeerRelayReady() ? "ready" : "unavailable",
      static_cast<unsigned long>(nodePeerSyncSuccesses()),
      static_cast<unsigned long>(nodePeerSyncFailures()),
      static_cast<unsigned long>(serverGuardDisconnectCount),
      static_cast<unsigned long>(serverGuardBackoffCount),
      static_cast<unsigned long>(serverPeerIsolationCount),
      serverGuardReasonName(lastServerGuardReason),
      static_cast<unsigned long>(ESP.getFreeHeap()),
      static_cast<unsigned long>(ESP.getMinFreeHeap()),
      static_cast<int>(esp_reset_reason()),
      static_cast<unsigned long>(millis()));
}

void handleSerialCommand(char* command) {
  if (strcasecmp(command, "PING") == 0) {
    Serial.println("PONG");
  } else if (strcasecmp(command, "STATUS") == 0) {
    printStatus();
  } else if (strcasecmp(command, "IDENTITY") == 0) {
    printNodeIdentity();
  } else if (strcasecmp(command, "VENUE_STATUS") == 0) {
    printVenueStatus();
  } else if (strncasecmp(command, "VENUE_BEGIN ", 12) == 0) {
    size_t expected = 0;
    if (!parseVenueLength(command + 12, &expected)) {
      Serial.println("ERROR venue_length_invalid");
    } else if (serverClientConnected || sessionReady || inboundActive ||
               !pendingOffers.empty() ||
               nodePeerRelayBusy()) {
      Serial.println("ERROR node_busy");
    } else {
      venueInventoryStaging.clear();
      venueInventoryStaging.reserve(expected);
      venueInventoryExpectedBytes = expected;
      Serial.printf("VENUE_BEGIN_OK bytes=%lu\n",
                    static_cast<unsigned long>(expected));
    }
  } else if (strncasecmp(command, "VENUE_CHUNK ", 12) == 0) {
    if (!appendVenueChunk(command + 12)) {
      Serial.println("ERROR venue_chunk_invalid");
    } else {
      Serial.printf("VENUE_CHUNK_OK received=%lu remaining=%lu\n",
                    static_cast<unsigned long>(venueInventoryStaging.size()),
                    static_cast<unsigned long>(venueInventoryExpectedBytes -
                                               venueInventoryStaging.size()));
    }
  } else if (strcasecmp(command, "VENUE_COMMIT") == 0) {
    if (venueInventoryExpectedBytes == 0 ||
        venueInventoryStaging.size() != venueInventoryExpectedBytes) {
      Serial.println("ERROR venue_incomplete");
    } else if (installVenueInventory(venueInventoryStaging)) {
      venueInventoryStaging.clear();
      venueInventoryExpectedBytes = 0;
      Serial.println("VENUE_COMMIT_OK");
      printVenueStatus();
    } else {
      Serial.println("ERROR venue_rejected");
    }
  } else if (strcasecmp(command, "VENUE_ABORT") == 0) {
    venueInventoryStaging.clear();
    venueInventoryExpectedBytes = 0;
    Serial.println("VENUE_ABORT_OK");
  } else if (strcasecmp(command, "VENUE_RESET CONFIRM") == 0) {
    if (resetVenuePolicyToLab()) {
      Serial.println("VENUE_RESET_OK mode=lab records=preserved identity=preserved");
    } else {
      Serial.println("ERROR venue_reset_failed");
    }
  } else if (strcasecmp(command, "HELP") == 0) {
    Serial.println(
        "COMMANDS PING STATUS IDENTITY VENUE_STATUS VENUE_BEGIN VENUE_CHUNK "
        "VENUE_COMMIT VENUE_ABORT VENUE_RESET NODE_SYNC CLEAR_RECORDS REBOOT");
  } else if (strcasecmp(command, "NODE_SYNC") == 0) {
    requestNodePeerSync();
    Serial.println("NODE_SYNC scheduled");
  } else if (strcasecmp(command, "CLEAR_RECORDS") == 0) {
    if (!storageReady) {
      Serial.println("ERROR storage_unavailable");
    } else if (sessionReady || inboundActive || !pendingOffers.empty() ||
               nodePeerRelayBusy()) {
      Serial.println("ERROR node_busy");
    } else {
      size_t removedRecords = 0;
      if (clearStoredRecords(&removedRecords)) {
        Serial.printf("CLEAR_OK records_removed=%lu identity=preserved\n",
                      static_cast<unsigned long>(removedRecords));
      } else {
        Serial.printf("ERROR clear_failed records_remaining=%lu\n",
                      static_cast<unsigned long>(recordCount()));
      }
    }
  } else if (strcasecmp(command, "REBOOT") == 0) {
    Serial.println("REBOOTING");
    Serial.flush();
    delay(100);
    ESP.restart();
  } else {
    Serial.println("ERROR unknown_command");
  }
}

void finishSerialCommand() {
  if (serialOverflow) {
    Serial.println("ERROR command_too_long");
  } else if (serialCommandBytes > 0) {
    serialCommand[serialCommandBytes] = '\0';
    handleSerialCommand(serialCommand);
  }
  serialCommandBytes = 0;
  serialOverflow = false;
}

}  // namespace

void startLoopWatchdog() {
  // Node-to-node sync legitimately blocks loop() for several seconds, so the default 5 s
  // loop watchdog would cause false resets. A genuinely hung node reboots after 60 s;
  // records and identity persist in flash.
  esp_task_wdt_config_t config = {};
  config.timeout_ms = kLoopWatchdogMs;
  config.idle_core_mask = 0;
  config.trigger_panic = true;
  if (esp_task_wdt_reconfigure(&config) != ESP_OK) esp_task_wdt_init(&config);
  enableLoopWDT();
}

void setup() {
  Serial.begin(kSerialBaud);
  delay(250);
  storageReady = initializeStorage();
  identityReady = initializeIdentity();
  loadVenuePolicy();
  startBle();
  startNodePeerRelay();
  startLoopWatchdog();
  Serial.println("HYPHA_FIXED_NODE/1 READY");
  printStatus();
}

void loop() {
  while (Serial.available() > 0) {
    const char incoming = static_cast<char>(Serial.read());
    if (incoming == '\r' || incoming == '\n') {
      finishSerialCommand();
    } else if (!serialOverflow) {
      if (serialCommandBytes >= sizeof(serialCommand) - 1) {
        serialOverflow = true;
      } else {
        serialCommand[serialCommandBytes++] = incoming;
      }
    }
  }
  pollServerConnectionGuard();
  pollServerAdvertisingBackoff();
  pollNodePeerRelay();
  delay(2);
}
