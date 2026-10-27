// Included after verbatim firmware functions by run_esp32_custody_audit.mjs.
// Repaired paths assert their intended invariants; remaining known findings are
// explicitly labelled. Neither is evidence of physical ESP32 behavior.
struct AuditNode {
  AuditFsState fs;
  std::vector<PendingOffer> offers;
};
void activate(AuditNode& node) {
  LittleFS.state = &node.fs;
  pendingOffers = node.offers;
}
void save(AuditNode& node) { node.offers = pendingOffers; }
void requireAudit(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}
void emit(const char* id, const char* status, const std::string& details) {
  std::cout << "{\"id\":\"" << id << "\",\"status\":\"" << status
            << "\",\"details\":" << details << "}\n";
}
std::vector<uint8_t> envelope(uint16_t idNumber, uint16_t copies = 8,
                             uint8_t priority = 2, uint64_t age = 0,
                             uint64_t lifetime = 60'000) {
  std::vector<uint8_t> wire(kRlyHeaderBytes + 1, 0);
  std::memcpy(wire.data(), kRlyMagic, sizeof(kRlyMagic));
  wire[4] = 1;
  wire[5] = priority;
  wire[kRlyIdOffset] = static_cast<uint8_t>(idNumber >> 8);
  wire[kRlyIdOffset + 1] = static_cast<uint8_t>(idNumber);
  putU64(wire.data() + kRlyLifetimeOffset, lifetime);
  putU64(wire.data() + kRlyAgeOffset, age);
  wire[kRlyHopLimitOffset] = 8;
  putU16(wire.data() + kRlyCopyBudgetOffset, copies);
  putU32(wire.data() + kRlyCiphertextLengthOffset, 1);
  wire.back() = 0x5a;
  return wire;
}
ObjectId objectId(const std::vector<uint8_t>& wire) {
  ObjectId id{};
  requireAudit(validateEnvelope(wire.data(), wire.size(), &id), "fixture envelope invalid");
  return id;
}
uint16_t storedCopies(const ObjectId& id) {
  StoredRecord value;
  requireAudit(readRecord(id, &value), "expected durable record missing");
  return readU16(value.wire.data() + kRlyCopyBudgetOffset);
}
std::vector<uint8_t> firstOffer(AuditNode& sender) {
  activate(sender);
  std::vector<uint8_t> response;
  requireAudit(processMeshRequest(encodeExchange(kRmsRequestMagic, {}, {}), &response),
               "source request failed");
  ExchangeView decoded;
  requireAudit(decodeExchange(response, kRmsResponseMagic, &decoded), "response decode failed");
  requireAudit(decoded.primaryEnvelopes.size() == 1, "expected one offer");
  save(sender);
  return decoded.primaryEnvelopes.front();
}
void custodyAckCase(bool loseAck) {
  AuditNode sender, receiver;
  const auto original = envelope(1);
  const auto id = objectId(original);
  activate(sender);
  requireAudit(storeEnvelope(original.data(), original.size()) == StoreOutcome::kCommitted,
               "seed failed");
  const auto offered = firstOffer(sender);
  activate(receiver);
  requireAudit(storeEnvelope(offered.data(), offered.size()) == StoreOutcome::kCommitted,
               "receiving custody failed");
  const auto receiverInventory = nodePeerInventory();
  const auto receiverCopies = storedCopies(id);
  activate(sender);
  if (!loseAck) {
    std::vector<uint8_t> completion;
    requireAudit(processMeshAck(encodeExchange(kRmsAckMagic, {id}, {}), &completion),
                 "source ack failed");
  }
  const auto senderCopies = storedCopies(id);
  // A disconnected/rebooted encounter loses the in-RAM pending offer list.
  pendingOffers.clear();
  std::vector<uint8_t> nextResponse;
  requireAudit(processMeshRequest(encodeExchange(kRmsRequestMagic, receiverInventory, {}),
                                  &nextResponse), "next encounter failed");
  requireAudit(pendingOffers.empty(), "known peer object was reoffered");
  requireAudit(senderCopies == (loseAck ? 8 : 4) && receiverCopies == 4,
               "custody observation changed; review the finding");
  emit(loseAck ? "lost_custody_ack" : "normal_custody_ack",
       loseAck ? "invariant_violation_reproduced" : "control_passed",
       "{\"initialBudget\":8,\"senderBudget\":" + std::to_string(senderCopies) +
       ",\"receiverBudget\":4,\"combinedBudget\":" +
       std::to_string(senderCopies + receiverCopies) + ",\"nextEncounterOffers\":0}");
}
void rebootRecoveryCase() {
  AuditNode node;
  activate(node);
  const auto original = envelope(2);
  const auto id = objectId(original);
  requireAudit(storeEnvelope(original.data(), original.size()) == StoreOutcome::kCommitted,
               "seed failed");
  auto updated = original;
  putU16(updated.data() + kRlyCopyBudgetOffset, 4);
  node.fs.afterRename = [](const std::string&, const std::string& target) {
    if (target.ends_with(".bak")) throw AuditPowerCut{};
  };
  bool interrupted = false;
  try { replaceEnvelope(id, updated); } catch (const AuditPowerCut&) { interrupted = true; }
  requireAudit(interrupted, "expected power-loss checkpoint was not reached");
  node.fs.afterRename = {};
  pendingOffers.clear();
  requireAudit(recoverStoreFiles(), "record recovery failed");
  StoredRecord recovered;
  const bool readable = readRecord(id, &recovered);
  requireAudit(readable && recovered.wire == original && node.fs.files.size() == 1 &&
               node.fs.rejectedRelativePaths == 0, "durable record was not restored cleanly");
  emit("reboot_during_record_replace", "regression_passed",
       "{\"readableAfterRecovery\":true,\"recordsInventoried\":" +
       std::to_string(nodePeerInventory().size()) + ",\"remainingFiles\":" +
       std::to_string(node.fs.files.size()) + ",\"relativePathsRejected\":" +
       std::to_string(node.fs.rejectedRelativePaths) + "}");
}
void duplicateCases() {
  AuditNode node;
  activate(node);
  const auto original = envelope(3);
  requireAudit(storeEnvelope(original.data(), original.size()) == StoreOutcome::kCommitted,
               "seed failed");
  requireAudit(storeEnvelope(original.data(), original.size()) == StoreOutcome::kDuplicate,
               "exact duplicate not idempotent");
  auto conflict = original;
  conflict.back() ^= 1;
  requireAudit(storeEnvelope(conflict.data(), conflict.size()) == StoreOutcome::kConflict,
               "ciphertext conflict accepted");
  emit("exact_duplicate_and_ciphertext_conflict", "control_passed",
       "{\"records\":1,\"ciphertextConflictRejected\":true}");
  auto changedLimit = original;
  changedLimit[kRlyHopLimitOffset] = 9;
  requireAudit(storeEnvelope(changedLimit.data(), changedLimit.size()) == StoreOutcome::kConflict,
               "immutable hop-limit conflict was not rejected");
  auto mutableForward = original;
  putU64(mutableForward.data() + kRlyAgeOffset, 500);
  mutableForward[kRlyHopsTakenOffset] = 1;
  putU16(mutableForward.data() + kRlyCopyBudgetOffset, 4);
  requireAudit(storeEnvelope(mutableForward.data(), mutableForward.size()) == StoreOutcome::kDuplicate,
               "safe mutable forwarding fields no longer deduplicate");
  emit("immutable_hop_limit_conflict", "regression_passed",
       "{\"hopLimitConflictRejected\":true,\"mutableForwardDeduplicated\":true}");
}
void corruptLengthCase() {
  AuditNode node;
  activate(node);
  const auto original = envelope(4);
  const auto id = objectId(original);
  requireAudit(storeEnvelope(original.data(), original.size()) == StoreOutcome::kCommitted,
               "seed failed");
  auto& file = node.fs.files.begin()->second;
  file[4] = 0xff;
  file[5] = 0xff;
  StoredRecord result;
  auditLargestAllocation = 0;
  auditTrackAllocations = true;
  const bool read = readRecord(id, &result);
  auditTrackAllocations = false;
  requireAudit(!read && auditLargestAllocation <= kMaximumRecordBytes,
               "corrupt record length allocated beyond its bound");
  emit("corrupt_record_allocation", "regression_passed",
       "{\"accepted\":false,\"largestAllocationBytes\":" +
       std::to_string(auditLargestAllocation) + ",\"recordLimitBytes\":4352}");
}

std::string auditRecordPath(const ObjectId& id, const char* suffix) {
  char path[64] = {};
  requireAudit(makeRecordPath(id, suffix, path, sizeof(path)), "invalid fixture path");
  return path;
}
void replacementInterruptionMatrix() {
  const auto original = envelope(5);
  const auto id = objectId(original);
  auto updated = original;
  putU16(updated.data() + kRlyCopyBudgetOffset, 4);
  int checkpoints = 0;
  {
    AuditNode node;
    activate(node);
    requireAudit(storeEnvelope(original.data(), original.size()) == StoreOutcome::kCommitted,
                 "seed failed");
    node.fs.afterMutation = [&](const std::string&, const std::string&) { ++checkpoints; };
    requireAudit(replaceEnvelope(id, updated), "uninterrupted replacement failed");
  }
  for (int cut = 1; cut <= checkpoints; ++cut) {
    AuditNode node;
    activate(node);
    requireAudit(storeEnvelope(original.data(), original.size()) == StoreOutcome::kCommitted,
                 "seed failed");
    int operations = 0;
    node.fs.afterMutation = [&](const std::string&, const std::string&) {
      if (++operations == cut) throw AuditPowerCut{};
    };
    bool interrupted = false;
    try { replaceEnvelope(id, updated); } catch (const AuditPowerCut&) { interrupted = true; }
    requireAudit(interrupted, "replacement checkpoint missing");
    node.fs.afterMutation = {};
    requireAudit(recoverStoreFiles(), "interrupted replacement did not recover");
    StoredRecord recovered;
    requireAudit(readRecord(id, &recovered) &&
                 (recovered.wire == original || recovered.wire == updated) &&
                 node.fs.files.size() == 1 && node.fs.rejectedRelativePaths == 0,
                 "replacement interruption lost or corrupted durable custody");
    requireAudit(recoverStoreFiles(), "recovery is not idempotent");
  }
  emit("replacement_interruption_matrix", "regression_passed",
       "{\"mutationCheckpoints\":" + std::to_string(checkpoints) + "}");
}
void recoveryValidationCases() {
  const auto original = envelope(6);
  const auto id = objectId(original);
  const auto finalPath = auditRecordPath(id, ".obj");
  const auto backupPath = auditRecordPath(id, ".bak");
  const auto tempPath = auditRecordPath(id, ".tmp");
  for (int scenario = 0; scenario < 3; ++scenario) {
    AuditNode node;
    activate(node);
    requireAudit(storeEnvelope(original.data(), original.size()) == StoreOutcome::kCommitted,
                 "seed failed");
    node.fs.files[backupPath] = node.fs.files.at(finalPath);
    node.fs.files[tempPath] = {0, 1, 2};
    node.fs.files["/mesh/operator-note.txt"] = {7};
    if (scenario == 0) node.fs.files.at(backupPath).back() ^= 1;
    if (scenario >= 1) node.fs.files.at(finalPath).back() ^= 1;
    if (scenario == 2) node.fs.files.at(backupPath).back() ^= 1;
    const auto before = node.fs.files;
    const bool recovered = recoverStoreFiles();
    StoredRecord record;
    if (scenario < 2) {
      requireAudit(recovered && readRecord(id, &record) && record.wire == original &&
                   node.fs.files.size() == 2 && node.fs.files.contains("/mesh/operator-note.txt"),
                   "valid committed or backup record was discarded");
    } else {
      requireAudit(!recovered && node.fs.files == before,
                   "unrecoverable corruption must preserve evidence and fail closed");
    }
  }
  emit("recovery_validation", "regression_passed",
       "{\"validFinalKept\":true,\"validBackupRestored\":true,\"invalidPairPreserved\":true}");
}
void recoveryInterruptionMatrix() {
  const auto original = envelope(7);
  const auto id = objectId(original);
  const auto finalPath = auditRecordPath(id, ".obj");
  const auto backupPath = auditRecordPath(id, ".bak");
  const auto tempPath = auditRecordPath(id, ".tmp");
  int checkpoints = 0;
  for (int cut = 0; cut <= checkpoints; ++cut) {
    AuditNode node;
    activate(node);
    requireAudit(storeEnvelope(original.data(), original.size()) == StoreOutcome::kCommitted,
                 "seed failed");
    node.fs.files[backupPath] = node.fs.files.at(finalPath);
    node.fs.files.at(finalPath).back() ^= 1;
    node.fs.files[tempPath] = {0};
    int operations = 0;
    node.fs.afterMutation = [&](const std::string&, const std::string&) {
      ++operations;
      if (cut != 0 && operations == cut) throw AuditPowerCut{};
    };
    try { requireAudit(recoverStoreFiles(), "recovery failed"); }
    catch (const AuditPowerCut&) {}
    if (cut == 0) checkpoints = operations;
    node.fs.afterMutation = {};
    requireAudit(recoverStoreFiles(), "reboot during recovery did not recover");
    StoredRecord record;
    requireAudit(readRecord(id, &record) && record.wire == original && node.fs.files.size() == 1,
                 "repeated recovery lost valid backup");
  }
  emit("recovery_interruption_matrix", "regression_passed",
       "{\"mutationCheckpoints\":" + std::to_string(checkpoints) + "}");
}
void pressureRecoveryFailsClosed() {
  AuditNode node;
  activate(node);
  for (uint16_t index = 1; index <= kMaximumRecords; ++index) {
    const auto wire = envelope(index, 2, index <= 168 ? 2 : 0);
    requireAudit(storeEnvelope(wire.data(), wire.size()) == StoreOutcome::kCommitted,
                 "pressure fixture failed");
  }
  node.fs.afterRename = [](const std::string&, const std::string& target) {
    if (target.ends_with(".obj")) throw AuditPowerCut{};
  };
  const auto incoming = envelope(301, 2, 0);
  bool interrupted = false;
  try { storeEnvelope(incoming.data(), incoming.size()); }
  catch (const AuditPowerCut&) { interrupted = true; }
  requireAudit(interrupted, "pressure interruption missing");
  node.fs.afterRename = {};
  storageReady = recoverStoreFiles();
  requireAudit(!storageReady && recordCount() == 193 && node.fs.files.size() == 193,
               "over-capacity recovery must retain records and refuse ready custody");
  const auto rejected = envelope(302, 2, 0);
  requireAudit(storeEnvelope(rejected.data(), rejected.size()) == StoreOutcome::kFailed,
               "unavailable store accepted new custody");
  planNodeOffers({});
  requireAudit(pendingOffers.empty(), "unavailable store offered custody");
  storageReady = true;
  emit("pressure_recovery_fails_closed", "regression_passed",
       "{\"ready\":false,\"preservedRecords\":193,\"automaticEvictionRecovery\":false}");
}
void controlEvictionCase() {
  AuditNode node;
  activate(node);
  for (uint16_t index = 1; index <= kMaximumRecords; ++index) {
    const auto wire = envelope(index, 1, index <= 168 ? 2 : 0);
    requireAudit(storeEnvelope(wire.data(), wire.size()) == StoreOutcome::kCommitted,
                 "store-pressure fixture failed");
  }
  ObjectId candidate{};
  requireAudit(selectControlEvictionCandidate(&candidate), "no eviction candidate");
  requireAudit(storedCopies(candidate) == 1, "fixture is not a last-copy record");
  const auto control = envelope(300, 2, 0);
  requireAudit(storeEnvelope(control.data(), control.size()) == StoreOutcome::kCommitted,
               "new control not stored");
  StoredRecord removed;
  requireAudit(!readRecord(candidate, &removed) && recordCount() == 192,
               "eviction behavior changed; review finding");
  emit("control_eviction_redundancy", "documented_policy_mismatch_reproduced",
       "{\"evictedRecordCopyBudget\":1,\"recordCountAfterEviction\":192}");
}
void expiredBoundaryCase() {
  AuditNode node;
  activate(node);
  const auto expired = envelope(400, 8, 2, 60'000, 60'000);
  requireAudit(storeEnvelope(expired.data(), expired.size()) == StoreOutcome::kCommitted,
               "expiry-boundary behavior changed; review finding");
  planNodeOffers({});
  requireAudit(pendingOffers.size() == 1, "expiry boundary was not offered");
  emit("expired_boundary_forwarding", "known_expiry_gap_reproduced",
       "{\"ageMs\":60000,\"lifetimeMs\":60000,\"offered\":true}");
}
int main() {
  try {
    custodyAckCase(false);
    custodyAckCase(true);
    rebootRecoveryCase();
    duplicateCases();
    corruptLengthCase();
    replacementInterruptionMatrix();
    recoveryValidationCases();
    recoveryInterruptionMatrix();
    pressureRecoveryFailsClosed();
    controlEvictionCase();
    expiredBoundaryCase();
  } catch (const std::exception& error) {
    std::cerr << "AUDIT HARNESS ERROR: " << error.what() << '\n';
    return 1;
  }
}
