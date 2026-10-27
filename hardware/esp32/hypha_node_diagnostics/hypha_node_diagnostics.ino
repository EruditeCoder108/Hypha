#include <Arduino.h>
#include <FS.h>
#include <LittleFS.h>
#include <Preferences.h>
#include <mbedtls/sha256.h>

#include <cctype>
#include <cstring>

namespace {

constexpr uint32_t kSerialBaud = 115200;
constexpr size_t kObjectIdHexBytes = 32;
constexpr size_t kMaximumPayloadBytes = 256;
constexpr size_t kMaximumCommandBytes =
    4 + kObjectIdHexBytes + 1 + (kMaximumPayloadBytes * 2);
constexpr size_t kMaximumRecords = 32;
constexpr char kStoreDirectory[] = "/hypha";
constexpr uint8_t kRecordMagic[] = {'H', 'N', 'O', '1'};
constexpr size_t kDigestBytes = 32;
constexpr size_t kRecordHeaderBytes = sizeof(kRecordMagic) + 2 + kDigestBytes;

char commandBuffer[kMaximumCommandBytes + 1] = {};
size_t commandLength = 0;
bool commandOverflow = false;
bool storageReady = false;

enum class RecordState {
  kMissing,
  kValid,
  kCorrupt,
};

bool isHexString(const char* value, size_t expectedLength) {
  if (strlen(value) != expectedLength) {
    return false;
  }
  for (size_t index = 0; index < expectedLength; ++index) {
    if (!isxdigit(static_cast<unsigned char>(value[index]))) {
      return false;
    }
  }
  return true;
}

void normalizeObjectId(char* value) {
  for (size_t index = 0; index < kObjectIdHexBytes; ++index) {
    value[index] = static_cast<char>(
        tolower(static_cast<unsigned char>(value[index])));
  }
}

int hexNibble(char value) {
  if (value >= '0' && value <= '9') {
    return value - '0';
  }
  value = static_cast<char>(tolower(static_cast<unsigned char>(value)));
  if (value >= 'a' && value <= 'f') {
    return value - 'a' + 10;
  }
  return -1;
}

bool decodeHex(const char* source, uint8_t* destination, size_t* decodedBytes) {
  const size_t encodedBytes = strlen(source);
  if (encodedBytes == 0 || encodedBytes > kMaximumPayloadBytes * 2 ||
      (encodedBytes % 2) != 0) {
    return false;
  }
  for (size_t index = 0; index < encodedBytes; index += 2) {
    const int high = hexNibble(source[index]);
    const int low = hexNibble(source[index + 1]);
    if (high < 0 || low < 0) {
      return false;
    }
    destination[index / 2] = static_cast<uint8_t>((high << 4) | low);
  }
  *decodedBytes = encodedBytes / 2;
  return true;
}

bool makeRecordPath(const char* objectId, const char* suffix,
                    char* destination, size_t destinationBytes) {
  const int written = snprintf(destination, destinationBytes, "%s/%s%s",
                               kStoreDirectory, objectId, suffix);
  return written > 0 && static_cast<size_t>(written) < destinationBytes;
}

bool digestPayload(const uint8_t* payload, size_t payloadBytes,
                   uint8_t digest[kDigestBytes]) {
  return mbedtls_sha256(payload, payloadBytes, digest, 0) == 0;
}

bool readExact(File& file, uint8_t* destination, size_t byteCount) {
  return file.read(destination, byteCount) == byteCount;
}

RecordState readRecord(const char* path, uint8_t* payload,
                       size_t* payloadBytes) {
  if (!LittleFS.exists(path)) {
    return RecordState::kMissing;
  }

  File file = LittleFS.open(path, FILE_READ);
  if (!file || file.isDirectory()) {
    if (file) {
      file.close();
    }
    return RecordState::kCorrupt;
  }

  uint8_t magic[sizeof(kRecordMagic)] = {};
  uint8_t encodedLength[2] = {};
  uint8_t storedDigest[kDigestBytes] = {};
  bool valid = readExact(file, magic, sizeof(magic)) &&
               readExact(file, encodedLength, sizeof(encodedLength)) &&
               readExact(file, storedDigest, sizeof(storedDigest));
  const size_t length =
      (static_cast<size_t>(encodedLength[0]) << 8) | encodedLength[1];
  valid = valid && memcmp(magic, kRecordMagic, sizeof(magic)) == 0 &&
          length > 0 && length <= kMaximumPayloadBytes &&
          file.size() == kRecordHeaderBytes + length &&
          readExact(file, payload, length);
  file.close();

  uint8_t calculatedDigest[kDigestBytes] = {};
  valid = valid && digestPayload(payload, length, calculatedDigest) &&
          memcmp(storedDigest, calculatedDigest, kDigestBytes) == 0;
  if (!valid) {
    return RecordState::kCorrupt;
  }
  *payloadBytes = length;
  return RecordState::kValid;
}

bool hasSuffix(const char* value, const char* suffix) {
  const size_t valueBytes = strlen(value);
  const size_t suffixBytes = strlen(suffix);
  return valueBytes >= suffixBytes &&
         strcmp(value + valueBytes - suffixBytes, suffix) == 0;
}

void countRecords(size_t* recordCount, size_t* corruptCount) {
  *recordCount = 0;
  *corruptCount = 0;
  File directory = LittleFS.open(kStoreDirectory);
  if (!directory || !directory.isDirectory()) {
    if (directory) {
      directory.close();
    }
    return;
  }

  File entry = directory.openNextFile();
  while (entry) {
    const char* name = entry.name();
    if (!entry.isDirectory() && hasSuffix(name, ".obj")) {
      ++(*recordCount);
      if (entry.size() < kRecordHeaderBytes + 1 ||
          entry.size() > kRecordHeaderBytes + kMaximumPayloadBytes) {
        ++(*corruptCount);
      }
    }
    entry.close();
    entry = directory.openNextFile();
  }
  directory.close();
}

bool initializeStorage() {
  Preferences preferences;
  if (!preferences.begin("hypha-node", false)) {
    return false;
  }
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
  return true;
}

void printStatus() {
  size_t records = 0;
  size_t corrupt = 0;
  if (storageReady) {
    countRecords(&records, &corrupt);
  }
  Serial.printf(
      "STATUS firmware=hypha-node-store/1 storage=%s records=%lu "
      "corrupt=%lu limit=%lu free_heap=%lu uptime_ms=%lu\n",
      storageReady ? "ready" : "unavailable",
      static_cast<unsigned long>(records),
      static_cast<unsigned long>(corrupt),
      static_cast<unsigned long>(kMaximumRecords),
      static_cast<unsigned long>(ESP.getFreeHeap()),
      static_cast<unsigned long>(millis()));
}

void handlePut(char* arguments) {
  if (!storageReady) {
    Serial.println("ERROR storage_unavailable");
    return;
  }
  char* separator = strchr(arguments, ' ');
  if (separator == nullptr || separator == arguments || separator[1] == '\0') {
    Serial.println("ERROR usage_put");
    return;
  }
  *separator = '\0';
  char* objectId = arguments;
  const char* encodedPayload = separator + 1;
  if (!isHexString(objectId, kObjectIdHexBytes)) {
    Serial.println("ERROR invalid_object_id");
    return;
  }
  if (strchr(encodedPayload, ' ') != nullptr) {
    Serial.println("ERROR invalid_payload");
    return;
  }
  normalizeObjectId(objectId);

  uint8_t payload[kMaximumPayloadBytes] = {};
  size_t payloadBytes = 0;
  if (!decodeHex(encodedPayload, payload, &payloadBytes)) {
    Serial.println("ERROR invalid_payload");
    return;
  }

  char finalPath[48] = {};
  char temporaryPath[48] = {};
  if (!makeRecordPath(objectId, ".obj", finalPath, sizeof(finalPath)) ||
      !makeRecordPath(objectId, ".tmp", temporaryPath, sizeof(temporaryPath))) {
    Serial.println("ERROR internal_path");
    return;
  }

  uint8_t existingPayload[kMaximumPayloadBytes] = {};
  size_t existingBytes = 0;
  const RecordState existingState =
      readRecord(finalPath, existingPayload, &existingBytes);
  if (existingState == RecordState::kCorrupt) {
    Serial.println("ERROR existing_record_corrupt");
    return;
  }
  if (existingState == RecordState::kValid) {
    if (existingBytes == payloadBytes &&
        memcmp(existingPayload, payload, payloadBytes) == 0) {
      Serial.printf("STORED id=%s bytes=%lu state=duplicate\n", objectId,
                    static_cast<unsigned long>(payloadBytes));
    } else {
      Serial.println("ERROR object_id_conflict");
    }
    return;
  }

  size_t records = 0;
  size_t corrupt = 0;
  countRecords(&records, &corrupt);
  if (corrupt > 0) {
    Serial.println("ERROR store_contains_corrupt_record");
    return;
  }
  if (records >= kMaximumRecords) {
    Serial.println("ERROR quota_full");
    return;
  }

  uint8_t digest[kDigestBytes] = {};
  if (!digestPayload(payload, payloadBytes, digest)) {
    Serial.println("ERROR digest_failed");
    return;
  }

  if (LittleFS.exists(temporaryPath) && !LittleFS.remove(temporaryPath)) {
    Serial.println("ERROR stale_temporary_record");
    return;
  }
  File file = LittleFS.open(temporaryPath, FILE_WRITE);
  const uint8_t encodedLength[] = {
      static_cast<uint8_t>((payloadBytes >> 8) & 0xff),
      static_cast<uint8_t>(payloadBytes & 0xff),
  };
  const bool wrote = file &&
                     file.write(kRecordMagic, sizeof(kRecordMagic)) ==
                         sizeof(kRecordMagic) &&
                     file.write(encodedLength, sizeof(encodedLength)) ==
                         sizeof(encodedLength) &&
                     file.write(digest, sizeof(digest)) == sizeof(digest) &&
                     file.write(payload, payloadBytes) == payloadBytes;
  if (file) {
    file.flush();
    file.close();
  }
  if (!wrote || !LittleFS.rename(temporaryPath, finalPath)) {
    LittleFS.remove(temporaryPath);
    Serial.println("ERROR durable_commit_failed");
    return;
  }

  uint8_t committedPayload[kMaximumPayloadBytes] = {};
  size_t committedBytes = 0;
  if (readRecord(finalPath, committedPayload, &committedBytes) !=
          RecordState::kValid ||
      committedBytes != payloadBytes ||
      memcmp(committedPayload, payload, payloadBytes) != 0) {
    Serial.println("ERROR durable_verify_failed");
    return;
  }
  Serial.printf("STORED id=%s bytes=%lu state=committed\n", objectId,
                static_cast<unsigned long>(payloadBytes));
}

void handleGet(char* objectId) {
  if (!storageReady) {
    Serial.println("ERROR storage_unavailable");
    return;
  }
  if (!isHexString(objectId, kObjectIdHexBytes)) {
    Serial.println("ERROR invalid_object_id");
    return;
  }
  normalizeObjectId(objectId);
  char path[48] = {};
  if (!makeRecordPath(objectId, ".obj", path, sizeof(path))) {
    Serial.println("ERROR internal_path");
    return;
  }
  uint8_t payload[kMaximumPayloadBytes] = {};
  size_t payloadBytes = 0;
  const RecordState state = readRecord(path, payload, &payloadBytes);
  if (state == RecordState::kMissing) {
    Serial.println("ERROR not_found");
    return;
  }
  if (state == RecordState::kCorrupt) {
    Serial.println("ERROR record_corrupt");
    return;
  }

  Serial.printf("OBJECT id=%s bytes=%lu data=", objectId,
                static_cast<unsigned long>(payloadBytes));
  static constexpr char kHex[] = "0123456789abcdef";
  for (size_t index = 0; index < payloadBytes; ++index) {
    Serial.print(kHex[payload[index] >> 4]);
    Serial.print(kHex[payload[index] & 0x0f]);
  }
  Serial.println();
}

void handleList() {
  if (!storageReady) {
    Serial.println("ERROR storage_unavailable");
    return;
  }
  File directory = LittleFS.open(kStoreDirectory);
  if (!directory || !directory.isDirectory()) {
    if (directory) {
      directory.close();
    }
    Serial.println("ERROR store_unavailable");
    return;
  }

  size_t records = 0;
  File entry = directory.openNextFile();
  while (entry) {
    const char* name = entry.name();
    if (!entry.isDirectory() && hasSuffix(name, ".obj")) {
      const char* baseName = strrchr(name, '/');
      baseName = baseName == nullptr ? name : baseName + 1;
      const size_t baseBytes = strlen(baseName);
      if (baseBytes == kObjectIdHexBytes + 4) {
        Serial.print("ID ");
        Serial.write(reinterpret_cast<const uint8_t*>(baseName),
                     kObjectIdHexBytes);
        Serial.println();
        ++records;
      }
    }
    entry.close();
    entry = directory.openNextFile();
  }
  directory.close();
  Serial.printf("LIST_END records=%lu\n",
                static_cast<unsigned long>(records));
}

void handleCommand(char* command) {
  if (strcasecmp(command, "PING") == 0) {
    Serial.println("PONG");
    return;
  }
  if (strcasecmp(command, "STATUS") == 0) {
    printStatus();
    return;
  }
  if (strcasecmp(command, "LIST") == 0) {
    handleList();
    return;
  }
  if (strncasecmp(command, "PUT ", 4) == 0) {
    handlePut(command + 4);
    return;
  }
  if (strncasecmp(command, "GET ", 4) == 0) {
    handleGet(command + 4);
    return;
  }
  if (strcasecmp(command, "HELP") == 0) {
    Serial.println("COMMANDS PING STATUS PUT <32hex-id> <hex-data> "
                   "GET <32hex-id> LIST HELP REBOOT");
    return;
  }
  if (strcasecmp(command, "REBOOT") == 0) {
    Serial.println("REBOOTING");
    Serial.flush();
    delay(100);
    ESP.restart();
    return;
  }
  Serial.println("ERROR unknown_command");
}

void finishCommand() {
  if (commandOverflow) {
    Serial.println("ERROR command_too_long");
  } else if (commandLength > 0) {
    commandBuffer[commandLength] = '\0';
    handleCommand(commandBuffer);
  }
  commandLength = 0;
  commandOverflow = false;
}

}  // namespace

void setup() {
  Serial.begin(kSerialBaud);
  delay(250);
  storageReady = initializeStorage();
  Serial.println("HYPHA_NODE_STORE/1 READY");
  printStatus();
}

void loop() {
  while (Serial.available() > 0) {
    const char incoming = static_cast<char>(Serial.read());
    if (incoming == '\r' || incoming == '\n') {
      finishCommand();
      continue;
    }
    if (commandOverflow) {
      continue;
    }
    if (commandLength >= kMaximumCommandBytes) {
      commandOverflow = true;
      continue;
    }
    commandBuffer[commandLength++] = incoming;
  }
  delay(2);
}
