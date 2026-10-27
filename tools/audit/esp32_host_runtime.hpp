#pragma once

// Audit-only host doubles for the Arduino filesystem surface. File::name() returns a
// basename and FS operations require absolute paths, matching installed esp32 3.3.11.
// This does not emulate flash wear, torn sectors, BLE, NVS, or the ESP scheduler.
#include <algorithm>
#include <array>
#include <cctype>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <map>
#include <new>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

inline bool auditTrackAllocations = false;
inline size_t auditLargestAllocation = 0;
void* operator new(size_t bytes) {
  if (auditTrackAllocations) auditLargestAllocation = std::max(auditLargestAllocation, bytes);
  if (void* value = std::malloc(bytes == 0 ? 1 : bytes)) return value;
  throw std::bad_alloc();
}
void operator delete(void* value) noexcept { std::free(value); }
void operator delete(void* value, size_t) noexcept { std::free(value); }
void* operator new[](size_t bytes) { return ::operator new(bytes); }
void operator delete[](void* value) noexcept { ::operator delete(value); }
void operator delete[](void* value, size_t) noexcept { ::operator delete(value); }

class String : public std::string {
 public:
  using std::string::string;
  String(const std::string& value) : std::string(value) {}
  operator const char*() const { return c_str(); }
  bool endsWith(const char* suffix) const {
    const size_t bytes = std::strlen(suffix);
    return size() >= bytes && compare(size() - bytes, bytes, suffix) == 0;
  }
  String substring(size_t start, size_t end = std::string::npos) const {
    return substr(start, end == std::string::npos ? end : end - start);
  }
};

struct AuditPowerCut {};
struct AuditFsState {
  std::map<std::string, std::vector<uint8_t>> files;
  size_t rejectedRelativePaths = 0;
  std::function<void(const std::string&, const std::string&)> afterRename;
  std::function<void(const std::string&, const std::string&)> afterMutation;
};
constexpr int FILE_READ = 0;
constexpr int FILE_WRITE = 1;

class File {
 public:
  File() = default;
  File(AuditFsState* state, std::string path, bool directory = false)
      : state_(state), path_(std::move(path)), directory_(directory), valid_(true) {
    const auto separator = path_.find_last_of('/');
    name_ = path_.substr(separator == std::string::npos ? 0 : separator + 1);
    if (directory_) {
      const std::string prefix = path_ + "/";
      for (const auto& [path, _] : state_->files) {
        if (path.starts_with(prefix)) entries_.push_back(path);
      }
    }
  }
  explicit operator bool() const { return valid_; }
  bool isDirectory() const { return directory_; }
  const char* name() const { return name_.c_str(); }
  const char* path() const { return path_.c_str(); }
  size_t size() const {
    const auto found = state_->files.find(path_);
    return found == state_->files.end() ? 0 : found->second.size();
  }
  size_t read(uint8_t* output, size_t bytes) {
    auto& data = state_->files.at(path_);
    const size_t available = data.size() > offset_ ? data.size() - offset_ : 0;
    const size_t count = std::min(bytes, available);
    if (count != 0) std::memcpy(output, data.data() + offset_, count);
    offset_ += count;
    return count;
  }
  size_t write(const uint8_t* input, size_t bytes) {
    auto& data = state_->files.at(path_);
    data.insert(data.end(), input, input + bytes);
    if (state_->afterMutation) state_->afterMutation("write", path_);
    return bytes;
  }
  void flush() {
    if (state_->afterMutation) state_->afterMutation("flush", path_);
  }
  void close() { valid_ = false; }
  File openNextFile() {
    while (nextEntry_ < entries_.size()) {
      const std::string candidate = entries_[nextEntry_++];
      if (state_->files.contains(candidate)) return File(state_, candidate);
    }
    return {};
  }
 private:
  AuditFsState* state_ = nullptr;
  std::string path_;
  std::string name_;
  bool directory_ = false;
  bool valid_ = false;
  size_t offset_ = 0;
  size_t nextEntry_ = 0;
  std::vector<std::string> entries_;
};

struct AuditFs {
  AuditFsState* state = nullptr;
  bool absolute(const char* path) {
    if (path != nullptr && path[0] == '/') return true;
    ++state->rejectedRelativePaths;
    return false;
  }
  bool exists(const char* path) {
    return absolute(path) && (std::strcmp(path, "/mesh") == 0 || state->files.contains(path));
  }
  File open(const char* path, int mode = FILE_READ) {
    if (!absolute(path)) return {};
    if (std::strcmp(path, "/mesh") == 0) return File(state, path, true);
    if (mode == FILE_WRITE) {
      state->files[path].clear();
      if (state->afterMutation) state->afterMutation("open-write", path);
    }
    return state->files.contains(path) ? File(state, path) : File{};
  }
  bool remove(const char* path) {
    if (!absolute(path) || state->files.erase(path) == 0) return false;
    if (state->afterMutation) state->afterMutation("remove", path);
    return true;
  }
  bool rename(const char* source, const char* destination) {
    if (!absolute(source) || !absolute(destination) || !state->files.contains(source)) return false;
    state->files[destination] = std::move(state->files.at(source));
    state->files.erase(source);
    if (state->afterRename) state->afterRename(source, destination);
    if (state->afterMutation) state->afterMutation("rename", destination);
    return true;
  }
};
inline AuditFs LittleFS;

// Real host SHA-256; no substitute integrity function is used in storage tests.
inline int mbedtls_sha256(const uint8_t* bytes, size_t length, uint8_t* output, int is224) {
  if (is224 != 0 || length > ULONG_MAX) return -1;
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return -1;
  DWORD objectBytes = 0, resultBytes = 0;
  NTSTATUS result = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
      reinterpret_cast<PUCHAR>(&objectBytes), sizeof(objectBytes), &resultBytes, 0);
  std::vector<uint8_t> hashObject(objectBytes);
  BCRYPT_HASH_HANDLE hash = nullptr;
  if (result == 0) result = BCryptCreateHash(algorithm, &hash, hashObject.data(), objectBytes,
                                            nullptr, 0, 0);
  if (result == 0) result = BCryptHashData(hash, const_cast<PUCHAR>(bytes),
                                          static_cast<ULONG>(length), 0);
  if (result == 0) result = BCryptFinishHash(hash, output, 32, 0);
  if (hash != nullptr) BCryptDestroyHash(hash);
  BCryptCloseAlgorithmProvider(algorithm, 0);
  return result == 0 ? 0 : -1;
}
