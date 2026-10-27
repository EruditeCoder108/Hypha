#ifndef HYPHA_VENUE_INVENTORY_H
#define HYPHA_VENUE_INVENTORY_H

#include <array>
#include <cstddef>
#include <cstdint>

namespace HyphaVenueInventory {

constexpr size_t kP256PublicBytes = 65;
constexpr size_t kVenueIdBytes = 16;
constexpr size_t kHeaderBytes = 99;
constexpr size_t kEntryBytes = 67;
constexpr size_t kMaximumEntries = 64;
constexpr size_t kMaximumSignatureBytes = 80;
constexpr size_t kMaximumWireBytes =
    kHeaderBytes + kEntryBytes * kMaximumEntries + 2 + kMaximumSignatureBytes;
constexpr uint8_t kRoleCourier = 1;
constexpr uint8_t kStatusActive = 1;
constexpr uint8_t kStatusRevoked = 2;
constexpr uint8_t kStatusReplaced = 3;
constexpr uint8_t kStatusUnknown = 0;
constexpr char kSignatureDomain[] = "Hypha venue inventory v1\0";

struct View {
  uint64_t version = 0;
  const uint8_t* venueId = nullptr;
  const uint8_t* authorityPublicKey = nullptr;
  const uint8_t* entries = nullptr;
  uint16_t entryCount = 0;
  const uint8_t* signature = nullptr;
  uint16_t signatureBytes = 0;
  size_t unsignedBytes = 0;
};

constexpr uint16_t readU16(const uint8_t* source) {
  return (static_cast<uint16_t>(source[0]) << 8) | source[1];
}

constexpr uint64_t readU64(const uint8_t* source) {
  uint64_t value = 0;
  for (size_t index = 0; index < 8; ++index) {
    value = (value << 8) | source[index];
  }
  return value;
}

constexpr int compareUnsigned(const uint8_t* left, const uint8_t* right,
                              size_t bytes) {
  for (size_t index = 0; index < bytes; ++index) {
    if (left[index] < right[index]) return -1;
    if (left[index] > right[index]) return 1;
  }
  return 0;
}

constexpr bool structurallyValid(const uint8_t* wire, size_t bytes,
                                 View* view = nullptr) {
  if (wire == nullptr || bytes < kHeaderBytes + kEntryBytes + 3 ||
      wire[0] != 'H' || wire[1] != 'V' || wire[2] != 'I' || wire[3] != '1' ||
      wire[4] != 1 || wire[5] != 1 || wire[6] != 0 || wire[7] != 0) {
    return false;
  }
  const uint64_t version = readU64(wire + 8);
  if (version == 0 || version > INT64_MAX) return false;
  bool venueNonZero = false;
  for (size_t index = 0; index < kVenueIdBytes; ++index) {
    venueNonZero = venueNonZero || wire[16 + index] != 0;
  }
  if (!venueNonZero || wire[32] != 0x04) return false;
  const uint16_t entryCount = readU16(wire + 97);
  if (entryCount == 0 || entryCount > kMaximumEntries) return false;
  const size_t entriesEnd = kHeaderBytes + entryCount * kEntryBytes;
  if (entriesEnd + 2 > bytes) return false;
  bool hasActive = false;
  const uint8_t* previous = nullptr;
  for (uint16_t index = 0; index < entryCount; ++index) {
    const uint8_t* entry = wire + kHeaderBytes + index * kEntryBytes;
    if (entry[0] != 0x04 || entry[65] != kRoleCourier ||
        (entry[66] != kStatusActive && entry[66] != kStatusRevoked &&
         entry[66] != kStatusReplaced) ||
        (previous != nullptr &&
         compareUnsigned(previous, entry, kP256PublicBytes) >= 0)) {
      return false;
    }
    hasActive = hasActive || entry[66] == kStatusActive;
    previous = entry;
  }
  if (!hasActive) return false;
  const uint16_t signatureBytes = readU16(wire + entriesEnd);
  if (signatureBytes == 0 || signatureBytes > kMaximumSignatureBytes ||
      entriesEnd + 2 + signatureBytes != bytes) {
    return false;
  }
  if (view != nullptr) {
    view->version = version;
    view->venueId = wire + 16;
    view->authorityPublicKey = wire + 32;
    view->entries = wire + kHeaderBytes;
    view->entryCount = entryCount;
    view->signature = wire + entriesEnd + 2;
    view->signatureBytes = signatureBytes;
    view->unsignedBytes = entriesEnd;
  }
  return true;
}

constexpr uint8_t statusFor(const View& view, const uint8_t* publicKey) {
  if (publicKey == nullptr || view.entries == nullptr) return kStatusUnknown;
  for (uint16_t index = 0; index < view.entryCount; ++index) {
    const uint8_t* entry = view.entries + index * kEntryBytes;
    const int order = compareUnsigned(entry, publicKey, kP256PublicBytes);
    if (order == 0) return entry[66];
    if (order > 0) break;
  }
  return kStatusUnknown;
}

constexpr bool installVersionAllowed(bool managed, bool policyReady,
                                     uint64_t highestVersion,
                                     bool sameVenue, bool sameAuthority,
                                     uint64_t incomingVersion) {
  if (!managed) return incomingVersion > 0 && incomingVersion <= INT64_MAX;
  if (!sameVenue || !sameAuthority || incomingVersion < highestVersion) {
    return false;
  }
  return incomingVersion > highestVersion ||
      (incomingVersion == highestVersion && !policyReady);
}

constexpr std::array<uint8_t, kHeaderBytes + kEntryBytes + 3>
makeStaticFixture(uint8_t schema, uint8_t status) {
  std::array<uint8_t, kHeaderBytes + kEntryBytes + 3> wire{};
  wire[0] = 'H';
  wire[1] = 'V';
  wire[2] = 'I';
  wire[3] = '1';
  wire[4] = schema;
  wire[5] = 1;
  wire[15] = 1;
  wire[16] = 1;
  wire[32] = 4;
  wire[97] = 0;
  wire[98] = 1;
  wire[kHeaderBytes] = 4;
  wire[kHeaderBytes + 65] = kRoleCourier;
  wire[kHeaderBytes + 66] = status;
  wire[kHeaderBytes + kEntryBytes] = 0;
  wire[kHeaderBytes + kEntryBytes + 1] = 1;
  wire[kHeaderBytes + kEntryBytes + 2] = 1;
  return wire;
}

constexpr auto kValidFixture = makeStaticFixture(1, kStatusActive);
constexpr auto kRevokedOnlyFixture = makeStaticFixture(1, kStatusRevoked);
constexpr auto kUnsupportedFixture = makeStaticFixture(2, kStatusActive);
constexpr std::array<uint8_t, kHeaderBytes + kEntryBytes * 2 + 3>
makeTwoEntryFixture(bool duplicate, bool reversed) {
  std::array<uint8_t, kHeaderBytes + kEntryBytes * 2 + 3> wire{};
  wire[0] = 'H';
  wire[1] = 'V';
  wire[2] = 'I';
  wire[3] = '1';
  wire[4] = 1;
  wire[5] = 1;
  wire[15] = 1;
  wire[16] = 1;
  wire[32] = 4;
  wire[98] = 2;
  wire[kHeaderBytes] = 4;
  wire[kHeaderBytes + 64] = reversed ? 2 : 1;
  wire[kHeaderBytes + 65] = kRoleCourier;
  wire[kHeaderBytes + 66] = kStatusActive;
  const size_t second = kHeaderBytes + kEntryBytes;
  wire[second] = 4;
  wire[second + 64] = duplicate ? wire[kHeaderBytes + 64]
                                : (reversed ? 1 : 2);
  wire[second + 65] = kRoleCourier;
  wire[second + 66] = kStatusActive;
  wire[kHeaderBytes + kEntryBytes * 2 + 1] = 1;
  wire[kHeaderBytes + kEntryBytes * 2 + 2] = 1;
  return wire;
}
constexpr auto kSortedFixture = makeTwoEntryFixture(false, false);
constexpr auto kDuplicateFixture = makeTwoEntryFixture(true, false);
constexpr auto kReversedFixture = makeTwoEntryFixture(false, true);
static_assert(structurallyValid(kValidFixture.data(), kValidFixture.size()),
              "A bounded HVI1 active inventory must parse.");
static_assert(structurallyValid(kSortedFixture.data(), kSortedFixture.size()),
              "Sorted unique HVI1 entries must parse.");
static_assert(!structurallyValid(kDuplicateFixture.data(),
                                 kDuplicateFixture.size()),
              "Duplicate HVI1 node keys must fail.");
static_assert(!structurallyValid(kReversedFixture.data(),
                                 kReversedFixture.size()),
              "Unsorted HVI1 node keys must fail.");
static_assert(!structurallyValid(kRevokedOnlyFixture.data(),
                                 kRevokedOnlyFixture.size()),
              "An HVI1 inventory without an active courier must fail.");
static_assert(!structurallyValid(kUnsupportedFixture.data(),
                                 kUnsupportedFixture.size()),
              "Unsupported HVI1 versions must fail closed.");
static_assert(installVersionAllowed(false, false, 0, false, false, 1),
              "Explicit lab bootstrap accepts a valid first version.");
static_assert(!installVersionAllowed(true, true, 7, true, true, 7),
              "Equal-version replay must fail while policy is ready.");
static_assert(installVersionAllowed(true, false, 7, true, true, 7),
              "Exact fenced version may recover an unavailable policy.");
static_assert(!installVersionAllowed(true, false, 7, true, true, 6),
              "Rollback must fail even during recovery.");
static_assert(!installVersionAllowed(true, true, 7, false, true, 8),
              "A different venue cannot replace the trust anchor.");
static_assert(!installVersionAllowed(true, true, 7, true, false, 8),
              "A different authority cannot replace the trust anchor.");
static_assert(installVersionAllowed(true, true, 7, true, true, 8),
              "A signed higher inventory version must update.");

}  // namespace HyphaVenueInventory

#endif  // HYPHA_VENUE_INVENTORY_H
