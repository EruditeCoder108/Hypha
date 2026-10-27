#ifndef HYPHA_BLE_SESSION_GUARD_H
#define HYPHA_BLE_SESSION_GUARD_H

#include <array>
#include <stddef.h>
#include <stdint.h>

namespace HyphaBleSessionGuard {

constexpr uint32_t kAuthenticationDeadlineMs = 15U * 1000U;
constexpr uint32_t kAuthenticatedIdleTimeoutMs = 65U * 1000U;
constexpr uint32_t kMaximumConnectionMs = 5U * 60U * 1000U;
constexpr uint32_t kMaximumTransferStarts = 8;
constexpr uint32_t kMaximumHelloStarts = 1;
constexpr uint32_t kMaximumDeclaredBytes = 64U * 1024U;
constexpr uint32_t kMaximumWrites = 8192;
constexpr uint32_t kMaximumReads = 8192;
constexpr uint32_t kResourceWindowMs = 60U * 1000U;
constexpr uint32_t kMaximumConnectionsPerPeerWindow = 8;
constexpr uint32_t kMaximumConnectionsPerWindow = 96;
constexpr uint32_t kMaximumDeclaredBytesPerWindow = 512U * 1024U;
constexpr uint32_t kMaximumWritesPerWindow = 65536;
constexpr uint32_t kMaximumReadsPerWindow = 65536;
constexpr uint32_t kFailureWindowMs = 60U * 1000U;
constexpr uint8_t kFailuresBeforeBackoff = 3;
constexpr uint32_t kBackoffMs = 5U * 1000U;
constexpr size_t kPeerAddressBytes = 6;
constexpr size_t kTrackedPeerWindows = 16;

enum class DisconnectReason : uint8_t {
  kNone = 0,
  kProtocolViolation,
  kHandshakeLimit,
  kTransferLimit,
  kDeclaredByteLimit,
  kWriteLimit,
  kReadLimit,
  kPeerConnectionWindowLimit,
  kConnectionWindowLimit,
  kDeclaredByteWindowLimit,
  kWriteWindowLimit,
  kReadWindowLimit,
  kAuthenticationDeadline,
  kConnectionLifetime,
  kAuthenticatedIdle,
};

struct WindowSnapshot {
  uint32_t connections;
  uint32_t declaredBytes;
  uint32_t writes;
  uint32_t reads;
};

struct Snapshot {
  bool connected;
  bool authenticated;
  bool protocolViolation;
  uint32_t connectedAtMs;
  uint32_t lastActivityMs;
  uint32_t declaredBytes;
  uint32_t transferStarts;
  uint32_t helloStarts;
  uint32_t writes;
  uint32_t reads;
};

using PeerAddress = std::array<uint8_t, kPeerAddressBytes>;

struct PeerConnectionWindow {
  bool occupied;
  PeerAddress address;
  uint32_t startedAtMs;
  uint32_t lastSeenAtMs;
  uint32_t connections;
};

struct PeerConnectionWindows {
  std::array<PeerConnectionWindow, kTrackedPeerWindows> entries;
};

struct PeerConnectionDecision {
  uint32_t peerConnections;
  bool peerLimited;
  bool countsTowardAggregate;
};

constexpr uint32_t elapsed(uint32_t nowMs, uint32_t sinceMs) {
  return nowMs - sinceMs;
}

constexpr DisconnectReason evaluate(const Snapshot& state, uint32_t nowMs) {
  return !state.connected
      ? DisconnectReason::kNone
      : state.protocolViolation
          ? DisconnectReason::kProtocolViolation
          : state.helloStarts > kMaximumHelloStarts
              ? DisconnectReason::kHandshakeLimit
              : state.transferStarts > kMaximumTransferStarts
                  ? DisconnectReason::kTransferLimit
                  : state.declaredBytes > kMaximumDeclaredBytes
                      ? DisconnectReason::kDeclaredByteLimit
                      : state.writes > kMaximumWrites
                          ? DisconnectReason::kWriteLimit
                          : state.reads > kMaximumReads
                              ? DisconnectReason::kReadLimit
                              : !state.authenticated &&
                                        elapsed(nowMs, state.connectedAtMs) >=
                                            kAuthenticationDeadlineMs
                                  ? DisconnectReason::kAuthenticationDeadline
                                  : elapsed(nowMs, state.connectedAtMs) >=
                                            kMaximumConnectionMs
                                      ? DisconnectReason::kConnectionLifetime
                                      : state.authenticated &&
                                                elapsed(nowMs,
                                                        state.lastActivityMs) >=
                                                    kAuthenticatedIdleTimeoutMs
                                          ? DisconnectReason::kAuthenticatedIdle
                                          : DisconnectReason::kNone;
}

constexpr DisconnectReason evaluateWindow(const WindowSnapshot& state) {
  return state.connections > kMaximumConnectionsPerWindow
      ? DisconnectReason::kConnectionWindowLimit
      : state.declaredBytes > kMaximumDeclaredBytesPerWindow
          ? DisconnectReason::kDeclaredByteWindowLimit
          : state.writes > kMaximumWritesPerWindow
              ? DisconnectReason::kWriteWindowLimit
              : state.reads > kMaximumReadsPerWindow
                  ? DisconnectReason::kReadWindowLimit
                  : DisconnectReason::kNone;
}

constexpr DisconnectReason evaluatePeerWindow(uint32_t connections) {
  return connections > kMaximumConnectionsPerPeerWindow
      ? DisconnectReason::kPeerConnectionWindowLimit
      : DisconnectReason::kNone;
}

constexpr bool countsTowardAggregateWindow(uint32_t peerConnections) {
  return evaluatePeerWindow(peerConnections) == DisconnectReason::kNone;
}

constexpr bool samePeerAddress(const PeerAddress& left,
                               const PeerAddress& right) {
  for (size_t index = 0; index < left.size(); ++index) {
    if (left[index] != right[index]) return false;
  }
  return true;
}

constexpr PeerConnectionDecision recordPeerConnection(
    PeerConnectionWindows& windows, const PeerAddress& address,
    uint32_t nowMs) {
  size_t match = kTrackedPeerWindows;
  size_t available = kTrackedPeerWindows;
  size_t oldest = kTrackedPeerWindows;
  uint32_t oldestAge = 0;
  for (size_t index = 0; index < windows.entries.size(); ++index) {
    PeerConnectionWindow& candidate = windows.entries[index];
    if (candidate.occupied &&
        elapsed(nowMs, candidate.startedAtMs) >= kResourceWindowMs) {
      candidate = PeerConnectionWindow{};
    }
    if (!candidate.occupied) {
      if (available == kTrackedPeerWindows) available = index;
      continue;
    }
    if (samePeerAddress(candidate.address, address)) {
      match = index;
      break;
    }
    const uint32_t age = elapsed(nowMs, candidate.lastSeenAtMs);
    if (oldest == kTrackedPeerWindows || age > oldestAge) {
      oldest = index;
      oldestAge = age;
    }
  }
  const size_t selected = match != kTrackedPeerWindows
      ? match
      : available != kTrackedPeerWindows ? available : oldest;
  if (match == kTrackedPeerWindows) {
    windows.entries[selected] = PeerConnectionWindow{};
    windows.entries[selected].occupied = true;
    windows.entries[selected].address = address;
    windows.entries[selected].startedAtMs = nowMs;
  }
  PeerConnectionWindow& entry = windows.entries[selected];
  entry.lastSeenAtMs = nowMs;
  if (entry.connections != UINT32_MAX) ++entry.connections;
  return PeerConnectionDecision{
      entry.connections,
      evaluatePeerWindow(entry.connections) != DisconnectReason::kNone,
      countsTowardAggregateWindow(entry.connections),
  };
}

constexpr bool shouldBackoff(uint8_t failuresInWindow) {
  return failuresInWindow >= kFailuresBeforeBackoff;
}

constexpr Snapshot kDisconnected = {
    false, false, false, 100, 100, 0, 0, 0, 0, 0};
constexpr Snapshot kLegitimateSession = {
    true, true, false, 1000, 59000, 24U * 1024U, 6, 1, 2200, 1800};
constexpr Snapshot kUnauthenticated = {
    true, false, false, 1000, 14999, 93, 1, 1, 8, 0};
constexpr PeerAddress kPeerA = {0x10, 0, 0, 0, 0, 1};
constexpr PeerAddress kPeerB = {0x20, 0, 0, 0, 0, 2};

constexpr bool peerIsolationCheck() {
  PeerConnectionWindows windows{};
  PeerConnectionDecision decision{};
  for (uint32_t connection = 0;
       connection < kMaximumConnectionsPerPeerWindow; ++connection) {
    decision = recordPeerConnection(windows, kPeerA, 1000);
    if (decision.peerLimited || !decision.countsTowardAggregate) return false;
  }
  const PeerConnectionDecision blocked =
      recordPeerConnection(windows, kPeerA, 1000);
  const PeerConnectionDecision other =
      recordPeerConnection(windows, kPeerB, 1000);
  return blocked.peerLimited && !blocked.countsTowardAggregate &&
      other.peerConnections == 1 && !other.peerLimited &&
      other.countsTowardAggregate;
}

constexpr bool peerWindowExpiryCheck() {
  PeerConnectionWindows windows{};
  recordPeerConnection(windows, kPeerA, 1000);
  return recordPeerConnection(
             windows, kPeerA, 1000 + kResourceWindowMs).peerConnections == 1;
}

constexpr bool peerWindowWrapCheck() {
  PeerConnectionWindows windows{};
  recordPeerConnection(windows, kPeerA, UINT32_MAX - 99U);
  return recordPeerConnection(
             windows, kPeerA, kResourceWindowMs - 100U).peerConnections == 1;
}

static_assert(evaluate(kDisconnected, UINT32_MAX) == DisconnectReason::kNone,
              "a disconnected server has no guard action");
static_assert(evaluate(kLegitimateSession, 60000) == DisconnectReason::kNone,
              "a bounded legitimate node session remains admitted");
static_assert(evaluate(kUnauthenticated, 15999) == DisconnectReason::kNone,
              "the authentication deadline is inclusive only at its bound");
static_assert(evaluate(kUnauthenticated, 16000) ==
                  DisconnectReason::kAuthenticationDeadline,
              "a stalled handshake is disconnected at the deadline");
static_assert(
    evaluate(Snapshot{true, true, false, 1000, 2000, 100, 2, 1, 3, 2},
             2000 + kAuthenticatedIdleTimeoutMs) ==
        DisconnectReason::kAuthenticatedIdle,
    "an authenticated silent client is disconnected at the idle bound");
static_assert(
    evaluate(Snapshot{true, true, false, 1000, 1000 + kMaximumConnectionMs - 1,
                      100, 2, 1, 3, 2},
             1000 + kMaximumConnectionMs) ==
        DisconnectReason::kConnectionLifetime,
    "activity cannot extend a connection beyond its absolute lifetime");
static_assert(
    evaluate(Snapshot{true, false, true, 0, 0, 0, 0, 0, 0, 0}, 0) ==
        DisconnectReason::kProtocolViolation,
    "malformed protocol state is terminal");
static_assert(
    evaluate(Snapshot{true, false, false, 0, 0, 0, 2, 2, 1, 0}, 1) ==
        DisconnectReason::kHandshakeLimit,
    "a second hello exceeds the connection handshake budget");
static_assert(
    evaluate(Snapshot{true, true, false, 0, 0, 0, 9, 1, 9, 0}, 1) ==
        DisconnectReason::kTransferLimit,
    "transfer starts are bounded per connection");
static_assert(
    evaluate(Snapshot{true, true, false, 0, 0, kMaximumDeclaredBytes + 1,
                      2, 1, 2, 0},
             1) == DisconnectReason::kDeclaredByteLimit,
    "declared client bytes are bounded per connection");
static_assert(
    evaluate(Snapshot{true, true, false, 0, 0, 0, 2, 1,
                      kMaximumWrites + 1, 0},
             1) == DisconnectReason::kWriteLimit,
    "writes are bounded per connection");
static_assert(
    evaluate(Snapshot{true, true, false, 0, 0, 0, 2, 1, 1,
                      kMaximumReads + 1},
             1) == DisconnectReason::kReadLimit,
    "reads are bounded per connection");
static_assert(
    evaluatePeerWindow(kMaximumConnectionsPerPeerWindow) ==
        DisconnectReason::kNone,
    "a peer remains admitted at its exact connection-window bound");
static_assert(
    evaluatePeerWindow(kMaximumConnectionsPerPeerWindow + 1) ==
        DisconnectReason::kPeerConnectionWindowLimit,
    "one noisy peer is isolated after its bounded connection window");
static_assert(
    !countsTowardAggregateWindow(kMaximumConnectionsPerPeerWindow + 1),
    "an already-isolated peer cannot poison the aggregate window");
static_assert(peerIsolationCheck(),
              "one noisy peer cannot consume another peer's allowance");
static_assert(peerWindowExpiryCheck(),
              "a peer receives a fresh allowance after its bounded window");
static_assert(peerWindowWrapCheck(),
              "peer-window expiry remains correct across millis wrap");
static_assert(
    evaluateWindow(WindowSnapshot{kMaximumConnectionsPerWindow + 1, 0, 0, 0}) ==
        DisconnectReason::kConnectionWindowLimit,
    "connections are bounded across the anonymous resource window");
static_assert(
    evaluateWindow(WindowSnapshot{1, kMaximumDeclaredBytesPerWindow + 1, 0, 0}) ==
        DisconnectReason::kDeclaredByteWindowLimit,
    "declared bytes are bounded across the anonymous resource window");
static_assert(
    evaluateWindow(WindowSnapshot{1, 0, kMaximumWritesPerWindow + 1, 0}) ==
        DisconnectReason::kWriteWindowLimit,
    "writes are bounded across the anonymous resource window");
static_assert(
    evaluateWindow(WindowSnapshot{1, 0, 0, kMaximumReadsPerWindow + 1}) ==
        DisconnectReason::kReadWindowLimit,
    "reads are bounded across the anonymous resource window");
static_assert(
    evaluate(Snapshot{true, false, false, UINT32_MAX - 99U, UINT32_MAX - 99U,
                      0, 0, 0, 0, 0},
             kAuthenticationDeadlineMs - 100U) ==
        DisconnectReason::kAuthenticationDeadline,
    "unsigned monotonic elapsed time remains correct across millis wrap");
static_assert(!shouldBackoff(kFailuresBeforeBackoff - 1),
              "isolated guard failures do not pause advertising");
static_assert(shouldBackoff(kFailuresBeforeBackoff),
              "repeated guard failures trigger bounded backoff");

}  // namespace HyphaBleSessionGuard

#endif  // HYPHA_BLE_SESSION_GUARD_H
