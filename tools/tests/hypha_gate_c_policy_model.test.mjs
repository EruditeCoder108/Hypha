import assert from 'node:assert/strict';
import test from 'node:test';
import { CLASS_PRIORITY, GateCPolicyModel } from '../hypha_gate_c_policy_model.mjs';

function policy() {
  const classLimit = (reserveObjects, reserveBytes) => ({
    maxObjects: 8,
    maxBytes: 800,
    reserveObjects,
    reserveBytes,
  });
  return {
    venueId: 'venue-a',
    operatorEpoch: 7,
    proofVersion: 1,
    store: { maxObjects: 8, maxBytes: 800 },
    session: {
      maxTracked: 16,
      maxAttempts: 12,
      maxFailedProofs: 3,
      maxDuplicates: 3,
      maxConflicts: 2,
      maxNewObjects: 6,
      maxNewBytes: 700,
    },
    ticket: { maxEntries: 12, maxDuplicateAttempts: 2 },
    classes: {
      security: classLimit(1, 100),
      receipt: classLimit(2, 200),
      text: classLimit(2, 200),
      manifest: classLimit(0, 0),
      bulk: classLimit(0, 0),
    },
  };
}

function envelope(id, objectClass = 'text', overrides = {}) {
  const digest = overrides.digest ?? `digest-${id}`;
  return {
    id,
    digest,
    binding: overrides.binding ?? `binding-${id}-${digest}`,
    objectClass,
    priority: overrides.priority ?? CLASS_PRIORITY[objectClass],
    encodedBytes: overrides.encodedBytes ?? 100,
    lifetimeMs: overrides.lifetimeMs ?? 60_000,
    hopLimit: overrides.hopLimit ?? 8,
    copyBudget: overrides.copyBudget ?? 4,
  };
}

function proofFor(value, overrides = {}) {
  return {
    verified: overrides.verified ?? true,
    venueId: overrides.venueId ?? 'venue-a',
    operatorEpoch: overrides.operatorEpoch ?? 7,
    proofVersion: overrides.proofVersion ?? 1,
    ticketId: overrides.ticketId ?? `ticket-${value.id}`,
    binding: overrides.binding ?? value.binding,
    objectClass: overrides.objectClass ?? value.objectClass,
    maxEncodedBytes: overrides.maxEncodedBytes ?? 100,
    maxLifetimeMs: overrides.maxLifetimeMs ?? 60_000,
    maxHopLimit: overrides.maxHopLimit ?? 8,
    maxCopyBudget: overrides.maxCopyBudget ?? 4,
    revoked: overrides.revoked ?? false,
  };
}

function offer(model, sessionId, value, proofOverrides = {}) {
  return model.admit({
    sessionId,
    envelope: value,
    proof: proofFor(value, proofOverrides),
  });
}

function assertNoCustody(result) {
  assert.equal(result.accepted, false);
  assert.equal(result.custodyAcknowledged, false);
  assert.equal(result.copyBudgetChanged, false);
}

test('valid admission commits once and exact duplicate is idempotent', () => {
  const model = new GateCPolicyModel(policy());
  const value = envelope('message-1');

  const accepted = offer(model, 'session-a', value);
  assert.equal(accepted.kind, 'accepted');
  assert.equal(accepted.custodyAcknowledged, true);
  assert.equal(accepted.copyBudgetChanged, false);

  const duplicate = offer(model, 'session-a', value);
  assert.equal(duplicate.kind, 'duplicate');
  assert.equal(model.snapshot().storedObjects, 1);
  assert.equal(model.snapshot().trackedTickets, 1);
});

test('valid-looking junk and failed proofs back off without consuming store or quota', () => {
  const model = new GateCPolicyModel(policy());
  for (let index = 0; index < 3; index += 1) {
    const value = envelope(`junk-${index}`);
    assertNoCustody(offer(model, 'attacker-session', value, {
      verified: false,
      ticketId: `junk-ticket-${index}`,
    }));
  }
  assert.equal(offer(model, 'attacker-session', envelope('junk-late')).reason, 'session_backoff');
  assert.equal(model.snapshot().storedObjects, 0);
  assert.equal(model.snapshot().trackedTickets, 0);

  assert.equal(offer(model, 'clean-session', envelope('legitimate')).kind, 'accepted');
});

test('ordinary authorization cannot forge control or receipt priority', () => {
  const model = new GateCPolicyModel(policy());
  const forged = envelope('forged-control', 'text', { priority: 0 });
  const result = offer(model, 'session-a', forged);

  assert.equal(result.reason, 'forged_priority');
  assertNoCustody(result);
  assert.equal(model.snapshot().storedObjects, 0);
});

test('duplicate flood is bounded and never recharges normal object or byte quota', () => {
  const model = new GateCPolicyModel(policy());
  const value = envelope('duplicate-target');
  assert.equal(offer(model, 'session-a', value).kind, 'accepted');
  assert.equal(offer(model, 'session-a', value).kind, 'duplicate');
  assert.equal(offer(model, 'session-a', value).kind, 'duplicate');
  const limited = offer(model, 'session-a', value);

  assert.equal(limited.reason, 'duplicate_limit');
  assertNoCustody(limited);
  assert.equal(model.snapshot().storedObjects, 1);
  assert.equal(model.snapshot().trackedTickets, 1);
});

test('same-ID conflict preserves first bytes and tombstones the conflicting ticket', () => {
  const model = new GateCPolicyModel(policy());
  const first = envelope('shared-id', 'text', { digest: 'digest-first' });
  const conflict = envelope('shared-id', 'text', { digest: 'digest-conflict' });
  assert.equal(offer(model, 'session-a', first).kind, 'accepted');

  const rejected = offer(model, 'session-b', conflict, {
    ticketId: 'conflicting-ticket',
  });
  assert.equal(rejected.reason, 'same_id_conflict');
  assertNoCustody(rejected);
  assert.equal(model.snapshot().records[0].digest, 'digest-first');
  assert.equal(model.snapshot().storedObjects, 1);

  const repeated = offer(model, 'session-b', conflict, {
    ticketId: 'conflicting-ticket',
  });
  assert.equal(repeated.reason, 'ticket_conflict');
  assertNoCustody(repeated);
});

test('rotating sessions cannot reuse one HAT1 ticket for different envelopes', () => {
  const model = new GateCPolicyModel(policy());
  const first = envelope('rotation-first');
  assert.equal(offer(model, 'rotating-radio-0', first, {
    ticketId: 'portable-ticket',
  }).kind, 'accepted');
  assert.equal(offer(model, 'rotating-radio-1', first, {
    ticketId: 'portable-ticket',
  }).kind, 'duplicate');
  const blocked = offer(model, 'rotating-radio-2', envelope('rotation-other'), {
    ticketId: 'portable-ticket',
  });
  assert.equal(blocked.reason, 'ticket_replay');
  assertNoCustody(blocked);
  assert.equal(model.snapshot().storedObjects, 1);
});

test('bulk pressure cannot consume receipt and text reserves', () => {
  const model = new GateCPolicyModel(policy());
  for (let index = 0; index < 3; index += 1) {
    const value = envelope(`bulk-${index}`, 'bulk');
    assert.equal(offer(model, `bulk-session-${index}`, value).kind, 'accepted');
  }
  const refusedBulk = offer(model, 'bulk-session-3', envelope('bulk-3', 'bulk'));
  assert.equal(refusedBulk.reason, 'store_reserve');

  for (let index = 0; index < 2; index += 1) {
    assert.equal(offer(model, `receipt-session-${index}`, envelope(`receipt-${index}`, 'receipt')).kind, 'accepted');
    assert.equal(offer(model, `text-session-${index}`, envelope(`text-${index}`, 'text')).kind, 'accepted');
  }
  assert.equal(model.snapshot().storedObjects, 7);
});

test('wrong policy, revocation, and ticket replay fail closed without deleting custody', () => {
  const model = new GateCPolicyModel(policy());
  const kept = envelope('kept');
  assert.equal(offer(model, 'session-kept', kept).kind, 'accepted');

  const wrongVenue = offer(model, 'wrong-venue', envelope('wrong-venue'), {
    venueId: 'venue-b',
  });
  assert.equal(wrongVenue.reason, 'wrong_venue');
  assertNoCustody(wrongVenue);

  const wrongEpoch = offer(model, 'wrong-epoch', envelope('wrong-epoch'), {
    operatorEpoch: 6,
  });
  assert.equal(wrongEpoch.reason, 'wrong_epoch');
  assertNoCustody(wrongEpoch);

  const revoked = envelope('revoked');
  model.revokeTicket('revoked-ticket');
  const revokedResult = offer(model, 'revoked-session', revoked, {
    ticketId: 'revoked-ticket',
  });
  assert.equal(revokedResult.reason, 'revoked');
  assertNoCustody(revokedResult);

  const replayTarget = envelope('ticket-replay');
  const replayResult = offer(model, 'replay-session', replayTarget, {
    ticketId: 'ticket-kept',
  });
  assert.equal(replayResult.reason, 'ticket_replay');
  assertNoCustody(replayResult);
  assert.equal(model.snapshot().records[0].id, 'kept');
  assert.equal(model.snapshot().storedObjects, 1);
});

test('legitimate receipt and text service stays ahead of admitted bulk after attacks', () => {
  const model = new GateCPolicyModel(policy());
  for (let index = 0; index < 6; index += 1) {
    const junk = envelope(`rotating-junk-${index}`);
    assertNoCustody(offer(model, `junk-session-${index}`, junk, {
      verified: false,
      ticketId: `junk-${index}`,
    }));
  }
  for (let index = 0; index < 3; index += 1) {
    assert.equal(offer(model, `bulk-${index}`, envelope(`queued-bulk-${index}`, 'bulk')).kind, 'accepted');
  }
  assert.equal(offer(model, 'receipt', envelope('good-receipt', 'receipt')).kind, 'accepted');
  assert.equal(offer(model, 'text', envelope('good-text', 'text')).kind, 'accepted');

  assert.deepEqual(model.serviceOrder(2), [
    { id: 'good-receipt', objectClass: 'receipt' },
    { id: 'good-text', objectClass: 'text' },
  ]);
});

test('ticket tombstones cannot grow beyond the declared accounting bound', () => {
  const boundedPolicy = policy();
  boundedPolicy.ticket.maxEntries = 3;
  const model = new GateCPolicyModel(boundedPolicy);
  const value = envelope('accounting-target');
  assert.equal(offer(model, 'session-a', value, {
    ticketId: 'ticket-a',
  }).kind, 'accepted');
  assert.equal(offer(model, 'session-b', value, {
    ticketId: 'ticket-b',
  }).kind, 'duplicate');

  const conflict = envelope('accounting-target', 'text', { digest: 'conflict' });
  assert.equal(offer(model, 'session-d', conflict, {
    ticketId: 'ticket-c',
  }).reason, 'same_id_conflict');
  const ticketFull = offer(model, 'session-e', value, {
    ticketId: 'ticket-d',
  });
  assert.equal(ticketFull.reason, 'ticket_table_full');
  assertNoCustody(ticketFull);
  assert.equal(model.snapshot().storedObjects, 1);
});
