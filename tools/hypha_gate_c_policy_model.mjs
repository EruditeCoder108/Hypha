/**
 * Deterministic semantic model for selected ADR 0011 HAT1 admission.
 *
 * This is not production admission code. proof.verified is a test fixture standing
 * in for the isolated HAT1 cryptographic verifier. Participant issuance quotas live
 * at the supervised blind issuer and are deliberately not modeled as a node tag.
 */

export const CLASS_PRIORITY = Object.freeze({
  security: 0,
  receipt: 0,
  text: 2,
  manifest: 4,
  bulk: 5,
});

const CLASS_ORDER = Object.freeze(['security', 'receipt', 'text', 'manifest', 'bulk']);

function emptyUsage() {
  return { objects: 0, bytes: 0, duplicates: 0, conflicts: 0 };
}

function requireLimit(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe integer.`);
  }
  return value;
}

function copyUsage(usage) {
  return {
    objects: usage.objects,
    bytes: usage.bytes,
    duplicates: usage.duplicates,
    conflicts: usage.conflicts,
  };
}

export class GateCPolicyModel {
  constructor(policy) {
    this.policy = normalizePolicy(policy);
    this.records = new Map();
    this.tickets = new Map();
    this.classes = new Map(CLASS_ORDER.map((name) => [name, emptyUsage()]));
    this.sessions = new Map();
    this.revokedTickets = new Set();
    this.sequence = 0;
    this.totalBytes = 0;
  }

  revokeTicket(ticketId) {
    this.revokedTickets.add(ticketId);
  }

  snapshot() {
    return {
      storedObjects: this.records.size,
      storedBytes: this.totalBytes,
      records: [...this.records.entries()].map(([id, record]) => ({
        id,
        digest: record.digest,
        objectClass: record.objectClass,
        encodedBytes: record.encodedBytes,
      })),
      trackedTickets: this.tickets.size,
      classes: Object.fromEntries(
        [...this.classes.entries()].map(([name, usage]) => [name, copyUsage(usage)]),
      ),
    };
  }

  serviceOrder(limit = this.records.size) {
    requireLimit(limit, 'Service limit');
    return [...this.records.values()]
      .sort((left, right) => {
        const classDifference = CLASS_ORDER.indexOf(left.objectClass)
          - CLASS_ORDER.indexOf(right.objectClass);
        return classDifference || left.sequence - right.sequence;
      })
      .slice(0, limit)
      .map(({ id, objectClass }) => ({ id, objectClass }));
  }

  admit({ sessionId, envelope, proof }) {
    const session = this.#session(sessionId);
    if (!session) return rejected('session_table_full');
    if (session.backedOff) return rejected('session_backoff');
    session.attempts += 1;
    if (session.attempts > this.policy.session.maxAttempts) {
      session.backedOff = true;
      return rejected('session_attempt_limit');
    }
    if (!validEnvelopeFixture(envelope)) return this.#proofFailure(session, 'invalid_envelope');
    if (!proof?.verified) return this.#proofFailure(session, 'invalid_proof');
    if (!validProofFixture(proof)) return this.#proofFailure(session, 'invalid_proof_claims');
    if (proof.venueId !== this.policy.venueId) return rejected('wrong_venue');
    if (proof.operatorEpoch !== this.policy.operatorEpoch) return rejected('wrong_epoch');
    if (proof.proofVersion !== this.policy.proofVersion) return rejected('unsupported_proof');
    if (proof.revoked || this.revokedTickets.has(proof.ticketId)) return rejected('revoked');
    if (proof.binding !== envelope.binding) return rejected('binding_mismatch');
    if (CLASS_PRIORITY[proof.objectClass] !== envelope.priority) {
      return rejected('forged_priority');
    }
    if (
      proof.objectClass !== envelope.objectClass
      || envelope.encodedBytes > proof.maxEncodedBytes
      || envelope.lifetimeMs > proof.maxLifetimeMs
      || envelope.hopLimit > proof.maxHopLimit
      || envelope.copyBudget > proof.maxCopyBudget
    ) {
      return rejected('authorization_ceiling');
    }

    const priorTicket = this.tickets.get(proof.ticketId);
    if (priorTicket && priorTicket.binding !== proof.binding) return rejected('ticket_replay');
    if (priorTicket?.state === 'conflict') return rejected('ticket_conflict');
    if (!priorTicket && this.tickets.size >= this.policy.ticket.maxEntries) {
      return rejected('ticket_table_full');
    }

    const existing = this.records.get(envelope.id);
    if (existing) {
      if (existing.digest !== envelope.digest) {
        if (!priorTicket) {
          this.tickets.set(proof.ticketId, {
            binding: proof.binding,
            state: 'conflict',
            duplicates: 0,
          });
        }
        session.conflicts += 1;
        if (session.conflicts >= this.policy.session.maxConflicts) session.backedOff = true;
        return rejected('same_id_conflict');
      }
      const ticket = priorTicket ?? {
        binding: proof.binding,
        state: 'duplicate',
        duplicates: 0,
      };
      if (!priorTicket) this.tickets.set(proof.ticketId, ticket);
      ticket.duplicates += 1;
      session.duplicates += 1;
      if (
        ticket.duplicates > this.policy.ticket.maxDuplicateAttempts
        || session.duplicates > this.policy.session.maxDuplicates
      ) {
        session.backedOff = true;
        return rejected('duplicate_limit');
      }
      return accepted('duplicate', false);
    }

    if (priorTicket) return rejected('ticket_without_record');
    if (session.newObjects + 1 > this.policy.session.maxNewObjects) {
      return rejected('session_object_quota');
    }
    if (session.newBytes + envelope.encodedBytes > this.policy.session.maxNewBytes) {
      return rejected('session_byte_quota');
    }
    const classUsage = this.classes.get(proof.objectClass);
    const classLimit = this.policy.classes[proof.objectClass];
    if (classUsage.objects + 1 > classLimit.maxObjects) {
      return rejected('class_object_quota');
    }
    if (classUsage.bytes + envelope.encodedBytes > classLimit.maxBytes) {
      return rejected('class_byte_quota');
    }
    if (!this.#reserveAllows(proof.objectClass, envelope.encodedBytes)) {
      return rejected('store_reserve');
    }

    // The real implementation must commit these facts atomically before custody.
    const record = {
      id: envelope.id,
      digest: envelope.digest,
      objectClass: proof.objectClass,
      encodedBytes: envelope.encodedBytes,
      sequence: this.sequence,
    };
    this.sequence += 1;
    this.records.set(envelope.id, record);
    this.tickets.set(proof.ticketId, {
      binding: proof.binding,
      state: 'accepted',
      duplicates: 0,
    });
    session.newObjects += 1;
    session.newBytes += envelope.encodedBytes;
    classUsage.objects += 1;
    classUsage.bytes += envelope.encodedBytes;
    this.totalBytes += envelope.encodedBytes;
    return accepted('accepted', true);
  }

  #session(sessionId) {
    if (typeof sessionId !== 'string' || sessionId.length === 0) {
      throw new Error('A process-local session id is required by the model.');
    }
    let session = this.sessions.get(sessionId);
    if (!session) {
      if (this.sessions.size >= this.policy.session.maxTracked) return null;
      session = {
        attempts: 0,
        failedProofs: 0,
        duplicates: 0,
        conflicts: 0,
        newObjects: 0,
        newBytes: 0,
        backedOff: false,
      };
      this.sessions.set(sessionId, session);
    }
    return session;
  }

  #proofFailure(session, reason) {
    session.failedProofs += 1;
    if (session.failedProofs >= this.policy.session.maxFailedProofs) {
      session.backedOff = true;
    }
    return rejected(reason);
  }

  #reserveAllows(objectClass, encodedBytes) {
    if (
      this.records.size + 1 > this.policy.store.maxObjects
      || this.totalBytes + encodedBytes > this.policy.store.maxBytes
    ) {
      return false;
    }
    const candidateRank = CLASS_ORDER.indexOf(objectClass);
    let requiredObjects = 0;
    let requiredBytes = 0;
    for (let index = 0; index < candidateRank; index += 1) {
      const higherClass = CLASS_ORDER[index];
      const usage = this.classes.get(higherClass);
      const reserve = this.policy.classes[higherClass];
      requiredObjects += Math.max(0, reserve.reserveObjects - usage.objects);
      requiredBytes += Math.max(0, reserve.reserveBytes - usage.bytes);
    }
    const objectsAfter = this.records.size + 1;
    const bytesAfter = this.totalBytes + encodedBytes;
    return this.policy.store.maxObjects - objectsAfter >= requiredObjects
      && this.policy.store.maxBytes - bytesAfter >= requiredBytes;
  }
}

function normalizePolicy(policy) {
  if (!policy || typeof policy.venueId !== 'string' || policy.venueId.length === 0) {
    throw new Error('Policy venueId is required.');
  }
  if (!Number.isSafeInteger(policy.operatorEpoch) || policy.operatorEpoch < 1) {
    throw new Error('Policy operatorEpoch must be positive.');
  }
  const normalized = {
    venueId: policy.venueId,
    operatorEpoch: policy.operatorEpoch,
    proofVersion: requireLimit(policy.proofVersion, 'Proof version'),
    store: {
      maxObjects: requireLimit(policy.store?.maxObjects, 'Store object limit'),
      maxBytes: requireLimit(policy.store?.maxBytes, 'Store byte limit'),
    },
    session: {
      maxTracked: requireLimit(policy.session?.maxTracked, 'Tracked session limit'),
      maxAttempts: requireLimit(policy.session?.maxAttempts, 'Session attempt limit'),
      maxFailedProofs: requireLimit(policy.session?.maxFailedProofs, 'Failed proof limit'),
      maxDuplicates: requireLimit(policy.session?.maxDuplicates, 'Session duplicate limit'),
      maxConflicts: requireLimit(policy.session?.maxConflicts, 'Session conflict limit'),
      maxNewObjects: requireLimit(policy.session?.maxNewObjects, 'Session object limit'),
      maxNewBytes: requireLimit(policy.session?.maxNewBytes, 'Session byte limit'),
    },
    ticket: {
      maxEntries: requireLimit(policy.ticket?.maxEntries, 'Ticket table limit'),
      maxDuplicateAttempts: requireLimit(
        policy.ticket?.maxDuplicateAttempts,
        'Ticket duplicate limit',
      ),
    },
    classes: {},
  };
  for (const name of CLASS_ORDER) {
    const source = policy.classes?.[name];
    normalized.classes[name] = {
      maxObjects: requireLimit(source?.maxObjects, `${name} object limit`),
      maxBytes: requireLimit(source?.maxBytes, `${name} byte limit`),
      reserveObjects: requireLimit(source?.reserveObjects, `${name} object reserve`),
      reserveBytes: requireLimit(source?.reserveBytes, `${name} byte reserve`),
    };
  }
  return normalized;
}

function validEnvelopeFixture(envelope) {
  return envelope
    && typeof envelope.id === 'string'
    && envelope.id.length > 0
    && typeof envelope.digest === 'string'
    && envelope.digest.length > 0
    && typeof envelope.binding === 'string'
    && envelope.binding.length > 0
    && Object.hasOwn(CLASS_PRIORITY, envelope.objectClass)
    && Number.isSafeInteger(envelope.priority)
    && Number.isSafeInteger(envelope.encodedBytes)
    && envelope.encodedBytes > 0
    && Number.isSafeInteger(envelope.lifetimeMs)
    && envelope.lifetimeMs > 0
    && Number.isSafeInteger(envelope.hopLimit)
    && envelope.hopLimit > 0
    && Number.isSafeInteger(envelope.copyBudget)
    && envelope.copyBudget > 0;
}

function validProofFixture(proof) {
  return typeof proof.venueId === 'string'
    && Number.isSafeInteger(proof.operatorEpoch)
    && Number.isSafeInteger(proof.proofVersion)
    && typeof proof.ticketId === 'string'
    && proof.ticketId.length > 0
    && typeof proof.binding === 'string'
    && proof.binding.length > 0
    && Object.hasOwn(CLASS_PRIORITY, proof.objectClass)
    && Number.isSafeInteger(proof.maxEncodedBytes)
    && Number.isSafeInteger(proof.maxLifetimeMs)
    && Number.isSafeInteger(proof.maxHopLimit)
    && Number.isSafeInteger(proof.maxCopyBudget);
}

function accepted(kind, newRecord) {
  return {
    accepted: true,
    kind,
    newRecord,
    custodyAcknowledged: true,
    copyBudgetChanged: false,
  };
}

function rejected(reason) {
  return {
    accepted: false,
    kind: 'rejected',
    reason,
    newRecord: false,
    custodyAcknowledged: false,
    copyBudgetChanged: false,
  };
}
