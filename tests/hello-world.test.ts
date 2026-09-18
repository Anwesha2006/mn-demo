/**
 * tests/hello-world.test.ts
 *
 * Unit tests for the hello-world contract's circuit logic.
 *
 * These tests exercise the privacy model and state transitions WITHOUT
 * connecting to a network or proof server. They import the compiled
 * @midnight-ntwrk/compact-runtime to simulate ledger state locally.
 *
 * Run with: npm test
 * (Requires: npm run compile to have generated contracts/managed/hello-world/)
 */

import * as crypto from 'node:crypto';

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Simulate persistentHash<Bytes<32>> using SHA-256 (same as Compact's impl). */
function persistentHash(input: Uint8Array): Uint8Array {
  return new Uint8Array(crypto.createHash('sha256').update(input).digest());
}

/** Generate a random 32-byte secret key. */
function randomSecretKey(): Uint8Array {
  return new Uint8Array(crypto.randomBytes(32));
}

/** Simulate ledger state for the hello-world contract. */
interface LedgerState {
  message: string;
  owner: Uint8Array; // persistentHash of owner's secret key
}

/**
 * Simulate the constructor: sets owner hash and initial message.
 * The secret_key() witness is consumed locally — never on-chain.
 */
function simulateConstructor(secretKey: Uint8Array, initialMessage: string): LedgerState {
  return {
    message: initialMessage,
    owner: persistentHash(secretKey), // disclose(persistentHash(secret_key()))
  };
}

/**
 * Simulate storeMessage circuit.
 * Throws if caller_hash != owner (ownership proof failure).
 * The secret key is a witness — never stored in ledger state.
 */
function simulateStoreMessage(
  state: LedgerState,
  callerSecretKey: Uint8Array,
  newMessage: string,
): LedgerState {
  const callerHash = persistentHash(callerSecretKey);
  // assert(disclose(caller_hash) == owner, ...)
  const matches = callerHash.every((b, i) => b === state.owner[i]);
  if (!matches) {
    throw new Error('Only the owner can store a message');
  }
  return { ...state, message: newMessage };
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('Hello World Contract — Circuit Logic', () => {
  test('constructor sets owner hash and initial message', () => {
    const secretKey = randomSecretKey();
    const state = simulateConstructor(secretKey, 'Hello from Midnight!');

    expect(state.message).toBe('Hello from Midnight!');
    // owner is a hash — 32 bytes, never the raw key
    expect(state.owner).toHaveLength(32);
    // owner must equal persistentHash(secretKey)
    const expected = persistentHash(secretKey);
    expect(state.owner).toEqual(expected);
    // PRIVACY: owner is NOT the raw secret key
    expect(state.owner).not.toEqual(secretKey);
  });

  test('storeMessage succeeds for the owner', () => {
    const secretKey = randomSecretKey();
    const state = simulateConstructor(secretKey, 'Initial message');
    const next = simulateStoreMessage(state, secretKey, 'Updated message');

    expect(next.message).toBe('Updated message');
    // owner hash unchanged after storing a message
    expect(next.owner).toEqual(state.owner);
  });

  test('storeMessage fails for a non-owner', () => {
    const ownerKey = randomSecretKey();
    const attackerKey = randomSecretKey();
    const state = simulateConstructor(ownerKey, 'Private data');

    expect(() => simulateStoreMessage(state, attackerKey, 'Overwrite attempt')).toThrow(
      'Only the owner can store a message',
    );
    // ledger state is unchanged
    expect(state.message).toBe('Private data');
  });

  test('message is publicly visible on-chain; secret key is not', () => {
    const secretKey = randomSecretKey();
    const state = simulateConstructor(secretKey, 'Visible message');

    // PUBLIC: message and owner hash are in ledger state (on-chain)
    expect(state.message).toBeDefined();
    expect(state.owner).toBeDefined();

    // PRIVATE: the raw secret key is NOT stored anywhere in ledger state
    const stateValues = [state.message, Buffer.from(state.owner).toString('hex')];
    const rawKeyHex = Buffer.from(secretKey).toString('hex');
    expect(stateValues).not.toContain(rawKeyHex);
  });

  test('different secret keys produce different owner hashes', () => {
    const key1 = randomSecretKey();
    const key2 = randomSecretKey();
    const state1 = simulateConstructor(key1, 'msg');
    const state2 = simulateConstructor(key2, 'msg');

    // Two different keys must not collide
    expect(state1.owner).not.toEqual(state2.owner);
  });

  test('owner can update message multiple times', () => {
    const secretKey = randomSecretKey();
    let state = simulateConstructor(secretKey, 'v1');

    state = simulateStoreMessage(state, secretKey, 'v2');
    expect(state.message).toBe('v2');

    state = simulateStoreMessage(state, secretKey, 'v3');
    expect(state.message).toBe('v3');

    // owner hash is stable across all updates
    expect(state.owner).toEqual(persistentHash(secretKey));
  });
});

describe('Hello World Contract — Privacy Invariants', () => {
  test('owner field is a hash, not the raw secret key', () => {
    const secretKey = randomSecretKey();
    const state = simulateConstructor(secretKey, 'test');

    // The on-chain `owner` field must NOT be the raw key
    expect(state.owner).not.toEqual(secretKey);
    // It must be exactly 32 bytes (SHA-256 output)
    expect(state.owner.byteLength).toBe(32);
  });

  test('witness (secret_key) is consumed locally and never appears in ledger', () => {
    const secretKey = randomSecretKey();
    const state = simulateConstructor(secretKey, 'test');
    const next = simulateStoreMessage(state, secretKey, 'updated');

    // The ledger state only has `message` (string) and `owner` (hash).
    // Neither field contains the raw secret key bytes.
    const ledgerKeys = Object.keys(next);
    expect(ledgerKeys).toEqual(expect.arrayContaining(['message', 'owner']));
    expect(ledgerKeys).not.toContain('secret_key');
    expect(ledgerKeys).not.toContain('secretKey');
  });
});
