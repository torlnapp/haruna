import { beforeAll, describe, expect, test } from 'bun:test';
import { encode } from '@msgpack/msgpack';
import { generateBaseTEOSHash, verifySignature } from '../src/lib';
import { createTEOS, extractTEOS } from '../src/main';
import type { AAD, TEOS } from '../src/types/teos';

const aad: AAD = {
  groupId: 'group-123',
  epochId: 42,
  senderClientId: 'client-7',
  messageSequence: 3,
  timestamp: Date.now(),
  objectId: 'object-abc',
  channelId: 'channel-1',
};

let aesKey: CryptoKey;
let senderKeyPair: CryptoKeyPair;

const encodePayload = (value: unknown): ArrayBuffer => {
  const encoded = new Uint8Array(encode(value));
  return encoded.buffer.slice(
    encoded.byteOffset,
    encoded.byteOffset + encoded.byteLength,
  );
};

beforeAll(async () => {
  aesKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );

  const ed25519Key = await crypto.subtle.generateKey('Ed25519', true, [
    'sign',
    'verify',
  ]);

  if ('privateKey' in ed25519Key && 'publicKey' in ed25519Key) {
    senderKeyPair = ed25519Key;
  } else {
    throw new Error('Failed to generate Ed25519 key pair');
  }
});

describe('TEOS flows', () => {
  test('createTEOS (psk) encrypts payload, signs envelope, and extractTEOS restores plaintext', async () => {
    const original = {
      message: 'hello world',
      count: 5,
      nested: { active: true },
    };

    const teos = (await createTEOS(
      'psk',
      aad,
      aesKey,
      senderKeyPair,
      encodePayload(original),
    )) as TEOS;

    const hash = await generateBaseTEOSHash(teos);
    const directValid = await crypto.subtle.verify(
      { name: 'Ed25519' },
      senderKeyPair.publicKey,
      teos.envelope.auth.signature,
      hash,
    );
    expect(directValid).toBe(true);

    const signatureValid = await verifySignature(
      senderKeyPair.publicKey,
      hash.buffer,
      teos.envelope.auth.signature.buffer,
    );
    expect(signatureValid).toBe(true);

    expect(teos.mode).toBe('psk');
    expect('pskId' in teos.envelope ? teos.envelope.pskId : '').toBe(
      'your-psk-id',
    );
    expect(teos.nonce.length).toBe(12);
    expect(teos.tag.length).toBe(16);
    expect(teos.ciphertext.length).toBeGreaterThan(0);

    const recovered = await extractTEOS<typeof original>(
      teos,
      aesKey,
      senderKeyPair.publicKey,
    );
    expect(recovered).toEqual(original);
  });

  test('createTEOS (mls) produces MLS envelope and extractTEOS succeeds', async () => {
    const original = { status: 'ok', items: [1, 2, 3] };

    const teos = await createTEOS(
      'mls',
      { ...aad, channelId: null },
      aesKey,
      senderKeyPair,
      encodePayload(original),
    );

    const hash = await generateBaseTEOSHash(teos);
    const signatureValid = await verifySignature(
      senderKeyPair.publicKey,
      hash.buffer,
      teos.envelope.auth.signature.buffer,
    );
    expect(signatureValid).toBe(true);

    expect(teos.mode).toBe('mls');
    expect(teos.envelope.suite).toBe(
      'MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519',
    );

    const recovered = await extractTEOS<typeof original>(
      teos,
      aesKey,
      senderKeyPair.publicKey,
    );
    expect(recovered).toEqual(original);
  });

  test('extractTEOS rejects tampered signatures', async () => {
    const original = { compromised: true };
    const teos = await createTEOS(
      'psk',
      aad,
      aesKey,
      senderKeyPair,
      encodePayload(original),
    );

    const tamperedSignature = teos.envelope.auth.signature.slice(1, -1);

    const tampered = {
      ...teos,
      envelope: {
        ...teos.envelope,
        auth: {
          ...teos.envelope.auth,
          signature: tamperedSignature,
        },
      },
    };

    await expect(
      extractTEOS<typeof original>(tampered, aesKey, senderKeyPair.publicKey),
    ).rejects.toThrow('Invalid TEOS signature');
  });
});
