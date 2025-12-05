import { beforeAll, describe, expect, test } from 'bun:test';
import { generateNonce, processCiphertext } from '../src/lib/crypto';
import { generateSignature, verifySignature } from '../src/lib/signature';
import { deserializeTEOS, getTEOSDto, serializeTEOS } from '../src/lib/teos';
import { createPskTEOS } from '../src/psk';
import {
  defaultAAD as aad,
  createCryptoContext,
  encodePayload,
} from './test-utils';

let aesKey: CryptoKey;
let senderKeyPair: CryptoKeyPair;
let pskBytes: Uint8Array<ArrayBuffer>;

beforeAll(async () => {
  ({ aesKey, senderKeyPair, pskBytes } = await createCryptoContext());
});

describe('lib helpers', () => {
  test('generateNonce returns 12 random bytes', () => {
    const nonce = generateNonce();
    expect(nonce).toBeInstanceOf(Uint8Array);
    expect(nonce.length).toBe(12);
    expect(Array.from(nonce).some((value) => value !== 0)).toBe(true);
  });

  test('processCiphertext splits AES-GCM payload', async () => {
    const iv = new Uint8Array(12);
    const payload = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
      },
      aesKey,
      encodePayload({ sample: true }),
    );

    const { ciphertext, tag } = processCiphertext(new Uint8Array(payload));
    const totalLength = new Uint8Array(payload).length;

    expect(ciphertext.length + tag.length).toBe(totalLength);
    expect(tag.length).toBe(16);
    expect(ciphertext.length).toBeGreaterThan(0);
  });

  test('generateSignature output passes verifySignature', async () => {
    const data = new TextEncoder().encode('sign me');
    const signature = await generateSignature(senderKeyPair.privateKey, data);

    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.length).toBe(64);

    const valid = await verifySignature(
      senderKeyPair.publicKey,
      data,
      signature,
    );
    expect(valid).toBe(true);
  });

  test('serializeTEOS and deserializeTEOS round-trip the payload', async () => {
    const teos = await createPskTEOS(
      aad,
      pskBytes,
      senderKeyPair.privateKey,
      encodePayload({ foo: 'bar' }),
    );

    const serialized = serializeTEOS(teos);
    expect(serialized).toBeInstanceOf(Uint8Array);

    const parsed = deserializeTEOS(serialized);
    expect(parsed).toEqual(teos);
  });

  test('getTEOSDto mirrors TEOS metadata', async () => {
    const teos = await createPskTEOS(
      aad,
      pskBytes,
      senderKeyPair.privateKey,
      encodePayload({ hello: 'world' }),
    );

    const serialized = serializeTEOS(teos);
    const dto = getTEOSDto(teos);

    expect(dto.type).toBe('torln.teos.dto.v1');
    expect(dto.id).toBe(teos.aad.identifier);
    expect(dto.mode).toBe(teos.mode);
    expect(dto.ciphersuite).toBe(teos.envelope.suite);
    expect(dto.blob).toEqual(serialized);
    expect(dto.timestamp.getTime()).toBe(teos.aad.timestamp);
  });
});
