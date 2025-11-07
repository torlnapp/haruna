import { decode } from '@msgpack/msgpack';
import {
  generateBaseTEOSHash,
  generateNonce,
  generateSignature,
  processCiphertext,
  verifySignature,
  version,
} from './lib';
import type {
  AAD,
  BaseTEOS,
  EnvelopeAuth,
  MLS_TEOS,
  MLSEnvelope,
  PSK_TEOS,
  PSKEnvelope,
  TEOS,
} from './types/teos';

async function createBaseTEOS(
  aad: AAD,
  aesKey: CryptoKey,
  data: ArrayBuffer,
): Promise<BaseTEOS> {
  const nonce = generateNonce();
  const payload = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
    },
    aesKey,
    data,
  );

  const { ciphertext, tag } = processCiphertext(payload);
  const baseResult: BaseTEOS = {
    type: 'torln.teos.v1',
    version,
    algorithm: 'AES-GCM',
    aad,
    nonce,
    tag,
    ciphertext,
  };

  return baseResult;
}

export async function createPskTEOS(
  aad: AAD,
  aesKey: CryptoKey,
  senderKeyPair: CryptoKeyPair,
  data: ArrayBuffer,
): Promise<PSK_TEOS> {
  const base = await createBaseTEOS(aad, aesKey, data);
  const hash = await generateBaseTEOSHash(base);
  const auth: EnvelopeAuth = {
    publicKey: await crypto.subtle.exportKey('jwk', senderKeyPair.publicKey),
    signature: await generateSignature(senderKeyPair.privateKey, hash.buffer),
  };

  const envelope: PSKEnvelope = {
    suite: 'PSK+AES-256-GCM',
    auth,
    pskId: 'your-psk-id',
  };

  return {
    ...base,
    mode: 'psk',
    envelope,
  };
}

export async function createMlsTEOS(
  aad: AAD,
  aesKey: CryptoKey,
  senderKeyPair: CryptoKeyPair,
  data: ArrayBuffer,
): Promise<MLS_TEOS> {
  const base = await createBaseTEOS(aad, aesKey, data);
  const hash = await generateBaseTEOSHash(base);
  const auth: EnvelopeAuth = {
    publicKey: await crypto.subtle.exportKey('jwk', senderKeyPair.publicKey),
    signature: await generateSignature(senderKeyPair.privateKey, hash.buffer),
  };

  const envelope: MLSEnvelope = {
    suite: 'MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519',
    auth,
  };

  return {
    ...base,
    mode: 'mls',
    envelope,
  };
}

export async function extractTEOS<T>(
  payload: TEOS | ArrayBuffer,
  aesKey: CryptoKey,
  publicKey: CryptoKey,
): Promise<T> {
  if (payload instanceof ArrayBuffer) {
    payload = decode(payload) as TEOS;
  }

  const hash = await generateBaseTEOSHash(payload);
  const isValid = await verifySignature(
    publicKey,
    hash.buffer,
    payload.envelope.auth.signature.buffer,
  );
  if (!isValid) {
    throw new Error('Invalid TEOS signature');
  }

  const result = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: payload.nonce,
    },
    aesKey,
    new Uint8Array([...payload.ciphertext, ...payload.tag]).buffer,
  );

  return decode(result) as T;
}
