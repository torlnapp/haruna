import { decode } from '@msgpack/msgpack';
import {
  deserializeTEOS,
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

  const teos: PSK_TEOS = {
    ...base,
    mode: 'psk',
    envelope,
  };

  const isValid = await verifyTEOS(teos);
  if (!isValid) {
    throw new Error('[TEOS] Generated PSK TEOS signature is invalid');
  }

  return teos;
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

  const teos: MLS_TEOS = {
    ...base,
    mode: 'mls',
    envelope,
  };

  const isValid = await verifyTEOS(teos);
  if (!isValid) {
    throw new Error('[TEOS] Generated MLS TEOS signature is invalid');
  }

  return teos;
}

export async function extractTEOS<T>(
  payload: TEOS | ArrayBuffer,
  aesKey: CryptoKey,
  publicKey: CryptoKey,
): Promise<T> {
  if (payload instanceof ArrayBuffer) {
    payload = deserializeTEOS(payload);
  }

  const hash = await generateBaseTEOSHash(payload);
  const isValid = await verifySignature(
    publicKey,
    hash.buffer,
    payload.envelope.auth.signature.buffer,
  );
  if (!isValid) {
    throw new Error('[TEOS] Invalid TEOS signature');
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

export async function verifyTEOS(teos: TEOS): Promise<boolean> {
  const hash = await generateBaseTEOSHash(teos);
  const publicKey = await crypto.subtle.importKey(
    'jwk',
    teos.envelope.auth.publicKey,
    { name: 'Ed25519' },
    false,
    ['verify'],
  );

  const isSignatureValid = await verifySignature(
    publicKey,
    hash.buffer,
    teos.envelope.auth.signature.buffer,
  );

  return isSignatureValid;
}
