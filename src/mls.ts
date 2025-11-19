import { decode } from '@msgpack/msgpack';
import { generateSignature, verifySignature } from './lib/signature';
import { deserializeTEOS, generateBaseTEOSHash } from './lib/teos';
import type {
  AADPayload,
  EnvelopeAuth,
  MLS_TEOS,
  MLSEnvelope,
  TEOS,
} from './types/teos';
import { createBaseMlsTEOS } from './utils/teos';

export async function createMlsTEOS(
  aad: AADPayload,
  signerPrivateKey: CryptoKey,
  data: ArrayBuffer,
): Promise<MLS_TEOS> {
  const identifier = crypto.randomUUID();
  const base = await createBaseMlsTEOS(identifier, aad, data);
  const hash = await generateBaseTEOSHash(base);
  const auth: EnvelopeAuth = {
    signature: await generateSignature(signerPrivateKey, hash.buffer),
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

  return teos;
}

export async function extractTEOS<T>(
  payload: TEOS | ArrayBuffer,
  aesKey: CryptoKey,
  signerPublicKey: CryptoKey,
): Promise<T> {
  if (payload instanceof ArrayBuffer) {
    payload = deserializeTEOS(payload);
  }

  const hash = await generateBaseTEOSHash(payload);
  const isValid = await verifySignature(
    signerPublicKey,
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
