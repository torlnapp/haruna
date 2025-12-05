import { version } from '../lib/common';
import { generateNonce, processCiphertext } from '../lib/crypto';
import { verifySignature } from '../lib/signature';
import { generateBaseTEOSHash } from '../lib/teos';
import type { AADPayload, BaseTEOS, TEOS } from '../types/teos';

export async function createBasePskTEOS(
  identifier: string,
  aad: AADPayload,
  aesKey: CryptoKey,
  data: Uint8Array<ArrayBuffer>,
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

  const { ciphertext, tag } = processCiphertext(new Uint8Array(payload));
  const baseResult: BaseTEOS = {
    type: 'torln.teos.v1',
    version,
    algorithm: 'AES-GCM',
    aad: {
      identifier,
      timestamp: Date.now(),
      ...aad,
    },
    nonce,
    tag,
    ciphertext,
  };

  return baseResult;
}

export async function createBaseMlsTEOS(
  identifier: string,
  aad: AADPayload,
  data: Uint8Array<ArrayBuffer>,
): Promise<BaseTEOS> {
  const { ciphertext, tag } = processCiphertext(data);

  const baseResult: BaseTEOS = {
    type: 'torln.teos.v1',
    version,
    algorithm: 'ChaCha20-Poly1305',
    aad: {
      identifier,
      timestamp: Date.now(),
      ...aad,
    },
    nonce: new Uint8Array(12),
    tag,
    ciphertext,
  };

  return baseResult;
}

export async function verifyTEOS(
  teos: TEOS,
  authorPublicKey: globalThis.JsonWebKey,
): Promise<boolean> {
  const hash = await generateBaseTEOSHash(teos);
  const publicKey = await crypto.subtle.importKey(
    'jwk',
    authorPublicKey,
    { name: 'Ed25519' },
    false,
    ['verify'],
  );

  const isSignatureValid = await verifySignature(
    publicKey,
    hash,
    teos.envelope.auth.signature,
  );

  return isSignatureValid;
}
