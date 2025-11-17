import { version } from '../lib/common';
import { generateNonce, processCiphertext } from '../lib/crypto';
import { verifySignature } from '../lib/signature';
import { generateBaseTEOSHash } from '../lib/teos';
import type { AADPayload, BaseTEOS, TEOS } from '../types/teos';

export async function createBaseTEOS(
  identifier: string,
  aad: AADPayload,
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
