import { decode, encode } from '@msgpack/msgpack';
import canonicalize from 'canonicalize';
import packageJson from '../package.json';
import type { BaseTEOS, TEOS } from './types/teos';

export const version = packageJson.version;

export function generateNonce(): Uint8Array<ArrayBuffer> {
  const nonce = new Uint8Array(12);
  crypto.getRandomValues(nonce);

  return nonce;
}

export function processCiphertext(payload: ArrayBuffer) {
  const payloadArray = new Uint8Array(payload);
  const tagLength = 16;
  const ciphertext = payloadArray.slice(0, payloadArray.length - tagLength);
  const tag = payloadArray.slice(payloadArray.length - tagLength);

  return { ciphertext, tag };
}

export async function generateSignature(key: CryptoKey, data: ArrayBuffer) {
  const signature = await crypto.subtle.sign(
    {
      name: 'Ed25519',
    },
    key,
    data,
  );

  return new Uint8Array(signature);
}

export async function verifySignature(
  key: CryptoKey,
  data: ArrayBuffer,
  signature: ArrayBuffer,
) {
  return crypto.subtle.verify(
    {
      name: 'Ed25519',
    },
    key,
    signature,
    data,
  );
}

export async function generateBaseTEOSHash(payload: TEOS | BaseTEOS) {
  const data: BaseTEOS = {
    type: 'torln.teos.v1',
    version: payload.version,
    algorithm: payload.algorithm,
    aad: payload.aad,
    nonce: payload.nonce,
    tag: payload.tag,
    ciphertext: payload.ciphertext,
  };

  const canonicalized = canonicalize(data);
  if (!canonicalized) {
    throw new Error('Failed to canonicalize TEOS payload');
  }

  const buffer = await crypto.subtle.digest(
    {
      name: 'SHA-256',
    },
    new Uint8Array(encode(canonicalized)),
  );

  return new Uint8Array(buffer);
}

export function serializeTEOS(teos: TEOS): Uint8Array<ArrayBuffer> {
  return new Uint8Array(encode(teos));
}

export function deserializeTEOS(buffer: ArrayBuffer): TEOS {
  const data = decode(buffer);
  if (
    typeof data === 'object' &&
    data !== null &&
    'type' in data &&
    data.type === 'torln.teos.v1'
  ) {
    return data as TEOS;
  }
  throw new Error('Invalid TEOS format');
}

export async function verifyTEOS(teos: TEOS): Promise<boolean> {
  const hash = await generateBaseTEOSHash(teos);

  const isSignatureValid = await verifySignature(
    await crypto.subtle.importKey(
      'jwk',
      teos.envelope.auth.publicKey,
      'Ed25519',
      false,
      ['verify'],
    ),
    hash.buffer,
    teos.envelope.auth.signature.buffer,
  );

  return isSignatureValid;
}
