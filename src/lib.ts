import { decode, encode } from '@msgpack/msgpack';
import canonicalize from 'canonicalize';
import packageJson from '../package.json';
import type { TEOSDto } from './types/dto';
import type { BaseTEOS, TEOS } from './types/teos';
import { convertToTightUint8Arrays } from './utils';

export const version = packageJson.version;

export function generateNonce(): Uint8Array<ArrayBuffer> {
  const nonce = new Uint8Array(12);
  crypto.getRandomValues(nonce);

  return nonce;
}

export function processCiphertext(payload: ArrayBuffer) {
  const payloadUint8 = new Uint8Array(payload);
  const tagLength = 16;
  const ciphertext = payloadUint8.slice(0, payloadUint8.length - tagLength);
  const tag = payloadUint8.slice(payloadUint8.length - tagLength);

  return { ciphertext, tag };
}

export async function generateSignature(
  privateKey: CryptoKey,
  data: ArrayBuffer,
) {
  const signature = await crypto.subtle.sign(
    { name: 'Ed25519' },
    privateKey,
    data,
  );

  return new Uint8Array(signature);
}

export async function verifySignature(
  publicKey: CryptoKey,
  data: ArrayBuffer,
  signature: ArrayBuffer,
) {
  if (signature.byteLength !== 64) {
    throw new Error(
      '[TEOS] Invalid signature length. Expected 64 bytes. Got ' +
        signature.byteLength +
        ' bytes.',
    );
  }

  return crypto.subtle.verify({ name: 'Ed25519' }, publicKey, signature, data);
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
    throw new Error('[TEOS] Failed to canonicalize TEOS payload');
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
  const data = convertToTightUint8Arrays(decode(buffer));
  if (
    typeof data === 'object' &&
    data !== null &&
    'type' in data &&
    data.type === 'torln.teos.v1'
  ) {
    return data as TEOS;
  }
  throw new Error('[TEOS] Invalid TEOS format');
}

export function getTEOSDto(teos: TEOS): TEOSDto {
  return {
    type: 'torln.teos.dto.v1',
    id: teos.aad.objectId,
    mode: teos.mode,
    ciphersuite: teos.envelope.suite,
    blob: serializeTEOS(teos),
    timestamp: new Date(teos.aad.timestamp),
  };
}
