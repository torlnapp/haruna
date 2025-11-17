import { decode, encode } from '@msgpack/msgpack';
import canonicalize from 'canonicalize';
import type { TEOSDto } from '../types/dto';
import type { BaseTEOS, TEOS } from '../types/teos';
import { convertToTightUint8Arrays } from '../utils/array';

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
    id: teos.aad.identifier,
    mode: teos.mode,
    ciphersuite: teos.envelope.suite,
    blob: serializeTEOS(teos),
    timestamp: new Date(teos.aad.timestamp),
  };
}
