import { encode } from '@msgpack/msgpack';
import type { AADPayload } from '../src/types/teos';

export const defaultAAD: AADPayload = {
  contextId: 'group-123',
  epochId: 42,
  senderClientId: 'client-7',
  messageSequence: 3,
  scopes: ['scope1'],
};

export const encodePayload = (value: unknown): Uint8Array<ArrayBuffer> => {
  return new Uint8Array(encode(value));
};

export const encryptPayloadForMls = async (
  key: CryptoKey,
  plaintext: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> => {
  const nonce = new Uint8Array(12);
  const result = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
    },
    key,
    plaintext,
  );

  return new Uint8Array(result);
};

export async function createCryptoContext(): Promise<{
  aesKey: CryptoKey;
  senderKeyPair: CryptoKeyPair;
  pskBytes: Uint8Array<ArrayBuffer>;
}> {
  const aesKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );

  const ed25519Key = await crypto.subtle.generateKey('Ed25519', true, [
    'sign',
    'verify',
  ]);

  if (!('privateKey' in ed25519Key) || !('publicKey' in ed25519Key)) {
    throw new Error('Failed to generate Ed25519 key pair');
  }

  const pskSeed = crypto.getRandomValues(new Uint8Array(32));
  const pskBytes = new Uint8Array(pskSeed);

  return {
    aesKey,
    senderKeyPair: ed25519Key,
    pskBytes,
  };
}
