import { encode } from '@msgpack/msgpack';
import type { AAD } from '../src/types/teos';

export const defaultAAD: AAD = {
  groupId: 'group-123',
  epochId: 42,
  senderClientId: 'client-7',
  messageSequence: 3,
  timestamp: Math.floor(Date.now() / 1000),
  objectId: 'object-abc',
  channelId: 'channel-1',
};

export const encodePayload = (value: unknown): ArrayBuffer => {
  const encoded = new Uint8Array(encode(value));
  return encoded.buffer.slice(
    encoded.byteOffset,
    encoded.byteOffset + encoded.byteLength,
  );
};

export async function createCryptoContext(): Promise<{
  aesKey: CryptoKey;
  senderKeyPair: CryptoKeyPair;
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

  return {
    aesKey,
    senderKeyPair: ed25519Key,
  };
}
