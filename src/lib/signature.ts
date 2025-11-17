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
