export function generateNonce(): Uint8Array<ArrayBuffer> {
  const nonce = new Uint8Array(12);
  crypto.getRandomValues(nonce);

  return nonce;
}

export function processCiphertext(payload: Uint8Array<ArrayBuffer>) {
  const payloadUint8 = new Uint8Array(payload);
  const tagLength = 16;
  const ciphertext = payloadUint8.slice(0, payloadUint8.length - tagLength);
  const tag = payloadUint8.slice(payloadUint8.length - tagLength);

  return { ciphertext, tag };
}
