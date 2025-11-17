export function encodeText(text: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(text);
}
