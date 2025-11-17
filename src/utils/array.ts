export function convertToTightUint8Arrays(data: unknown) {
  if (!data || !isProcessableObject(data)) {
    return data;
  }

  if (isUint8Array(data)) {
    return toTightUint8Array(data);
  }

  for (const key in data) {
    if (!isObjectKey(key, data)) {
      continue;
    }

    const prop = data[key];
    if (isUint8Array(prop)) {
      data[key] = toTightUint8Array(prop);
    } else if (isProcessableObject(prop)) {
      data[key] = convertToTightUint8Arrays(prop);
    }
  }

  return data;
}

function toTightUint8Array(
  array: Uint8Array<ArrayBuffer>,
): Uint8Array<ArrayBuffer> {
  if (array.byteOffset === 0 && array.byteLength === array.buffer.byteLength) {
    return array;
  }

  return array.slice();
}

function isObjectKey(
  key: string,
  obj: Record<string, unknown>,
): key is keyof typeof obj {
  return Object.hasOwn(obj, key);
}

function isProcessableObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isUint8Array(value: unknown): value is Uint8Array<ArrayBuffer> {
  return value instanceof Uint8Array;
}
