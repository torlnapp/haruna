import os from 'node:os';
import { encode } from '@msgpack/msgpack';
import { Bench } from 'tinybench';
import { createMlsTEOS, extractTEOS } from '../src/mls';
import { createPskTEOS, extractPskTEOS } from '../src/psk';
import type { AADPayload } from '../src/types/teos';

const defaultAAD: AADPayload = {
  contextId: 'bench-group',
  epochId: 1,
  senderClientId: 'bench-client',
  messageSequence: 1,
  scopes: ['bench-scope1'],
};

const encodePayload = (value: unknown): Uint8Array<ArrayBuffer> => {
  return new Uint8Array(encode(value));
};

const encryptPayloadForMls = async (
  key: CryptoKey,
  plaintext: Uint8Array<ArrayBuffer>,
  iv: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> => {
  const result = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    key,
    plaintext,
  );

  return new Uint8Array(result);
};

async function createCryptoContext(): Promise<{
  aesKey: CryptoKey;
  senderKeyPair: CryptoKeyPair;
  pskBytes: Uint8Array<ArrayBuffer>;
}> {
  const aesKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );

  const ed25519 = await crypto.subtle.generateKey('Ed25519', true, [
    'sign',
    'verify',
  ]);

  if (!('privateKey' in ed25519) || !('publicKey' in ed25519)) {
    throw new Error('[bench] Failed to create Ed25519 key pair');
  }

  const pskArray = crypto.getRandomValues(new Uint8Array(32));
  const pskBytes = new Uint8Array(pskArray);

  return { aesKey, senderKeyPair: ed25519, pskBytes };
}

async function main() {
  const { aesKey, senderKeyPair, pskBytes } = await createCryptoContext();
  const payload = encodePayload({
    hello: 'world',
    count: 42,
    flags: [true, false, true],
  });
  const initialNonce = crypto.getRandomValues(new Uint8Array(12));
  const mlsCiphertext = await encryptPayloadForMls(
    aesKey,
    payload,
    initialNonce,
  );

  const referenceMlsTEOS = await createMlsTEOS(
    defaultAAD,
    senderKeyPair.privateKey,
    mlsCiphertext,
    initialNonce,
  );

  const referencePskTEOS = await createPskTEOS(
    defaultAAD,
    pskBytes,
    senderKeyPair.privateKey,
    payload,
  );

  const bench = new Bench({
    name: 'TEOS Benchmarks',
    warmupTime: 500,
    time: 2_000,
  });

  bench
    .add('createPskTEOS', async () => {
      await createPskTEOS(
        defaultAAD,
        pskBytes,
        senderKeyPair.privateKey,
        payload,
      );
    })
    .add('createMlsTEOS', async () => {
      const nonce = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = await encryptPayloadForMls(aesKey, payload, nonce);
      await createMlsTEOS(defaultAAD, senderKeyPair.privateKey, ciphertext, nonce);
    })
    .add('extractMlsTEOS', async () => {
      await extractTEOS(referenceMlsTEOS, aesKey, senderKeyPair.publicKey);
    })
    .add('extractPskTEOS', async () => {
      await extractPskTEOS(referencePskTEOS, pskBytes, senderKeyPair.publicKey);
    });

  await bench.run();

  const formatMs = (value?: number | null) =>
    value === undefined || value === null ? 'n/a' : (value * 1_000).toFixed(3);

  console.log('=== TEOS Benchmark Results ===');
  console.table(
    bench.tasks.map((task) => {
      const result = task.result;
      const throughputMean = result?.throughput?.mean ?? null;
      const latencyStats = result?.latency ?? null;
      return {
        Task: task.name,
        'ops/sec':
          typeof throughputMean === 'number'
            ? throughputMean.toFixed(2)
            : 'n/a',
        'avg (ms)': formatMs(latencyStats?.mean ?? null),
        'p75 (ms)': formatMs(latencyStats?.p75 ?? null),
        'p99 (ms)': formatMs(latencyStats?.p99 ?? null),
        samples: latencyStats?.samples.length ?? 0,
        error: result?.error?.message ?? 'none',
      };
    }),
  );

  const cpus = os.cpus();
  const cpuModel = cpus.length > 0 ? cpus[0]?.model : 'unknown';
  const cpuCount = cpus.length > 0 ? cpus.length : 'unknown';

  console.log('=== Device Info ===');
  console.table({
    platform: os.platform(),
    release: os.release(),
    arch: os.arch(),
    cpu: cpuModel,
    cpuCount,
    totalMemory: `${(os.totalmem() / 1024 ** 3).toFixed(2)} GB`,
    runtime: `${bench.runtime} ${bench.runtimeVersion}`,
  });
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
