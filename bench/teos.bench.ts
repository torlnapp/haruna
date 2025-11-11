import os from 'node:os';
import { encode } from '@msgpack/msgpack';
import { Bench } from 'tinybench';
import { deserializeTEOS, serializeTEOS } from '../src/lib';
import { createMlsTEOS, createPskTEOS, extractTEOS } from '../src/main';
import type { AAD } from '../src/types/teos';

const defaultAAD: AAD = {
  groupId: 'bench-group',
  epochId: 1,
  senderClientId: 'bench-client',
  messageSequence: 1,
  timestamp: Math.floor(Date.now() / 1000),
  objectId: 'bench-object',
  channelId: 'bench-channel',
};

const encodePayload = (value: unknown): ArrayBuffer => {
  const encoded = new Uint8Array(encode(value));
  return encoded.buffer.slice(
    encoded.byteOffset,
    encoded.byteOffset + encoded.byteLength,
  );
};

const toArrayBuffer = (view: Uint8Array<ArrayBuffer>) =>
  view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength);

async function createCryptoContext(): Promise<{
  aesKey: CryptoKey;
  senderKeyPair: CryptoKeyPair;
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

  return { aesKey, senderKeyPair: ed25519 };
}

async function main() {
  const { aesKey, senderKeyPair } = await createCryptoContext();
  const payload = encodePayload({
    hello: 'world',
    count: 42,
    flags: [true, false, true],
  });

  const referenceTEOS = await createPskTEOS(
    defaultAAD,
    aesKey,
    senderKeyPair,
    payload,
  );
  const serialized = serializeTEOS(referenceTEOS);
  const serializedBuffer = toArrayBuffer(serialized);

  const bench = new Bench({
    name: 'TEOS Benchmarks',
    warmupTime: 500,
    time: 2_000,
  });

  bench
    .add('createPskTEOS', async () => {
      await createPskTEOS(defaultAAD, aesKey, senderKeyPair, payload);
    })
    .add('createMlsTEOS', async () => {
      await createMlsTEOS(defaultAAD, aesKey, senderKeyPair, payload);
    })
    .add('extractTEOS', async () => {
      await extractTEOS(referenceTEOS, aesKey, senderKeyPair.publicKey);
    })
    .add('deserializeTEOS', () => {
      deserializeTEOS(serializedBuffer);
    });

  await bench.run();

  const formatMs = (value?: number) =>
    value === undefined ? 'n/a' : (value * 1_000).toFixed(3);

  console.log('=== TEOS Benchmark Results ===');
  console.table(
    bench.tasks.map((task) => {
      const result = task.result;
      return {
        Task: task.name,
        'ops/sec': result ? result.throughput.mean.toFixed(2) : 'n/a',
        'avg (ms)': result ? formatMs(result.latency.mean) : 'n/a',
        'p75 (ms)': result ? formatMs(result.latency.p75) : 'n/a',
        'p99 (ms)': result ? formatMs(result.latency.p99) : 'n/a',
        samples: result?.latency.samples.length ?? 0,
      };
    }),
  );

  console.log('=== Device Info ===');
  console.table({
    platform: os.platform(),
    release: os.release(),
    arch: os.arch(),
    cpu: os.cpus().map((cpu) => cpu.model)[0],
    cpuCount: os.cpus().length,
    totalMemory: `${(os.totalmem() / 1024 ** 3).toFixed(2)} GB`,
    runtime: `${bench.runtime} ${bench.runtimeVersion}`,
  });
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
