import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: './src/index.ts',
  platform: 'neutral',
  outDir: './dist',
  target: 'ES2020',
  dts: true,
  sourcemap: true,
  exports: true,
});
