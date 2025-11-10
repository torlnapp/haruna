import type { Mode } from './teos';

export interface TEOSDto {
  type: 'torln.teos.dto.v1';
  id: string;
  mode: Mode;
  ciphersuite: string;
  blob: Uint8Array<ArrayBuffer>;
  timestamp: Date;
}
