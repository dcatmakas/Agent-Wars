import path from 'path';
import type { ScanOptions, Severity } from '../types.js';

export const DEFAULT_OPTIONS: ScanOptions = {
  target: '.',
  output: './agent-wars-report',
  maxIterations: 3,
  severity: 'low' as Severity,
  fix: true,
  model: 'claude-sonnet-4-5-20250929',
  budget: 5.0,
  verbose: false,
};

export function resolveOptions(opts: Partial<ScanOptions>): ScanOptions {
  const merged = { ...DEFAULT_OPTIONS, ...opts };
  merged.target = path.resolve(merged.target);
  merged.output = path.resolve(merged.output);
  return merged;
}
