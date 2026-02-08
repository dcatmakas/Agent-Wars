import fs from 'fs/promises';
import path from 'path';
import type { SecurityReport } from '../types.js';

export async function generateJsonReport(
  report: SecurityReport,
  outputDir: string
): Promise<string> {
  await fs.mkdir(outputDir, { recursive: true });
  const filePath = path.join(outputDir, 'report.json');
  await fs.writeFile(filePath, JSON.stringify(report, null, 2), 'utf-8');
  return filePath;
}
