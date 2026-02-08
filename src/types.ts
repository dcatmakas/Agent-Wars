export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Vulnerability {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  file: string;
  line?: number;
  description: string;
  impact: string;
  evidence: string;
  cwe?: string;
}

export interface Fix {
  vulnerabilityId: string;
  file: string;
  description: string;
  diff: string;
  verified: boolean;
}

export interface ScanIteration {
  round: number;
  phase: 'red' | 'blue' | 'verify';
  vulnerabilitiesFound: number;
  fixesApplied: number;
  remainingIssues: number;
}

export interface SecurityReport {
  projectName: string;
  projectPath: string;
  scanDate: string;
  duration: number;
  iterations: ScanIteration[];
  totalIterations: number;
  summary: Record<Severity, number>;
  vulnerabilities: Vulnerability[];
  fixes: Fix[];
  unfixed: Vulnerability[];
  score: number;
  recommendations: string[];
  costUsd: number;
}

export interface ScanOptions {
  target: string;
  output: string;
  maxIterations: number;
  severity: Severity;
  fix: boolean;
  model: string;
  budget: number;
  verbose: boolean;
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#ff0000',
  high: '#ff6600',
  medium: '#ffcc00',
  low: '#00ccff',
  info: '#888888',
};
