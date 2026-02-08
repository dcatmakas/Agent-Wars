import chalk from 'chalk';
import ora, { type Ora } from 'ora';
import type { Vulnerability, Severity, SecurityReport } from '../types.js';

const BANNER = `
${chalk.red('  ___                    _')}   ${chalk.blue(' _    _')}
${chalk.red(' / _ \\  __ _  ___ _ __ | |_')}  ${chalk.blue('| |  | | __ _ _ __ ___')}
${chalk.red("| |_| |/ _\` |/ _ \\ '_ \\| __|")} ${chalk.blue('| |  | |/ _\` | \'__/ __|')}
${chalk.red('|  _  | (_| |  __/ | | | |_ ')} ${chalk.blue('| |/\\| | (_| | |  \\__ \\\\')}
${chalk.red('|_| |_|\\__, |\\___|_| |_|\\__|')} ${chalk.blue(' \\__/\\__/\\__,_|_|  |___/')}
${chalk.red('       |___/')}
${chalk.gray('       Multi-Agent Security Testing Tool')}
${chalk.gray('       Red Team vs Blue Team vs Green Team')}
`;

let spinner: Ora | null = null;
let verboseMode = false;

export function setVerbose(v: boolean) {
  verboseMode = v;
}

export function printBanner() {
  console.log(BANNER);
  console.log();
}

export function startSpinner(text: string): Ora {
  if (spinner) spinner.stop();
  spinner = ora({ text, color: 'cyan' }).start();
  return spinner;
}

export function updateSpinner(text: string) {
  if (spinner) spinner.text = text;
}

export function succeedSpinner(text: string) {
  if (spinner) spinner.succeed(text);
  spinner = null;
}

export function failSpinner(text: string) {
  if (spinner) spinner.fail(text);
  spinner = null;
}

export function stopSpinner() {
  if (spinner) spinner.stop();
  spinner = null;
}

export function logRed(msg: string) {
  console.log(chalk.red.bold('[RED AGENT]') + ' ' + chalk.red(msg));
}

export function logBlue(msg: string) {
  console.log(chalk.blue.bold('[BLUE AGENT]') + ' ' + chalk.blue(msg));
}

export function logGreen(msg: string) {
  console.log(chalk.green.bold('[GREEN AGENT]') + ' ' + chalk.green(msg));
}

export function logVerbose(msg: string) {
  if (verboseMode) {
    console.log(chalk.gray('[VERBOSE] ' + msg));
  }
}

export function logPhase(phase: string, description: string) {
  console.log();
  console.log(chalk.bgWhite.black(` ${phase} `) + ' ' + chalk.white.bold(description));
  console.log(chalk.gray('─'.repeat(60)));
}

const severityBadge = (severity: Severity): string => {
  const badges: Record<Severity, string> = {
    critical: chalk.bgRed.white.bold(' CRITICAL '),
    high: chalk.bgYellow.black.bold(' HIGH '),
    medium: chalk.bgHex('#ffcc00').black(' MEDIUM '),
    low: chalk.bgCyan.black(' LOW '),
    info: chalk.bgGray.white(' INFO '),
  };
  return badges[severity];
};

export function printVulnerabilityTable(vulns: Vulnerability[]) {
  if (vulns.length === 0) {
    console.log(chalk.green('  No vulnerabilities found!'));
    return;
  }

  console.log();
  for (const v of vulns) {
    console.log(
      `  ${severityBadge(v.severity)} ${chalk.white.bold(v.title)}`
    );
    console.log(
      chalk.gray(`    ${v.file}${v.line ? ':' + v.line : ''} | ${v.category}${v.cwe ? ' | ' + v.cwe : ''}`)
    );
    console.log(chalk.gray(`    ${v.description}`));
    console.log();
  }
}

export function printScoreBar(score: number) {
  const width = 40;
  const filled = Math.round((score / 100) * width);
  const empty = width - filled;

  let color: typeof chalk;
  if (score >= 80) color = chalk.green;
  else if (score >= 60) color = chalk.yellow;
  else if (score >= 40) color = chalk.hex('#ff6600');
  else color = chalk.red;

  const bar = color('█'.repeat(filled)) + chalk.gray('░'.repeat(empty));
  console.log();
  console.log(`  Security Score: ${bar} ${color.bold(score + '/100')}`);
  console.log();
}

export function printSummary(report: SecurityReport) {
  console.log();
  console.log(chalk.white.bold('  Scan Summary'));
  console.log(chalk.gray('  ' + '─'.repeat(40)));
  console.log(`  ${chalk.gray('Project:')}     ${chalk.white(report.projectName)}`);
  console.log(`  ${chalk.gray('Duration:')}    ${chalk.white((report.duration / 1000).toFixed(1) + 's')}`);
  console.log(`  ${chalk.gray('Iterations:')}  ${chalk.white(String(report.totalIterations))}`);
  console.log(`  ${chalk.gray('API Cost:')}    ${chalk.white('$' + report.costUsd.toFixed(4))}`);
  console.log();
  console.log(`  ${chalk.red.bold(String(report.summary.critical))} Critical  ${chalk.hex('#ff6600').bold(String(report.summary.high))} High  ${chalk.yellow.bold(String(report.summary.medium))} Medium  ${chalk.cyan.bold(String(report.summary.low))} Low  ${chalk.gray.bold(String(report.summary.info))} Info`);
  console.log();
  console.log(`  ${chalk.green.bold(String(report.fixes.length))} fixed  ${chalk.red.bold(String(report.unfixed.length))} remaining`);

  printScoreBar(report.score);
}
