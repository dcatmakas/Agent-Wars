#!/usr/bin/env node

import { Command } from 'commander';
import { resolveOptions } from './utils/config.js';
import {
  printBanner,
  setVerbose,
  logGreen,
  logPhase,
  printSummary,
  printVulnerabilityTable,
} from './utils/logger.js';
import { runScan } from './orchestrator.js';
import { generateJsonReport } from './reporter/json-reporter.js';
import { generateHtmlReport } from './reporter/html-reporter.js';
import type { Severity } from './types.js';
import chalk from 'chalk';
import fs from 'fs/promises';
import path from 'path';

const program = new Command();

program
  .name('agent-wars')
  .description('Multi-Agent Security Testing Tool - Red Team vs Blue Team vs Green Team')
  .version('1.0.0');

program
  .command('scan')
  .description('Scan a project for security vulnerabilities')
  .requiredOption('-t, --target <path>', 'Target project directory')
  .option('-o, --output <path>', 'Report output directory', './agent-wars-report')
  .option('-i, --max-iterations <number>', 'Maximum Red/Blue iteration rounds', '3')
  .option('-s, --severity <level>', 'Minimum severity to report (critical|high|medium|low|info)', 'low')
  .option('--fix', 'Apply automatic fixes (default: true)', true)
  .option('--no-fix', 'Scan only, do not apply fixes')
  .option('-m, --model <model>', 'Claude model to use', 'claude-sonnet-4-5-20250929')
  .option('-b, --budget <usd>', 'Maximum API budget in USD', '5')
  .option('-v, --verbose', 'Enable verbose output', false)
  .action(async (opts) => {
    printBanner();

    // Validate target exists
    const targetPath = path.resolve(opts.target);
    try {
      const stat = await fs.stat(targetPath);
      if (!stat.isDirectory()) {
        console.error(chalk.red(`Error: ${targetPath} is not a directory`));
        process.exit(1);
      }
    } catch {
      console.error(chalk.red(`Error: Target directory not found: ${targetPath}`));
      process.exit(1);
    }

    const options = resolveOptions({
      target: opts.target,
      output: opts.output,
      maxIterations: parseInt(opts.maxIterations, 10),
      severity: opts.severity as Severity,
      fix: opts.fix,
      model: opts.model,
      budget: parseFloat(opts.budget),
      verbose: opts.verbose,
    });

    setVerbose(options.verbose);

    logGreen(`Starting security scan of: ${chalk.white.bold(options.target)}`);
    console.log(chalk.gray(`  Model: ${options.model}`));
    console.log(chalk.gray(`  Budget: $${options.budget}`));
    console.log(chalk.gray(`  Max Iterations: ${options.maxIterations}`));
    console.log(chalk.gray(`  Auto-fix: ${options.fix ? 'enabled' : 'disabled'}`));
    console.log();

    try {
      const report = await runScan(options);

      // Generate reports
      logPhase('REPORTS', 'Generating output files');

      const [jsonPath, htmlPath] = await Promise.all([
        generateJsonReport(report, options.output),
        generateHtmlReport(report, options.output),
      ]);

      // Print final summary
      printSummary(report);

      console.log(chalk.gray('  Reports generated:'));
      console.log(chalk.gray(`    JSON: ${jsonPath}`));
      console.log(chalk.gray(`    HTML: ${htmlPath}`));
      console.log();

      if (report.unfixed.length > 0) {
        logPhase('REMAINING ISSUES', `${report.unfixed.length} unfixed vulnerabilities`);
        printVulnerabilityTable(report.unfixed);
      }

      console.log(
        chalk.green.bold('  Scan complete!') +
          chalk.gray(` Open ${htmlPath} in your browser for the full report.`)
      );
      console.log();
    } catch (err) {
      console.error(chalk.red(`\nFatal error: ${err instanceof Error ? err.message : String(err)}`));
      if (err instanceof Error && err.stack) {
        console.error(chalk.gray(err.stack));
      }
      process.exit(1);
    }
  });

program.parse();
