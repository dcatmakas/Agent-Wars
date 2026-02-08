import { query, type SDKMessage, type Options } from '@anthropic-ai/claude-agent-sdk';
import path from 'path';
import { redAgent } from './agents/red.js';
import { blueAgent } from './agents/blue.js';
import type {
  ScanOptions,
  SecurityReport,
  Vulnerability,
  Fix,
  ScanIteration,
  Severity,
} from './types.js';
import { SEVERITY_ORDER } from './types.js';
import {
  logRed,
  logBlue,
  logGreen,
  logVerbose,
  logPhase,
  startSpinner,
  succeedSpinner,
  failSpinner,
  stopSpinner,
  printVulnerabilityTable,
} from './utils/logger.js';

function parseJsonFromText(text: string): unknown | null {
  // Try to extract JSON from markdown code blocks first
  const codeBlockMatches = text.matchAll(/```(?:json)?\s*\n?([\s\S]*?)\n?\s*```/g);
  for (const match of codeBlockMatches) {
    try {
      const parsed = JSON.parse(match[1].trim());
      if (Array.isArray(parsed) && parsed.length > 0) return parsed;
    } catch {
      // try next
    }
  }
  // Try to find a raw JSON array (greedy - find the largest one)
  const arrayMatches = text.matchAll(/\[\s*\{[\s\S]*?\}\s*\]/g);
  for (const match of arrayMatches) {
    try {
      const parsed = JSON.parse(match[0]);
      if (Array.isArray(parsed) && parsed.length > 0) return parsed;
    } catch {
      // try next
    }
  }
  // Last resort: try to find any JSON array even with single objects
  try {
    const lastBracket = text.lastIndexOf(']');
    const firstBracket = text.indexOf('[');
    if (firstBracket !== -1 && lastBracket !== -1 && lastBracket > firstBracket) {
      const candidate = text.slice(firstBracket, lastBracket + 1);
      const parsed = JSON.parse(candidate);
      if (Array.isArray(parsed)) return parsed;
    }
  } catch {
    // fall through
  }
  return null;
}

function extractResultText(messages: SDKMessage[]): string {
  // Collect ALL text from all messages - result, assistant, and subagent outputs
  const allTexts: string[] = [];

  for (const msg of messages) {
    // Final result
    if (msg.type === 'result' && msg.subtype === 'success') {
      const resultText = (msg as any).result ?? '';
      if (resultText) allTexts.push(resultText);
    }
    // Assistant messages (including Green Agent relaying subagent output)
    if (msg.type === 'assistant' && msg.message?.content) {
      for (const block of msg.message.content as any[]) {
        if (block.type === 'text' && block.text) {
          allTexts.push(block.text);
        }
        // Also check tool_result blocks that might contain subagent output
        if (block.type === 'tool_result' && typeof block.content === 'string') {
          allTexts.push(block.content);
        }
      }
    }
    // User messages might contain tool results from subagents
    if (msg.type === 'user' && msg.message?.content) {
      const content = (msg as any).message.content;
      if (Array.isArray(content)) {
        for (const block of content) {
          if (block.type === 'tool_result' && typeof block.content === 'string') {
            allTexts.push(block.content);
          }
          if (block.type === 'tool_result' && Array.isArray(block.content)) {
            for (const part of block.content) {
              if (part.type === 'text' && part.text) {
                allTexts.push(part.text);
              }
            }
          }
        }
      }
    }
  }

  return allTexts.join('\n');
}

async function runAgent(
  prompt: string,
  options: Options
): Promise<{ messages: SDKMessage[]; resultText: string; costUsd: number }> {
  const messages: SDKMessage[] = [];
  let costUsd = 0;

  for await (const message of query({ prompt, options })) {
    messages.push(message);
    if (message.type === 'result') {
      costUsd = (message as any).total_cost_usd ?? 0;
    }
    if (message.type === 'assistant') {
      const content = (message as any).message?.content;
      if (content && Array.isArray(content)) {
        for (const block of content) {
          if (block.type === 'text' && block.text) {
            logVerbose(block.text.slice(0, 200) + (block.text.length > 200 ? '...' : ''));
          }
        }
      }
    }
  }

  const resultText = extractResultText(messages);
  return { messages, resultText, costUsd };
}

export async function runScan(options: ScanOptions): Promise<SecurityReport> {
  const startTime = Date.now();
  const projectName = path.basename(options.target);
  let totalCost = 0;

  const allVulnerabilities: Vulnerability[] = [];
  const allFixes: Fix[] = [];
  const iterations: ScanIteration[] = [];

  const greenSystemPrompt = `You are the GREEN AGENT - a security orchestrator. Your ONLY job is to delegate tasks to subagents and relay their output EXACTLY as they return it.

CRITICAL RULES:
1. When asked to run the red-agent, invoke it via the Task tool with subagent_type "red-agent"
2. When asked to run the blue-agent, invoke it via the Task tool with subagent_type "blue-agent"
3. After the subagent completes, you MUST copy their COMPLETE JSON output (the \`\`\`json code block) into your response VERBATIM - do NOT summarize, do NOT paraphrase, do NOT omit findings
4. If the subagent found vulnerabilities, include the FULL JSON array in your response
5. If the subagent found 0 vulnerabilities, respond with: \`\`\`json\n[]\n\`\`\`
6. Do NOT add your own analysis. Just delegate and relay.`;

  const baseOptions: Options = {
    cwd: options.target,
    model: options.model,
    maxBudgetUsd: options.budget,
    permissionMode: 'bypassPermissions',
    allowDangerouslySkipPermissions: true,
    systemPrompt: greenSystemPrompt,
    agents: {
      'red-agent': redAgent,
      'blue-agent': blueAgent,
    },
    allowedTools: ['Read', 'Grep', 'Glob', 'Bash', 'Edit', 'Write', 'Task'],
  };

  // ─── GREEN AGENT ORCHESTRATION LOOP ───
  for (let round = 1; round <= options.maxIterations; round++) {
    // ─── PHASE 1: RED AGENT ATTACK ───
    logPhase(`ROUND ${round}/${options.maxIterations}`, 'Red Agent - Vulnerability Scan');
    const redSpinner = startSpinner('Red Agent analyzing project for vulnerabilities...');

    const previousFindings = allVulnerabilities
      .filter((v) => !allFixes.some((f) => f.vulnerabilityId === v.id && f.verified))
      .map((v) => v.id)
      .join(', ');

    const redPrompt =
      round === 1
        ? `Invoke the red-agent subagent with the following prompt:

"Perform a FULL offensive security assessment of the project at ${options.target}. You MUST do ALL of the following steps:

STEP 1 - RECONNAISSANCE:
- Read package.json, requirements.txt, or equivalent to understand the tech stack
- Use Glob to map the full project structure
- Identify the framework (Express, Next.js, Django, Flask, FastAPI, Spring, etc.)
- Find all entry points (routes, controllers, API endpoints)

STEP 2 - STATIC ANALYSIS:
- Use Grep to search for hardcoded secrets: passwords, API keys, tokens, connection strings
  Patterns: 'password\\s*=', 'secret', 'api_key', 'token', 'AWS_', 'PRIVATE_KEY', 'connectionString'
- Search for dangerous functions: eval, exec, innerHTML, dangerouslySetInnerHTML, child_process, subprocess
- Search for SQL queries built with string concatenation
- Check .env files, config files for sensitive data
- Check .gitignore to see if sensitive files are excluded

STEP 3 - DEPENDENCY AUDIT:
- Run 'npm audit' or 'pip audit' or equivalent
- Check for known vulnerable package versions

STEP 4 - OWASP TOP 10 ANALYSIS:
- Check every route handler for input validation
- Look for SQL/NoSQL injection points
- Look for XSS vulnerabilities (unescaped user input in responses)
- Check authentication implementation (password hashing, session management, JWT handling)
- Check authorization (are routes protected? is there role-based access?)
- Look for CSRF protection
- Check CORS configuration
- Look for path traversal vulnerabilities
- Check for SSRF possibilities
- Check security headers (helmet, CSP, X-Frame-Options)

STEP 5 - INFRASTRUCTURE:
- Check Dockerfile if present (running as root? secrets in build?)
- Check docker-compose.yml for exposed ports, default passwords
- Check for .env files with real credentials committed

STEP 6 - ACTIVE TESTING (if possible):
- Try to start the project locally with 'npm start' or equivalent
- If it starts, use curl to test endpoints for injection, auth bypass, etc.
- Test rate limiting on login/auth endpoints

You MUST find at least something - no project is 100% secure. Even if the code looks clean, check for:
- Missing rate limiting
- Missing security headers
- Overly permissive CORS
- Missing input validation on any endpoint
- Dependencies with known CVEs
- Missing HTTPS enforcement
- Weak password requirements
- Missing logging/monitoring

Output your findings as a JSON array in a \`\`\`json code block."

After the red-agent completes, copy its COMPLETE JSON output into your response verbatim.`
        : `Invoke the red-agent subagent with the following prompt:

"Re-scan the project at ${options.target}. Previous vulnerabilities that were supposedly fixed: ${previousFindings}.

You must:
1. Verify each previous fix is actually correct and complete
2. Check if any fixes introduced NEW vulnerabilities
3. Look for any vulnerabilities missed in the first scan
4. Try to bypass the fixes that were applied

Output your findings as a JSON array in a \`\`\`json code block. Include ONLY vulnerabilities that still exist (not fixed ones)."

After the red-agent completes, copy its COMPLETE JSON output into your response verbatim.`;

    try {
      const redResult = await runAgent(redPrompt, baseOptions);
      totalCost += redResult.costUsd;
      succeedSpinner('Red Agent scan complete');

      const parsed = parseJsonFromText(redResult.resultText);
      const foundVulns: Vulnerability[] = Array.isArray(parsed)
        ? (parsed as Vulnerability[]).map((v, i) => ({
            ...v,
            id: v.id || `VULN-${String(allVulnerabilities.length + i + 1).padStart(3, '0')}`,
            severity: (v.severity || 'medium') as Severity,
          }))
        : [];

      // Deduplicate - don't add if same title+file already exists
      const newVulns = foundVulns.filter(
        (v) =>
          !allVulnerabilities.some(
            (existing) => existing.title === v.title && existing.file === v.file
          )
      );

      allVulnerabilities.push(...newVulns);

      logRed(`Found ${foundVulns.length} vulnerabilities (${newVulns.length} new)`);
      printVulnerabilityTable(
        [...newVulns].sort(
          (a, b) => (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4)
        )
      );

      const currentUnfixed = allVulnerabilities.filter(
        (v) => !allFixes.some((f) => f.vulnerabilityId === v.id && f.verified)
      );

      iterations.push({
        round,
        phase: 'red',
        vulnerabilitiesFound: foundVulns.length,
        fixesApplied: 0,
        remainingIssues: currentUnfixed.length,
      });

      // If no vulnerabilities found and not first round, we're done
      if (currentUnfixed.length === 0 && round > 1) {
        logGreen('All vulnerabilities have been resolved! Ending scan.');
        break;
      }

      if (currentUnfixed.length === 0 && round === 1) {
        logGreen('No vulnerabilities found. Project appears secure!');
        break;
      }

      // ─── PHASE 2: BLUE AGENT DEFENSE ───
      if (!options.fix) {
        logGreen('Fix mode disabled (--no-fix). Skipping Blue Agent phase.');
        continue;
      }

      logPhase(`ROUND ${round}/${options.maxIterations}`, 'Blue Agent - Applying Fixes');
      const blueSpinner = startSpinner('Blue Agent fixing vulnerabilities...');

      const vulnsForBlue = currentUnfixed
        .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4))
        .map((v) => ({
          id: v.id,
          title: v.title,
          severity: v.severity,
          category: v.category,
          file: v.file,
          line: v.line,
          description: v.description,
          evidence: v.evidence,
        }));

      const bluePrompt = `Invoke the blue-agent subagent with the following prompt:

"Fix ALL of the following security vulnerabilities in the project at ${options.target}:

${JSON.stringify(vulnsForBlue, null, 2)}

For EACH vulnerability:
1. Read the affected file
2. Apply the minimal correct fix using Edit tool
3. If tests exist, run them to make sure nothing breaks
4. Set verified=true if the fix is complete, verified=false if you couldn't fully fix it

Output your fixes as a JSON array in a \`\`\`json code block with the schema: [{vulnerabilityId, file, description, diff, verified}]"

After the blue-agent completes, copy its COMPLETE JSON output into your response verbatim.`;

      try {
        const blueResult = await runAgent(bluePrompt, baseOptions);
        totalCost += blueResult.costUsd;
        succeedSpinner('Blue Agent fixes applied');

        const parsedFixes = parseJsonFromText(blueResult.resultText);
        const fixes: Fix[] = Array.isArray(parsedFixes) ? (parsedFixes as Fix[]) : [];

        allFixes.push(...fixes);

        const verifiedCount = fixes.filter((f) => f.verified).length;
        logBlue(`Applied ${fixes.length} fixes (${verifiedCount} verified)`);

        iterations.push({
          round,
          phase: 'blue',
          vulnerabilitiesFound: 0,
          fixesApplied: fixes.length,
          remainingIssues: currentUnfixed.length - verifiedCount,
        });
      } catch (err) {
        failSpinner('Blue Agent encountered an error');
        logBlue(`Error: ${err instanceof Error ? err.message : String(err)}`);
        iterations.push({
          round,
          phase: 'blue',
          vulnerabilitiesFound: 0,
          fixesApplied: 0,
          remainingIssues: currentUnfixed.length,
        });
      }
    } catch (err) {
      failSpinner('Red Agent encountered an error');
      logRed(`Error: ${err instanceof Error ? err.message : String(err)}`);
      iterations.push({
        round,
        phase: 'red',
        vulnerabilitiesFound: 0,
        fixesApplied: 0,
        remainingIssues: allVulnerabilities.length,
      });
    }
  }

  stopSpinner();

  // ─── PHASE 3: GREEN AGENT - GENERATE REPORT ───
  logPhase('FINAL', 'Green Agent - Generating Security Report');

  const unfixed = allVulnerabilities.filter(
    (v) => !allFixes.some((f) => f.vulnerabilityId === v.id && f.verified)
  );

  const summary: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const v of allVulnerabilities) {
    summary[v.severity] = (summary[v.severity] || 0) + 1;
  }

  // Calculate security score
  const score = calculateScore(allVulnerabilities, allFixes);

  // Generate recommendations
  const recommendations = generateRecommendations(unfixed);

  const report: SecurityReport = {
    projectName,
    projectPath: options.target,
    scanDate: new Date().toISOString(),
    duration: Date.now() - startTime,
    iterations,
    totalIterations: iterations.filter((i) => i.phase === 'red').length,
    summary,
    vulnerabilities: allVulnerabilities.sort(
      (a, b) => (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4)
    ),
    fixes: allFixes,
    unfixed,
    score,
    recommendations,
    costUsd: totalCost,
  };

  return report;
}

function calculateScore(vulns: Vulnerability[], fixes: Fix[]): number {
  if (vulns.length === 0) return 100;

  const weights: Record<Severity, number> = {
    critical: 25,
    high: 15,
    medium: 8,
    low: 3,
    info: 1,
  };

  let totalPenalty = 0;
  let fixedPenalty = 0;

  for (const v of vulns) {
    const penalty = weights[v.severity] || 1;
    totalPenalty += penalty;
    if (fixes.some((f) => f.vulnerabilityId === v.id && f.verified)) {
      fixedPenalty += penalty;
    }
  }

  const remainingPenalty = totalPenalty - fixedPenalty;
  const score = Math.max(0, Math.round(100 - remainingPenalty));
  return Math.min(100, score);
}

function generateRecommendations(unfixed: Vulnerability[]): string[] {
  const recs: string[] = [];
  const categories = new Set(unfixed.map((v) => v.category));

  if (unfixed.some((v) => v.severity === 'critical')) {
    recs.push('URGENT: Address all critical vulnerabilities immediately before deploying to production.');
  }

  if (categories.has('Hardcoded Secret') || categories.has('Sensitive Data Exposure')) {
    recs.push('Implement a secrets management solution (e.g., HashiCorp Vault, AWS Secrets Manager).');
  }

  if (categories.has('SQL Injection') || categories.has('Command Injection')) {
    recs.push('Implement parameterized queries and input validation across all user-facing endpoints.');
  }

  if (categories.has('XSS') || categories.has('Cross-Site Scripting')) {
    recs.push('Implement Content Security Policy (CSP) headers and output encoding.');
  }

  if (categories.has('Broken Authentication')) {
    recs.push('Implement multi-factor authentication and review session management.');
  }

  if (categories.has('Security Misconfiguration')) {
    recs.push('Review and harden all security configurations. Consider using infrastructure-as-code.');
  }

  if (unfixed.length > 0) {
    recs.push('Set up automated security scanning in your CI/CD pipeline (e.g., SAST, DAST, SCA).');
    recs.push('Conduct regular security training for the development team.');
  }

  if (recs.length === 0) {
    recs.push('Continue maintaining security best practices and keep dependencies up to date.');
  }

  return recs;
}
