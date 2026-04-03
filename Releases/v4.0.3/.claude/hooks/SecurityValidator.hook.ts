#!/usr/bin/env bun
/**
 * SecurityValidator.hook.ts - Security Validation for Tool Calls (PreToolUse)
 *
 * PURPOSE:
 * Validates Bash commands and file operations against security patterns before
 * execution. Prevents accidental or malicious operations that could damage the
 * system, expose secrets, or compromise security.
 *
 * TRIGGER: PreToolUse (matcher: Bash, Edit, Write, Read)
 *
 * INPUT:
 * - tool_name: "Bash" | "Edit" | "Write" | "Read"
 * - tool_input: { command?: string, file_path?: string, ... }
 * - session_id: Current session identifier
 *
 * OUTPUT:
 * - stdout: JSON decision object
 *   - {"continue": true} → Allow operation
 *   - {hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "ask"}} → Prompt user
 * - exit(0): Normal completion (with decision)
 * - exit(2): Hard block (catastrophic operation prevented)
 *
 * SIDE EFFECTS:
 * - Writes to: MEMORY/SECURITY/YYYY/MM/security-{summary}-{timestamp}.jsonl
 * - User prompt: May trigger confirmation dialog for confirm-level operations
 *
 * INTER-HOOK RELATIONSHIPS:
 * - DEPENDS ON: patterns.yaml (security pattern definitions)
 * - COORDINATES WITH: None (standalone validation)
 * - MUST RUN BEFORE: Tool execution (blocking)
 * - MUST RUN AFTER: None
 *
 * ERROR HANDLING:
 * - Missing patterns.yaml: Uses default safe patterns
 * - Parse errors: Logs warning, allows operation (fail-open for usability)
 * - Logging failures: Silent (should not block operations)
 *
 * PERFORMANCE:
 * - Blocking: Yes (must complete before tool executes)
 * - Typical execution: <10ms
 * - Design: Fast path for safe operations, pattern matching only when needed
 *
 * PATTERN CATEGORIES:
 * Bash commands:
 * - blocked: Always prevented (rm -rf /, format, etc.)
 * - confirm: Requires user confirmation (git push --force, etc.)
 * - alert: Logged but allowed (sudo, etc.)
 *
 * File paths:
 * - zeroAccess: Never readable or writable (~/.ssh, credentials, etc.)
 * - readOnly: Readable but not writable (system configs)
 * - confirmWrite: Requires confirmation to write
 * - noDelete: Cannot be deleted
 *
 * SECURITY MODEL:
 * - Defense in depth: Multiple pattern layers
 * - Fail-safe for catastrophic operations (exit 2)
 * - Fail-open for minor concerns (log and allow)
 * - All decisions logged for audit trail
 */

import { readFileSync, existsSync, writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { parse as parseYaml } from 'yaml';
import { paiPath } from './lib/paths';

// ========================================
// Security Event Logging
// ========================================

// Logs to individual files: MEMORY/SECURITY/YYYY/MM/security-{summary}-{timestamp}.jsonl
// Each event gets a descriptive filename for easy scanning

interface SecurityEvent {
  timestamp: string;
  session_id: string;
  event_type: 'block' | 'confirm' | 'alert' | 'allow';
  tool: string;
  category: 'bash_command' | 'path_access';
  target: string;  // command or path
  pattern_matched?: string;
  reason?: string;
  action_taken: string;
}

function generateEventSummary(event: SecurityEvent): string {
  // Create a 6-word-max slug from event type and target/reason
  const eventWord = event.event_type; // block, confirm, alert, allow

  // Extract key words from target or reason
  const source = event.reason || event.target || 'unknown';
  const words = source
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')  // Remove special chars
    .split(/\s+/)
    .filter(w => w.length > 1)     // Skip tiny words
    .slice(0, 5);                   // Max 5 words (+ event type = 6)

  return [eventWord, ...words].join('-');
}

function getSecurityLogPath(event: SecurityEvent): string {
  const now = new Date();
  const year = now.getFullYear().toString();
  const month = (now.getMonth() + 1).toString().padStart(2, '0');
  const day = now.getDate().toString().padStart(2, '0');
  const hour = now.getHours().toString().padStart(2, '0');
  const min = now.getMinutes().toString().padStart(2, '0');
  const sec = now.getSeconds().toString().padStart(2, '0');

  const summary = generateEventSummary(event);
  const timestamp = `${year}${month}${day}-${hour}${min}${sec}`;

  return paiPath('MEMORY', 'SECURITY', year, month, `security-${summary}-${timestamp}.jsonl`);
}

function logSecurityEvent(event: SecurityEvent): void {
  try {
    const logPath = getSecurityLogPath(event);
    const dir = logPath.substring(0, logPath.lastIndexOf('/'));

    // Ensure directory exists
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    const content = JSON.stringify(event, null, 2);
    writeFileSync(logPath, content);
  } catch (err) {
    // Logging failure should not block operations
    console.error('[SecurityValidator] logSecurityEvent:', err);
  }
}

// ========================================
// Types
// ========================================

interface HookInput {
  session_id: string;
  tool_name: string;
  tool_input: Record<string, unknown> | string;
}

interface Pattern {
  pattern: string;
  reason: string;
}

interface PatternsConfig {
  version: string;
  philosophy: {
    mode: string;
    principle: string;
  };
  bash: {
    trusted: Pattern[];
    blocked: Pattern[];
    confirm: Pattern[];
    alert: Pattern[];
  };
  paths: {
    zeroAccess: string[];
    readOnly: string[];
    confirmWrite: string[];
    noDelete: string[];
  };
  projects: Record<string, {
    path: string;
    rules: Array<{ action: string; reason: string }>;
  }>;
}

// ========================================
// Config Loading - Cascading Path Lookup
// ========================================

// Pattern paths in priority order:
// 1. PAI/USER/PAISECURITYSYSTEM/patterns.yaml (user's custom rules)
// 2. PAI/PAISECURITYSYSTEM/patterns.example.yaml (default template)
const USER_PATTERNS_PATH = paiPath('PAI', 'USER', 'PAISECURITYSYSTEM', 'patterns.yaml');
const SYSTEM_PATTERNS_PATH = paiPath('PAI', 'PAISECURITYSYSTEM', 'patterns.example.yaml');

let patternsCache: PatternsConfig | null = null;
let patternsSource: 'user' | 'system' | 'none' = 'none';

function getPatternsPath(): string | null {
  // Try USER patterns first (user's custom rules)
  if (existsSync(USER_PATTERNS_PATH)) {
    patternsSource = 'user';
    return USER_PATTERNS_PATH;
  }

  // Fall back to SYSTEM patterns (default template)
  if (existsSync(SYSTEM_PATTERNS_PATH)) {
    patternsSource = 'system';
    return SYSTEM_PATTERNS_PATH;
  }

  // No patterns found
  patternsSource = 'none';
  return null;
}

function loadPatterns(): PatternsConfig {
  if (patternsCache) return patternsCache;

  const patternsPath = getPatternsPath();

  if (!patternsPath) {
    // No patterns file - fail open (allow all)
    return {
      version: '0.0',
      philosophy: { mode: 'permissive', principle: 'No patterns loaded - fail open' },
      bash: { trusted: [], blocked: [], confirm: [], alert: [] },
      paths: { zeroAccess: [], readOnly: [], confirmWrite: [], noDelete: [] },
      projects: {}
    };
  }

  try {
    const content = readFileSync(patternsPath, 'utf-8');
    patternsCache = parseYaml(content) as PatternsConfig;
    return patternsCache;
  } catch (error) {
    // Parse error - fail open
    console.error(`Failed to parse ${patternsSource} patterns.yaml:`, error);
    return {
      version: '0.0',
      philosophy: { mode: 'permissive', principle: 'Parse error - fail open' },
      bash: { trusted: [], blocked: [], confirm: [], alert: [] },
      paths: { zeroAccess: [], readOnly: [], confirmWrite: [], noDelete: [] },
      projects: {}
    };
  }
}

// ========================================
// Command Normalization
// ========================================

/**
 * Strip leading environment variable assignments from a command.
 * Prevents bypass like: LANG=C rm -rf / or FOO="bar" dangerous-cmd
 * Also strips leading whitespace.
 */
function stripEnvVarPrefix(command: string): string {
  return command.replace(
    /^\s*(?:[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|[^\s]*)\s+)*/,
    ''
  );
}

// ========================================
// Pattern Matching
// ========================================

function matchesPattern(command: string, pattern: string): boolean {
  // Convert pattern to regex
  // Patterns can use .* for wildcards
  try {
    const regex = new RegExp(pattern, 'i');
    return regex.test(command);
  } catch (err) {
    // Invalid regex - try literal match
    console.error('[SecurityValidator] matchesPattern invalid regex:', err);
    return command.toLowerCase().includes(pattern.toLowerCase());
  }
}

function expandPath(path: string): string {
  // Expand ~ to home directory
  if (path.startsWith('~')) {
    return path.replace('~', homedir());
  }
  return path;
}

function matchesPathPattern(filePath: string, pattern: string): boolean {
  const expandedPattern = expandPath(pattern);
  const expandedPath = expandPath(filePath);

  // Handle glob patterns
  if (pattern.includes('*')) {
    // First replace ** with a placeholder, then escape, then convert back
    let regexPattern = expandedPattern
      .replace(/\*\*/g, '<<<DOUBLESTAR>>>')  // Protect **
      .replace(/\*/g, '<<<SINGLESTAR>>>')    // Protect *
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')  // Escape special chars
      .replace(/<<<DOUBLESTAR>>>/g, '.*')    // ** = anything including /
      .replace(/<<<SINGLESTAR>>>/g, '[^/]*'); // * = anything except /

    try {
      const regex = new RegExp(`^${regexPattern}$`);
      return regex.test(expandedPath);
    } catch (err) {
      console.error('[SecurityValidator] matchesPathPattern regex:', err);
      return false;
    }
  }

  // Exact match or prefix match for directories
  return expandedPath === expandedPattern ||
         expandedPath.startsWith(expandedPattern.endsWith('/') ? expandedPattern : expandedPattern + '/');
}

// ========================================
// Bash Command Validation
// ========================================

function validateBashCommand(command: string): { action: 'allow' | 'block' | 'confirm' | 'alert'; reason?: string } {
  const patterns = loadPatterns();

  // Check trusted patterns FIRST (fast-path allow, no logging)
  for (const p of (patterns.bash.trusted || [])) {
    if (matchesPattern(command, p.pattern)) {
      return { action: 'allow' };
    }
  }

  // Check blocked patterns (hard block)
  for (const p of patterns.bash.blocked) {
    if (matchesPattern(command, p.pattern)) {
      return { action: 'block', reason: p.reason };
    }
  }

  // Check confirm patterns (prompt user)
  for (const p of patterns.bash.confirm) {
    if (matchesPattern(command, p.pattern)) {
      return { action: 'confirm', reason: p.reason };
    }
  }

  // Check alert patterns (log but allow)
  for (const p of patterns.bash.alert) {
    if (matchesPattern(command, p.pattern)) {
      return { action: 'alert', reason: p.reason };
    }
  }

  return { action: 'allow' };
}

// ========================================
// Path Validation
// ========================================

type PathAction = 'read' | 'write' | 'delete';

function validatePath(filePath: string, action: PathAction): { action: 'allow' | 'block' | 'confirm'; reason?: string } {
  const patterns = loadPatterns();

  // Check zeroAccess (complete denial)
  for (const p of patterns.paths.zeroAccess) {
    if (matchesPathPattern(filePath, p)) {
      return { action: 'block', reason: `Zero access path: ${p}` };
    }
  }

  // Check readOnly (can read, cannot write/delete)
  if (action === 'write' || action === 'delete') {
    for (const p of patterns.paths.readOnly) {
      if (matchesPathPattern(filePath, p)) {
        return { action: 'block', reason: `Read-only path: ${p}` };
      }
    }
  }

  // Check confirmWrite (can read, writing requires confirmation)
  if (action === 'write') {
    for (const p of patterns.paths.confirmWrite) {
      if (matchesPathPattern(filePath, p)) {
        return { action: 'confirm', reason: `Writing to protected file requires confirmation: ${p}` };
      }
    }
  }

  // Check noDelete (can read/write, cannot delete)
  if (action === 'delete') {
    for (const p of patterns.paths.noDelete) {
      if (matchesPathPattern(filePath, p)) {
        return { action: 'block', reason: `Cannot delete protected path: ${p}` };
      }
    }
  }

  return { action: 'allow' };
}

// ========================================
// Bash Path Extraction
// ========================================

/**
 * Extract file paths from Bash commands that perform file writes.
 * Catches common bypass vectors: bun/node -e with writeFileSync,
 * shell redirections (> >>), cp/mv targets, tee, sed -i, etc.
 *
 * Not exhaustive — defense in depth, not perimeter.
 */
function extractWritePathsFromBash(command: string): string[] {
  // Fast exit: skip commands that can't possibly write files
  if (!/writeFileSync|>>?|[^|]\btee\b|\bsed\b.*-i|\bcp\b|\bmv\b/.test(command)) {
    return [];
  }

  const paths: string[] = [];
  const home = homedir();

  // Strip heredoc bodies to avoid false positives on embedded path strings.
  // Heredoc delimiters: << EOF ... EOF, << 'EOF' ... EOF, <<- EOF ... EOF
  // The <<- variant allows indented closing delimiters.
  const cmd = command.replace(/<<-?\s*'?(\w+)'?.*?\n[\s\S]*?\n\s*\1\b/g, '');

  // writeFileSync / writeFile with string literal path
  const wfsMatches = cmd.matchAll(/writeFileSync\s*\(\s*['"`]([^'"`]+)['"`]/g);
  for (const m of wfsMatches) paths.push(m[1]);

  // Shell redirections: > file, >> file
  const redirectMatches = cmd.matchAll(/>{1,2}\s*['"]?([^\s;|&'"]+)/g);
  for (const m of redirectMatches) paths.push(m[1]);

  // tee target
  const teeMatches = cmd.matchAll(/\btee\s+(?:-a\s+)?['"]?([^\s;|&'"]+)/g);
  for (const m of teeMatches) paths.push(m[1]);

  // sed -i (in-place edit)
  const sedMatches = cmd.matchAll(/\bsed\s+-i[^\s]*\s+(?:'[^']*'|"[^"]*"|\S+)\s+['"]?([^\s;|&'"]+)/g);
  for (const m of sedMatches) paths.push(m[1]);

  // cp/mv target (last argument)
  const cpMvMatches = cmd.matchAll(/\b(?:cp|mv)\s+(?:-[^\s]+\s+)*(?:\S+\s+)+['"]?([^\s;|&'"]+)/g);
  for (const m of cpMvMatches) paths.push(m[1]);

  // Resolve relative paths and ~ expansion
  return paths.map(p => {
    if (p.startsWith('~')) return p.replace('~', home);
    if (p.startsWith('/')) return p;
    // Relative paths — can't resolve reliably, include as-is
    return p;
  });
}

// ========================================
// Tool-Specific Handlers
// ========================================

function handleBash(input: HookInput): void {
  const rawCommand = typeof input.tool_input === 'string'
    ? input.tool_input
    : (input.tool_input?.command as string) || '';

  if (!rawCommand) {
    console.log(JSON.stringify({ continue: true }));
    return;
  }

  // Normalize: strip env var prefixes to prevent bypass (e.g., LANG=C rm -rf /)
  const command = stripEnvVarPrefix(rawCommand);
  const result = validateBashCommand(command);

  // If command passes bash pattern checks, also check for file write bypass.
  // Prevents: bun -e "writeFileSync('settings.json', ...)" bypassing Edit/Write guards.
  if (result.action === 'allow') {
    const writePaths = extractWritePathsFromBash(command);
    for (const wp of writePaths) {
      const pathResult = validatePath(wp, 'write');
      if (pathResult.action === 'block') {
        logSecurityEvent({
          timestamp: new Date().toISOString(),
          session_id: input.session_id,
          event_type: 'block',
          tool: 'Bash',
          category: 'path_access',
          target: wp,
          pattern_matched: command.slice(0, 200),
          reason: `Bash write to protected path: ${pathResult.reason}`,
          action_taken: 'Hard block - exit 2'
        });
        console.error(`[PAI SECURITY] 🚨 BLOCKED: Bash write to protected path`);
        console.error(`Path: ${wp}`);
        console.error(`Command: ${command.slice(0, 200)}`);
        process.exit(2);
      }
      if (pathResult.action === 'confirm') {
        logSecurityEvent({
          timestamp: new Date().toISOString(),
          session_id: input.session_id,
          event_type: 'confirm',
          tool: 'Bash',
          category: 'path_access',
          target: wp,
          pattern_matched: command.slice(0, 200),
          reason: `Bash write to protected path: ${pathResult.reason}`,
          action_taken: 'Prompted user for confirmation'
        });
        console.log(JSON.stringify({
          hookSpecificOutput: {
            hookEventName: 'PreToolUse',
            permissionDecision: 'ask'
          },
          message: `[PAI SECURITY] ⚠️ Bash command writes to protected path\n\nPath: ${wp}\nReason: ${pathResult.reason}\nCommand: ${command.slice(0, 200)}\n\nProceed?`
        }));
        return;
      }
    }
  }

  switch (result.action) {
    case 'block':
      logSecurityEvent({
        timestamp: new Date().toISOString(),
        session_id: input.session_id,
        event_type: 'block',
        tool: 'Bash',
        category: 'bash_command',
        target: command.slice(0, 500),
        reason: result.reason,
        action_taken: 'Hard block - exit 2'
      });
      console.error(`[PAI SECURITY] 🚨 BLOCKED: ${result.reason}`);
      console.error(`Command: ${command.slice(0, 100)}`);
      process.exit(2);
      break;

    case 'confirm':
      logSecurityEvent({
        timestamp: new Date().toISOString(),
        session_id: input.session_id,
        event_type: 'confirm',
        tool: 'Bash',
        category: 'bash_command',
        target: command.slice(0, 500),
        reason: result.reason,
        action_taken: 'Prompted user for confirmation'
      });
      console.log(JSON.stringify({
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'ask'
        },
        message: `[PAI SECURITY] ⚠️ ${result.reason}\n\nCommand: ${command.slice(0, 200)}\n\nProceed?`
      }));
      break;

    case 'alert':
      logSecurityEvent({
        timestamp: new Date().toISOString(),
        session_id: input.session_id,
        event_type: 'alert',
        tool: 'Bash',
        category: 'bash_command',
        target: command.slice(0, 500),
        reason: result.reason,
        action_taken: 'Logged alert, allowed execution'
      });
      console.error(`[PAI SECURITY] ⚠️ ALERT: ${result.reason}`);
      console.error(`Command: ${command.slice(0, 100)}`);
      console.log(JSON.stringify({ continue: true }));
      break;

    default:
      console.log(JSON.stringify({ continue: true }));
  }
}

function handleFileWrite(input: HookInput, toolName: string): void {
  const filePath = typeof input.tool_input === 'string'
    ? input.tool_input
    : (input.tool_input?.file_path as string) || '';

  if (!filePath) {
    console.log(JSON.stringify({ continue: true }));
    return;
  }

  const result = validatePath(filePath, 'write');

  switch (result.action) {
    case 'block':
      logSecurityEvent({
        timestamp: new Date().toISOString(),
        session_id: input.session_id,
        event_type: 'block',
        tool: toolName,
        category: 'path_access',
        target: filePath,
        reason: result.reason,
        action_taken: 'Hard block - exit 2'
      });
      console.error(`[PAI SECURITY] 🚨 BLOCKED: ${result.reason}`);
      console.error(`Path: ${filePath}`);
      process.exit(2);
      break;

    case 'confirm':
      logSecurityEvent({
        timestamp: new Date().toISOString(),
        session_id: input.session_id,
        event_type: 'confirm',
        tool: toolName,
        category: 'path_access',
        target: filePath,
        reason: result.reason,
        action_taken: 'Prompted user for confirmation'
      });
      console.log(JSON.stringify({
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'ask'
        },
        message: `[PAI SECURITY] ⚠️ ${result.reason}\n\nPath: ${filePath}\n\nProceed?`
      }));
      break;

    default:
      console.log(JSON.stringify({ continue: true }));
  }
}

function handleRead(input: HookInput): void {
  const filePath = typeof input.tool_input === 'string'
    ? input.tool_input
    : (input.tool_input?.file_path as string) || '';

  if (!filePath) {
    console.log(JSON.stringify({ continue: true }));
    return;
  }

  const result = validatePath(filePath, 'read');

  switch (result.action) {
    case 'block':
      logSecurityEvent({
        timestamp: new Date().toISOString(),
        session_id: input.session_id,
        event_type: 'block',
        tool: 'Read',
        category: 'path_access',
        target: filePath,
        reason: result.reason,
        action_taken: 'Hard block - exit 2'
      });
      console.error(`[PAI SECURITY] 🚨 BLOCKED: ${result.reason}`);
      console.error(`Path: ${filePath}`);
      process.exit(2);
      break;

    default:
      console.log(JSON.stringify({ continue: true }));
  }
}

// ========================================
// Main
// ========================================

async function main(): Promise<void> {
  let input: HookInput;

  try {
    // Streaming stdin read with hard timeout.
    // Bun.stdin.text() can hang forever if stdin never closes (known Bun issue).
    // Use streaming reader + setTimeout that forces process.exit on timeout.
    const reader = Bun.stdin.stream().getReader();
    let raw = '';
    const readLoop = (async () => {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        raw += new TextDecoder().decode(value, { stream: true });
      }
    })();

    // Hard timeout: if stdin doesn't close in 200ms, exit the process.
    // setTimeout keeps the event loop alive, so we use process.exit to force cleanup.
    const timeout = setTimeout(() => {
      if (!raw.trim()) {
        console.log(JSON.stringify({ continue: true }));
        process.exit(0);
      }
    }, 200);

    await Promise.race([readLoop, new Promise<void>(r => setTimeout(r, 200))]);
    clearTimeout(timeout);

    if (!raw.trim()) {
      console.log(JSON.stringify({ continue: true }));
      return;
    }

    input = JSON.parse(raw);
  } catch (err) {
    // Parse error or timeout - fail open
    console.error('[SecurityValidator] main stdin parse:', err);
    console.log(JSON.stringify({ continue: true }));
    return;
  }

  // Route to appropriate handler
  switch (input.tool_name) {
    case 'Bash':
      handleBash(input);
      break;
    case 'Edit':
    case 'MultiEdit':
      handleFileWrite(input, input.tool_name);
      break;
    case 'Write':
      handleFileWrite(input, 'Write');
      break;
    case 'Read':
      handleRead(input);
      break;
    default:
      // Allow all other tools
      console.log(JSON.stringify({ continue: true }));
  }
}

// Run main, fail open on any error
main().catch(() => {
  console.log(JSON.stringify({ continue: true }));
});
