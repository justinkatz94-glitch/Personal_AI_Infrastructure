#!/usr/bin/env bun
/**
 * PRDSync.hook.ts — Read-only PRD → work.json sync via PostToolUse
 *
 * TRIGGER: PostToolUse (Write, Edit)
 *
 * v3.2.0: Hooks are READ-ONLY from PRD's perspective.
 * The AI writes all PRD content directly (criteria, checkboxes, frontmatter).
 * This hook ONLY reads the PRD and syncs to work.json for the dashboard.
 *
 * - Write/Edit on PRD.md → read frontmatter + criteria → sync to work.json
 */

import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import {
  parseFrontmatter,
  syncToWorkJson,
  readRegistry,
} from './lib/prd-utils';
import { setPhaseTab } from './lib/tab-setter';
import type { AlgorithmTabPhase } from './lib/tab-constants';

let input: any;
let responded = false;

async function readStdin(): Promise<any> {
  let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  try {
    const decoder = new TextDecoder();
    reader = Bun.stdin.stream().getReader();
    let raw = '';
    const timeout = new Promise<void>(r => setTimeout(r, 2000));
    const read = (async () => {
      while (true) {
        const { done, value } = await reader!.read();
        if (done) break;
        raw += decoder.decode(value, { stream: true });
      }
    })();
    await Promise.race([read, timeout]);
    reader.cancel().catch(() => {});
    if (raw.trim()) return JSON.parse(raw);
  } catch (err) {
    console.error('[PRDSync] readStdin:', err);
    if (reader) reader.cancel().catch(() => {});
  }
  return null;
}

async function main() {
  input = await readStdin();
  if (!input) process.exit(0);
  const toolInput = input.tool_input || {};
  // Only trigger for PRD.md files in MEMORY/WORK/
  const filePath = toolInput.file_path || '';
  if (!filePath.includes('MEMORY/WORK/') || !filePath.endsWith('PRD.md')) return;

  // Use the actual file path that was just written/edited, not findLatestPRD()
  // findLatestPRD() scans all PRDs by mtime and can return the wrong file
  // when multiple sessions exist or when a file's mtime is bumped by git ops.
  const prdPath = filePath;
  if (!existsSync(prdPath)) return;

  const content = readFileSync(prdPath, 'utf-8');
  const fm = parseFrontmatter(content);
  if (!fm) return;

  // Check existing phase before sync to detect phase changes
  const newPhase = (fm.phase || '').toUpperCase();
  let oldPhase = '';
  if (fm.slug) {
    try {
      const registry = readRegistry();
      const existing = registry.sessions[fm.slug];
      if (existing) oldPhase = (existing.phase || '').toUpperCase();
    } catch (err) { console.error('[PRDSync] readRegistry skipping (silent):', err); }
  }

  // Gate: when phase transitions to COMPLETE, check for reflection JSONL (before sync overwrites oldPhase)
  if (newPhase === 'COMPLETE' && oldPhase !== 'COMPLETE' && fm.slug) {
    const paiDir = process.env.PAI_DIR || join(process.env.HOME!, '.claude');
    const reflPath = join(paiDir, 'MEMORY', 'LEARNING', 'REFLECTIONS', 'algorithm-reflections.jsonl');
    let hasReflection = false;
    if (existsSync(reflPath)) {
      hasReflection = readFileSync(reflPath, 'utf-8').includes(fm.slug);
    }
    if (!hasReflection) {
      console.log(JSON.stringify({
        continue: true,
        additionalContext: `<system-reminder>\n⚠️ REFLECTION MISSING: PRD "${fm.slug}" set to phase: complete but NO reflection entry in algorithm-reflections.jsonl. Write the reflection JSONL now. Do not end this session without it.\n</system-reminder>`
      }));
      responded = true;
    }
  }

  // Sync frontmatter + criteria to work.json (pass session_id for session name lookup)
  syncToWorkJson(fm, prdPath, content, input.session_id);

  // Update tab color when algorithm phase changes
  const VALID_PHASES = new Set(['OBSERVE', 'THINK', 'PLAN', 'BUILD', 'EXECUTE', 'VERIFY', 'LEARN', 'COMPLETE']);
  if (newPhase !== oldPhase && VALID_PHASES.has(newPhase) && input.session_id) {
    try {
      setPhaseTab(newPhase as AlgorithmTabPhase, input.session_id);
    } catch (err) {
      console.error('[PRDSync] setPhaseTab failed:', err);
    }
  }

}

main().catch(() => {}).finally(() => {
  if (!responded) console.log(JSON.stringify({ continue: true }));
  process.exit(0);
});
