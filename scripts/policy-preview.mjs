import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const SAFE_POLICY_COMMIT = 'bcf605d1abde9e923d174faf4d7f4f1a19481639';
export const SAFE_POLICY_SHA256 = 'efba12c7ca228a3f3ccc5b7d5cab0c49ca4624f6738a782e5f68e600decf74ef';
const POLICY_PATH = 'src/decider.mjs';

const fingerprint = (value) => createHash('sha256').update(value).digest('hex');
const git = (...args) => execFileSync('git', args, {
  cwd: root, encoding: 'utf8', timeout: 5000, maxBuffer: 1024 * 1024,
  env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0' },
});

// Only report line ranges. A changed policy could contain confidential values.
export function inspectPolicy() {
  let safePolicy;
  try {
    safePolicy = git('show', `${SAFE_POLICY_COMMIT}:${POLICY_PATH}`);
  } catch {
    throw new Error('verified_policy_snapshot_missing');
  }
  if (fingerprint(safePolicy) !== SAFE_POLICY_SHA256) {
    throw new Error('verified_policy_snapshot_mismatch');
  }

  const currentPath = join(root, POLICY_PATH);
  if (!lstatSync(currentPath).isFile()) throw new Error('invalid_current_policy_file');
  const currentPolicy = readFileSync(currentPath, 'utf8');
  const changed = currentPolicy !== safePolicy;
  const diff = changed
    ? git('diff', '--no-ext-diff', '--unified=0', SAFE_POLICY_COMMIT, '--', POLICY_PATH)
    : '';
  const ranges = [...diff.matchAll(/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/gmu)]
    .map((match) => ({
      safeStart: Number(match[1]), safeLines: Number(match[2] ?? 1),
      currentStart: Number(match[3]), currentLines: Number(match[4] ?? 1),
    }));
  if (changed && !ranges.length) throw new Error('policy_difference_unavailable');

  return {
    policyPath: POLICY_PATH,
    safeCommit: SAFE_POLICY_COMMIT,
    safeSha256: SAFE_POLICY_SHA256,
    currentSha256: fingerprint(currentPolicy),
    changed,
    ranges,
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const result = inspectPolicy();
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`정책 비교 중단: ${error.message}\n`);
    process.exitCode = 1;
  }
}
