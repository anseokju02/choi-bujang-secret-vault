import { execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { appendFileSync, existsSync, lstatSync, mkdirSync, readFileSync, renameSync,
  writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspectPolicy, SAFE_POLICY_COMMIT, SAFE_POLICY_SHA256 } from './policy-preview.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const policyPath = join(root, 'src', 'decider.mjs');
const auditDir = join(root, 'private-restore-audit');
const auditLog = join(auditDir, 'policy-restores.jsonl');
const fingerprint = (value) => createHash('sha256').update(value).digest('hex');

function verifiedSafePolicy() {
  let safe;
  try {
    safe = execFileSync('git', ['show', `${SAFE_POLICY_COMMIT}:src/decider.mjs`], {
      cwd: root, encoding: 'utf8', timeout: 5000,
      env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0' },
    });
  } catch {
    throw new Error('verified_policy_snapshot_missing');
  }
  if (fingerprint(safe) !== SAFE_POLICY_SHA256) {
    throw new Error('verified_policy_snapshot_mismatch');
  }
  return safe;
}

function audit(entry) {
  appendFileSync(auditLog, `${JSON.stringify(entry)}\n`, { encoding: 'utf8', mode: 0o600 });
}

// Preview is the default. Apply changes only to this one policy file after
// verifying the exact hash shown in the preview; keep a private before-copy.
export function restorePolicy({ apply = false, expectedCurrentSha256 } = {}) {
  const report = inspectPolicy();
  if (!apply || !report.changed) return { ...report, applied: false };
  if (!/^[a-f0-9]{64}$/u.test(expectedCurrentSha256 ?? '')
      || expectedCurrentSha256 !== report.currentSha256) {
    throw new Error('policy_changed_since_preview');
  }
  const safe = verifiedSafePolicy();
  if (!lstatSync(policyPath).isFile()
      || fingerprint(readFileSync(policyPath)) !== expectedCurrentSha256) {
    throw new Error('policy_changed_since_preview');
  }
  if (existsSync(auditDir) && !lstatSync(auditDir).isDirectory()) {
    throw new Error('invalid_private_audit_location');
  }
  mkdirSync(auditDir, { mode: 0o700 });
  if (existsSync(auditLog) && !lstatSync(auditLog).isFile()) {
    throw new Error('invalid_private_audit_log');
  }

  const id = randomUUID();
  const before = readFileSync(policyPath);
  const backup = join(auditDir, `policy-before-${id}.mjs`);
  const temp = join(dirname(policyPath), `.decider-restore-${id}.mjs`);
  writeFileSync(backup, before, { flag: 'wx', mode: 0o600 });
  audit({ id, at: new Date().toISOString(), action: 'policy_restore_started',
    policyPath: report.policyPath, fromSha256: report.currentSha256,
    toSha256: SAFE_POLICY_SHA256, backup: `policy-before-${id}.mjs` });
  writeFileSync(temp, safe, { flag: 'wx', mode: 0o600 });
  renameSync(temp, policyPath);
  audit({ id, at: new Date().toISOString(), action: 'policy_restore_completed',
    policyPath: report.policyPath, toSha256: SAFE_POLICY_SHA256 });
  return { ...report, applied: true, newSha256: fingerprint(readFileSync(policyPath)) };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const apply = process.argv.includes('--apply');
    const expectedArg = process.argv.find((value) => value.startsWith('--expect-current-sha='));
    if (process.argv.slice(2).some((value) => value !== '--apply'
        && value !== expectedArg)) throw new Error('invalid_restore_option');
    const result = restorePolicy({ apply,
      expectedCurrentSha256: expectedArg?.slice('--expect-current-sha='.length) });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`정책 복구 중단: ${error.message}\n`);
    process.exitCode = 1;
  }
}
