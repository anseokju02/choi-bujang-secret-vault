import { lstatSync, readFileSync } from 'node:fs';
import { noteDigest, verifiedNoteBackup } from '../src/restore-note.mjs';

// Run locally with a previously trusted private B memo snapshot JSON file.
// Print only its digest, never its owner ID or contents.
try {
  const path = process.argv[2];
  if (!path || process.argv.length !== 3 || !lstatSync(path).isFile()
      || lstatSync(path).size > 10000) throw new Error('invalid_backup_file');
  const json = readFileSync(path, 'utf8');
  const candidate = JSON.parse(json);
  const digest = noteDigest(candidate);
  if (!verifiedNoteBackup(json, digest)) throw new Error('invalid_backup_file');
  process.stdout.write(`검증용 사본 SHA-256: ${digest}\n`);
} catch {
  process.stderr.write('비공개 사본 확인 중단: 형식·파일을 확인하세요.\n');
  process.exitCode = 1;
}
