import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { runOperationChecks } from '../public/operation-checks.js';

const root = resolve(import.meta.dirname, '..');
try {
  const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
  const rows = await runOperationChecks({ baseUrl: config.publicAppUrl });
  const report = { schema: 'aleph.operations.evidence.v1',
    site: config.publicAppUrl, rows };
  await mkdir(resolve(root, 'artifacts'), { recursive: true });
  await writeFile(resolve(root, 'artifacts', 'stage12-http-evidence.json'),
    `${JSON.stringify(report, null, 2)}\n`);
  const measured = rows.filter(row => row.source === 'actual_http_response');
  for (const row of measured) {
    process.stdout.write(`${row.outcome} · ${row.name} · ${row.actual} · ${row.checkId} · ${row.checkedAt}\n`);
  }
  process.stdout.write(`실제 HTTP ${measured.length}건 · 미실행 ${rows.length - measured.length}건\n`);
  if (measured.some(row => row.outcome !== '기대와 일치')) process.exitCode = 1;
} catch (error) {
  process.stderr.write(`실제 HTTP 확인 첫 오류: ${error.message}\n`);
  process.exitCode = 1;
}
