import * as fs from 'fs';
import * as path from 'path';

// Private keys must never be loaded into identity-service for signing.
// Only the KV -> key provider migration may read legacy KV secrets.
const ROOT = path.resolve(__dirname, '..');
const ALLOWED = [
  path.join('keys', 'migration'),
  path.join('keys', 'testing'),
  path.join('utils', 'vault.service.ts'),
  path.join('utils', 'test-infra.util.ts'),
];
const FORBIDDEN = /readPvtKey|writePvtKey|mergePvtKey|privateKeyMultibase|privateKeyBase58|privateKeyPem|privateKeyJwk|extractable:\s*true/;

function walk(dir: string): string[] {
  const files: string[] = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) files.push(...walk(p));
    else if (p.endsWith('.ts') && !p.endsWith('.spec.ts')) files.push(p);
  }
  return files;
}

describe('guard: no private key material in runtime code', () => {
  it('finds no private-key access outside the migration', () => {
    const offenders = walk(ROOT)
      .filter((f) => !ALLOWED.some((a) => path.relative(ROOT, f).startsWith(a)))
      .filter((f) => FORBIDDEN.test(fs.readFileSync(f, 'utf8')))
      .map((f) => path.relative(ROOT, f));
    expect(offenders).toEqual([]);
  });
});
