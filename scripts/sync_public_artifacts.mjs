import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const ROOT = process.cwd();
const RAW_DIR = path.join(ROOT, 'public', 'raw');

const SPEC_FILES = [
  'SPEC.md',
  'spec/01-bitcoin-taproot-vault-enforcement.md',
  'spec/02-btc-authorization-domain-and-spv.md',
  'spec/03-settlement-minted-zbtc-and-feeless-rails.md',
  'spec/04-bitcoin-anchoring-and-light-client.md',
  'spec/05-go-zenon-upgrade-plan.md',
];

const REVIEW_FILES = [
  'reviews/HOSTILE_REVIEW_R1.md',
  'reviews/HOSTILE_REVIEW_R2.md',
  'reviews/HOSTILE_REVIEW_R3.md',
  'reviews/HOSTILE_REVIEW_R4.md',
  'reviews/HOSTILE_REVIEW_R5.md',
  'reviews/HOSTILE_REVIEW_R6.md',
  'reviews/HOSTILE_REVIEW_R7_CONSOLIDATED.md',
];

function copyFile(srcRel, dstRel) {
  const src = path.join(ROOT, srcRel);
  if (!fs.existsSync(src)) return;
  const dst = path.join(RAW_DIR, dstRel);
  fs.mkdirSync(path.dirname(dst), { recursive: true });
  fs.copyFileSync(src, dst);
}

// 1. Verify immutable v0 SHA-256 manifest before doing anything else (B5)
const v0Dir = path.join(ROOT, 'versions', 'v0');
const shaManifestPath = path.join(v0Dir, 'SHA256SUMS.txt');
const shaLines = fs
  .readFileSync(shaManifestPath, 'utf-8')
  .split(/\r?\n/)
  .map((l) => l.trim())
  .filter(Boolean);

for (const line of shaLines) {
  const match = line.match(/^([0-9a-f]{64})\s+(.+)$/);
  if (!match) throw new Error(`Invalid SHA256SUMS.txt line: ${line}`);
  const [, expected, rel] = match;
  const full = path.join(v0Dir, rel);
  const actual = crypto.createHash('sha256').update(fs.readFileSync(full)).digest('hex');
  if (actual !== expected) {
    throw new Error(`Immutable v0 integrity failure for versions/v0/${rel}: expected ${expected}, got ${actual}`);
  }
}
console.log(`Verified ${shaLines.length} immutable v0 files against versions/v0/SHA256SUMS.txt.`);

// 2. Sync current v1 raw files + changelog + reviews
for (const f of [...SPEC_FILES, 'CHANGELOG.md', 'scripts/verify_spec_bounds.py', ...REVIEW_FILES]) {
  copyFile(f, f);
}

// 3. Sync archived v0 raw files + SHA-256 manifest
for (const f of [
  ...SPEC_FILES,
  'scripts/verify_spec_bounds.py',
  'reviews/HOSTILE_REVIEW_R1.md',
  'reviews/HOSTILE_REVIEW_R2.md',
  'reviews/HOSTILE_REVIEW_R3.md',
  'reviews/HOSTILE_REVIEW_R4.md',
  'reviews/HOSTILE_REVIEW_R5.md',
  'reviews/HOSTILE_REVIEW_R6.md',
  'SHA256SUMS.txt',
]) {
  copyFile(path.join('versions', 'v0', f), path.join('v0', f));
}

// 4. Run v1 consistency & bounds checker + archived v0 oracle
const v1OracleOutput = execFileSync('python3', ['-I', path.join(ROOT, 'scripts', 'verify_spec_bounds.py')], {
  encoding: 'utf-8',
});
fs.writeFileSync(path.join(RAW_DIR, 'oracle-output.txt'), v1OracleOutput, 'utf-8');

const v0OracleOutput = execFileSync(
  'python3',
  ['-I', path.join(v0Dir, 'scripts', 'verify_spec_bounds.py')],
  { encoding: 'utf-8' }
);
fs.writeFileSync(path.join(RAW_DIR, 'v0', 'oracle-output.txt'), v0OracleOutput, 'utf-8');

// 5. Build deterministic single-fetch public/llms-full.txt (v1 current)
const llmsIndex = fs.readFileSync(path.join(ROOT, 'public', 'llms.txt'), 'utf-8').trim();
const oracleSource = fs.readFileSync(path.join(ROOT, 'scripts', 'verify_spec_bounds.py'), 'utf-8').trim();
const changelogBody = fs.readFileSync(path.join(ROOT, 'CHANGELOG.md'), 'utf-8').trim();

const sections = [
  llmsIndex,
  '\n================================================================================\n# FULL NORMATIVE SPECIFICATION CORPUS — v1 (v3.0.0-rfc)\n================================================================================\n',
];

for (const rel of SPEC_FILES) {
  const body = fs.readFileSync(path.join(ROOT, rel), 'utf-8').trim();
  sections.push(`\n<!-- BEGIN FILE: ${rel} -->\n\n${body}\n\n<!-- END FILE: ${rel} -->\n`);
}

sections.push(`\n<!-- BEGIN FILE: CHANGELOG.md -->\n\n${changelogBody}\n\n<!-- END FILE: CHANGELOG.md -->\n`);

sections.push(
  `\n<!-- BEGIN FILE: scripts/verify_spec_bounds.py -->\n\n# Deterministic Consistency & Bounds Checker (\`scripts/verify_spec_bounds.py\`)\n\n\`\`\`python\n${oracleSource}\n\`\`\`\n\n<!-- END FILE: scripts/verify_spec_bounds.py -->\n`
);

sections.push(
  `\n<!-- BEGIN VERIFIED CHECKER OUTPUT -->\n\n# Verified Output of \`python3 -I scripts/verify_spec_bounds.py\`\n\n\`\`\`text\n${v1OracleOutput.trim()}\n\`\`\`\n\n<!-- END VERIFIED CHECKER OUTPUT -->\n`
);

fs.writeFileSync(path.join(ROOT, 'public', 'llms-full.txt'), sections.join('\n'), 'utf-8');
console.log('Synced public/raw/ (v1 + archived v0) and generated public/llms-full.txt cleanly.');
