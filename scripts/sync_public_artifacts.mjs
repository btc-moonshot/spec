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
];

function copyToRaw(relPath) {
  const src = path.join(ROOT, relPath);
  if (!fs.existsSync(src)) return;
  const dst = path.join(RAW_DIR, relPath);
  fs.mkdirSync(path.dirname(dst), { recursive: true });
  fs.copyFileSync(src, dst);
}

for (const f of [...SPEC_FILES, 'scripts/verify_spec_bounds.py', ...REVIEW_FILES]) {
  copyToRaw(f);
}

// Run executable oracle to capture fresh verified stdout
const oracleOutput = execFileSync('python3', ['-I', path.join(ROOT, 'scripts', 'verify_spec_bounds.py')], {
  encoding: 'utf-8',
});
fs.writeFileSync(path.join(RAW_DIR, 'oracle-output.txt'), oracleOutput, 'utf-8');

// Build deterministic single-fetch public/llms-full.txt
const llmsIndex = fs.readFileSync(path.join(ROOT, 'public', 'llms.txt'), 'utf-8').trim();
const oracleSource = fs.readFileSync(path.join(ROOT, 'scripts', 'verify_spec_bounds.py'), 'utf-8').trim();

const sections = [
  llmsIndex,
  '\n================================================================================\n# FULL NORMATIVE SPECIFICATION CORPUS (v2.5.0-rfc)\n================================================================================\n',
];

for (const rel of SPEC_FILES) {
  const body = fs.readFileSync(path.join(ROOT, rel), 'utf-8').trim();
  sections.push(`\n<!-- BEGIN FILE: ${rel} -->\n\n${body}\n\n<!-- END FILE: ${rel} -->\n`);
}

sections.push(
  `\n<!-- BEGIN FILE: scripts/verify_spec_bounds.py -->\n\n# Executable Numeric Oracle (\`scripts/verify_spec_bounds.py\`)\n\n\`\`\`python\n${oracleSource}\n\`\`\`\n\n<!-- END FILE: scripts/verify_spec_bounds.py -->\n`
);

sections.push(
  `\n<!-- BEGIN VERIFIED ORACLE OUTPUT -->\n\n# Verified Output of \`python3 -I scripts/verify_spec_bounds.py\`\n\n\`\`\`text\n${oracleOutput.trim()}\n\`\`\`\n\n<!-- END VERIFIED ORACLE OUTPUT -->\n`
);

fs.writeFileSync(path.join(ROOT, 'public', 'llms-full.txt'), sections.join('\n'), 'utf-8');
console.log('Synced public/raw/ and generated public/llms-full.txt cleanly.');
