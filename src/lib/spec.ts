import fs from 'node:fs';
import path from 'node:path';
import { Marked } from 'marked';
import { computeLineDiff, renderDiffHtml, type FileDiffResult } from './diff';

export type SpecVersionId = 'v1' | 'v0';

export interface VersionMeta {
  id: SpecVersionId;
  shortLabel: string;
  semver: string;
  label: string;
  status: 'current' | 'archived';
  routePrefix: string;
  filePrefix: string;
  rawPrefix: string;
}

export const VERSIONS: Record<SpecVersionId, VersionMeta> = {
  v1: {
    id: 'v1',
    shortLabel: 'v1',
    semver: 'v3.0.0-rfc',
    label: 'v1 · v3.0.0-rfc (current)',
    status: 'current',
    routePrefix: '/spec/',
    filePrefix: '',
    rawPrefix: 'raw/',
  },
  v0: {
    id: 'v0',
    shortLabel: 'v0',
    semver: 'v2.5.0-rfc',
    label: 'v0 · v2.5.0-rfc (archived)',
    status: 'archived',
    routePrefix: '/spec/v0/',
    filePrefix: 'versions/v0/',
    rawPrefix: 'raw/v0/',
  },
};

export const VERSION_LIST: VersionMeta[] = [VERSIONS.v1, VERSIONS.v0];

export interface TocItem {
  id: string;
  label: string;
  level: 2 | 3;
}

export interface RenderedSpec {
  title: string;
  html: string;
  toc: TocItem[];
  rawText: string;
}

const BASE = '/spec/';

function routeMapFor(version: SpecVersionId): Record<string, string> {
  const prefix = VERSIONS[version].routePrefix;
  return {
    'SPEC.md': `${prefix}`,
    'spec/01-bitcoin-taproot-vault-enforcement.md': `${prefix}part-01/`,
    '01-bitcoin-taproot-vault-enforcement.md': `${prefix}part-01/`,
    'spec/02-btc-authorization-domain-and-spv.md': `${prefix}part-02/`,
    '02-btc-authorization-domain-and-spv.md': `${prefix}part-02/`,
    'spec/03-settlement-minted-zbtc-and-feeless-rails.md': `${prefix}part-03/`,
    '03-settlement-minted-zbtc-and-feeless-rails.md': `${prefix}part-03/`,
    'spec/04-bitcoin-anchoring-and-light-client.md': `${prefix}part-04/`,
    '04-bitcoin-anchoring-and-light-client.md': `${prefix}part-04/`,
    'spec/05-go-zenon-upgrade-plan.md': `${prefix}part-05/`,
    '05-go-zenon-upgrade-plan.md': `${prefix}part-05/`,
    'scripts/verify_spec_bounds.py': `${prefix}oracle/`,
    'CHANGELOG.md': `${BASE}changelog/`,
  };
}

function slugify(text: string): string {
  return text
    .replace(/<[^>]+>/g, '')
    .replace(/`([^`]+)`/g, '$1')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 72);
}

function rewriteHref(href: string, version: SpecVersionId): { href: string; external: boolean } {
  if (!href) return { href: '#', external: false };
  if (href.startsWith('http://') || href.startsWith('https://')) {
    return { href, external: true };
  }
  if (href.startsWith('#')) {
    return { href, external: false };
  }
  const [rawTarget, hashPart] = href.split('#');
  const hash = hashPart ? `#${hashPart}` : '';
  const clean = rawTarget.replace(/^(\.\.\/|\.\/)+/, '');
  const routes = routeMapFor(version);
  if (routes[clean]) {
    return { href: `${routes[clean]}${hash}`, external: false };
  }
  if (clean === 'versions/v0/' || clean === 'versions/v0/SPEC.md') {
    return { href: `${VERSIONS.v0.routePrefix}`, external: false };
  }
  if (clean === 'versions/v0/SHA256SUMS.txt') {
    return { href: `${BASE}raw/v0/SHA256SUMS.txt`, external: false };
  }
  if (clean.startsWith('reviews/HOSTILE_REVIEW_R')) {
    const rawRoot = version === 'v0' ? 'raw/v0/' : 'raw/';
    return { href: `${BASE}${rawRoot}${clean}`, external: false };
  }
  return { href, external: false };
}

export function readVersionedFile(relPath: string, version: SpecVersionId = 'v1'): string {
  const fullPath = path.join(process.cwd(), VERSIONS[version].filePrefix, relPath);
  return fs.readFileSync(fullPath, 'utf-8');
}

export function renderSpecFile(relPath: string, version: SpecVersionId = 'v1'): RenderedSpec {
  const rawText = readVersionedFile(relPath, version);
  let md = rawText;

  // Extract H1 title and strip it from body so the page header renders it cleanly once
  let title = 'zBTC Protocol Specification';
  const h1Match = md.match(/^#\s+(.+)$/m);
  if (h1Match) {
    title = h1Match[1].replace(/`/g, '').trim();
    md = md.replace(/^#\s+.+\r?\n+/, '');
  }

  const toc: TocItem[] = [];
  const usedIds = new Map<string, number>();

  const marked = new Marked({ gfm: true, breaks: false });
  marked.use({
    renderer: {
      heading({ tokens, depth }) {
        const inner = this.parser.parseInline(tokens);
        const plain = inner.replace(/<[^>]+>/g, '').trim();
        let id = slugify(plain) || `section-${toc.length + 1}`;
        const prev = usedIds.get(id) ?? 0;
        usedIds.set(id, prev + 1);
        if (prev > 0) id = `${id}-${prev + 1}`;

        if (depth === 2 || depth === 3) {
          toc.push({ id, label: plain, level: depth });
        }
        return `<h${depth} id="${id}">${inner}</h${depth}>\n`;
      },
      table(token) {
        const headerCells = token.header
          .map((cell, i) => {
            const align = token.align[i] ? ` style="text-align:${token.align[i]}"` : '';
            return `<th${align}>${this.parser.parseInline(cell.tokens)}</th>`;
          })
          .join('');
        const bodyRows = token.rows
          .map((row) => {
            const tds = row
              .map((cell, i) => {
                const align = token.align[i] ? ` style="text-align:${token.align[i]}"` : '';
                return `<td${align}>${this.parser.parseInline(cell.tokens)}</td>`;
              })
              .join('');
            return `<tr>${tds}</tr>`;
          })
          .join('');
        return `<div class="table-wrap"><table><thead><tr>${headerCells}</tr></thead><tbody>${bodyRows}</tbody></table></div>\n`;
      },
      link({ href, title: linkTitle, tokens }) {
        const text = this.parser.parseInline(tokens);
        const mapped = rewriteHref(href ?? '', version);
        const titleAttr = linkTitle ? ` title="${linkTitle.replace(/"/g, '&quot;')}"` : '';
        const extAttrs = mapped.external ? ' target="_blank" rel="noopener noreferrer"' : '';
        return `<a href="${mapped.href}"${titleAttr}${extAttrs}>${text}</a>`;
      },
    },
  });

  const html = marked.parse(md) as string;
  return { title, html, toc, rawText };
}

export interface VersionDiffBundle {
  diff: FileDiffResult;
  html: string;
}

export function buildV1ToV0Diff(relPath: string): VersionDiffBundle {
  const v0Text = readVersionedFile(relPath, 'v0');
  const v1Text = readVersionedFile(relPath, 'v1');
  const diff = computeLineDiff(v0Text, v1Text, 2);
  const html = renderDiffHtml(diff, `v0/${relPath}`, `v1/${relPath}`);
  return { diff, html };
}

export const TRACKED_SPEC_FILES = [
  { key: 'index', label: '00 Overview (SPEC.md)', relPath: 'SPEC.md', slug: '' },
  { key: 'part-01', label: '01 Bitcoin Custody (Part 1)', relPath: 'spec/01-bitcoin-taproot-vault-enforcement.md', slug: 'part-01/' },
  { key: 'part-02', label: '02 Direct-L1 SPV (Part 2)', relPath: 'spec/02-btc-authorization-domain-and-spv.md', slug: 'part-02/' },
  { key: 'part-03', label: '03 Settlement & Rails (Part 3)', relPath: 'spec/03-settlement-minted-zbtc-and-feeless-rails.md', slug: 'part-03/' },
  { key: 'part-04', label: '04 Anchoring & Light Client (Part 4)', relPath: 'spec/04-bitcoin-anchoring-and-light-client.md', slug: 'part-04/' },
  { key: 'part-05', label: '05 go-zenon Upgrades (Part 5)', relPath: 'spec/05-go-zenon-upgrade-plan.md', slug: 'part-05/' },
  { key: 'oracle', label: 'Bounds Checker (verify_spec_bounds.py)', relPath: 'scripts/verify_spec_bounds.py', slug: 'oracle/' },
] as const;

export function getSpecNav(version: SpecVersionId) {
  const prefix = VERSIONS[version].routePrefix;
  const raw = VERSIONS[version].rawPrefix;
  return [
    { key: 'index', label: '00 overview', href: `${prefix}`, raw: `${raw}SPEC.md`, versioned: true },
    { key: 'part-01', label: '01 custody', href: `${prefix}part-01/`, raw: `${raw}spec/01-bitcoin-taproot-vault-enforcement.md`, versioned: true },
    { key: 'part-02', label: '02 spv', href: `${prefix}part-02/`, raw: `${raw}spec/02-btc-authorization-domain-and-spv.md`, versioned: true },
    { key: 'part-03', label: '03 settlement', href: `${prefix}part-03/`, raw: `${raw}spec/03-settlement-minted-zbtc-and-feeless-rails.md`, versioned: true },
    { key: 'part-04', label: '04 anchoring', href: `${prefix}part-04/`, raw: `${raw}spec/04-bitcoin-anchoring-and-light-client.md`, versioned: true },
    { key: 'part-05', label: '05 go-zenon', href: `${prefix}part-05/`, raw: `${raw}spec/05-go-zenon-upgrade-plan.md`, versioned: true },
    { key: 'oracle', label: 'checker', href: `${prefix}oracle/`, raw: `${raw}scripts/verify_spec_bounds.py`, versioned: true },
    { key: 'changelog', label: 'changelog', href: `${BASE}changelog/`, raw: 'raw/CHANGELOG.md', versioned: false },
    { key: 'reviews', label: 'reviews', href: `${BASE}reviews/`, raw: 'raw/reviews/HOSTILE_REVIEW_R7_CONSOLIDATED.md', versioned: false },
    { key: 'review-guide', label: 'review / pr', href: `${BASE}review-guide/`, raw: 'llms.txt', versioned: false },
  ] as const;
}

export function versionSwitchUrl(activeKey: string, targetVersion: SpecVersionId): string {
  const prefix = VERSIONS[targetVersion].routePrefix;
  const map: Record<string, string> = {
    index: `${prefix}`,
    'part-01': `${prefix}part-01/`,
    'part-02': `${prefix}part-02/`,
    'part-03': `${prefix}part-03/`,
    'part-04': `${prefix}part-04/`,
    'part-05': `${prefix}part-05/`,
    oracle: `${prefix}oracle/`,
  };
  return map[activeKey] ?? `${prefix}`;
}
