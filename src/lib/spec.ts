import fs from 'node:fs';
import path from 'node:path';
import { Marked } from 'marked';

export interface TocItem {
  id: string;
  label: string;
  level: 2 | 3;
}

export interface RenderedSpec {
  title: string;
  html: string;
  toc: TocItem[];
}

const BASE = '/spec/';

const ROUTE_MAP: Record<string, string> = {
  'SPEC.md': `${BASE}`,
  'spec/01-bitcoin-taproot-vault-enforcement.md': `${BASE}part-01/`,
  '01-bitcoin-taproot-vault-enforcement.md': `${BASE}part-01/`,
  'spec/02-btc-authorization-domain-and-spv.md': `${BASE}part-02/`,
  '02-btc-authorization-domain-and-spv.md': `${BASE}part-02/`,
  'spec/03-settlement-minted-zbtc-and-feeless-rails.md': `${BASE}part-03/`,
  '03-settlement-minted-zbtc-and-feeless-rails.md': `${BASE}part-03/`,
  'spec/04-bitcoin-anchoring-and-light-client.md': `${BASE}part-04/`,
  '04-bitcoin-anchoring-and-light-client.md': `${BASE}part-04/`,
  'spec/05-go-zenon-upgrade-plan.md': `${BASE}part-05/`,
  '05-go-zenon-upgrade-plan.md': `${BASE}part-05/`,
  'scripts/verify_spec_bounds.py': `${BASE}oracle/`,
};

function slugify(text: string): string {
  return text
    .replace(/<[^>]+>/g, '')
    .replace(/`([^`]+)`/g, '$1')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 72);
}

function rewriteHref(href: string): { href: string; external: boolean } {
  if (!href) return { href: '#', external: false };
  if (href.startsWith('http://') || href.startsWith('https://')) {
    return { href, external: true };
  }
  const [rawTarget] = href.split('#');
  const clean = rawTarget.replace(/^(\.\.\/|\.\/)+/, '');
  if (ROUTE_MAP[clean]) {
    return { href: ROUTE_MAP[clean], external: false };
  }
  if (clean.startsWith('reviews/HOSTILE_REVIEW_R')) {
    return { href: `${BASE}raw/${clean}`, external: false };
  }
  return { href, external: false };
}

export function renderSpecFile(relPath: string): RenderedSpec {
  const fullPath = path.join(process.cwd(), relPath);
  let md = fs.readFileSync(fullPath, 'utf-8');

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
        const mapped = rewriteHref(href ?? '');
        const titleAttr = linkTitle ? ` title="${linkTitle.replace(/"/g, '&quot;')}"` : '';
        const extAttrs = mapped.external ? ' target="_blank" rel="noopener noreferrer"' : '';
        return `<a href="${mapped.href}"${titleAttr}${extAttrs}>${text}</a>`;
      },
    },
  });

  const html = marked.parse(md) as string;
  return { title, html, toc };
}

export const SPEC_NAV = [
  { key: 'index', label: '00 overview', href: `${BASE}`, raw: 'raw/SPEC.md' },
  { key: 'part-01', label: '01 vaults', href: `${BASE}part-01/`, raw: 'raw/spec/01-bitcoin-taproot-vault-enforcement.md' },
  { key: 'part-02', label: '02 spv', href: `${BASE}part-02/`, raw: 'raw/spec/02-btc-authorization-domain-and-spv.md' },
  { key: 'part-03', label: '03 settlement', href: `${BASE}part-03/`, raw: 'raw/spec/03-settlement-minted-zbtc-and-feeless-rails.md' },
  { key: 'part-04', label: '04 anchoring', href: `${BASE}part-04/`, raw: 'raw/spec/04-bitcoin-anchoring-and-light-client.md' },
  { key: 'part-05', label: '05 go-zenon', href: `${BASE}part-05/`, raw: 'raw/spec/05-go-zenon-upgrade-plan.md' },
  { key: 'oracle', label: 'oracle', href: `${BASE}oracle/`, raw: 'raw/scripts/verify_spec_bounds.py' },
  { key: 'reviews', label: 'reviews', href: `${BASE}reviews/`, raw: 'raw/reviews/HOSTILE_REVIEW_R6.md' },
  { key: 'review-guide', label: 'review / pr', href: `${BASE}review-guide/`, raw: 'llms.txt' },
] as const;
