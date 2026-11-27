export interface DiffLine {
  type: 'context' | 'add' | 'del';
  oldNum: number | null;
  newNum: number | null;
  html: string;
}

export interface DiffHunk {
  header: string;
  lines: DiffLine[];
}

export interface FileDiffResult {
  addedLines: number;
  removedLines: number;
  hunks: DiffHunk[];
  identical: boolean;
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function tokenizeWords(line: string): string[] {
  return line.match(/(\s+|[^\s\w]+|\w+)/g) ?? [];
}

/**
 * Simple O(N*M) LCS diff on small arrays (lines or words) with a graceful
 * fallback when either side is very long.
 */
function lcsOps<T>(a: T[], b: T[], maxCells = 180_000): Array<{ op: 'eq' | 'del' | 'add'; val: T }> {
  const n = a.length;
  const m = b.length;

  // Trim common prefix & suffix first to keep DP tiny
  let start = 0;
  while (start < n && start < m && a[start] === b[start]) start++;
  let endA = n;
  let endB = m;
  while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) {
    endA--;
    endB--;
  }

  const midA = a.slice(start, endA);
  const midB = b.slice(start, endB);
  const ops: Array<{ op: 'eq' | 'del' | 'add'; val: T }> = [];

  for (let i = 0; i < start; i++) ops.push({ op: 'eq', val: a[i] });

  if (midA.length === 0) {
    for (const v of midB) ops.push({ op: 'add', val: v });
  } else if (midB.length === 0) {
    for (const v of midA) ops.push({ op: 'del', val: v });
  } else if (midA.length * midB.length > maxCells) {
    // Fallback for huge differing blocks: mark deletions then additions cleanly
    for (const v of midA) ops.push({ op: 'del', val: v });
    for (const v of midB) ops.push({ op: 'add', val: v });
  } else {
    const rows = midA.length + 1;
    const cols = midB.length + 1;
    const dp = new Uint32Array(rows * cols);
    for (let i = midA.length - 1; i >= 0; i--) {
      for (let j = midB.length - 1; j >= 0; j--) {
        if (midA[i] === midB[j]) {
          dp[i * cols + j] = dp[(i + 1) * cols + (j + 1)] + 1;
        } else {
          const down = dp[(i + 1) * cols + j];
          const right = dp[i * cols + (j + 1)];
          dp[i * cols + j] = down >= right ? down : right;
        }
      }
    }
    let i = 0;
    let j = 0;
    while (i < midA.length && j < midB.length) {
      if (midA[i] === midB[j]) {
        ops.push({ op: 'eq', val: midA[i] });
        i++;
        j++;
      } else if (dp[(i + 1) * cols + j] >= dp[i * cols + (j + 1)]) {
        ops.push({ op: 'del', val: midA[i] });
        i++;
      } else {
        ops.push({ op: 'add', val: midB[j] });
        j++;
      }
    }
    while (i < midA.length) ops.push({ op: 'del', val: midA[i++] });
    while (j < midB.length) ops.push({ op: 'add', val: midB[j++] });
  }

  for (let i = endA; i < n; i++) ops.push({ op: 'eq', val: a[i] });
  return ops;
}

function renderWordPair(oldLine: string, newLine: string): { oldHtml: string; newHtml: string } {
  const wA = tokenizeWords(oldLine);
  const wB = tokenizeWords(newLine);
  // Only run intra-line word diff if lines share meaningful similarity
  const ops = lcsOps(wA, wB, 40_000);
  const eqCount = ops.filter((o) => o.op === 'eq' && o.val.trim().length > 0).length;
  const totalWords = Math.max(1, wA.filter((w) => w.trim()).length + wB.filter((w) => w.trim()).length);
  if ((eqCount * 2) / totalWords < 0.22) {
    return { oldHtml: escapeHtml(oldLine), newHtml: escapeHtml(newLine) };
  }

  let oldHtml = '';
  let newHtml = '';
  for (const item of ops) {
    const esc = escapeHtml(item.val);
    if (item.op === 'eq') {
      oldHtml += esc;
      newHtml += esc;
    } else if (item.op === 'del') {
      oldHtml += `<mark class="dw-del">${esc}</mark>`;
    } else {
      newHtml += `<mark class="dw-add">${esc}</mark>`;
    }
  }
  return { oldHtml, newHtml };
}

export function computeLineDiff(oldText: string, newText: string, contextLines = 3): FileDiffResult {
  const oldLines = oldText.replace(/\r\n/g, '\n').split('\n');
  const newLines = newText.replace(/\r\n/g, '\n').split('\n');
  const rawOps = lcsOps(oldLines, newLines, 400_000);

  let oldNum = 1;
  let newNum = 1;
  let addedLines = 0;
  let removedLines = 0;

  interface IndexedOp {
    type: 'context' | 'del' | 'add';
    oldNum: number | null;
    newNum: number | null;
    text: string;
    html?: string;
  }

  const flat: IndexedOp[] = [];
  for (const item of rawOps) {
    if (item.op === 'eq') {
      flat.push({ type: 'context', oldNum: oldNum++, newNum: newNum++, text: item.val });
    } else if (item.op === 'del') {
      removedLines++;
      flat.push({ type: 'del', oldNum: oldNum++, newNum: null, text: item.val });
    } else {
      addedLines++;
      flat.push({ type: 'add', oldNum: null, newNum: newNum++, text: item.val });
    }
  }

  if (addedLines === 0 && removedLines === 0) {
    return { addedLines: 0, removedLines: 0, hunks: [], identical: true };
  }

  // Pair adjacent del/add runs for intra-line word-level highlighting
  let idx = 0;
  while (idx < flat.length) {
    if (flat[idx].type === 'del') {
      const delStart = idx;
      while (idx < flat.length && flat[idx].type === 'del') idx++;
      const addStart = idx;
      while (idx < flat.length && flat[idx].type === 'add') idx++;
      const delCount = addStart - delStart;
      const addCount = idx - addStart;
      const pairs = Math.min(delCount, addCount);
      for (let p = 0; p < pairs; p++) {
        const { oldHtml, newHtml } = renderWordPair(flat[delStart + p].text, flat[addStart + p].text);
        flat[delStart + p].html = oldHtml;
        flat[addStart + p].html = newHtml;
      }
    } else {
      idx++;
    }
  }

  // Group into hunks with `contextLines` surrounding changed lines
  const changedIndices: number[] = [];
  for (let i = 0; i < flat.length; i++) {
    if (flat[i].type !== 'context') changedIndices.push(i);
  }

  const ranges: Array<[number, number]> = [];
  for (const ci of changedIndices) {
    const lo = Math.max(0, ci - contextLines);
    const hi = Math.min(flat.length - 1, ci + contextLines);
    if (ranges.length && lo <= ranges[ranges.length - 1][1] + 1) {
      ranges[ranges.length - 1][1] = Math.max(ranges[ranges.length - 1][1], hi);
    } else {
      ranges.push([lo, hi]);
    }
  }

  const hunks: DiffHunk[] = ranges.map(([lo, hi]) => {
    const slice = flat.slice(lo, hi + 1);
    const firstOld = slice.find((l) => l.oldNum !== null)?.oldNum ?? 0;
    const firstNew = slice.find((l) => l.newNum !== null)?.newNum ?? 0;
    const oldCount = slice.filter((l) => l.oldNum !== null).length;
    const newCount = slice.filter((l) => l.newNum !== null).length;
    return {
      header: `@@ -${firstOld},${oldCount} +${firstNew},${newCount} @@`,
      lines: slice.map((l) => ({
        type: l.type,
        oldNum: l.oldNum,
        newNum: l.newNum,
        html: l.html ?? escapeHtml(l.text),
      })),
    };
  });

  return { addedLines, removedLines, hunks, identical: false };
}

export function renderDiffHtml(diff: FileDiffResult, fromLabel = 'v0 (v2.5.0-rfc)', toLabel = 'v1 (v3.0.0-rfc)'): string {
  if (diff.identical) {
    return `<div class="diff-empty">No textual changes between ${escapeHtml(fromLabel)} and ${escapeHtml(toLabel)}.</div>`;
  }

  const hunkHtml = diff.hunks
    .map((h) => {
      const rows = h.lines
        .map((l) => {
          const sign = l.type === 'add' ? '+' : l.type === 'del' ? '-' : ' ';
          const oNum = l.oldNum !== null ? String(l.oldNum) : '';
          const nNum = l.newNum !== null ? String(l.newNum) : '';
          return `<tr class="dl-${l.type}"><td class="dn">${oNum}</td><td class="dn">${nNum}</td><td class="ds">${sign}</td><td class="dc">${l.html || '&nbsp;'}</td></tr>`;
        })
        .join('');
      return `<tr class="dl-hunk"><td colspan="4">${escapeHtml(h.header)}</td></tr>${rows}`;
    })
    .join('');

  return `<div class="diff-box">
  <div class="diff-meta">
    <span>diff <code>${escapeHtml(fromLabel)}</code> &rarr; <code>${escapeHtml(toLabel)}</code></span>
    <span class="diff-counts"><span class="dc-add">+${diff.addedLines}</span> / <span class="dc-del">-${diff.removedLines}</span> lines</span>
  </div>
  <div class="diff-scroll">
    <table class="diff-table"><tbody>${hunkHtml}</tbody></table>
  </div>
</div>`;
}
