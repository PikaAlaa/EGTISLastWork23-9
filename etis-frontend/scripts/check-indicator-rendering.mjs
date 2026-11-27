// Static check for raw indicator rendering (docs/design/core-v2.md §4.4, step 9).
//
// Fails when a page or component passes an indicator field (value, host, domain,
// registered_domain, reported_value) to <InertValue> or renders it directly as JSX text,
// instead of using <IndicatorValue>, which always de-fangs. Run:
//   node scripts/check-indicator-rendering.mjs
import { readFileSync, readdirSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

export const FIELDS = ['value', 'host', 'domain', 'registered_domain', 'reported_value'];
const FIELD = `(?:${FIELDS.join('|')})`;
// <InertValue ... value={...something.field...} ...>
const INERT = new RegExp(`<InertValue\\b[^>]*\\bvalue=\\{[^}]*\\.${FIELD}\\b[^}]*\\}`, 'g');
// >{something.field}  or a line holding only {something.field}: rendered directly as text.
const RAW = new RegExp(`(?:>|^)\\s*\\{\\s*[A-Za-z_$][\\w$]*(?:\\??\\.[A-Za-z_$][\\w$]*)*\\??\\.${FIELD}\\s*\\}`, 'gm');
// Files that define the display components themselves.
const EXEMPT = new Set(['components/InertValue.tsx', 'components/IndicatorValue.tsx']);

export function findViolations(source) {
  const found = [];
  for (const [rule, pattern] of [['inert_value_indicator_field', INERT], ['raw_indicator_field', RAW]]) {
    pattern.lastIndex = 0;
    for (let match = pattern.exec(source); match; match = pattern.exec(source)) {
      const line = source.slice(0, match.index).split('\n').length + (match[0].startsWith('\n') ? 1 : 0);
      found.push({ rule, line, text: match[0].trim() });
    }
  }
  return found;
}

function* sourceFiles(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) yield* sourceFiles(path);
    else if (/\.tsx$/.test(entry.name)) yield path;
  }
}

export function checkTree(srcDir) {
  const problems = [];
  for (const file of sourceFiles(srcDir)) {
    const rel = relative(srcDir, file).split('\\').join('/');
    if (EXEMPT.has(rel)) continue;
    for (const v of findViolations(readFileSync(file, 'utf-8'))) problems.push({ file: rel, ...v });
  }
  return problems;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const src = fileURLToPath(new URL('../src', import.meta.url));
  const problems = checkTree(src);
  for (const p of problems) console.error(`${p.file}:${p.line} ${p.rule}: ${p.text}`);
  console.log(problems.length ? `${problems.length} raw indicator rendering problem(s)` : 'indicator rendering: ok');
  process.exit(problems.length ? 1 : 0);
}
