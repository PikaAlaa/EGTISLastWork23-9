// The static raw-indicator check (docs/design/core-v2.md §4.4, step 9). Snippets are invented.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { checkTree, findViolations } from '../scripts/check-indicator-rendering.mjs';

test('flags indicator fields passed to InertValue', () => {
  for (const snippet of ['<InertValue value={i.value} />', '<InertValue value={indicator.registered_domain} />',
    '<InertValue muted value={r.reported_value} />', '<InertValue value={link.host} />']) {
    assert.equal(findViolations(snippet)[0]?.rule, 'inert_value_indicator_field', snippet);
  }
});

test('flags indicator fields rendered directly as text', () => {
  for (const snippet of ['<TableCell>{entry.domain}</TableCell>', '<span>{ link.host }</span>',
    '<p>\n  {detail.indicator?.value}\n</p>', '<b>{r.reported_value}</b>']) {
    assert.equal(findViolations(snippet)[0]?.rule, 'raw_indicator_field', snippet);
  }
});

test('allows IndicatorValue, attributes and non-indicator text', () => {
  for (const snippet of ['<IndicatorValue type="domain" value={entry.domain} />', 'value={filters.domain}',
    '<InertValue value={detail.engine_version} />', '<InertValue value={detail.technique.url} />',
    "<TableCell>{t(`soc.domain.${d}`)}</TableCell>", '<InertValue value={shortHash(i.value_hash)} muted />']) {
    assert.deepEqual(findViolations(snippet), [], snippet);
  }
});

test('the console source has no raw indicator rendering', () => {
  assert.deepEqual(checkTree(fileURLToPath(new URL('../src', import.meta.url))), []);
});
