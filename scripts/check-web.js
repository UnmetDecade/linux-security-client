#!/usr/bin/env node
/* Static checks for the web UI, the i18n tables, and the docs landing pages.
 *
 * There is no JavaScript test framework in this project. These checks cover the
 * failure modes that matter for a dependency-free UI:
 *   - syntax errors in the shipped scripts;
 *   - missing/extra keys between the English and Chinese translation tables;
 *   - data-i18n and t('...') references that do not exist;
 *   - docs pages with nested anchors (breaks card layout) or broken relative
 *     links.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const WEB = path.join(ROOT, 'src', 'lsec', 'web');
const DOCS = path.join(ROOT, 'docs');
const failures = [];

function fail(message) {
  failures.push(message);
}

function rel(file) {
  return path.relative(ROOT, file);
}

/* --------------------------------------------------------------- syntax */
for (const file of ['app.js', 'i18n.js']) {
  const full = path.join(WEB, file);
  try {
    execFileSync(process.execPath, ['--check', full], { stdio: 'pipe' });
  } catch (err) {
    fail(`${rel(full)}: syntax error\n${err.stderr ? err.stderr.toString() : err.message}`);
  }
}

/* --------------------------------------------------------- translations */
const sandbox = {
  document: {
    readyState: 'loading',
    documentElement: {},
    querySelectorAll: () => [],
    addEventListener: () => {},
  },
  localStorage: { getItem: () => null, setItem: () => {} },
  location: { reload: () => {} },
};
vm.createContext(sandbox);
const i18nSource = fs.readFileSync(path.join(WEB, 'i18n.js'), 'utf8')
  + '\n;globalThis.__I18N_EXPORT__ = { MESSAGES, SERVER_TEXT, SERVER_LABELS };';
try {
  vm.runInContext(i18nSource, sandbox, { filename: 'i18n.js' });
} catch (err) {
  fail(`i18n.js: cannot evaluate translation tables: ${err.message}`);
}

const exported = sandbox.__I18N_EXPORT__;
if (exported) {
  const en = Object.keys(exported.MESSAGES.en).sort();
  const zh = Object.keys(exported.MESSAGES.zh).sort();
  for (const key of en) {
    if (!Object.prototype.hasOwnProperty.call(exported.MESSAGES.zh, key)) {
      fail(`i18n: zh is missing key "${key}"`);
    }
  }
  for (const key of zh) {
    if (!Object.prototype.hasOwnProperty.call(exported.MESSAGES.en, key)) {
      fail(`i18n: en is missing key "${key}"`);
    }
  }

  const known = new Set(en);
  const checkKeys = (source, file) => {
    const patterns = [
      /data-i18n="([^"]+)"/g,
      /data-i18n-attr="[^"]*?:([^";]+)/g,
      /\bt\('([A-Za-z0-9_.-]+)'/g,
    ];
    for (const pattern of patterns) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(source)) !== null) {
        if (!known.has(match[1])) {
          fail(`${file}: unknown i18n key "${match[1]}"`);
        }
      }
    }
  };
  checkKeys(fs.readFileSync(path.join(WEB, 'index.html'), 'utf8'), 'index.html');
  checkKeys(fs.readFileSync(path.join(WEB, 'app.js'), 'utf8'), 'app.js');
  console.log(`i18n: ${en.length} en keys / ${zh.length} zh keys checked`);
}

/* --------------------------------------------------------------- docs */
const docsPages = fs.readdirSync(DOCS).filter((name) => name.endsWith('.html'));
const tagPattern = /<\/?a\b[^>]*>/gi;

for (const page of docsPages) {
  const full = path.join(DOCS, page);
  const source = fs.readFileSync(full, 'utf8');

  let depth = 0;
  let match;
  tagPattern.lastIndex = 0;
  while ((match = tagPattern.exec(source)) !== null) {
    if (match[0][1] === '/') {
      depth = Math.max(0, depth - 1);
    } else if (!match[0].endsWith('/>')) {
      depth += 1;
      if (depth > 1) {
        fail(`docs/${page}: nested <a> elements break the card layout`);
        depth = 1;
      }
    }
  }

  const refPattern = /(?:href|src)="([^"]+)"/g;
  while ((match = refPattern.exec(source)) !== null) {
    const target = match[1];
    if (/^(?:[a-z]+:|#|\/\/)/i.test(target)) continue;
    const clean = decodeURIComponent(target.split('#')[0].split('?')[0]);
    if (!clean) continue;
    const resolved = path.resolve(DOCS, clean);
    if (!fs.existsSync(resolved)) {
      fail(`docs/${page}: relative link not found: ${target}`);
    }
  }
}

if (docsPages.length === 0) fail('docs: no landing page found');

/* ------------------------------------------------------------- report */
if (failures.length > 0) {
  console.error(`web checks failed (${failures.length}):`);
  for (const failure of failures) console.error(`  - ${failure}`);
  process.exit(1);
}
console.log('web checks passed');
