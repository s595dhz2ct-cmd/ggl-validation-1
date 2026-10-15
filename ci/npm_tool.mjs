// Pinned Node only. Acquisition and offline installation are separate commands.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const root = fileURLToPath(new URL('../', import.meta.url));
const read = relative => JSON.parse(fs.readFileSync(path.join(root, relative)));
const hash = value => createHash('sha256').update(value).digest('hex');
export const pins = read('ci/pins.json');
const names = ['playwright', 'playwright-core', 'lighthouse'];
const dependencies = { '@playwright/test': '1.63.0', 'playwright-core': '1.63.0', lighthouse: '13.5.0' };
const browser = pins.tools.chromium;
export const shell = path.join(root, '.tools/chromium/chrome-headless-shell-linux64/chrome-headless-shell');
const env = {
  PATH: process.env.PATH, LANG: 'C.UTF-8', HOME: path.join(root, '.tools/home'),
  PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: '1', npm_config_update_notifier: 'false',
};
export function command(args) {
  const result = spawnSync(args[0], args.slice(1), {
    cwd: root, env, timeout: 300000, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024,
  });
  assert(!result.error && result.status === 0, `BLOCKED command failed: ${args[0]} ${result.stderr || ''}`);
  return result.stdout;
}
function regular(filename) {
  for (let p = filename; p !== path.dirname(p); p = path.dirname(p)) {
    assert(!fs.lstatSync(p).isSymbolicLink(), 'artifact links refused');
  }
  const s = fs.statSync(filename);
  assert(s.isFile() && s.nlink === 1, 'artifact type refused');
  return fs.readFileSync(filename);
}
export function validate() {
  assert.equal(process.version, 'v22.23.3', 'Node version mismatch');
  assert.equal(pins.tools['ci-image'].digests.node,
    'node@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c');
  const lockPath = 'ci/check-tools/package-lock.json';
  const value = regular(path.join(root, lockPath));
  const lock = JSON.parse(value);
  for (const name of names) {
    const tool = pins.tools[name];
    assert.equal(tool.dependency_lock, lockPath);
    assert.equal(hash(value), tool.dependency_lock_sha256, 'dependency lock SHA-256 mismatch');
    const item = lock.packages[`node_modules/${tool.npm_package}`];
    assert.equal(item.version, tool.version_to_verify);
    assert.equal(item.integrity, tool.integrity);
  }
  assert.equal(lock.lockfileVersion, 3);
  assert.equal(lock.name, 'foundry-landing-check-tools');
  assert.equal(lock.version, '1.0.0');
  assert.deepEqual(lock.packages[''].dependencies, dependencies);
  assert.deepEqual(read('ci/check-tools/package.json'), {
    name: lock.name, version: '1.0.0', private: true, dependencies,
  });
  assert.equal(Object.keys(lock.packages).length, 117);
  for (const [name, item] of Object.entries(lock.packages)) {
    if (!name) continue;
    assert(/^node_modules\/(?:[@A-Za-z0-9_.+-]+\/)*[A-Za-z0-9_.+-]+$/.test(name) && !name.includes('..'));
    assert(!item.link && /^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$/.test(item.version));
    assert(/^https:\/\/registry\.npmjs\.org\/[@A-Za-z0-9_./+-]+\.tgz$/.test(item.resolved));
    assert(typeof item.integrity === 'string' && /^sha512-[A-Za-z0-9+/]{86}==$/.test(item.integrity), 'missing npm integrity');
    assert.equal(Buffer.from(item.integrity.slice(7), 'base64').toString('base64'), item.integrity.slice(7));
  }
  assert.equal(browser.version_to_verify, '153.0.8010.12');
  assert.equal(browser.sha256, 'a9da028861a0cf789ff25c2fed45f5f1aaf969ed9247835b6a7821a4f7af9d1d');
  assert.equal(browser.url, 'https://storage.googleapis.com/chrome-for-testing-public/153.0.8010.12/linux64/chrome-headless-shell-linux64.zip');
  assert.equal(browser.license, 'BSD-3-Clause (Chromium)');
  return Object.entries(lock.packages).filter(([name]) => name).map(([, item]) => item);
}
function verified(value, item, algorithm) {
  const expected = algorithm === 'sha512' ? item.integrity.slice(7) : item.sha256;
  assert.equal(createHash(algorithm).update(value).digest(algorithm === 'sha512' ? 'base64' : 'hex'), expected, 'download integrity mismatch');
}
async function download(items) {
  fs.mkdirSync(path.join(root, '.tools/downloads'), { recursive: false });
  for (const [i, item] of [...items, browser].entries()) {
    const response = await fetch(item.resolved || item.url, { signal: AbortSignal.timeout(120000), redirect: 'error' });
    assert(response.ok, 'artifact download failed');
    const value = Buffer.from(await response.arrayBuffer());
    verified(value, item, i === items.length ? 'sha256' : 'sha512');
    fs.writeFileSync(path.join(root, `.tools/downloads/${i}.artifact`), value, { flag: 'wx' });
  }
}
function install(items) {
  // Recheck every tarball before the first npm command or archive extraction.
  for (const [i, item] of [...items, browser].entries()) {
    verified(regular(path.join(root, `.tools/downloads/${i}.artifact`)), item, i === items.length ? 'sha256' : 'sha512');
  }
  const target = path.join(root, '.tools/npm/check-tools');
  assert(!fs.existsSync(target), 'preserve existing npm tool directory');
  fs.mkdirSync(target, { recursive: true });
  for (const name of ['package.json', 'package-lock.json']) {
    fs.copyFileSync(path.join(root, 'ci/check-tools', name), path.join(target, name), fs.constants.COPYFILE_EXCL);
  }
  const cache = path.join(root, '.tools/npm-cache');
  for (const [i] of items.entries()) {
    // npm recognizes tarballs by extension; preserve the verified input as well.
    const filename = path.join(root, `.tools/downloads/${i}.tgz`);
    fs.copyFileSync(path.join(root, `.tools/downloads/${i}.artifact`), filename, fs.constants.COPYFILE_EXCL);
    command(['npm', 'cache', 'add', '--offline', '--ignore-scripts', '--cache', cache, filename]);
  }
  command(['npm', 'ci', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--cache', cache, '--prefix', target]);
  for (const name of names) {
    const tool = pins.tools[name];
    assert.equal(read(`.tools/npm/check-tools/node_modules/${tool.npm_package}/package.json`).version, tool.version_to_verify);
  }
  const directory = path.join(root, '.tools/chromium');
  fs.mkdirSync(directory);
  command(['unzip', '-q', path.join(root, `.tools/downloads/${items.length}.artifact`), '-d', directory]);
  fs.chmodSync(shell, 0o700);
}
export function installed() {
  const items = validate();
  const installedLock = regular(path.join(root, '.tools/npm/check-tools/package-lock.json'));
  assert.equal(hash(installedLock), pins.tools['playwright-core'].dependency_lock_sha256);
  verified(regular(path.join(root, `.tools/downloads/${items.length}.artifact`)), browser, 'sha256');
  // Bind the extracted executable to the hash-checked archive, not its ZIP hash.
  const archive = path.join(root, `.tools/downloads/${items.length}.artifact`);
  const expected = spawnSync('unzip', ['-p', archive, 'chrome-headless-shell-linux64/chrome-headless-shell'], {
    env, timeout: 15000, maxBuffer: 400 * 1024 * 1024,
  });
  assert.equal(expected.status, 0, 'browser archive member missing');
  assert.equal(hash(regular(shell)), hash(expected.stdout), 'extracted browser mismatch');
  const libraries = command(['ldd', shell]);
  assert(!libraries.includes('not found'), `BLOCKED missing browser runtime libraries: ${libraries}`);
  assert(command([shell, '--version']).includes(browser.version_to_verify), 'browser version mismatch');
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const items = validate();
    const kind = process.argv[2];
    assert(process.argv.length === 3 && ['validate', 'download', 'install'].includes(kind), 'tool arguments refused');
    if (kind !== 'validate') fs.mkdirSync(path.join(root, '.tools'), { recursive: true });
    if (kind === 'download') await download(items);
    if (kind === 'install') install(items);
    process.stdout.write(`PASS pinned Node ${kind}\n`);
  } catch (error) {
    process.stderr.write(`BLOCKED pinned Node tool: ${error.message}\n`);
    process.exitCode = 2;
  }
}
