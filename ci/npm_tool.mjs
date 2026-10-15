// Pinned Node only. Acquisition and offline installation are separate commands.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { inflateRawSync } from 'node:zlib';

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
export function validateRuntime(version = process.versions.node,
  workflow = fs.readFileSync(path.join(root, '.github/workflows/ci.yml'), 'utf8')) {
  assert.equal(version.split('.')[0], '24', 'Node major mismatch');
  const image = 'mcr.microsoft.com/playwright@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27';
  assert.equal(pins.tools['ci-image'].digests.browser, image, 'browser image pin mismatch');
  const jobs = workflow.split(/^  (?=[a-z-]+:\n)/m);
  for (const name of ['playwright', 'lighthouse']) {
    const job = jobs.filter(block => block.startsWith(`${name}:\n`));
    assert.equal(job.length, 1, 'browser job coverage mismatch');
    assert.deepEqual(job[0].match(/^      image: .+$/gm), [`      image: ${image}`],
      'browser job image mismatch');
  }
}
export function validate() {
  validateRuntime();
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
// ZIP32 only. Bound metadata before inflating, then bound actual output as well.
const ZIP_LIMIT = 512 * 1024 * 1024;
function zipExtra(value) {
  for (let offset = 0; offset < value.length;) {
    assert(offset + 4 <= value.length, 'ZIP extra field truncated');
    const kind = value.readUInt16LE(offset);
    const length = value.readUInt16LE(offset + 2);
    assert(kind !== 1, 'ZIP64 refused');
    offset += 4 + length;
    assert(offset <= value.length, 'ZIP extra field truncated');
  }
}
export function zipEntries(value) {
  assert(Buffer.isBuffer(value) && value.length >= 22 && value.length <= ZIP_LIMIT, 'ZIP size refused');
  let end = value.length - 22;
  const first = Math.max(0, end - 65535);
  while (end >= first && (value.readUInt32LE(end) !== 0x06054b50 ||
    end + 22 + value.readUInt16LE(end + 20) !== value.length)) end--;
  assert(end >= first, 'ZIP end record missing');
  const count = value.readUInt16LE(end + 10);
  const start = value.readUInt32LE(end + 16);
  assert(value.readUInt16LE(end + 4) === 0 && value.readUInt16LE(end + 6) === 0 &&
    value.readUInt16LE(end + 8) === count, 'ZIP multidisk refused');
  assert(count !== 0xffff && start !== 0xffffffff &&
    value.readUInt32LE(end + 12) !== 0xffffffff, 'ZIP64 refused');
  assert(count > 0 && count <= 4096 && start + value.readUInt32LE(end + 12) === end, 'ZIP directory refused');
  const entries = [];
  const names = new Set();
  let offset = start, total = 0;
  for (let i = 0; i < count; i++) {
    assert(offset + 46 <= end && value.readUInt32LE(offset) === 0x02014b50, 'ZIP directory truncated');
    const flags = value.readUInt16LE(offset + 8);
    const method = value.readUInt16LE(offset + 10);
    const packed = value.readUInt32LE(offset + 20);
    const size = value.readUInt32LE(offset + 24);
    const length = value.readUInt16LE(offset + 28);
    const extra = value.readUInt16LE(offset + 30);
    const comment = value.readUInt16LE(offset + 32);
    const attributes = value.readUInt32LE(offset + 38);
    const local = value.readUInt32LE(offset + 42);
    assert(packed !== 0xffffffff && size !== 0xffffffff && local !== 0xffffffff &&
      value.readUInt16LE(offset + 6) < 45, 'ZIP64 refused');
    assert(!(flags & ~0x080e), 'ZIP encryption or flags refused');
    assert(method === 0 || method === 8, 'ZIP compression refused');
    assert(value.readUInt16LE(offset + 34) === 0, 'ZIP multidisk refused');
    assert(length > 0 && length <= 4096 && offset + 46 + length + extra + comment <= end, 'ZIP name truncated');
    const rawName = value.subarray(offset + 46, offset + 46 + length);
    const name = rawName.toString('utf8');
    assert(Buffer.from(name).equals(rawName) && !/[\\\x00-\x1f\x7f:]/.test(name), 'ZIP path refused');
    const directory = name.endsWith('/');
    const relative = directory ? name.slice(0, -1) : name;
    assert(relative.split('/').every(part => part && part !== '.' && part !== '..'), 'ZIP path refused');
    assert(!names.has(relative), 'ZIP duplicate path refused');
    names.add(relative);
    const type = (attributes >>> 16) & 0xf000;
    assert(type === 0 || type === (directory ? 0x4000 : 0x8000), 'ZIP symlink or special entry refused');
    assert(directory || !(attributes & 0x10), 'ZIP directory attributes refused');
    zipExtra(value.subarray(offset + 46 + length, offset + 46 + length + extra));
    total += size;
    assert(total <= ZIP_LIMIT && (!directory || size === 0), 'ZIP expanded size refused');
    assert(local + 30 <= start && value.readUInt32LE(local) === 0x04034b50, 'ZIP local header refused');
    const localLength = value.readUInt16LE(local + 26);
    const localExtra = value.readUInt16LE(local + 28);
    const data = local + 30 + localLength + localExtra;
    assert(value.readUInt32LE(local + 18) !== 0xffffffff &&
      value.readUInt32LE(local + 22) !== 0xffffffff, 'ZIP64 refused');
    assert(data + packed <= start && value.readUInt16LE(local + 4) < 45, 'ZIP local size or ZIP64 refused');
    assert(value.readUInt16LE(local + 6) === flags && value.readUInt16LE(local + 8) === method &&
      rawName.equals(value.subarray(local + 30, local + 30 + localLength)), 'ZIP local metadata differs');
    zipExtra(value.subarray(local + 30 + localLength, data));
    if (!(flags & 8)) {
      assert(value.readUInt32LE(local + 14) === value.readUInt32LE(offset + 16) &&
        value.readUInt32LE(local + 18) === packed && value.readUInt32LE(local + 22) === size, 'ZIP local sizes differ');
    }
    assert(method !== 0 || packed === size, 'ZIP stored size differs');
    entries.push({ name: relative, directory, size, method, mode: 0o600 | ((attributes >>> 16) & 0o111),
      local, end: data + packed, compressed: value.subarray(data, data + packed) });
    offset += 46 + length + extra + comment;
  }
  assert(offset === end, 'ZIP directory size differs');
  let previous = 0;
  for (const entry of [...entries].sort((a, b) => a.local - b.local)) {
    assert(entry.local >= previous, 'ZIP overlapping entries refused');
    previous = entry.end;
    for (let parent = path.posix.dirname(entry.name); parent !== '.'; parent = path.posix.dirname(parent)) {
      assert(!entries.some(other => other.name === parent && !other.directory), 'ZIP file parent refused');
    }
  }
  return entries;
}
function zipContent(entry) {
  const value = entry.method === 0 ? entry.compressed :
    inflateRawSync(entry.compressed, { maxOutputLength: Math.max(1, entry.size) });
  assert.equal(value.length, entry.size, 'ZIP expanded size differs');
  return value;
}
export function extractZip(value, directory) {
  const entries = zipEntries(value);
  // A fresh destination and exclusive files prevent pre-existing links/overwrites.
  for (let p = path.resolve(directory, '..');; p = path.dirname(p)) {
    assert(fs.lstatSync(p).isDirectory() && !fs.lstatSync(p).isSymbolicLink(), 'ZIP destination links refused');
    if (p === path.dirname(p)) break;
  }
  fs.mkdirSync(directory, { mode: 0o700 });
  for (const entry of entries) {
    const target = path.join(directory, entry.name);
    fs.mkdirSync(entry.directory ? target : path.dirname(target), { recursive: true, mode: 0o700 });
    if (!entry.directory) {
      fs.writeFileSync(target, zipContent(entry), { flag: 'wx', mode: entry.mode });
      fs.chmodSync(target, entry.mode);
    }
  }
}
export function extractChromium(value, directory) {
  verified(value, browser, 'sha256');
  extractZip(value, directory);
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
  extractChromium(regular(path.join(root, `.tools/downloads/${items.length}.artifact`)), directory);
}
export function installed() {
  const items = validate();
  const installedLock = regular(path.join(root, '.tools/npm/check-tools/package-lock.json'));
  assert.equal(hash(installedLock), pins.tools['playwright-core'].dependency_lock_sha256);
  const archive = regular(path.join(root, `.tools/downloads/${items.length}.artifact`));
  verified(archive, browser, 'sha256');
  // Bind the extracted executable to the hash-checked archive, not its ZIP hash.
  const expected = zipEntries(archive).find(entry => entry.name === 'chrome-headless-shell-linux64/chrome-headless-shell');
  assert(expected && !expected.directory, 'browser archive member missing');
  assert.equal(hash(regular(shell)), hash(zipContent(expected)), 'extracted browser mismatch');
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
