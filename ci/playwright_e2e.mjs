// The pinned Playwright image supplies libraries; both checks use the verified CfT ZIP.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import { createRequire } from 'node:module';
import path from 'node:path';
import { installed, pins, root, shell } from './npm_tool.mjs';

const kind = process.argv[2];
assert(process.argv.length === 3 && ['playwright', 'lighthouse'].includes(kind), 'browser arguments refused');
installed();
const watchdog = setTimeout(() => { process.stderr.write('BLOCKED browser deadline\n'); process.exit(2); }, 150000);
const allowed = new Set(['index.html', 'styles.css', 'waitlist.js', 'mark.svg', 'privacy.html', 'rights.html']);
const types = { html: 'text/html', css: 'text/css', js: 'text/javascript', svg: 'image/svg+xml' };
const server = http.createServer((request, response) => {
  const name = request.url === '/' ? 'index.html' : request.url?.slice(1);
  if (request.method !== 'GET' || !allowed.has(name)) { response.writeHead(404); response.end(); return; }
  response.setHeader('Content-Type', types[name.split('.').pop()]);
  response.end(fs.readFileSync(path.join(root, 'public', name)));
});
const flags = [
  '--headless', '--no-sandbox', '--disable-dev-shm-usage', '--disable-background-networking',
  '--disable-component-update', '--disable-domain-reliability', '--disable-sync',
  '--metrics-recording-only', '--no-first-run',
  '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1',
];
const require = createRequire(import.meta.url);
try {
  await new Promise((resolve, reject) => {
    server.once('error', reject); server.listen(8765, '127.0.0.1', resolve);
  });
  if (kind === 'playwright') {
    const { chromium } = require(path.join(root, '.tools/npm/check-tools/node_modules/playwright-core'));
    const browser = await chromium.launch({ executablePath: shell, args: flags, headless: true, timeout: 15000 });
    try {
      for (const [width, height] of [[1440, 1000], [375, 812]]) {
        const context = await browser.newContext({ viewport: { width, height }, reducedMotion: 'reduce' });
        try {
          const page = await context.newPage();
          page.setDefaultTimeout(5000);
          const external = [];
          await page.route('**/*', route => {
            if (route.request().url().startsWith('http://127.0.0.1:8765/')) return route.continue();
            external.push(route.request().url()); return route.abort();
          });
          await page.goto('http://127.0.0.1:8765/', { waitUntil: 'networkidle', timeout: 10000 });
          await page.locator('.hero a[href="#waitlist"]').click();
          assert(page.url().endsWith('#waitlist'));
          for (const selector of ['#email', '#consent', 'button[type=submit]']) assert(await page.locator(selector).isDisabled());
          await page.locator('#waitlist-form').dispatchEvent('submit');
          assert((await page.locator('#form-status').innerText()).includes('No address was submitted'));
          await page.keyboard.press('Tab');
          assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
          assert.equal(external.length, 0);
          await page.screenshot({ path: path.join(root, `desktop-${width}.png`), fullPage: true });
        } finally { await context.close(); }
      }
    } finally { await browser.close(); }
  } else {
    fs.mkdirSync(path.join(root, '.tools/home'), { recursive: true, mode: 0o700 });
    for (const preset of ['mobile', 'desktop']) {
      const report = path.join(root, `lighthouse-${preset}.json`);
      const args = [
        path.join(root, '.tools/npm/check-tools/node_modules/lighthouse/cli/index.js'),
        'http://127.0.0.1:8765/', '--output=json', `--output-path=${report}`,
        `--chrome-flags=${flags.map(flag => `"${flag}"`).join(' ')}`, '--quiet',
      ];
      if (preset === 'desktop') args.push('--preset=desktop');
      const child = spawn(process.execPath, args, {
        cwd: root, env: { PATH: process.env.PATH, LANG: 'C.UTF-8', HOME: path.join(root, '.tools/home'), CHROME_PATH: shell },
        stdio: ['ignore', 'ignore', 'pipe'], timeout: 60000, killSignal: 'SIGKILL',
      });
      let stderr = '';
      child.stderr.on('data', chunk => { stderr = (stderr + chunk).slice(-8192); });
      await new Promise((resolve, reject) => {
        child.once('error', reject);
        child.once('exit', code => {
          if (code === 0) return resolve();
          process.stderr.write(stderr + '\n');
          reject(new Error('Lighthouse execution failed'));
        });
      });
      const result = JSON.parse(fs.readFileSync(report));
      assert(!result.runtimeError && !result.runWarnings?.length, 'Lighthouse coverage incomplete');
      for (const [category, floor] of Object.entries(pins.lighthouse_floors)) {
        const score = result.categories?.[category]?.score;
        assert(typeof score === 'number' && score >= floor / 100 && score <= 1, `Lighthouse ${category} floor/coverage failed`);
      }
    }
  }
  process.stdout.write(`PASS ${kind}: desktop and mobile\n`);
} finally {
  server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); clearTimeout(watchdog);
}
