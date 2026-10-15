// The Python wrapper verifies image, Node, npm lock and Chromium before starting
// this driver, serves only public/ on loopback, and bounds the entire process group.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const root = new URL('../', import.meta.url);
const require = createRequire(import.meta.url);
const { chromium } = require(fileURLToPath(new URL('.tools/npm/playwright-core/node_modules/playwright-core', root)));
const browser = await chromium.launch({
  executablePath: fileURLToPath(new URL('.tools/chromium', root)),
  headless: true,
  timeout: 10000,
});
try {
  for (const [width, height] of [[1440, 1000], [375, 812]]) {
    const context = await browser.newContext({ viewport: { width, height }, reducedMotion: 'reduce' });
    try {
      const page = await context.newPage();
      page.setDefaultTimeout(5000);
      const external = [];
      await page.route('**/*', route => {
        if (route.request().url().startsWith('http://127.0.0.1:8765/')) return route.continue();
        external.push(route.request().url());
        return route.abort();
      });
      await page.goto('http://127.0.0.1:8765/', { waitUntil: 'networkidle', timeout: 10000 });
      await page.locator('.hero a[href="#waitlist"]').click();
      assert(page.url().endsWith('#waitlist'));
      for (const selector of ['#email', '#consent', 'button[type=submit]']) {
        assert(await page.locator(selector).isDisabled());
      }
      await page.locator('#waitlist-form').dispatchEvent('submit');
      assert((await page.locator('#form-status').innerText()).includes('No address was submitted'));
      await page.keyboard.press('Tab');
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      assert.equal(external.length, 0);
      await page.screenshot({ path: fileURLToPath(new URL(`desktop-${width}.png`, root)), fullPage: true });
    } finally {
      await context.close();
    }
  }
} finally {
  await browser.close();
}
