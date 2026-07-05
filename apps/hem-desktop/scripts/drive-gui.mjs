/**
 * Drive the running dev app over CDP: visit every view, open the palette
 * and the new-secret modal, screenshot each state into /tmp/hem-desk-shots,
 * and dump renderer console errors. Verification harness only — no writes.
 */
import { mkdirSync } from 'node:fs';
import puppeteer from 'puppeteer-core';

const OUT = '/tmp/hem-desk-shots';
mkdirSync(OUT, { recursive: true });

const browser = await puppeteer.connect({
  browserURL: 'http://127.0.0.1:9223',
  defaultViewport: null,
});
const pages = await browser.pages();
const page = pages.find((p) => p.url().includes('localhost'));
if (!page) throw new Error('renderer page not found');

const consoleErrors = [];
page.on('console', (msg) => {
  if (msg.type() === 'error') consoleErrors.push(msg.text());
});
page.on('pageerror', (err) => consoleErrors.push(`pageerror: ${err.message}`));

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const shot = async (name) => {
  await page.screenshot({ path: `${OUT}/${name}.png` });
  console.log(`shot ${name}`);
};

const nav = async (label) => {
  await page.evaluate((l) => {
    const buttons = [...document.querySelectorAll('nav button')];
    const target = buttons.find((b) => b.textContent.includes(l));
    target?.click();
  }, label);
  await sleep(1200);
};

await sleep(2500);
await shot('1-overview');

await nav('Vault');
await sleep(800);
await shot('2-vault');

await nav('Mesh');
await sleep(1500);
await shot('3-mesh');

await nav('Approvals');
await shot('4-approvals');

await nav('Tokens');
await shot('5-tokens');

await nav('Audit');
await shot('6-audit');

// palette via the titlebar Search button
await page.evaluate(() => {
  const buttons = [...document.querySelectorAll('button')];
  buttons.find((b) => b.textContent.includes('Search') && b.textContent.includes('⌘K'))?.click();
});
await sleep(600);
await page.keyboard.type('open');
await sleep(400);
await shot('7-palette');
await page.keyboard.press('Escape');
await sleep(400);

// new secret modal via ⌘N handler (dispatch key event)
await nav('Vault');
await page.keyboard.down('Meta');
await page.keyboard.press('n');
await page.keyboard.up('Meta');
await sleep(600);
await shot('8-new-secret');
await page.keyboard.press('Escape');

// wait for the ~30 s mesh probe to finish, then re-shoot mesh
await nav('Mesh');
await sleep(35_000);
await shot('9-mesh-probed');

console.log('console errors:', JSON.stringify(consoleErrors, null, 2));
await browser.disconnect();
