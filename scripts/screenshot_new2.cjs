const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({
    headless: true,
    executablePath: `${process.env.HOME}/Library/Caches/ms-playwright/chromium-1208/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing`
  });
  const page = await browser.newPage();
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('file:///Users/yonko/Projects/wraith-protocol/docs/index.html', { waitUntil: 'networkidle' });
  await page.waitForTimeout(2000);

  const sections = [
    { y: 2500, name: 'anonymity' },
    { y: 3300, name: 'integrate' },
    { y: 4100, name: 'specs' },
    { y: 4900, name: 'limits' },
    { y: 5700, name: 'roadmap' },
  ];

  for (const { y, name } of sections) {
    await page.evaluate(sy => window.scrollTo(0, sy), y);
    await page.waitForTimeout(500);
    await page.screenshot({ path: `/tmp/new-${name}.png` });
    console.log(`captured ${name}`);
  }

  // Mobile
  await page.setViewportSize({ width: 390, height: 844 });
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.waitForTimeout(500);
  await page.screenshot({ path: '/tmp/new-mob-hero.png' });
  await page.evaluate(() => window.scrollTo(0, 1200));
  await page.waitForTimeout(400);
  await page.screenshot({ path: '/tmp/new-mob-limits.png' });
  console.log('mobile done');

  await browser.close();
  console.log('DONE');
})().catch(e => { console.error(e.message); process.exit(1); });
