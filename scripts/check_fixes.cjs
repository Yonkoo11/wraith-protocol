const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({
    headless: false,
    executablePath: `${process.env.HOME}/Library/Caches/ms-playwright/chromium-1208/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing`
  });

  const page = await browser.newPage();
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('file:///Users/yonko/Projects/wraith-protocol/docs/index.html', { waitUntil: 'networkidle' });
  await page.waitForTimeout(1500);

  // Scroll to limits cards
  const limitsTop = await page.evaluate(() => {
    const el = document.getElementById('limits');
    return el ? el.getBoundingClientRect().top + window.scrollY + 300 : 5500;
  });
  await page.evaluate((y) => window.scrollTo(0, y), limitsTop);
  await page.waitForTimeout(900);
  await page.screenshot({ path: '/tmp/limits-cards.png' });
  console.log('limits cards captured');

  // Mobile hero
  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto('file:///Users/yonko/Projects/wraith-protocol/docs/index.html', { waitUntil: 'networkidle' });
  await page.waitForTimeout(1500);
  await page.screenshot({ path: '/tmp/mobile-hero.png' });
  console.log('mobile hero captured');

  await browser.close();
})().catch(e => { console.error(e.message); process.exit(1); });
