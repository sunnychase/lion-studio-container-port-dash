// Created by Sunny Chase (https://github.com/sunnychase) in collaboration with Claude (Anthropic) · Lion Studio - Container Port Dash
// record_demo.cjs -- a short tour of the page in demo mode (made-up data) as a video, for docs/media.
//   PORTS_DEMO=1 PORTS_LAN=192.0.2.0/24 PORTS_UPLOAD_ALERT_MB=5 python3 app.py &      (wait ~20 s for traffic and alerts)
//   NODE_PATH=<a node_modules with playwright> node scripts/record_demo.cjs http://127.0.0.1:8660 OUT_DIR
const { chromium } = require('playwright');
const [url, out] = [process.argv[2] || 'http://127.0.0.1:8660', process.argv[3] || 'out'];
const wait = ms => new Promise(r => setTimeout(r, ms));
(async () => {
  const b = await chromium.launch();
  const ctx = await b.newContext({ viewport: { width: 1280, height: 760 }, colorScheme: 'dark', deviceScaleFactor: 1,
                                   recordVideo: { dir: out, size: { width: 1280, height: 760 } } });
  const p = await ctx.newPage();
  await p.goto(url); await wait(4500);
  const smooth = async y => { await p.evaluate(y => window.scrollTo({ top: y, behavior: 'smooth' }), y); await wait(1600); };
  const top = async sel => (await p.locator(sel).boundingBox()).y + await p.evaluate(() => window.scrollY) - 70;
  await smooth(await top('#lq')); await wait(1200);
  await p.locator('#lq').pressSequentially('unknown', { delay: 120 }); await wait(2600);
  await p.locator('#lq').fill(''); await p.locator('#lq').dispatchEvent('input');
  await smooth(await top('#ports')); await wait(800);
  await p.locator('#ports tr.x', { hasText: 'chat-ui' }).first().click(); await wait(2600);
  await p.locator('#ports tr.x', { hasText: 'Report builder' }).locator('button.kill').click(); await wait(2400);
  await p.locator('#pw').pressSequentially('demo', { delay: 160 }); await wait(700);
  await p.locator('#go').click(); await wait(3200);
  await smooth(0); await wait(3000);
  await ctx.close(); await b.close();
})();
