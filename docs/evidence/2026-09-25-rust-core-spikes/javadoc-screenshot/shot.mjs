import { chromium } from '$SCRATCH/shot/node_modules/playwright-core/index.mjs';
const b = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium' + '' });
const p = await b.newPage({ viewport: { width: 1100, height: 1300 } });
await p.goto('file://$SCRATCH/jvm-spike/target/dokkaJavadoc/uniffi/aprv_uniffi/ReceiptVerifier.html');
await p.screenshot({ path: '$SCRATCH/javadoc-receiptverifier.png', fullPage: false });
await b.close();
