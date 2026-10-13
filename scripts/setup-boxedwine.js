const fs = require('fs');
const os = require('os');
const path = require('path');
const { Readable } = require('stream');
const { pipeline } = require('stream/promises');
const extract = require('extract-zip');

const outDir = path.join(__dirname, '..', 'public', 'boxedwine');

const url = process.env.BOXEDWINE_URL;

if (!url) {
  console.log('BOXEDWINE_URL not set; skipping Boxedwine download.');
} else {
  setupBoxedwine().catch((error) => {
    console.error('Boxedwine setup failed:', error);
    process.exitCode = 1;
  });
}

async function setupBoxedwine() {
  fs.mkdirSync(outDir, { recursive: true });

  console.log('Downloading Boxedwine...');
  const response = await fetch(url);
  if (!response.ok || !response.body) {
    throw new Error(`Boxedwine download failed: HTTP ${response.status}`);
  }

  const zipPath = path.join(os.tmpdir(), `boxedwine-${process.pid}.zip`);
  try {
    await pipeline(Readable.fromWeb(response.body), fs.createWriteStream(zipPath));
    await extract(zipPath, { dir: outDir });
  } finally {
    fs.rmSync(zipPath, { force: true });
  }

  console.log('Boxedwine ready.');
}
