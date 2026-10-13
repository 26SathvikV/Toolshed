const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const outDir = path.join(__dirname, '..', 'public', 'boxedwine');
fs.mkdirSync(outDir, { recursive: true });

const url = process.env.BOXEDWINE_URL;

if (!url) {
  console.log('BOXEDWINE_URL not set; skipping Boxedwine download.');
  process.exit(0);
}

console.log('Downloading Boxedwine...');
execSync(`curl -fL "${url}" -o /tmp/boxedwine.zip`, { stdio: 'inherit' });
execSync(`unzip -o /tmp/boxedwine.zip -d "${outDir}"`, { stdio: 'inherit' });
console.log('Boxedwine ready.');
