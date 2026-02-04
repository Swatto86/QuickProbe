#!/usr/bin/env node

/**
 * Icon generation script for QuickProbe
 * Generates PNG icons from SVG source
 *
 * Usage:
 *   npm install sharp --save-dev (first time only)
 *   node generate-icons.js
 *
 * Alternative (without sharp):
 *   Use online converter like cloudconvert.com or
 *   Use ImageMagick: convert -background none icon.svg -resize 256x256 icons/icon.png
 */

const fs = require('fs');
const path = require('path');

const sizes = [
  // Main application icons
  { input: 'icons/icon.svg', output: 'icons/icon.png', size: 256 },
  { input: 'icons/icon.svg', output: 'icons/32x32.png', size: 32 },
  { input: 'icons/icon.svg', output: 'icons/128x128.png', size: 128 },
  { input: 'icons/icon.svg', output: 'icons/128x128@2x.png', size: 256 },
  // Windows Store logos
  { input: 'icons/icon.svg', output: 'icons/StoreLogo.png', size: 50 },
  { input: 'icons/icon.svg', output: 'icons/Square30x30Logo.png', size: 30 },
  { input: 'icons/icon.svg', output: 'icons/Square44x44Logo.png', size: 44 },
  { input: 'icons/icon.svg', output: 'icons/Square71x71Logo.png', size: 71 },
  { input: 'icons/icon.svg', output: 'icons/Square89x89Logo.png', size: 89 },
  { input: 'icons/icon.svg', output: 'icons/Square107x107Logo.png', size: 107 },
  { input: 'icons/icon.svg', output: 'icons/Square142x142Logo.png', size: 142 },
  { input: 'icons/icon.svg', output: 'icons/Square150x150Logo.png', size: 150 },
  { input: 'icons/icon.svg', output: 'icons/Square284x284Logo.png', size: 284 },
  { input: 'icons/icon.svg', output: 'icons/Square310x310Logo.png', size: 310 },
  // Website icons
  { input: 'icons/icon.svg', output: 'swatto.co.uk/icon.png', size: 256 },
  { input: 'icons/icon.svg', output: 'swatto.co.uk/favicon-32x32.png', size: 32 },
];

console.log('QuickProbe Icon Generator');
console.log('========================\n');

// Check if sharp is available
try {
  const sharp = require('sharp');

  console.log('Using sharp for icon generation...\n');

  // Generate each size
  Promise.all(
    sizes.map(({ input, output, size }) => {
      console.log(`Generating ${output} (${size}x${size})...`);
      return sharp(input)
        .resize(size, size)
        .png({ compressionLevel: 9 })
        .toFile(output)
        .then(() => console.log(`✓ ${output} created`));
    })
  )
    .then(async () => {
      console.log('\n✓ All PNG icons generated successfully!');

      // Generate ICO files from PNGs
      try {
        const toIco = require('to-ico');
        const icoSizes = [16, 24, 32, 48, 64, 256];
        const pngBuffers = await Promise.all(
          icoSizes.map(size =>
            sharp('icons/icon.svg')
              .resize(size, size)
              .png()
              .toBuffer()
          )
        );
        const ico = await toIco(pngBuffers);
        fs.writeFileSync('icons/icon.ico', ico);
        console.log('✓ icons/icon.ico created');
        fs.writeFileSync('swatto.co.uk/favicon.ico', ico);
        console.log('✓ swatto.co.uk/favicon.ico created');
      } catch (icoErr) {
        console.log('\nNote: ICO generation skipped (install to-ico: npm install to-ico)');
        console.log('  Error:', icoErr.message);
      }

      console.log('\nNote: ICNS files need macOS-specific tools (iconutil)');
    })
    .catch(err => {
      console.error('Error generating icons:', err);
      process.exit(1);
    });

} catch (err) {
  console.log('Sharp not installed. Install it with:');
  console.log('  npm install sharp --save-dev\n');
  console.log('Alternative methods:');
  console.log('  1. Online converter: https://cloudconvert.com/svg-to-png');
  console.log('  2. ImageMagick: convert -background none icons/icon.svg -resize 256x256 icons/icon.png');
  console.log('  3. Inkscape: inkscape -w 256 -h 256 icons/icon.svg -o icons/icon.png');
  console.log('\nRequired icon sizes:');
  sizes.forEach(({ output, size }) => {
    console.log(`  - ${output} (${size}x${size})`);
  });
  process.exit(0);
}
