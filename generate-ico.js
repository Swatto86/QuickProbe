#!/usr/bin/env node

/**
 * ICO generation script for QuickProbe
 * Generates proper Windows ICO file from PNG sources
 */

const fs = require('fs');
const sharp = require('sharp');
const toIco = require('to-ico');

const sizes = [16, 32, 48, 64, 128, 256];

console.log('Generating Windows ICO file...\n');

// Generate all required sizes as PNG buffers
Promise.all(
  sizes.map(size => {
    console.log(`Generating ${size}x${size} PNG buffer...`);
    return sharp('icons/icon.svg')
      .resize(size, size)
      .png()
      .toBuffer();
  })
)
  .then(buffers => {
    console.log('\n✓ All PNG buffers generated');
    console.log('Creating proper ICO file...');

    return toIco(buffers);
  })
  .then(icoBuffer => {
    fs.writeFileSync('icons/icon.ico', icoBuffer);
    console.log('✓ icons/icon.ico created (proper Windows ICO format)');
    console.log(`\nFile size: ${(icoBuffer.length / 1024).toFixed(2)} KB`);
    console.log('Contains sizes: 16x16, 32x32, 48x48, 64x64, 128x128, 256x256');
  })
  .catch(err => {
    console.error('Error generating ICO:', err);
    process.exit(1);
  });
