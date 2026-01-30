#!/usr/bin/env node

import {copyFileSync, mkdirSync, existsSync} from "node:fs";
import {join, dirname} from "node:path";
import {fileURLToPath} from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '..');
const distDir = join(projectRoot, 'dist');

// Ensure dist directory exists
if (!existsSync(distDir)) {
  mkdirSync(distDir, { recursive: true });
}

// Copy well-known files
const filesToCopy = [
  'assetlinks.json',
  'apple-app-site-association'
];

filesToCopy.forEach(file => {
  const src = join(projectRoot, file);
  const dest = join(distDir, file);
  
  if (existsSync(src)) {
    copyFileSync(src, dest);
    console.log(`Copied ${file} to dist/`);
  } else {
    console.warn(`Warning: ${file} not found in project root`);
  }
});
