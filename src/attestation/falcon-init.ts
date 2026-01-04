import { readFileSync } from 'fs';
import path from 'path';
import { webcrypto } from 'crypto';

// Ensure crypto.getRandomValues is available for Node.js
if (typeof globalThis.crypto === 'undefined') {
  (globalThis as any).crypto = webcrypto;
}

// Polyfill fetch to load local WASM file
const wasmPath = path.join(
  process.cwd(),
  'node_modules/falcon-1024/dist/falcon_wasm.wasm'
);

const originalFetch = globalThis.fetch;
(globalThis as any).fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = input.toString();
  
  // Intercept WASM file requests
  if (url.includes('falcon_wasm.wasm')) {
    console.log('🔍 Intercepted fetch for:', url);
    const wasmBuffer = readFileSync(wasmPath);
    
    // Return a Response-like object
    return {
      ok: true,
      arrayBuffer: async () => wasmBuffer.buffer.slice(
        wasmBuffer.byteOffset,
        wasmBuffer.byteOffset + wasmBuffer.byteLength
      ),
    };
  }
  
  // Fall back to original fetch for other requests
  if (originalFetch) {
    return originalFetch(input, init);
  }
  
  throw new Error(`fetch not available for: ${url}`);
};

console.log('✅ Falcon environment configured (crypto + fetch polyfill)');
