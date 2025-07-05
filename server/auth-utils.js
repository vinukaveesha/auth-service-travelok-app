import { readFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import * as csl from '@emurgo/cardano-serialization-lib-nodejs';

const __dirname = dirname(fileURLToPath(import.meta.url));

export async function loadWalletConfig() {
  // Use __dirname to ensure correct path
  const configPath = resolve(__dirname, 'wallet-config.json');
  try {
    return JSON.parse(await readFile(configPath, 'utf8'));
  } catch (error) {
    console.error('Wallet config error:', error);
    throw new Error('Wallet config file missing or invalid: ' + configPath);
  }
}

export function generateNonce() {
  return crypto.randomBytes(16).toString('hex');
}

export function validateAddress(address) {
  return /^addr(_test)?1[0-9a-z]+$/.test(address);
}

// Cardano signature verification
export async function verifySignature(address, signature, key, message) {
  try {
    const publicKey = csl.PublicKey.from_bytes(Buffer.from(key, 'hex'));
    const ed25519Signature = csl.Ed25519Signature.from_bytes(Buffer.from(signature, 'hex'));
    
    return publicKey.verify(
      Buffer.from(message).buffer,
      ed25519Signature
    );
  } catch (error) {
    console.error('Signature verification error:', error);
    return false;
  }
}