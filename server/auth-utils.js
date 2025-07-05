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

// Enhanced address validation function
export function validateAddress(address) {
  if (!address || typeof address !== 'string') {
    console.log('Address validation failed: Invalid address type or empty', address);
    return false;
  }
  
  // Check for mainnet addresses (addr1...)
  if (address.startsWith('addr1')) {
    // Basic length check for mainnet bech32 addresses
    if (address.length >= 50 && address.length <= 110) {
      console.log('Valid mainnet address detected');
      return true;
    }
  }
  
  // Check for testnet addresses (addr_test1...)
  if (address.startsWith('addr_test1')) {
    // Basic length check for testnet bech32 addresses
    if (address.length >= 55 && address.length <= 120) {
      console.log('Valid testnet address detected');
      return true;
    }
  }
  
  // Legacy validation pattern (kept for backward compatibility)
  const legacyPattern = /^addr(_test)?1[0-9a-z]+$/;
  const isValidLegacy = legacyPattern.test(address);
  
  if (isValidLegacy) {
    console.log('Valid address (legacy pattern)');
    return true;
  }
  
  console.log('Address validation failed:', {
    address,
    startsWithAddr1: address.startsWith('addr1'),
    startsWithTestAddr: address.startsWith('addr_test1'),
    length: address.length,
    legacyPattern: isValidLegacy
  });
  
  return false;
}

// Enhanced signature verification
export async function verifySignature(address, signature, key, message) {
  try {
    console.log('Verifying signature for:', {
      address,
      signature: signature.substring(0, 20) + '...',
      key: key.substring(0, 20) + '...',
      message: message.substring(0, 50) + '...'
    });
    
    // Validate inputs
    if (!signature || !key || !message) {
      console.error('Missing required parameters for signature verification');
      return false;
    }
    
    // Convert hex strings to bytes
    const publicKeyBytes = Buffer.from(key, 'hex');
    const signatureBytes = Buffer.from(signature, 'hex');
    const messageBytes = Buffer.from(message, 'utf8');
    
    // Create CSL objects
    const publicKey = csl.PublicKey.from_bytes(publicKeyBytes);
    const ed25519Signature = csl.Ed25519Signature.from_bytes(signatureBytes);
    
    // Verify signature
    const isValid = publicKey.verify(messageBytes, ed25519Signature);
    
    console.log('Signature verification result:', isValid);
    return isValid;
    
  } catch (error) {
    console.error('Signature verification error:', error);
    return false;
  }
}

// Helper function to create authentication challenge
export function createAuthChallenge(address, nonce) {
  const timestamp = Date.now();
  return {
    message: `Please sign this message to authenticate your wallet.\n\nAddress: ${address}\nNonce: ${nonce}\nTimestamp: ${timestamp}`,
    nonce,
    timestamp,
    address
  };
}

// Helper function to validate challenge timing (prevent replay attacks)
export function validateChallengeTimestamp(timestamp, maxAgeMinutes = 5) {
  const now = Date.now();
  const challengeTime = parseInt(timestamp);
  const maxAge = maxAgeMinutes * 60 * 1000; // Convert to milliseconds
  
  return (now - challengeTime) <= maxAge;
}