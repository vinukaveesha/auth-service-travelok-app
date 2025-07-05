// Updated auth-utils.js with proper CBOR signature parsing
import { readFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import * as csl from '@emurgo/cardano-serialization-lib-nodejs';

const __dirname = dirname(fileURLToPath(import.meta.url));

export async function loadWalletConfig() {
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
  // Check for bech32 format (addr or addr_test)
  const bech32Pattern = /^addr(_test)?1[0-9a-z]+$/;
  
  // Check for hex format (typical Cardano address hex length is 114 characters)
  const hexPattern = /^[0-9a-f]{114}$/i;
  
  // Also check for shorter hex addresses (some wallets might return different lengths)
  const shortHexPattern = /^[0-9a-f]{56,116}$/i;
  
  const isValid = bech32Pattern.test(address) || hexPattern.test(address) || shortHexPattern.test(address);
  
  console.log('Address validation:', {
    address,
    length: address.length,
    isValid
  });
  
  return isValid;
}

// Helper function to parse CBOR signature from Lace wallet
function parseCBORSignature(signatureHex) {
  try {
    // The signature from Lace is in CBOR format
    // We need to extract the actual signature bytes
    const signatureBytes = Buffer.from(signatureHex, 'hex');
    
    // Parse the CBOR structure to extract the signature
    // The signature is typically at the end of the CBOR structure
    // Look for the last 64 bytes which should be the Ed25519 signature
    
    // For Lace wallet, the signature is usually the last 64 bytes
    const actualSignature = signatureBytes.slice(-64);
    
    console.log('Original signature length:', signatureBytes.length);
    console.log('Extracted signature length:', actualSignature.length);
    console.log('Extracted signature:', actualSignature.toString('hex'));
    
    return actualSignature;
  } catch (error) {
    console.error('CBOR parsing error:', error);
    throw new Error('Failed to parse CBOR signature');
  }
}

// Helper function to parse CBOR key from Lace wallet
function parseCBORKey(keyHex) {
  try {
    const keyBytes = Buffer.from(keyHex, 'hex');
    
    // For Lace wallet, extract the public key
    // The public key is typically 32 bytes and can be found in the CBOR structure
    // Look for a 32-byte sequence that represents the public key
    
    // Try to find the public key in the CBOR structure
    // It's usually near the end, before the signature
    let publicKey;
    
    // Method 1: Look for the last 32 bytes
    if (keyBytes.length >= 32) {
      publicKey = keyBytes.slice(-32);
    } else {
      throw new Error('Key too short');
    }
    
    console.log('Original key length:', keyBytes.length);
    console.log('Extracted key length:', publicKey.length);
    console.log('Extracted key:', publicKey.toString('hex'));
    
    return publicKey;
  } catch (error) {
    console.error('CBOR key parsing error:', error);
    throw new Error('Failed to parse CBOR key');
  }
}

// Cardano signature verification with CBOR parsing
export async function verifySignature(address, signature, key, message) {
  try {
    console.log('Verifying signature for address:', address);
    console.log('Raw signature:', signature);
    console.log('Raw key:', key);
    console.log('Message:', message);
    
    // Parse CBOR signature and key
    const actualSignature = parseCBORSignature(signature);
    const actualKey = parseCBORKey(key);
    
    // Create CSL objects
    const publicKey = csl.PublicKey.from_bytes(actualKey);
    const ed25519Signature = csl.Ed25519Signature.from_bytes(actualSignature);
    
    // Convert message to bytes
    const messageBytes = Buffer.from(message, 'utf8');
    
    console.log('Message bytes:', messageBytes.toString('hex'));
    
    // Verify the signature
    const isValid = publicKey.verify(messageBytes, ed25519Signature);
    
    console.log('Signature verification result:', isValid);
    
    return isValid;
  } catch (error) {
    console.error('Signature verification error:', error);
    
    // Fallback: try different parsing approaches
    try {
      console.log('Trying alternative verification method...');
      
      // Alternative approach: try to use the signature as-is
      const signatureBytes = Buffer.from(signature, 'hex');
      const keyBytes = Buffer.from(key, 'hex');
      
      // Try different offsets to find the actual signature and key
      for (let sigOffset = Math.max(0, signatureBytes.length - 64); sigOffset <= signatureBytes.length - 64; sigOffset++) {
        for (let keyOffset = Math.max(0, keyBytes.length - 32); keyOffset <= keyBytes.length - 32; keyOffset++) {
          try {
            const testSig = signatureBytes.slice(sigOffset, sigOffset + 64);
            const testKey = keyBytes.slice(keyOffset, keyOffset + 32);
            
            const publicKey = csl.PublicKey.from_bytes(testKey);
            const ed25519Signature = csl.Ed25519Signature.from_bytes(testSig);
            const messageBytes = Buffer.from(message, 'utf8');
            
            const isValid = publicKey.verify(messageBytes, ed25519Signature);
            
            if (isValid) {
              console.log('Found valid signature at offsets:', { sigOffset, keyOffset });
              return true;
            }
          } catch (e) {
            // Continue trying different offsets
          }
        }
      }
      
      return false;
    } catch (fallbackError) {
      console.error('Fallback verification also failed:', fallbackError);
      return false;
    }
  }
}