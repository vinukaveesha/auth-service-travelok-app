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
    const signatureBytes = Buffer.from(signatureHex, 'hex');
    
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
    
    // For Lace wallet, extract the public key (last 32 bytes)
    let publicKey;
    
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

// Helper function to convert string to hex
function stringToHex(str) {
  return Array.from(str)
    .map(char => char.charCodeAt(0).toString(16).padStart(2, '0'))
    .join('');
}

// Cardano signature verification with CBOR parsing
export async function verifySignature(address, signature, key, message, messageHex) {
  try {
    console.log('Verifying signature for address:', address);
    console.log('Raw signature:', signature);
    console.log('Raw key:', key);
    console.log('Message:', message);
    console.log('Message hex:', messageHex);
    
    // Parse CBOR signature and key
    const actualSignature = parseCBORSignature(signature);
    const actualKey = parseCBORKey(key);
    
    // Create CSL objects
    const publicKey = csl.PublicKey.from_bytes(actualKey);
    const ed25519Signature = csl.Ed25519Signature.from_bytes(actualSignature);
    
    // The wallet signs the hex-encoded message, so we need to verify against that
    const messageToVerify = messageHex || stringToHex(message);
    const messageBytes = Buffer.from(messageToVerify, 'hex');
    
    console.log('Message to verify (hex):', messageToVerify);
    console.log('Message bytes length:', messageBytes.length);
    
    // Verify the signature
    const isValid = publicKey.verify(messageBytes, ed25519Signature);
    
    console.log('Signature verification result:', isValid);
    
    return isValid;
  } catch (error) {
    console.error('Signature verification error:', error);
    
    // Fallback: try different approaches
    try {
      console.log('Trying alternative verification methods...');
      
      const signatureBytes = Buffer.from(signature, 'hex');
      const keyBytes = Buffer.from(key, 'hex');
      
      // Try different message formats
      const messageFormats = [
        messageHex || stringToHex(message), // Hex format
        Buffer.from(message, 'utf8'), // UTF-8 bytes
        message // Raw string
      ];
      
      // Try different offsets for signature and key extraction
      for (let sigOffset = Math.max(0, signatureBytes.length - 64); sigOffset <= signatureBytes.length - 64; sigOffset++) {
        for (let keyOffset = Math.max(0, keyBytes.length - 32); keyOffset <= keyBytes.length - 32; keyOffset++) {
          try {
            const testSig = signatureBytes.slice(sigOffset, sigOffset + 64);
            const testKey = keyBytes.slice(keyOffset, keyOffset + 32);
            
            const publicKey = csl.PublicKey.from_bytes(testKey);
            const ed25519Signature = csl.Ed25519Signature.from_bytes(testSig);
            
            for (const msgFormat of messageFormats) {
              try {
                let msgBytes;
                if (typeof msgFormat === 'string') {
                  msgBytes = Buffer.from(msgFormat, 'hex');
                } else {
                  msgBytes = msgFormat;
                }
                
                const isValid = publicKey.verify(msgBytes, ed25519Signature);
                
                if (isValid) {
                  console.log('Found valid signature at offsets:', { sigOffset, keyOffset });
                  console.log('Message format that worked:', msgFormat);
                  return true;
                }
              } catch (e) {
                // Continue trying
              }
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