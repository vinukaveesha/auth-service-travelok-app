// Fixed auth-utils.js with proper CBOR signature parsing
import { readFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import cbor from 'cbor';
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

// Fixed CBOR signature parsing for COSE_Sign1 format
function parseCBORSignature(signatureHex) {
  try {
    const signatureBytes = Buffer.from(signatureHex, 'hex');
    console.log('Parsing CBOR signature, length:', signatureBytes.length);
    
    // Decode the CBOR structure
    const decoded = cbor.decodeFirstSync(signatureBytes);
    console.log('CBOR decoded structure type:', typeof decoded);
    console.log('CBOR decoded is array:', Array.isArray(decoded));
    
    if (Array.isArray(decoded)) {
      console.log('CBOR array length:', decoded.length);
      
      // COSE_Sign1 format: [protected, unprotected, payload, signature]
      if (decoded.length >= 4) {
        const signature = decoded[3];
        console.log('Extracted signature from COSE_Sign1 array');
        console.log('Signature type:', typeof signature);
        console.log('Signature length:', signature?.length);
        
        if (Buffer.isBuffer(signature)) {
          return signature;
        } else if (signature instanceof Uint8Array) {
          return Buffer.from(signature);
        } else {
          throw new Error('Signature is not a buffer or Uint8Array');
        }
      }
    }
    
    // If it's a map/object, try to extract signature
    if (decoded && typeof decoded === 'object' && !Array.isArray(decoded)) {
      if (decoded.signature) {
        console.log('Found signature in object.signature');
        return Buffer.from(decoded.signature);
      }
      
      // Try Map interface
      if (decoded.get && typeof decoded.get === 'function') {
        const sig = decoded.get(3) || decoded.get('signature');
        if (sig) {
          console.log('Found signature in Map');
          return Buffer.from(sig);
        }
      }
    }
    
    throw new Error('Unable to extract signature from CBOR structure');
    
  } catch (error) {
    console.error('CBOR signature parsing error:', error);
    
    // Fallback: try to extract last 64 bytes as Ed25519 signature
    const signatureBytes = Buffer.from(signatureHex, 'hex');
    if (signatureBytes.length >= 64) {
      console.log('Using fallback: last 64 bytes as signature');
      return signatureBytes.slice(-64);
    }
    
    throw new Error('Failed to parse signature and fallback failed');
  }
}

// Fixed CBOR key parsing for COSE_Key format
function parseCBORKey(keyHex) {
  try {
    const keyBytes = Buffer.from(keyHex, 'hex');
    console.log('Parsing CBOR key, length:', keyBytes.length);
    
    // Decode the CBOR structure
    const decoded = cbor.decodeFirstSync(keyBytes);
    console.log('CBOR key decoded structure:', typeof decoded);
    
    // COSE_Key format uses integer keys
    if (decoded && typeof decoded === 'object') {
      // Try Map interface first
      if (decoded.get && typeof decoded.get === 'function') {
        // Key type -2 is the x coordinate for Ed25519
        const publicKey = decoded.get(-2);
        if (publicKey) {
          console.log('Extracted public key from COSE_Key map (-2)');
          console.log('Public key length:', publicKey.length);
          return Buffer.from(publicKey);
        }
        
        // Also try key type 1 (kty) and -1 (crv) combinations
        const kty = decoded.get(1);
        const crv = decoded.get(-1);
        console.log('Key type (kty):', kty, 'Curve (crv):', crv);
        
        // Try different key identifiers
        for (const keyId of [-2, -3, 1, 2]) {
          const key = decoded.get(keyId);
          if (key && (Buffer.isBuffer(key) || key instanceof Uint8Array) && key.length === 32) {
            console.log(`Found 32-byte key at position ${keyId}`);
            return Buffer.from(key);
          }
        }
      }
      
      // Try direct property access
      if (decoded.publicKey) {
        console.log('Found key in publicKey property');
        return Buffer.from(decoded.publicKey);
      }
    }
    
    throw new Error('Unable to extract public key from CBOR structure');
    
  } catch (error) {
    console.error('CBOR key parsing error:', error);
    
    // Fallback: try to extract 32 bytes for Ed25519 public key
    const keyBytes = Buffer.from(keyHex, 'hex');
    
    // Try different positions for 32-byte key
    for (let i = 0; i <= keyBytes.length - 32; i++) {
      const candidateKey = keyBytes.slice(i, i + 32);
      
      // Simple heuristic: Ed25519 public keys often don't start with 0x00
      if (candidateKey[0] !== 0x00) {
        console.log(`Using fallback key at position ${i}`);
        return candidateKey;
      }
    }
    
    // Last resort: use last 32 bytes
    if (keyBytes.length >= 32) {
      console.log('Using last 32 bytes as fallback key');
      return keyBytes.slice(-32);
    }
    
    throw new Error('Failed to parse public key and fallback failed');
  }
}

// Helper function to convert string to hex
function stringToHex(str) {
  return Array.from(str)
    .map(char => char.charCodeAt(0).toString(16).padStart(2, '0'))
    .join('');
}

// Enhanced Cardano signature verification
export async function verifySignature(address, signature, key, message, messageHex) {
  try {
    console.log('=== SIGNATURE VERIFICATION START ===');
    console.log('Address:', address);
    console.log('Message:', message);
    console.log('Message hex:', messageHex);
    console.log('Raw signature length:', signature.length);
    console.log('Raw key length:', key.length);
    
    // Parse CBOR signature and key
    const actualSignature = parseCBORSignature(signature);
    const actualKey = parseCBORKey(key);
    
    console.log('Parsed signature length:', actualSignature.length);
    console.log('Parsed key length:', actualKey.length);
    console.log('Parsed signature hex:', actualSignature.toString('hex'));
    console.log('Parsed key hex:', actualKey.toString('hex'));
    
    // Verify key and signature lengths
    if (actualKey.length !== 32) {
      throw new Error(`Invalid public key length: ${actualKey.length} (expected 32)`);
    }
    
    if (actualSignature.length !== 64) {
      throw new Error(`Invalid signature length: ${actualSignature.length} (expected 64)`);
    }
    
    // Create CSL objects
    const publicKey = csl.PublicKey.from_bytes(actualKey);
    const ed25519Signature = csl.Ed25519Signature.from_bytes(actualSignature);
    
    // Try different message formats
    const messageFormats = [
      { name: 'hex', data: Buffer.from(messageHex || stringToHex(message), 'hex') },
      { name: 'utf8', data: Buffer.from(message, 'utf8') },
      { name: 'ascii', data: Buffer.from(message, 'ascii') }
    ];
    
    for (const format of messageFormats) {
      try {
        console.log(`Trying verification with ${format.name} format:`, format.data.toString('hex'));
        
        const isValid = publicKey.verify(format.data, ed25519Signature);
        
        if (isValid) {
          console.log(`✓ Signature verified successfully with ${format.name} format!`);
          return true;
        } else {
          console.log(`✗ Signature verification failed with ${format.name} format`);
        }
      } catch (verifyError) {
        console.log(`Error verifying with ${format.name} format:`, verifyError.message);
      }
    }
    
    console.log('All verification attempts failed');
    return false;
    
  } catch (error) {
    console.error('Signature verification error:', error);
    console.error('Error stack:', error.stack);
    return false;
  } finally {
    console.log('=== SIGNATURE VERIFICATION END ===');
  }
}