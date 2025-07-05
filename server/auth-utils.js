// Fixed auth-utils.js with proper CBOR signature parsing for Lace wallet
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

// Fixed CBOR signature parsing for Lace wallet's COSE_Sign1 format
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
      console.log('CBOR array structure:', decoded.map((item, i) => `[${i}]: ${typeof item} (${item?.constructor?.name || 'unknown'})`));
      
      // COSE_Sign1 format: [protected, unprotected, payload, signature]
      if (decoded.length >= 4) {
        const signature = decoded[3];
        console.log('Signature at index 3:', signature);
        console.log('Signature type:', typeof signature);
        console.log('Signature length:', signature?.length);
        
        if (Buffer.isBuffer(signature)) {
          console.log('Signature is Buffer, length:', signature.length);
          return signature;
        } else if (signature instanceof Uint8Array) {
          console.log('Signature is Uint8Array, length:', signature.length);
          return Buffer.from(signature);
        } else {
          console.log('Signature is not a buffer, converting...');
          return Buffer.from(signature);
        }
      }
    }
    
    // If it's a map/object, try to extract signature
    if (decoded && typeof decoded === 'object' && !Array.isArray(decoded)) {
      console.log('Decoded is object/map');
      
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
    
    // Enhanced fallback for Lace wallet
    try {
      const signatureBytes = Buffer.from(signatureHex, 'hex');
      console.log('Trying enhanced fallback parsing...');
      
      // Look for 64-byte signature pattern in the hex
      // Ed25519 signatures are always 64 bytes
      for (let i = 0; i <= signatureBytes.length - 64; i++) {
        const candidateSignature = signatureBytes.slice(i, i + 64);
        
        // Simple heuristic: signatures usually don't start with many zeros
        const zeroCount = candidateSignature.slice(0, 8).filter(b => b === 0).length;
        if (zeroCount < 4) {
          console.log(`Found potential signature at offset ${i}`);
          console.log('Candidate signature:', candidateSignature.toString('hex'));
          return candidateSignature;
        }
      }
      
      // If that fails, try the last 64 bytes
      if (signatureBytes.length >= 64) {
        console.log('Using last 64 bytes as signature');
        return signatureBytes.slice(-64);
      }
      
    } catch (fallbackError) {
      console.error('Fallback parsing also failed:', fallbackError);
    }
    
    throw new Error('Failed to parse signature and all fallbacks failed');
  }
}

// Fixed CBOR key parsing for Lace wallet's COSE_Key format
function parseCBORKey(keyHex) {
  try {
    const keyBytes = Buffer.from(keyHex, 'hex');
    console.log('Parsing CBOR key, length:', keyBytes.length);
    
    // Decode the CBOR structure
    const decoded = cbor.decodeFirstSync(keyBytes);
    console.log('CBOR key decoded structure:', typeof decoded);
    console.log('CBOR key is Map:', decoded instanceof Map);
    
    // Handle Map objects (common in COSE_Key format)
    if (decoded instanceof Map) {
      console.log('Processing Map structure');
      console.log('Map keys:', Array.from(decoded.keys()));
      
      // COSE_Key format uses integer keys
      // -2 is typically the x coordinate for Ed25519
      // -1 is the curve identifier
      // 1 is the key type
      const possibleKeys = [-2, -3, 1, 2, 3];
      
      for (const keyId of possibleKeys) {
        const key = decoded.get(keyId);
        if (key) {
          console.log(`Found key at map position ${keyId}:`, typeof key, key?.length);
          
          if ((Buffer.isBuffer(key) || key instanceof Uint8Array) && key.length === 32) {
            console.log(`Using 32-byte key from position ${keyId}`);
            return Buffer.from(key);
          }
        }
      }
    }
    
    // Handle regular objects
    if (decoded && typeof decoded === 'object' && !Array.isArray(decoded)) {
      console.log('Processing object structure');
      
      // Try direct property access
      if (decoded.publicKey && decoded.publicKey.length === 32) {
        console.log('Found key in publicKey property');
        return Buffer.from(decoded.publicKey);
      }
      
      // Try numeric properties
      for (const prop of ['-2', '-3', '1', '2']) {
        if (decoded[prop] && decoded[prop].length === 32) {
          console.log(`Found key in property ${prop}`);
          return Buffer.from(decoded[prop]);
        }
      }
    }
    
    throw new Error('Unable to extract public key from CBOR structure');
    
  } catch (error) {
    console.error('CBOR key parsing error:', error);
    
    // Enhanced fallback for Lace wallet
    try {
      const keyBytes = Buffer.from(keyHex, 'hex');
      console.log('Trying enhanced key fallback parsing...');
      
      // Look for 32-byte Ed25519 public key pattern
      for (let i = 0; i <= keyBytes.length - 32; i++) {
        const candidateKey = keyBytes.slice(i, i + 32);
        
        // Ed25519 public keys are typically not all zeros or all 0xFF
        const zeroCount = candidateKey.filter(b => b === 0).length;
        const ffCount = candidateKey.filter(b => b === 0xFF).length;
        
        if (zeroCount < 16 && ffCount < 16) {
          console.log(`Found potential key at offset ${i}`);
          console.log('Candidate key:', candidateKey.toString('hex'));
          return candidateKey;
        }
      }
      
      // Last resort: use last 32 bytes
      if (keyBytes.length >= 32) {
        console.log('Using last 32 bytes as key');
        return keyBytes.slice(-32);
      }
      
    } catch (fallbackError) {
      console.error('Key fallback parsing also failed:', fallbackError);
    }
    
    throw new Error('Failed to parse public key and all fallbacks failed');
  }
}

// Helper function to convert string to hex
function stringToHex(str) {
  return Array.from(str)
    .map(char => char.charCodeAt(0).toString(16).padStart(2, '0'))
    .join('');
}

// Enhanced Cardano signature verification with proper CIP-30 support for Lace wallet
export async function verifySignature(address, signature, key, message, messageHex) {
  try {
    console.log('=== SIGNATURE VERIFICATION START ===');
    console.log('Address:', address);
    console.log('Message:', message);
    console.log('Message hex:', messageHex);
    console.log('Raw signature length:', signature.length);
    console.log('Raw key length:', key.length);
    console.log('Raw signature (first 100 chars):', signature.substring(0, 100));
    console.log('Raw key (first 100 chars):', key.substring(0, 100));
    
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
    
    console.log('Created CSL objects successfully');
    
    // Parse the original CBOR signature to extract the actual signed payload
    let signedPayload = null;
    try {
      const signatureBytes = Buffer.from(signature, 'hex');
      const decoded = cbor.decodeFirstSync(signatureBytes);
      
      if (Array.isArray(decoded) && decoded.length >= 3) {
        // COSE_Sign1 format: [protected, unprotected, payload, signature]
        const payload = decoded[2];
        if (payload && Buffer.isBuffer(payload)) {
          signedPayload = payload;
          console.log('Extracted signed payload from COSE_Sign1:', signedPayload.toString('hex'));
          console.log('Signed payload as UTF8:', signedPayload.toString('utf8'));
        }
      }
    } catch (e) {
      console.log('Could not extract signed payload from COSE structure');
    }
    
    // Try different message formats based on CIP-30 specification
    const messageFormats = [];
    
    // 1. If we extracted the signed payload, try that first
    if (signedPayload) {
      messageFormats.push({ name: 'extracted-payload', data: signedPayload });
    }
    
    // 2. Try the original message formats
    messageFormats.push(
      { name: 'original-hex', data: Buffer.from(messageHex || stringToHex(message), 'hex') },
      { name: 'utf8', data: Buffer.from(message, 'utf8') },
      { name: 'ascii', data: Buffer.from(message, 'ascii') }
    );
    
    // 3. Try CIP-30 structured format
    // According to CIP-30, the wallet might sign: "address" + "payload"
    try {
      const addressBytes = Buffer.from(address, 'hex');
      const messageBytes = Buffer.from(message, 'utf8');
      const combinedCIP30 = Buffer.concat([addressBytes, messageBytes]);
      messageFormats.push({ name: 'cip30-combined', data: combinedCIP30 });
    } catch (e) {
      console.log('Could not create CIP-30 combined format');
    }
    
    // 4. Try CBOR-encoded message (common in Cardano)
    try {
      const cborMessage = cbor.encode(message);
      messageFormats.push({ name: 'cbor-encoded', data: Buffer.from(cborMessage) });
    } catch (e) {
      console.log('Could not create CBOR encoded message');
    }
    
    // 5. Try different hashing approaches
    try {
      // Blake2b-256 hash of the message (common in Cardano)
      const blake2b = crypto.createHash('blake2b512');
      blake2b.update(message);
      const hashedMessage = blake2b.digest().slice(0, 32); // Take first 32 bytes
      messageFormats.push({ name: 'blake2b-256', data: hashedMessage });
    } catch (e) {
      console.log('Could not create Blake2b hash');
    }
    
    // Now try all formats
    for (const format of messageFormats) {
      try {
        console.log(`Trying verification with ${format.name} format:`);
        console.log('Message data (hex):', format.data.toString('hex'));
        console.log('Message data (utf8):', format.data.toString('utf8').substring(0, 100));
        console.log('Message data length:', format.data.length);
        
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
    
    // Debug: Let's also try to decode the entire CBOR structure to understand what Lace signed
    try {
      console.log('=== DEBUG: Analyzing CBOR structure ===');
      const signatureBytes = Buffer.from(signature, 'hex');
      const decoded = cbor.decodeFirstSync(signatureBytes);
      
      if (Array.isArray(decoded)) {
        console.log('CBOR structure analysis:');
        decoded.forEach((item, index) => {
          if (Buffer.isBuffer(item)) {
            console.log(`  [${index}]: Buffer (${item.length} bytes) - ${item.toString('hex').substring(0, 64)}...`);
            if (item.length < 200) {
              try {
                console.log(`    As UTF8: ${item.toString('utf8')}`);
              } catch (e) {
                console.log(`    Cannot convert to UTF8`);
              }
            }
          } else if (item && typeof item === 'object') {
            console.log(`  [${index}]: Object -`, Object.keys(item));
          } else {
            console.log(`  [${index}]: ${typeof item} -`, item);
          }
        });
      }
    } catch (e) {
      console.log('Could not analyze CBOR structure:', e.message);
    }
    
    return false;
    
  } catch (error) {
    console.error('Signature verification error:', error);
    console.error('Error stack:', error.stack);
    return false;
  } finally {
    console.log('=== SIGNATURE VERIFICATION END ===');
  }
}