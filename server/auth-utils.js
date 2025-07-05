// Fixed auth-utils.js with proper COSE_Sign1 verification for Lace wallet
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
    
    throw new Error('Unable to extract signature from CBOR structure');
    
  } catch (error) {
    console.error('CBOR signature parsing error:', error);
    throw new Error('Failed to parse signature');
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
      const key = decoded.get(-2);
      if (key && (Buffer.isBuffer(key) || key instanceof Uint8Array) && key.length === 32) {
        console.log('Using 32-byte key from position -2');
        return Buffer.from(key);
      }
    }
    
    throw new Error('Unable to extract public key from CBOR structure');
    
  } catch (error) {
    console.error('CBOR key parsing error:', error);
    throw new Error('Failed to parse public key');
  }
}

// Helper function to convert string to hex
function stringToHex(str) {
  return Array.from(str)
    .map(char => char.charCodeAt(0).toString(16).padStart(2, '0'))
    .join('');
}

// Create the COSE_Sign1 Sig_structure for verification
function createCOSESign1SigStructure(protectedHeaders, externalAAD, payload) {
  try {
    // COSE_Sign1 Sig_structure according to RFC 8152
    // Sig_structure = [
    //   "Signature1", // Context
    //   protected,    // Protected headers
    //   external_aad, // External additional authenticated data
    //   payload       // Payload
    // ]
    
    const context = "Signature1";
    const sigStructure = [
      context,
      protectedHeaders,
      externalAAD,
      payload
    ];
    
    // Encode the structure as CBOR
    const encodedSigStructure = cbor.encode(sigStructure);
    
    console.log('Created COSE_Sign1 Sig_structure:');
    console.log('  Context:', context);
    console.log('  Protected headers length:', protectedHeaders.length);
    console.log('  External AAD length:', externalAAD.length);
    console.log('  Payload length:', payload.length);
    console.log('  Encoded Sig_structure length:', encodedSigStructure.length);
    console.log('  Encoded Sig_structure hex:', Buffer.from(encodedSigStructure).toString('hex'));
    
    return Buffer.from(encodedSigStructure);
    
  } catch (error) {
    console.error('Error creating COSE_Sign1 Sig_structure:', error);
    throw error;
  }
}

// Enhanced Cardano signature verification with proper COSE_Sign1 support for Lace wallet
export async function verifySignature(address, signature, key, message, messageHex) {
  try {
    console.log('=== SIGNATURE VERIFICATION START ===');
    console.log('Address:', address);
    console.log('Message:', message);
    console.log('Message hex:', messageHex);
    console.log('Raw signature length:', signature.length);
    console.log('Raw key length:', key.length);
    
    // Parse the complete COSE_Sign1 structure
    const signatureBytes = Buffer.from(signature, 'hex');
    const coseSign1 = cbor.decodeFirstSync(signatureBytes);
    
    if (!Array.isArray(coseSign1) || coseSign1.length < 4) {
      throw new Error('Invalid COSE_Sign1 structure');
    }
    
    const [protectedHeaders, unprotectedHeaders, payload, sig] = coseSign1;
    
    console.log('COSE_Sign1 structure:');
    console.log('  Protected headers:', protectedHeaders);
    console.log('  Unprotected headers:', unprotectedHeaders);
    console.log('  Payload:', payload);
    console.log('  Signature:', sig);
    
    // Parse CBOR key
    const actualKey = parseCBORKey(key);
    console.log('Parsed key length:', actualKey.length);
    console.log('Parsed key hex:', actualKey.toString('hex'));
    
    // Verify key and signature lengths
    if (actualKey.length !== 32) {
      throw new Error(`Invalid public key length: ${actualKey.length} (expected 32)`);
    }
    
    if (sig.length !== 64) {
      throw new Error(`Invalid signature length: ${sig.length} (expected 64)`);
    }
    
    // Create CSL objects
    const publicKey = csl.PublicKey.from_bytes(actualKey);
    const ed25519Signature = csl.Ed25519Signature.from_bytes(sig);
    
    console.log('Created CSL objects successfully');
    
    // Create the COSE_Sign1 Sig_structure that was actually signed
    const externalAAD = Buffer.alloc(0); // Empty external AAD
    const sigStructure = createCOSESign1SigStructure(protectedHeaders, externalAAD, payload);
    
    console.log('Verifying COSE_Sign1 Sig_structure...');
    console.log('Sig_structure length:', sigStructure.length);
    console.log('Sig_structure hex:', sigStructure.toString('hex'));
    
    // Verify the signature against the Sig_structure
    const isValid = publicKey.verify(sigStructure, ed25519Signature);
    
    if (isValid) {
      console.log('✓ COSE_Sign1 signature verified successfully!');
      
      // Additional verification: check that the payload matches our expected message
      const payloadStr = payload.toString('utf8');
      console.log('Payload from COSE_Sign1:', payloadStr);
      console.log('Expected message:', message);
      
      if (payloadStr === message) {
        console.log('✓ Payload matches expected message!');
        return true;
      } else {
        console.log('✗ Payload does not match expected message');
        return false;
      }
    } else {
      console.log('✗ COSE_Sign1 signature verification failed');
      return false;
    }
    
  } catch (error) {
    console.error('Signature verification error:', error);
    console.error('Error stack:', error.stack);
    return false;
  } finally {
    console.log('=== SIGNATURE VERIFICATION END ===');
  }
}