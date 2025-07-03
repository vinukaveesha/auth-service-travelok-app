import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import session from 'express-session';
import { resolve } from 'node:path';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { 
  loadWalletConfig, 
  generateNonce, 
  validateAddress,
  verifySignature
} from './auth-utils.js';

dotenv.config();
const app = express();
const PORT = 3000;

console.log("PORT", PORT);

const __dirname = dirname(fileURLToPath(import.meta.url));

// Middleware
app.use(cors({
  origin: '*', // Allow all origins (for development only!)
  methods: ['GET', 'POST']
}));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-secret',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, maxAge: 300000 } // 5 minutes
}));

app.use(express.static(join(__dirname, '../client')));

// Wallet config cache
let walletConfig;

// 1. Get wallet configuration
app.get('/api/wallet-config', async (req, res) => {
  try {
    walletConfig = walletConfig || await loadWalletConfig();
    console.log('Loaded wallet config:', walletConfig);
    res.json(walletConfig);
  } catch (error) {
    console.error('Wallet config endpoint error:', error);
    res.status(500).json({ error: error.message });
  }
});

// 2. Generate authentication challenge
app.post('/api/auth-challenge', (req, res) => {
  const { address } = req.body;
  
  if (!validateAddress(address)) {
    return res.status(400).json({ error: 'Invalid Cardano address' });
  }

  const nonce = generateNonce();
  req.session.nonce = nonce;
  req.session.address = address;
  req.session.timestamp = Date.now();
  
  res.json({ 
    nonce,
    message: `Sign this message to authenticate: ${nonce}` 
  });
});

// 3. Verify signature and bind wallet
app.post('/api/verify-wallet', async (req, res) => {
  const { address, signature, key } = req.body;
  
  // Session validation
  if (!req.session.nonce || req.session.address !== address) {
    return res.status(400).json({ error: 'Session expired or invalid' });
  }

  // Cleanup old sessions
  if (Date.now() - req.session.timestamp > 300000) {
    req.session.destroy();
    return res.status(400).json({ error: 'Session expired' });
  }

  try {
    // Verify cryptographic signature
    const isValid = await verifySignature(
      address,
      signature,
      key,
      req.session.nonce
    );

    if (!isValid) {
      return res.status(401).json({ error: 'Invalid signature' });
    }

    // Success - Bind wallet to user
    req.session.destroy();
    
    res.json({ 
      success: true,
      message: 'Wallet bound successfully!',
      address
    });
    
  } catch (error) {
    res.status(500).json({ error: 'Verification failed: ' + error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Auth service running on http://localhost:${PORT}`);
});