document.addEventListener('DOMContentLoaded', async () => {
  // DOM Elements
  await detectWallets();
  const walletSection = document.getElementById('wallet-section');
  const walletButtons = document.getElementById('wallet-buttons');
  const walletInfo = document.getElementById('wallet-info');
  const walletAddress = document.getElementById('wallet-address');
  const bindWalletBtn = document.getElementById('bind-wallet');
  const signSection = document.getElementById('sign-section');
  const signButton = document.getElementById('sign-button');
  const challengeMessage = document.getElementById('challenge-message');
  const resultSection = document.getElementById('result-section');
  const resultMessage = document.getElementById('result-message');

  let selectedWallet = null;
  let userAddress = null;
  let challengeData = null;

  const API_BASE = 'https://localhost:3000';

  // Fetch wallet configuration from server
  async function loadWalletConfig() {
    try {
      const response = await fetch(`${API_BASE}/api/wallet-config`);
      const config = await response.json();
      renderWalletButtons(config.supportedWallets);
    } catch (error) {
      console.error('Failed to load wallet config:', error);
      showError('Failed to load wallet configuration');
    }
  }

  async function detectWallets() {
    return new Promise(resolve => {
      const check = () => {
        if (window.cardano) {
          console.log('Wallets detected:', Object.keys(window.cardano));
          resolve(true);
        } else {
          setTimeout(check, 3000);
        }
      };
      check();
    });
  }

  // Add retry mechanism for wallet detection
  async function checkWalletInstallation(walletKey, retries = 10, delay = 300) {
    return new Promise((resolve) => {
      const check = () => {
        if (isWalletInstalled(walletKey)) {
          resolve(true);
        } else if (retries > 0) {
          retries--;
          setTimeout(check, delay);
        } else {
          resolve(false);
        }
      };
      check();
    });
  }

  // Render wallet buttons
  async function renderWalletButtons(wallets) {
    walletButtons.innerHTML = '';

    console.log('Detected wallets:', window.cardano ? Object.keys(window.cardano) : 'No wallets detected');
    
    for (const wallet of wallets) {
      const walletKey = wallet.key.toLowerCase();
      const isInstalled = await checkWalletInstallation(walletKey);
      
      const button = document.createElement('button');
      button.className = `btn wallet-btn ${isInstalled ? '' : 'disabled'}`;
      button.innerHTML = `
        ${isInstalled ? `Connect with ${wallet.name}` : `Install ${wallet.name}`}
      `;
      
      if (isInstalled) {
        button.addEventListener('click', () => connectWallet(wallet));
      } else {
        button.addEventListener('click', () => {
          window.open(wallet.installUrl, '_blank');
        });
      }
      
      walletButtons.appendChild(button);
    }
  }

  // Correct wallet detection using window.cardano (not window.Cardano)
  function isWalletInstalled(walletKey) {
    return window.cardano && window.cardano[walletKey];
  }

  // Helper function to convert hex address to bech32
  function hexToBech32Address(hexAddress) {
    try {
      console.log('Converting hex address:', hexAddress);
      
      // If it's already a bech32 address, return as is
      if (hexAddress.startsWith('addr1') || hexAddress.startsWith('addr_test1')) {
        return hexAddress;
      }
      
      // Convert hex to bytes
      const addressBytes = new Uint8Array(hexAddress.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
      
      // Use Mesh SDK to convert to bech32 if available
      if (window.MeshSDK && window.MeshSDK.resolveDataHash) {
        return window.MeshSDK.resolveDataHash(addressBytes);
      }
      
      // Try using the cardano object to get bech32 address
      if (window.cardano && window.cardano.utils) {
        return window.cardano.utils.bytesToBech32(addressBytes);
      }
      
      // Fallback: return hex if conversion fails
      console.warn('Could not convert hex to bech32, returning hex');
      return hexAddress;
    } catch (error) {
      console.error('Address conversion error:', error);
      return hexAddress;
    }
  }

  // Updated connectWallet function with better address handling
  async function connectWallet(wallet) {
    try {
      const walletKey = wallet.key.toLowerCase();
      const walletAPI = window.cardano?.[walletKey];
      
      if (!walletAPI) {
        throw new Error(`${wallet.name} wallet not detected!`);
      }

      selectedWallet = await walletAPI.enable();
      
      // Get user address - try multiple methods
      let addresses;
      
      try {
        // Method 1: Try getUsedAddresses first
        addresses = await selectedWallet.getUsedAddresses();
        console.log('Used addresses:', addresses);
        
        if (!addresses || addresses.length === 0) {
          // Method 2: Try getUnusedAddresses if no used addresses
          addresses = await selectedWallet.getUnusedAddresses();
          console.log('Unused addresses:', addresses);
        }
        
        if (!addresses || addresses.length === 0) {
          throw new Error('No addresses found in wallet');
        }
        
        // Get the first address
        let rawAddress = addresses[0];
        console.log('Raw address from wallet:', rawAddress);
        
        // Handle different address formats
        if (typeof rawAddress === 'string') {
          // Check if it's already a proper bech32 address
          if (rawAddress.startsWith('addr1') || rawAddress.startsWith('addr_test1')) {
            userAddress = rawAddress;
          } else if (rawAddress.length > 50) {
            // This looks like a hex-encoded address, try to convert it
            try {
              // Try to decode as hex and convert to bech32
              const bytes = new Uint8Array(rawAddress.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
              
              // Use the CSL library to convert to bech32
              if (window.csl) {
                const addr = window.csl.Address.from_bytes(bytes);
                userAddress = addr.to_bech32();
              } else {
                // Fallback: assume it's mainnet and create bech32 manually
                userAddress = 'addr1' + rawAddress.substring(2);
              }
            } catch (conversionError) {
              console.error('Failed to convert hex address:', conversionError);
              userAddress = rawAddress; // Use as-is
            }
          } else {
            userAddress = rawAddress;
          }
        } else {
          // If it's not a string, try to convert it
          console.log('Non-string address, type:', typeof rawAddress);
          userAddress = String(rawAddress);
        }
        
        console.log('Processed address:', userAddress);
        
      } catch (addressError) {
        console.error('Address retrieval failed:', addressError);
        throw new Error(`Failed to get wallet address: ${addressError.message}`);
      }
      
      // More lenient validation - just check if it looks like an address
      if (!userAddress || 
          (!userAddress.startsWith('addr1') && 
           !userAddress.startsWith('addr_test1') && 
           userAddress.length < 50)) {
        console.error('Invalid address format:', userAddress);
        throw new Error(`Invalid address format received from wallet: ${userAddress}`);
      }
      
      // Update UI
      walletAddress.textContent = userAddress;
      walletInfo.classList.remove('hidden');
      
      console.log('Successfully connected to wallet. Address:', userAddress);
      
    } catch (error) {
      console.error('Wallet connection failed:', error);
      showError(`Wallet connection failed: ${error.message}`);
    }
  }

  // Initiate wallet binding
  bindWalletBtn.addEventListener('click', async () => {
    try {
      if (!userAddress) {
        throw new Error('No wallet address available');
      }
      
      console.log('Requesting challenge for address:', userAddress);
      
      // Request challenge from server
      const response = await fetch(`${API_BASE}/api/auth-challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ address: userAddress })
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Challenge request failed');
      }
      
      challengeData = await response.json();
      
      // Update UI
      challengeMessage.textContent = challengeData.message;
      walletSection.classList.add('hidden');
      signSection.classList.remove('hidden');
      
    } catch (error) {
      console.error('Challenge request failed:', error);
      showError(error.message);
    }
  });

  // Sign challenge message
  signButton.addEventListener('click', async () => {
    try {
      if (!challengeData || !selectedWallet) {
        throw new Error('No challenge data or wallet connection');
      }
      
      console.log('Signing message:', challengeData.message);
      
      // Sign message with wallet - use the original message, not hex
      const signResult = await selectedWallet.signData(userAddress, challengeData.message);
      
      console.log('Sign result:', signResult);
      
      // Verify signature with server
      const verifyResponse = await fetch(`${API_BASE}/api/verify-wallet`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          address: userAddress, 
          signature: signResult.signature,
          key: signResult.key,
          message: challengeData.message
        })
      });
      
      if (!verifyResponse.ok) {
        const errorData = await verifyResponse.json();
        throw new Error(errorData.error || 'Signature verification failed');
      }
      
      const result = await verifyResponse.json();
      
      // Show result
      signSection.classList.add('hidden');
      resultSection.classList.remove('hidden');
      
      if (result.success) {
        resultMessage.className = 'success';
        resultMessage.innerHTML = `
          <h3>✓ Wallet Bound Successfully!</h3>
          <p>Address: ${userAddress}</p>
          <p>You can now use this wallet for bookings and reviews.</p>
        `;
      } else {
        throw new Error(result.error || 'Wallet binding failed');
      }
    } catch (error) {
      console.error('Signature failed:', error);
      showError(`Signing failed: ${error.message}`);
    }
  });

  // Show error message
  function showError(message) {
    resultSection.classList.remove('hidden');
    resultMessage.className = 'error';
    resultMessage.innerHTML = `<h3>✗ Error:</h3><p>${message}</p>`;
  }

  // Initialize
  await loadWalletConfig();
});