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

  // Update connectWallet function
  async function connectWallet(wallet) {
  try {
    const walletKey = wallet.key.toLowerCase();
    const walletAPI = window.cardano?.[walletKey];
    
    if (!walletAPI) {
      throw new Error(`${wallet.name} wallet not detected!`);
    }

    selectedWallet = await walletAPI.enable();
    
    // Get user address - try used addresses first, then unused addresses
    let addresses = await selectedWallet.getUsedAddresses();
    console.log('Used addresses:', addresses);
    
    if (addresses.length === 0) {
      // If no used addresses, get unused addresses
      addresses = await selectedWallet.getUnusedAddresses();
      console.log('Unused addresses:', addresses);
    }
    
    if (addresses.length === 0) {
      throw new Error('No addresses available from wallet');
    }
    
    // Get the first available address
    const rawAddress = addresses[0];
    console.log('Raw address from wallet:', rawAddress);
    
    // For now, use the raw hex address directly
    // The server-side validation will need to be updated to handle hex addresses
    // or you'll need to implement proper bech32 encoding
    processedAddress = rawAddress;
    
    console.log('Processed address:', processedAddress);
    
    userAddress = processedAddress;
    
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
  // Helper function to convert string to hex
  function stringToHex(str) {
    return Array.from(str)
      .map(char => char.charCodeAt(0).toString(16).padStart(2, '0'))
      .join('');
  }

  // Helper function to convert hex to bytes (for verification)
  function hexToBytes(hex) {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
      bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return new Uint8Array(bytes);
  }

  // Updated sign button event listener
  signButton.addEventListener('click', async () => {
    try {
      // Convert message to hex properly
      const messageHex = stringToHex(challengeData.message);
      console.log('Original message:', challengeData.message);
      console.log('Message as hex:', messageHex);
      
      // Sign message with wallet
      const { signature, key } = await selectedWallet.signData(
        userAddress, 
        messageHex
      );
      
      console.log('Signature received:', signature);
      console.log('Key received:', key);
      
      // Verify signature with server
      const verifyResponse = await fetch(`${API_BASE}/api/verify-wallet`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          address: userAddress, 
          signature,
          key,
          message: challengeData.message // Send original message for server verification
        })
      });
      
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