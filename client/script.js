document.addEventListener('DOMContentLoaded', async () => {
  // DOM Elements
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

  const API_BASE = 'http://localhost:5000';

  // Fetch wallet configuration from server
  async function loadWalletConfig() {
    try {
      const response = await fetch(`${API_BASE}/api/wallet-config`);
      console.log("Response ",response)
      const config = await response.json();
      renderWalletButtons(config.supportedWallets);
    } catch (error) {
      console.error('Failed to load wallet config:', error);
      showError('Failed to load wallet configuration');
    }
  }

  // Add this helper function
function isWalletInstalled(walletKey) {
  return window.Cardano && window.Cardano[walletKey];
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

  console.log('Detected wallets:', window.Cardano ? Object.keys(window.Cardano) : 'No wallets detected');
  
  for (const wallet of wallets) {
    const walletKey = wallet.key.toLowerCase();
    const isInstalled = await checkWalletInstallation(walletKey);
    
    const button = document.createElement('button');
    button.className = `btn wallet-btn ${isInstalled ? '' : 'disabled'}`;
    button.innerHTML = `
      <img src="${wallet.icon}" alt="${wallet.name}" height="24">
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

// Connect to wallet
async function connectWallet(wallet) {
  try {
    const walletKey = wallet.key.toLowerCase();
    
    // Check if wallet exists
    if (!isWalletInstalled(walletKey)) {
      throw new Error(`${wallet.name} wallet not detected!`);
    }

    // Enable wallet
    selectedWallet = await window.Cardano[walletKey].enable();
    
    // Get user address
    const addresses = await selectedWallet.getUsedAddresses();
    userAddress = addresses[0];
    
    // Update UI
    walletAddress.textContent = userAddress;
    walletInfo.classList.remove('hidden');
  } catch (error) {
    console.error('Wallet connection failed:', error);
    showError(`Wallet connection failed: ${error.message}`);
  }
}

  // Initiate wallet binding
  bindWalletBtn.addEventListener('click', async () => {
    try {
      // Request challenge from server
      const response = await fetch(`${API_BASE}/api/auth-challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ address: userAddress })
      });
      
      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Challenge request failed');
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
      // Sign message with wallet
      const { signature, key } = await selectedWallet.signData(
        userAddress, 
        challengeData.message
      );
      
      // Verify signature with server
      const verifyResponse = await fetch(`${API_BASE}/api/verify-wallet`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          address: userAddress, 
          signature,
          key
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
      console.error('Signature verification failed:', error);
      showError(error.message);
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