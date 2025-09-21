// DataManager.js - Data management and API functionality
class DataManager {
  constructor(app) {
    this.app = app;
    this.lastSyncTime = 0;
    this.syncCooldown = 10000; // 10 seconds minimum between syncs
    this.lastRefreshTime = 0;
    this.refreshCooldown = 5000; // 5 seconds minimum between refreshes
    this.cryptoManager = null;
    this.encryptionKey = null;
    this.encryptionEnabled = false;
    this.migrationManager = null;
  }

  // Initialize encryption for the current user
  async initializeEncryption(userEmail, userPassword) {
    try {
      if (!CryptoManager.isSupported()) {
        this.encryptionEnabled = false;
        return false;
      }

      this.cryptoManager = new CryptoManager();
      this.encryptionKey = await this.cryptoManager.generateKey(userEmail, userPassword);
      this.encryptionEnabled = true;
      
      // Initialize migration manager
      this.migrationManager = new MigrationManager(this);
      
      // Check and perform migration if needed
      setTimeout(async () => {
        try {
          await this.migrationManager.checkAndMigrate({
            showProgress: true,
            autoRun: true,
            requireConfirmation: false
          });
          
          // Trigger card re-rendering after migration completes
          if (window.app && window.app.cardManager) {
            window.app.cardManager.renderCards();
          }
        } catch (error) {
          console.error('Auto-migration failed:', error);
        }
      }, 1000);
      
      return true;
    } catch (error) {
      console.error('Failed to initialize encryption:', error);
      this.encryptionEnabled = false;
      return false;
    }
  }

  // Disable encryption (for logout)
  disableEncryption() {
    this.cryptoManager = null;
    this.encryptionKey = null;
    this.encryptionEnabled = false;
    this.migrationManager = null;
  }

  async loadLocalData() {
    try {
      const userData = localStorage.getItem('user');
      const cardsData = localStorage.getItem('cards');
      
      if (userData) {
        const user = JSON.parse(userData);
        AppState.user = user;
      }
      
      if (cardsData) {
        const cards = JSON.parse(cardsData);
        if (Array.isArray(cards)) {
          // Check if we need to decrypt cards
          if (this.encryptionEnabled && this.encryptionKey) {
            try {
              AppState.cards = await this.cryptoManager.decryptCards(cards, this.encryptionKey);
            } catch (error) {
              console.error('Failed to decrypt cards, using as-is:', error);
              AppState.cards = cards;
            }
          } else {
            AppState.cards = cards;
          }
        } else {
          AppState.cards = [];
        }
      }
      
    } catch (error) {
      console.error('Error loading local data:', error);
      // Clear corrupted data
      localStorage.removeItem('user');
      localStorage.removeItem('cards');
      AppState.user = null;
      AppState.cards = [];
    }
  }

  async saveLocalData() {
    try {
      if (AppState.user) {
        localStorage.setItem('user', JSON.stringify(AppState.user));
      }
      
      if (AppState.cards && Array.isArray(AppState.cards)) {
        let cardsToSave = AppState.cards;
        
        // Encrypt cards before saving if encryption is enabled
        if (this.encryptionEnabled && this.encryptionKey && AppState.cards.length > 0) {
          try {
            cardsToSave = await this.cryptoManager.encryptCards(AppState.cards, this.encryptionKey);
          } catch (error) {
            console.error('Failed to encrypt cards, saving unencrypted:', error);
            cardsToSave = AppState.cards;
          }
        }
        
        localStorage.setItem('cards', JSON.stringify(cardsToSave));
      }
      
    } catch (error) {
      console.error('Error saving local data:', error);
    }
  }

  async syncData() {
    if (!AppState.isOnline || !AppState.user) {
      return;
    }

    // Check cooldown period
    const now = Date.now();
    if (now - this.lastSyncTime < this.syncCooldown) {
      return;
    }

    try {
      this.lastSyncTime = now;
      
      const response = await this.apiCall('/auth/me');
      
      if (response && response.user) {
        AppState.user = response.user;
        
        // Handle cards with potential decryption
        let serverCards = response.cards || [];
        if (this.encryptionEnabled && this.encryptionKey && serverCards.length > 0) {
          try {
            AppState.cards = await this.cryptoManager.decryptCards(serverCards, this.encryptionKey);
          } catch (error) {
            console.error('Failed to decrypt server cards:', error);
            AppState.cards = serverCards;
          }
        } else {
          AppState.cards = serverCards;
        }
        
        await this.saveLocalData();
        this.app.cards.renderCards();
        this.updateProfile();
        
        UIUtils.showToast('success', 'Дані синхронізовано');
      }
    } catch (error) {
      console.error('Sync error:', error);
    }
  }

  handleOnlineStatus() {
    AppState.isOnline = true;
    UIUtils.showToast('success', 'З\'єднання відновлено');
    
    // Sync data after coming online
    if (AppState.user) {
      setTimeout(() => {
        this.syncData();
      }, 1000);
    }
  }

  handleOfflineStatus() {
    AppState.isOnline = false;
    UIUtils.showToast('warning', 'Немає з\'єднання. Працюємо офлайн');
  }

  async apiCall(endpoint, options = {}) {
    // Check if API client is available
    if (!window.api) {
      console.error('window.api is not available. API client not loaded.');
      throw new Error('API client not loaded. Please refresh the page.');
    }
    
    // Initialize request count for debugging
    if (!window.apiRequestCount) {
      window.apiRequestCount = 0;
    }
    window.apiRequestCount++;
    
    try {
      // Map old endpoint format to new API client methods
      if (endpoint === '/auth/me') {
        return await window.api.getProfile();
      } else if (endpoint === '/auth/login') {
        return await window.api.login(JSON.parse(options.body));
      } else if (endpoint === '/auth/register') {
        return await window.api.register(JSON.parse(options.body));
      } else if (endpoint === '/auth/password' && options.method === 'PUT') {
        return await window.api.changePassword(JSON.parse(options.body));
      } else if (endpoint === '/auth/profile' && options.method === 'PUT') {
        return await window.api.updateProfile(JSON.parse(options.body));
      } else if (endpoint === '/auth/verify-code') {
        return await window.api.verifyTwoFactor(JSON.parse(options.body));
      } else if (endpoint === '/auth/resend-code') {
        return await window.api.resendCode(JSON.parse(options.body));
      } else if (endpoint === '/cards' && options.method === 'POST') {
        const cardData = JSON.parse(options.body);
        
        // Encrypt card data before sending to server if encryption is enabled
        if (this.encryptionEnabled && this.encryptionKey) {
          try {
            const encryptedCards = await this.cryptoManager.encryptCards([cardData], this.encryptionKey);
            return await window.api.createCard(encryptedCards[0]);
          } catch (error) {
            console.error('Failed to encrypt card for server, sending unencrypted:', error);
            return await window.api.createCard(cardData);
          }
        }
        
        return await window.api.createCard(cardData);
      } else if (endpoint.startsWith('/cards/') && options.method === 'DELETE') {
        const cardId = endpoint.split('/cards/')[1];
        return await window.api.deleteCard(cardId);
      } else {
        throw new Error(`Unsupported API call: ${options.method || 'GET'} ${endpoint}`);
      }
    } catch (error) {
      // Handle common error scenarios
      if (error.message.includes('401') || error.message.includes('Unauthorized')) {
        // Token expired or invalid
        localStorage.removeItem('authToken');
        window.api.setToken(null);
        AppState.user = null;
        AppState.cards = [];
        this.app.auth.showAuthScreen();
        throw new Error('Session expired');
      }
      
      throw error;
    }
  }

  updateProfile() {
    try {
      const userEmail = document.getElementById('user-email');
      const userName = document.getElementById('user-name');
      const userId = document.getElementById('user-id');
      const joinDate = document.getElementById('join-date');
      const cardsCount = document.getElementById('cards-count');
      
      if (AppState.user) {
        if (userEmail) userEmail.textContent = AppState.user.email;
        if (userName) userName.textContent = AppState.user.name;
        if (userId) userId.textContent = AppState.user._id || AppState.user.id;
      if (joinDate && AppState.user.createdAt) {
        const date = new Date(AppState.user.createdAt);
        joinDate.textContent = date.toLocaleDateString('uk-UA');
      }
      if (cardsCount) cardsCount.textContent = AppState.cards.length;
      
      // Update language selector
      if (AppState.user.language) {
        const languageInput = document.querySelector(`input[name="language"][value="${AppState.user.language}"]`);
        if (languageInput) {
          languageInput.checked = true;
        }
      }
    }
    } catch (error) {
      console.error('Error updating profile UI:', error);
    }
  }

  // Setup data-related event listeners
  setupDataEventListeners() {
    // Online/offline status
    window.addEventListener('online', this.handleOnlineStatus.bind(this));
    window.addEventListener('offline', this.handleOfflineStatus.bind(this));
    
    // App visibility change for data refresh
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) {
        this.app.auth.handleAppResume();
      }
    });
    
    // Window focus for data refresh
    window.addEventListener('focus', () => {
      this.app.auth.handleAppResume();
    });
  }

  // Pull-to-refresh data refresh
  async performRefresh() {
    if (!AppState.user || !localStorage.getItem('authToken')) {
      throw new Error('User not authenticated');
    }

    // Check cooldown period
    const now = Date.now();
    if (now - this.lastRefreshTime < this.refreshCooldown) {
      throw new Error('Please wait before refreshing again');
    }

    try {
      this.lastRefreshTime = now;
      const response = await this.apiCall('/auth/me');
      
      if (response.user) {
        // Save user data
        AppState.user = response.user;
        
        // Save cards data with decryption
        let serverCards = [];
        if (response.user.cards && Array.isArray(response.user.cards) && response.user.cards.length > 0) {
          serverCards = response.user.cards;
        } else if (response.cards && Array.isArray(response.cards) && response.cards.length > 0) {
          serverCards = response.cards;
        } else {
          serverCards = AppState.cards || [];
        }
        
        // Decrypt cards if encryption is enabled
        if (this.encryptionEnabled && this.encryptionKey && serverCards.length > 0) {
          try {
            AppState.cards = await this.cryptoManager.decryptCards(serverCards, this.encryptionKey);
          } catch (error) {
            console.error('Failed to decrypt server cards during refresh:', error);
            AppState.cards = serverCards;
          }
        } else {
          AppState.cards = serverCards;
        }
        
        // Sync data to localStorage
        await this.saveLocalData();
        
      } else {
        console.error('Invalid response from /auth/me:', response);
      }
    } catch (error) {
      console.error('Refresh failed:', error);
      
      if (error.message.includes('401') || error.message.includes('Unauthorized')) {
        this.app.auth.handleLogout();
        throw new Error('Session expired');
      }
      
      throw error;
    }
  }
}

// Export for use in other modules
window.DataManager = DataManager;