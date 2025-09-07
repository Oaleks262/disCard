// DataManager.js - Data management and API functionality
class DataManager {
  constructor(app) {
    this.app = app;
    this.lastSyncTime = 0;
    this.syncCooldown = 10000; // 10 seconds minimum between syncs
    this.lastRefreshTime = 0;
    this.refreshCooldown = 5000; // 5 seconds minimum between refreshes
  }

  loadLocalData() {
    try {
      const userData = localStorage.getItem('user');
      const cardsData = localStorage.getItem('cards');
      
      if (userData) {
        const user = JSON.parse(userData);
        AppState.user = user;
      }
      
      if (cardsData) {
        const cards = JSON.parse(cardsData);
        AppState.cards = Array.isArray(cards) ? cards : [];
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

  saveLocalData() {
    try {
      if (AppState.user) {
        localStorage.setItem('user', JSON.stringify(AppState.user));
      }
      
      if (AppState.cards && Array.isArray(AppState.cards)) {
        localStorage.setItem('cards', JSON.stringify(AppState.cards));
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
      console.log('Sync blocked: cooldown period active');
      return;
    }

    try {
      console.log('Starting data sync...');
      this.lastSyncTime = now;
      
      const response = await this.apiCall('/auth/me');
      
      if (response && response.user) {
        AppState.user = response.user;
        AppState.cards = response.cards || [];
        
        this.saveLocalData();
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
      console.error('❌ window.api is not available. API client not loaded.');
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
      } else if (endpoint === '/cards' && options.method === 'POST') {
        return await window.api.createCard(JSON.parse(options.body));
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
      console.log('Refresh blocked: cooldown period active');
      throw new Error('Please wait before refreshing again');
    }

    try {
      console.log('Starting data refresh...');
      this.lastRefreshTime = now;
      const response = await this.apiCall('/auth/me');
      
      if (response.user) {
        // Save user data
        AppState.user = response.user;
        
        // Save cards data
        let serverCards = [];
        if (response.user.cards && Array.isArray(response.user.cards) && response.user.cards.length > 0) {
          serverCards = response.user.cards;
        } else if (response.cards && Array.isArray(response.cards) && response.cards.length > 0) {
          serverCards = response.cards;
        } else {
          serverCards = AppState.cards || [];
        }
        
        AppState.cards = serverCards;
        
        // Sync data to localStorage
        this.saveLocalData();
        
      } else {
        console.warn('Invalid response from /auth/me:', response);
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