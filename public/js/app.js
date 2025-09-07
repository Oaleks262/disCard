// Main App JavaScript - Loyalty Cards PWA (Refactored)

// Global app state
const AppState = {
  user: null,
  cards: [],
  currentTab: 'cards',
  theme: 'light',
  isOnline: navigator.onLine,
  isLoading: false
};

// API Configuration
const API_CONFIG = {
  baseURL: window.location.origin + '/api',
  timeout: 10000,
  retries: 3
};

// Main App Class - Now orchestrates modules
class LoyaltyCardsApp {
  constructor() {
    // Initialize all managers
    this.data = new DataManager(this);
    this.auth = new AuthManager(this);
    this.cards = new CardManager(this);
    this.scanner = new ScannerManager(this);
    this.theme = new ThemeManager(this);
    // this.pullToRefresh = new PullToRefreshManager(this);
    
    this.init();
  }

  async init() {
    console.log('App initializing...');
    
    // Wait for DOM to be ready
    if (document.readyState === 'loading') {
      await new Promise(resolve => document.addEventListener('DOMContentLoaded', resolve));
    }
    
    // Wait for libraries to be ready
    await new Promise(resolve => {
      if (typeof QRCode !== 'undefined' && QRCode.toCanvas) {
        resolve();
      } else {
        window.addEventListener('librariesReady', resolve, { once: true });
      }
    });
    
    this.setupServiceWorker();
    this.setupOfflineHandling();
    // this.pullToRefresh.setupPullToRefresh();
    this.theme.initializeTheme();
    
    // Initialize i18n if available
    if (!window.i18n) {
      console.error('i18n not available during app init');
    }
    
    // Check authentication
    await this.auth.checkAuthentication();
    
    // Setup all event listeners
    this.setupEventListeners();
    
    // Hide loading screen
    this.hideLoadingScreen();
  }

  setupEventListeners() {
    // Navigation
    document.querySelectorAll('[data-tab]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const tab = e.currentTarget.dataset.tab;
        this.switchTab(tab);
      });
    });

    // Setup all module event listeners
    this.auth.setupAuthEventListeners();
    this.cards.setupCardEventListeners();
    this.scanner.setupScannerEventListeners();
    this.theme.setupThemeEventListeners();
    this.data.setupDataEventListeners();

    // Settings - Language switching
    const languageInputs = document.querySelectorAll('input[name="language"]');
    languageInputs.forEach(input => {
      input.addEventListener('change', this.handleLanguageChange.bind(this));
    });
  }

  // Core app methods
  switchTab(tabName) {
    // Update navigation
    document.querySelectorAll('.nav-item').forEach(item => {
      item.classList.remove('active');
    });
    
    const targetNavItem = document.querySelector(`[data-tab="${tabName}"]`);
    if (targetNavItem) {
      targetNavItem.classList.add('active');
    } else {
      // Try alternative selector as fallback
      const altNavItem = document.querySelector(`.nav-item[data-tab="${tabName}"]`);
      if (altNavItem) {
        altNavItem.classList.add('active');
      }
    }

    // Update panels - use correct class name
    document.querySelectorAll('.tab-panel').forEach(panel => {
      panel.classList.remove('active');
    });
    
    const targetPanel = document.getElementById(`${tabName}-panel`);
    if (targetPanel) {
      targetPanel.classList.add('active');
      AppState.currentTab = tabName;
      
      // Reset scroll position to top when switching tabs
      setTimeout(() => {
        window.scrollTo(0, 0);
        targetPanel.scrollTop = 0;
      }, 0);
      
      // Special handling for cards tab to ensure cards are rendered
      if (tabName === 'cards' && AppState.cards) {
        setTimeout(() => {
          this.renderCards();
        }, 10);
      }
    } else {
      console.error(`❌ Could not find panel with id="${tabName}-panel"`);
      // Debug: log available panels
      const availablePanels = Array.from(document.querySelectorAll('[id$="-panel"]')).map(p => p.id);
      console.log('Available panels:', availablePanels);
    }
  }

  closeAllModals() {
    // Close card modal
    document.getElementById('card-modal')?.classList.remove('show');
    
    // Close scanner modal
    document.getElementById('scanner-modal')?.classList.remove('show');
    if (this.scanner.currentStream) {
      this.scanner.closeScanner();
    }
    
    // Restore body scroll
    document.body.style.overflow = '';
  }

  hideLoadingScreen() {
    setTimeout(() => {
      document.getElementById('loading-screen').classList.add('hidden');
    }, 500);
  }

  // Language handling
  handleLanguageChange(e) {
    const language = e.target.value;
    window.i18n.setLanguage(language);
    window.i18n.updatePageTexts();
    
    // Update server if user is logged in
    if (AppState.user) {
      this.updateUserLanguage(language);
    }
  }

  async updateUserLanguage(language) {
    try {
      await this.data.apiCall('/auth/profile', {
        method: 'PUT',
        body: JSON.stringify({ language })
      });
      
      AppState.user.language = language;
      this.data.saveLocalData();
      UIUtils.showToast('success', 'Мову змінено');
    } catch (error) {
      console.error('Language update error:', error);
    }
  }

  // Service Worker setup
  setupServiceWorker() {
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register('/sw.js')
        .then(registration => {
          console.log('SW registered:', registration);
          
          registration.addEventListener('updatefound', () => {
            const newWorker = registration.installing;
            newWorker.addEventListener('statechange', () => {
              if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                UIUtils.showToast('info', 'Доступне оновлення додатку');
              }
            });
          });
        })
        .catch(error => {
          console.error('SW registration failed:', error);
        });
    }
  }

  // Offline handling
  setupOfflineHandling() {
    // Update online status
    AppState.isOnline = navigator.onLine;
    
    // Register for background sync if supported
    if ('serviceWorker' in navigator && 'sync' in window.ServiceWorkerRegistration.prototype) {
      // Register for background sync
    }
  }

  // Delegate methods to appropriate managers
  apiCall(endpoint, options = {}) {
    return this.data.apiCall(endpoint, options);
  }

  loadLocalData() {
    return this.data.loadLocalData();
  }

  saveLocalData() {
    return this.data.saveLocalData();
  }

  updateProfile() {
    return this.data.updateProfile();
  }

  renderCards() {
    return this.cards.renderCards();
  }

  updateCodePreview(codeType) {
    return this.cards.updateCodePreview(codeType);
  }

  generateCardPreview(card, cardElement) {
    return this.cards.generateCardPreview(card, cardElement);
  }

  // Legacy methods for compatibility
  showToast(type, message, duration) {
    return UIUtils.showToast(type, message, duration);
  }

  escapeHtml(text) {
    return UIUtils.escapeHtml(text);
  }

  safeT(key, fallback) {
    return UIUtils.safeT(key, fallback);
  }

  showModal(options) {
    return UIUtils.showModal(options);
  }

  showAlert(message, title) {
    return UIUtils.showAlert(message, title);
  }

  showConfirm(message, title) {
    return UIUtils.showConfirm(message, title);
  }

  showPrompt(message, defaultValue, title) {
    return UIUtils.showPrompt(message, defaultValue, title);
  }

  setButtonLoading(button, isLoading) {
    return UIUtils.setButtonLoading(button, isLoading);
  }
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  // Make app globally available
  window.app = new LoyaltyCardsApp();
});

// Also make app available immediately for testing
if (document.readyState === 'complete' || document.readyState === 'interactive') {
  window.app = new LoyaltyCardsApp();
}