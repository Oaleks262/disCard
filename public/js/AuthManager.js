// AuthManager.js - Authentication management functionality
class AuthManager {
  constructor(app) {
    this.app = app;
    this.lastActiveTime = Date.now();
    this.resumeDebounceTimeout = null;
    this.resumeDebounceDelay = 2000; // 2 seconds debounce
  }

  async checkAuthentication() {
    // Check if we have a token in localStorage and set it in API client
    const token = localStorage.getItem('authToken') || localStorage.getItem('token');
    
    if (token) {
      window.api.setToken(token);
      // Migrate old token key to new one if needed
      if (localStorage.getItem('token') && !localStorage.getItem('authToken')) {
        localStorage.setItem('authToken', token);
        localStorage.removeItem('token');
      }
    }
    
    if (!token) {
      this.showAuthScreen();
      return;
    }

    // Load cached data first
    this.app.loadLocalData();

    // Try server first, fallback to cache if offline
    try {
      const response = await this.app.apiCall('/auth/me');
      
      if (response.user) {
        // Save user data
        AppState.user = response.user;
        
        // Save cards data - check both possible locations  
        let serverCards = [];
        if (response.user.cards && Array.isArray(response.user.cards) && response.user.cards.length > 0) {
          serverCards = response.user.cards;
        } else if (response.cards && Array.isArray(response.cards) && response.cards.length > 0) {
          serverCards = response.cards;
        } else {
          // Don't overwrite AppState.cards if server has no cards
          serverCards = AppState.cards || [];
        }
        
        AppState.cards = serverCards;
        
        // Save to localStorage
        this.app.saveLocalData();
        
        // Set language
        if (response.user.language) {
          window.i18n.setLanguage(response.user.language);
        }
        
        // Show app
        this.showAppScreen();
        this.app.updateProfile();
        this.app.renderCards();
        
      } else {
        throw new Error('Invalid server response');
      }
    } catch (error) {
      console.error('Server validation failed:', error);
      
      // Only clear auth on explicit 401 Unauthorized, not on network errors
      if (error.message && (error.message.includes('Unauthorized') || error.message.includes('401'))) {
        localStorage.removeItem('authToken');
        window.api.setToken(null);
        AppState.user = null;
        AppState.cards = [];
        this.showAuthScreen();
      } else {
        // Server unavailable - try cache
        this.app.loadLocalData();
        
        if (AppState.user) {
          this.showAppScreen();
          this.app.updateProfile();
          this.app.renderCards();
          
          if (error.message && error.message.includes('Too many requests')) {
            UIUtils.showToast('warning', 'Забагато запитів. Використовуємо кешовані дані');
          } else {
            UIUtils.showToast('info', 'Немає з\'єднання. Працюємо офлайн');
          }
        } else {
          this.showAuthScreen();
        }
      }
    }
  }

  async handleLogin(e) {
    e.preventDefault();
    
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    
    if (!email || !password) {
      UIUtils.showToast('error', UIUtils.safeT('messages.fillAllFields', 'Заповніть всі поля'));
      return;
    }

    const submitBtn = e.target.querySelector('button[type="submit"]');
    UIUtils.setButtonLoading(submitBtn, true);

    try {
      const response = await this.app.apiCall('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password })
      });

      if (response.token) {
        // API client handles token storage
        AppState.user = response.user;
        AppState.cards = response.cards || [];
        
        // Update language
        if (response.user.language) {
          window.i18n.setLanguage(response.user.language);
          window.i18n.updatePageTexts();
        }
        
        UIUtils.showToast('success', UIUtils.safeT('messages.loginSuccess', 'Успішний вхід'));
        this.showAppScreen();
        this.app.updateProfile();
        this.app.renderCards();
      } else {
        throw new Error('No token received');
      }
    } catch (error) {
      console.error('Login error:', error);
      UIUtils.showToast('error', error.message || UIUtils.safeT('messages.invalidCredentials', 'Невірні дані для входу'));
    } finally {
      UIUtils.setButtonLoading(submitBtn, false);
    }
  }

  async handleRegister(e) {
    e.preventDefault();
    
    const name = document.getElementById('register-name').value;
    const email = document.getElementById('register-email').value;
    const password = document.getElementById('register-password').value;
    
    if (!name || !email || !password) {
      UIUtils.showToast('error', UIUtils.safeT('messages.fillAllFields', 'Заповніть всі поля'));
      return;
    }

    if (password.length < 6) {
      UIUtils.showToast('error', UIUtils.safeT('messages.passwordTooShort', 'Пароль повинен містити мінімум 6 символів'));
      return;
    }

    const submitBtn = e.target.querySelector('button[type="submit"]');
    UIUtils.setButtonLoading(submitBtn, true);

    try {
      const response = await this.app.apiCall('/auth/register', {
        method: 'POST',
        body: JSON.stringify({ 
          name, 
          email, 
          password,
          language: window.i18n.getCurrentLanguage()
        })
      });

      if (response.token) {
        // API client handles token storage
        AppState.user = response.user;
        AppState.cards = response.cards || [];
        
        UIUtils.showToast('success', UIUtils.safeT('messages.registerSuccess', 'Акаунт створено'));
        this.showAppScreen();
        this.app.updateProfile();
        this.app.renderCards();
      } else {
        throw new Error('No token received');
      }
    } catch (error) {
      console.error('Register error:', error);
      UIUtils.showToast('error', error.message || UIUtils.safeT('messages.serverError', 'Помилка сервера'));
    } finally {
      UIUtils.setButtonLoading(submitBtn, false);
    }
  }

  handleLogout() {
    window.api.logout();
    AppState.user = null;
    AppState.cards = [];
    
    UIUtils.showToast('success', UIUtils.safeT('messages.logoutSuccess', 'Вихід виконано'));
    this.showAuthScreen();
  }

  async handleChangePassword(e) {
    e.preventDefault();
    
    const currentPassword = document.getElementById('current-password').value;
    const newPassword = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-password').value;
    
    if (!currentPassword || !newPassword || !confirmPassword) {
      UIUtils.showToast('error', UIUtils.safeT('messages.fillAllFields', 'Заповніть всі поля'));
      return;
    }

    if (newPassword !== confirmPassword) {
      UIUtils.showToast('error', UIUtils.safeT('messages.passwordsDontMatch', 'Паролі не збігаються'));
      return;
    }

    if (newPassword.length < 6) {
      UIUtils.showToast('error', UIUtils.safeT('messages.passwordTooShort', 'Пароль занадто короткий'));
      return;
    }

    const submitBtn = e.target.querySelector('button[type="submit"]');
    UIUtils.setButtonLoading(submitBtn, true);

    try {
      await this.app.apiCall('/auth/password', {
        method: 'PUT',
        body: JSON.stringify({ currentPassword, newPassword })
      });

      UIUtils.showToast('success', UIUtils.safeT('messages.passwordChanged', 'Пароль змінено'));
      e.target.reset();
    } catch (error) {
      console.error('Change password error:', error);
      UIUtils.showToast('error', error.message || UIUtils.safeT('messages.serverError', 'Помилка сервера'));
    } finally {
      UIUtils.setButtonLoading(submitBtn, false);
    }
  }

  async handleEditName() {
    const nameSpan = document.getElementById('user-name');
    const currentName = nameSpan.textContent;
    
    const newName = await UIUtils.showPrompt(UIUtils.safeT('auth.name', 'Ім\'я'), currentName);
    if (newName && newName !== currentName) {
      try {
        const response = await this.app.apiCall('/auth/profile', {
          method: 'PUT',
          body: JSON.stringify({ name: newName })
        });

        AppState.user = response.user;
        this.app.updateProfile();
        UIUtils.showToast('success', UIUtils.safeT('messages.profileUpdated', 'Профіль оновлено'));
      } catch (error) {
        console.error('Update name error:', error);
        UIUtils.showToast('error', error.message || UIUtils.safeT('messages.serverError', 'Помилка сервера'));
      }
    }
  }

  showLoginForm() {
    document.getElementById('register-form').classList.add('hidden');
    document.getElementById('login-form').classList.remove('hidden');
  }

  showRegisterForm() {
    document.getElementById('login-form').classList.add('hidden');
    document.getElementById('register-form').classList.remove('hidden');
  }

  showAuthScreen() {
    document.getElementById('loading-screen').classList.add('hidden');
    document.getElementById('auth-screen').classList.remove('hidden');
    document.getElementById('app-container').classList.add('hidden');
  }

  showAppScreen() {
    document.getElementById('loading-screen').classList.add('hidden');
    document.getElementById('auth-screen').classList.add('hidden');
    document.getElementById('app-container').classList.remove('hidden');
    
    // Initialize default active tab if no tab is currently active
    if (!AppState.currentTab) {
      this.app.switchTab('cards');
    }
    
    // Close any open modals
    this.app.closeAllModals();
  }

  async handleAppResume() {
    // Don't check if user is not authenticated
    if (!AppState.user) {
      return;
    }

    // Check if we have a token
    const token = localStorage.getItem('authToken');
    if (!token) {
      this.handleLogout();
      return;
    }

    // Debounce rapid resume calls
    if (this.resumeDebounceTimeout) {
      clearTimeout(this.resumeDebounceTimeout);
    }

    this.resumeDebounceTimeout = setTimeout(async () => {
      // Only check token validity if app was in background for more than 30 seconds
      if (!this.lastActiveTime || Date.now() - this.lastActiveTime > 30000) {
        try {
          const response = await this.app.apiCall('/auth/me');
          
          if (response && response.user) {
            // Update app state with fresh data
            AppState.user = response.user;
            
            // Always update cards from server response
            if (response.cards && Array.isArray(response.cards)) {
              AppState.cards = response.cards;
            } else {
              AppState.cards = [];
            }
            
            // Save data immediately
            this.app.saveLocalData();
            
            // Update language if changed
            if (response.user.language && response.user.language !== window.i18n.getCurrentLanguage()) {
              window.i18n.setLanguage(response.user.language);
              window.i18n.updatePageTexts();
            }
            
            // Refresh UI
            this.app.updateProfile();
            this.app.renderCards();
          }
        } catch (error) {
          console.error('Token validation failed:', error);
          // Token is invalid, logout user
          this.handleLogout();
          UIUtils.showToast('error', UIUtils.safeT('messages.sessionExpired', 'Сесія закінчилася, увійдіть знову'));
        }
      }
      
      this.lastActiveTime = Date.now();
    }, this.resumeDebounceDelay);
  }

  // Setup authentication event listeners
  setupAuthEventListeners() {
    // Authentication forms
    document.getElementById('login-form-element')?.addEventListener('submit', this.handleLogin.bind(this));
    document.getElementById('register-form-element')?.addEventListener('submit', this.handleRegister.bind(this));
    
    // Auth switchers
    document.getElementById('show-register')?.addEventListener('click', (e) => {
      e.preventDefault();
      this.showRegisterForm();
    });
    
    document.getElementById('show-login')?.addEventListener('click', (e) => {
      e.preventDefault();
      this.showLoginForm();
    });

    // Profile actions
    document.getElementById('logout-button')?.addEventListener('click', this.handleLogout.bind(this));
    document.getElementById('change-password-form')?.addEventListener('submit', this.handleChangePassword.bind(this));
    document.getElementById('edit-name')?.addEventListener('click', this.handleEditName.bind(this));
  }
}

// Export for use in other modules
window.AuthManager = AuthManager;