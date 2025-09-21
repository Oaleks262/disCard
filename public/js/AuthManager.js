// AuthManager.js - Authentication management functionality
class AuthManager {
  constructor(app) {
    this.app = app;
    this.lastActiveTime = Date.now();
    this.resumeDebounceTimeout = null;
    this.resumeDebounceDelay = 2000; // 2 seconds debounce
    this.justAuthenticated = false; // Flag to prevent resume check right after login
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
        
        // Server handles encryption, cards come decrypted
        AppState.cards = response.cards || [];
        
        // Save data locally
        this.app.saveLocalData();
        
        // Update language
        if (response.user.language) {
          window.i18n.setLanguage(response.user.language);
          window.i18n.updatePageTexts();
        }
        
        UIUtils.showToast('success', UIUtils.safeT('messages.loginSuccess', 'Успішний вхід'));
        this.justAuthenticated = true; // Prevent resume check
        this.showAppScreen();
        
        // Wait for app screen to load before updating UI
        setTimeout(() => {
          this.app.updateProfile();
          
          // Wait for encryption initialization before rendering cards
          setTimeout(() => {
            this.app.renderCards();
          }, 1200); // Wait extra time for encryption setup
          
          // Reset flag after UI is updated
          setTimeout(() => {
            this.justAuthenticated = false;
          }, 2000);
        }, 100);
      } else if (response.requiresVerification) {
        // Show 2FA verification screen
        this.showTwoFactorScreen(response.email);
        UIUtils.showToast('info', UIUtils.safeT('twofa.sentTo', 'Код відправлено на:') + ' ' + response.email);
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
        // Don't automatically log in after registration
        // Clear any stored token and redirect to login form
        localStorage.removeItem('authToken');
        window.api.setToken(null);
        AppState.user = null;
        AppState.cards = [];
        
        UIUtils.showToast('success', UIUtils.safeT('messages.registerSuccess', 'Акаунт створено успішно! Увійдіть у свій акаунт'));
        
        // Clear registration form
        const registerForm = document.getElementById('register-form-element');
        if (registerForm) {
          registerForm.reset();
        }
        
        // Switch to login form
        this.showLoginForm();
        
        // Pre-fill email for convenience
        const emailInput = document.getElementById('login-email');
        if (emailInput) {
          emailInput.value = email;
          // Focus on password field
          setTimeout(() => {
            const passwordInput = document.getElementById('login-password');
            if (passwordInput) {
              passwordInput.focus();
            }
          }, 100);
        }
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
    
    // Clear any cached data
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
    document.getElementById('twofa-screen')?.classList.add('hidden');
    document.getElementById('app-container').classList.remove('hidden');
    
    // Initialize default active tab if no tab is currently active
    if (!AppState.currentTab) {
      this.app.switchTab('cards');
    }
    
    // Close any open modals
    this.app.closeAllModals();
  }

  showTwoFactorScreen(email) {
    document.getElementById('loading-screen').classList.add('hidden');
    document.getElementById('auth-screen').classList.add('hidden');
    
    // Show 2FA screen or create it if it doesn't exist
    let twofaScreen = document.getElementById('twofa-screen');
    if (!twofaScreen) {
      this.createTwoFactorScreen();
      twofaScreen = document.getElementById('twofa-screen');
    }
    
    twofaScreen.classList.remove('hidden');
    
    // Update email display
    const emailDisplay = document.getElementById('twofa-email');
    if (emailDisplay) {
      emailDisplay.textContent = email;
    }
    
    // Store email for verification
    this.verificationEmail = email;
    
    // Clear any previous input
    const codeInputs = document.querySelectorAll('.twofa-code-input');
    codeInputs.forEach(input => input.value = '');
    
    // Focus first input
    const firstInput = document.querySelector('.twofa-code-input');
    if (firstInput) {
      setTimeout(() => firstInput.focus(), 100);
    }
    
    // Start countdown timer
    this.startResendTimer();
  }

  createTwoFactorScreen() {
    const html = `
      <div class="auth-screen" id="twofa-screen">
        <div class="auth-container">
          <div class="auth-header">
            <div class="logo">
              <img src="/icons/logo.png" alt="disCard" width="48" height="48" class="logo-icon">
              <span class="logo-text">disCard</span>
            </div>
          </div>
          
          <div class="auth-form">
            <h2 class="auth-title" data-i18n="twofa.title">Підтвердження входу</h2>
            <p class="auth-subtitle" data-i18n="twofa.subtitle">Введіть код підтвердження, відправлений на вашу електронну пошту</p>
            
            <div class="twofa-email-display">
              <span data-i18n="twofa.sentTo">Надіслано на:</span>
              <strong id="twofa-email"></strong>
            </div>
            
            <form id="twofa-form">
              <div class="twofa-code-container">
                <input type="text" class="twofa-code-input" maxlength="1" pattern="[0-9]" data-index="0">
                <input type="text" class="twofa-code-input" maxlength="1" pattern="[0-9]" data-index="1">
                <input type="text" class="twofa-code-input" maxlength="1" pattern="[0-9]" data-index="2">
                <input type="text" class="twofa-code-input" maxlength="1" pattern="[0-9]" data-index="3">
                <input type="text" class="twofa-code-input" maxlength="1" pattern="[0-9]" data-index="4">
              </div>
              
              <button type="submit" class="auth-button" id="twofa-verify-btn" data-i18n="twofa.verify">Підтвердити</button>
            </form>
            
            <div class="twofa-actions">
              <button type="button" class="link-button" id="twofa-resend-btn" data-i18n="twofa.resend">Надіслати код повторно</button>
              <span class="twofa-timer" id="twofa-timer"></span>
            </div>
            
            <div class="auth-switch">
              <button type="button" class="link-button" id="twofa-back-btn" data-i18n="twofa.back">Назад до входу</button>
            </div>
          </div>
        </div>
      </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', html);
    
    // Setup event listeners
    this.setupTwoFactorEventListeners();
  }

  setupTwoFactorEventListeners() {
    const form = document.getElementById('twofa-form');
    const inputs = document.querySelectorAll('.twofa-code-input');
    const resendBtn = document.getElementById('twofa-resend-btn');
    const backBtn = document.getElementById('twofa-back-btn');
    
    // Handle form submission
    form?.addEventListener('submit', (e) => this.handleTwoFactorVerification(e));
    
    // Handle input navigation
    inputs.forEach((input, index) => {
      input.addEventListener('input', (e) => {
        const value = e.target.value.replace(/[^0-9]/g, '');
        e.target.value = value;
        
        if (value && index < inputs.length - 1) {
          inputs[index + 1].focus();
        }
        
        // Auto-submit when all inputs are filled
        if (index === inputs.length - 1 && value) {
          const allFilled = Array.from(inputs).every(input => input.value);
          if (allFilled) {
            this.handleTwoFactorVerification(new Event('submit'));
          }
        }
      });
      
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Backspace' && !e.target.value && index > 0) {
          inputs[index - 1].focus();
        }
      });
    });
    
    // Handle resend button
    resendBtn?.addEventListener('click', () => this.handleResendCode());
    
    // Handle back button
    backBtn?.addEventListener('click', () => this.showAuthScreen());
  }

  async handleTwoFactorVerification(e) {
    e.preventDefault();
    
    const inputs = document.querySelectorAll('.twofa-code-input');
    const code = Array.from(inputs).map(input => input.value).join('');
    
    if (code.length !== 5) {
      UIUtils.showToast('error', UIUtils.safeT('twofa.enterAllDigits', 'Введіть усі 5 цифр коду'));
      return;
    }
    
    const submitBtn = document.getElementById('twofa-verify-btn');
    UIUtils.setButtonLoading(submitBtn, true);
    
    try {
      const response = await this.app.apiCall('/auth/verify-code', {
        method: 'POST',
        body: JSON.stringify({ 
          email: this.verificationEmail, 
          code: code 
        })
      });
      
      if (response.token) {
        // API client handles token storage
        AppState.user = response.user;
        AppState.cards = response.cards || [];
        
        // Save data locally
        this.app.saveLocalData();
        
        // Update language
        if (response.user.language) {
          window.i18n.setLanguage(response.user.language);
          window.i18n.updatePageTexts();
        }
        
        UIUtils.showToast('success', UIUtils.safeT('twofa.verificationSuccess', 'Вхід підтверджено успішно'));
        this.justAuthenticated = true;
        this.showAppScreen();
        
        // Wait for app screen to load before updating UI
        setTimeout(() => {
          this.app.updateProfile();
          
          // Wait for encryption initialization before rendering cards
          setTimeout(() => {
            this.app.renderCards();
          }, 1200); // Wait extra time for encryption setup
          
          setTimeout(() => {
            this.justAuthenticated = false;
          }, 2000);
        }, 100);
      }
    } catch (error) {
      console.error('2FA verification error:', error);
      UIUtils.showToast('error', error.message || UIUtils.safeT('twofa.invalidCode', 'Невірний код підтвердження'));
      
      // Clear inputs on error
      inputs.forEach(input => input.value = '');
      inputs[0].focus();
    } finally {
      UIUtils.setButtonLoading(submitBtn, false);
    }
  }

  async handleResendCode() {
    const resendBtn = document.getElementById('twofa-resend-btn');
    UIUtils.setButtonLoading(resendBtn, true);
    
    try {
      await this.app.apiCall('/auth/resend-code', {
        method: 'POST',
        body: JSON.stringify({ email: this.verificationEmail })
      });
      
      UIUtils.showToast('success', UIUtils.safeT('twofa.resendSuccess', 'Код відправлено повторно'));
      this.startResendTimer();
    } catch (error) {
      console.error('Resend code error:', error);
      UIUtils.showToast('error', error.message || UIUtils.safeT('messages.networkError', 'Помилка мережі'));
    } finally {
      UIUtils.setButtonLoading(resendBtn, false);
    }
  }

  startResendTimer() {
    const timerElement = document.getElementById('twofa-timer');
    const resendBtn = document.getElementById('twofa-resend-btn');
    
    if (!timerElement || !resendBtn) return;
    
    let seconds = 60;
    resendBtn.disabled = true;
    
    const timer = setInterval(() => {
      timerElement.textContent = `(${UIUtils.safeT('twofa.resendIn', 'Повторне надсилання доступне через:')} ${seconds} ${UIUtils.safeT('twofa.seconds', 'секунд')})`;
      seconds--;
      
      if (seconds < 0) {
        clearInterval(timer);
        timerElement.textContent = '';
        resendBtn.disabled = false;
      }
    }, 1000);
  }

  async handleAppResume() {
    // Don't check if user is not authenticated
    if (!AppState.user) {
      return;
    }
    
    // Don't check if we just authenticated (prevent resume check right after login/register)
    if (this.justAuthenticated) {
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

    // Forgot password
    document.getElementById('forgot-password-btn')?.addEventListener('click', (e) => {
      e.preventDefault();
      this.showForgotPasswordModal();
    });

    // Profile actions
    document.getElementById('logout-button')?.addEventListener('click', this.handleLogout.bind(this));
    document.getElementById('change-password-form')?.addEventListener('submit', this.handleChangePassword.bind(this));
    document.getElementById('edit-name')?.addEventListener('click', this.handleEditName.bind(this));
  }

  // Forgot Password Modal functionality
  showForgotPasswordModal() {
    const modal = document.getElementById('forgot-password-modal');
    const form = document.getElementById('forgot-password-form');
    const emailInput = document.getElementById('forgot-email');
    const alert = document.getElementById('forgot-password-alert');
    const loading = document.getElementById('forgot-password-loading');

    // Reset form
    form.reset();
    alert.style.display = 'none';
    loading.classList.add('hidden');
    form.style.display = 'block';

    // Show modal
    modal.classList.remove('hidden');
    modal.classList.add('show');

    // Setup event listeners
    const closeModal = () => {
      modal.classList.add('hidden');
      modal.classList.remove('show');
    };

    // Close button
    document.getElementById('forgot-password-close').onclick = closeModal;
    document.getElementById('forgot-password-cancel').onclick = closeModal;

    // Close on backdrop click
    modal.onclick = (e) => {
      if (e.target === modal || e.target.classList.contains('modal-backdrop')) {
        closeModal();
      }
    };

    // Form submission
    form.onsubmit = (e) => this.handleForgotPassword(e);

    // Focus email input
    setTimeout(() => emailInput.focus(), 100);
  }

  async handleForgotPassword(e) {
    e.preventDefault();
    
    const emailInput = document.getElementById('forgot-email');
    const alert = document.getElementById('forgot-password-alert');
    const loading = document.getElementById('forgot-password-loading');
    const form = document.getElementById('forgot-password-form');
    const submitBtn = document.getElementById('forgot-password-submit');

    const email = emailInput.value.trim();
    
    if (!email) {
      this.showForgotPasswordAlert('error', 'Введіть електронну пошту');
      return;
    }

    // Show loading
    form.style.display = 'none';
    loading.classList.remove('hidden');
    alert.style.display = 'none';

    try {
      const response = await fetch('/api/auth/forgot-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email })
      });

      const data = await response.json();

      if (response.ok) {
        this.showForgotPasswordAlert('success', 
          `Новий пароль згенеровано та надіслано на ${email}. Перевірте вашу пошту.`
        );
        
        // Hide loading, show success
        loading.classList.add('hidden');
        
        // Close modal after 3 seconds
        setTimeout(() => {
          const modal = document.getElementById('forgot-password-modal');
          modal.classList.add('hidden');
          modal.classList.remove('show');
        }, 3000);
      } else {
        throw new Error(data.error || 'Помилка відновлення паролю');
      }
    } catch (error) {
      console.error('Forgot password error:', error);
      this.showForgotPasswordAlert('error', error.message);
      
      // Show form again
      loading.classList.add('hidden');
      form.style.display = 'block';
    }
  }

  showForgotPasswordAlert(type, message) {
    const alert = document.getElementById('forgot-password-alert');
    alert.className = `alert alert-${type}`;
    alert.textContent = message;
    alert.style.display = 'block';
  }
}

// Export for use in other modules
window.AuthManager = AuthManager;