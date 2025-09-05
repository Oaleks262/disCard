// Main App JavaScript - Loyalty Cards PWA

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

// Main App Class
class LoyaltyCardsApp {
  constructor() {
    this.init();
  }

  async init() {
    console.log('App initializing...');
    
    // Wait for DOM to be ready
    if (document.readyState === 'loading') {
      await new Promise(resolve => document.addEventListener('DOMContentLoaded', resolve));
    }
    
    // Wait for libraries to be ready
    console.log('⏳ Waiting for libraries to load...');
    await new Promise(resolve => {
      if (typeof QRCode !== 'undefined' && QRCode.toCanvas) {
        console.log('✅ Libraries already loaded');
        resolve();
      } else {
        window.addEventListener('librariesReady', resolve, { once: true });
      }
    });
    
    // Check if required libraries are loaded
    console.log('📚 Final library check:');
    console.log('- QRCode library:', typeof QRCode !== 'undefined' ? '✅' : '❌', QRCode?.toCanvas ? '(with toCanvas)' : '');
    console.log('- JsBarcode library:', typeof JsBarcode !== 'undefined' ? '✅' : '❌');
    console.log('- jsQR library:', typeof jsQR !== 'undefined' ? '✅' : '❌');
    console.log('- Quagga library:', typeof Quagga !== 'undefined' ? '✅' : '❌');
    
    this.setupServiceWorker();
    this.setupOfflineHandling();
    this.setupPullToRefresh();
    this.initializeTheme();
    
    // Check if i18n is available
    if (window.i18n) {
      console.log('i18n available, current language:', window.i18n.getCurrentLanguage());
    } else {
      console.error('i18n not available during app init');
    }
    
    // Check authentication
    await this.checkAuthentication();
    
    // Setup event listeners after everything else is ready
    this.setupEventListeners();
    
    // Add global test function for debugging
    window.testAddCard = () => {
      console.log('🧪 Testing add card function manually...');
      const form = document.getElementById('add-card-form');
      if (form) {
        const fakeEvent = { 
          preventDefault: () => console.log('preventDefault called'),
          target: form,
          type: 'submit'
        };
        this.handleAddCard(fakeEvent);
      }
    };
    
    // Add function to fill test data
    window.fillTestData = () => {
      console.log('📝 Filling test data...');
      const nameField = document.getElementById('card-name');
      const codeField = document.getElementById('card-code');
      const barcodeType = document.querySelector('input[name="codeType"][value="barcode"]');
      
      if (nameField) nameField.value = 'Тест картка';
      if (codeField) codeField.value = '1234567890123';
      if (barcodeType) barcodeType.checked = true;
      
      console.log('Test data filled');
    };
    
    // Add function to reset button handlers
    window.resetButtonHandlers = () => {
      console.log('🔄 Resetting button handlers...');
      this.setupEventListeners();
    };
    
    // Add function to enable button for testing
    window.enableButton = () => {
      const btn = document.querySelector('.submit-button');
      if (btn) {
        btn.disabled = false;
        console.log('🟢 Button manually enabled');
      }
    };
    
    // Add function to test QR code generation
    window.testQR = () => {
      console.log('🧪 Testing QR code generation...');
      const nameField = document.getElementById('card-name');
      const codeField = document.getElementById('card-code');
      const qrType = document.querySelector('input[name="codeType"][value="qrcode"]');
      
      if (nameField) nameField.value = 'Тест QR картка';
      if (codeField) codeField.value = 'https://example.com/qr-test';
      if (qrType) {
        qrType.checked = true;
        // Trigger change event
        qrType.dispatchEvent(new Event('change'));
      }
      
      // Force update preview
      setTimeout(() => {
        window.app.updateCodePreview('qrcode');
      }, 100);
      
      console.log('QR test data filled');
    };
    
    // Add global button test
    window.testButton = () => {
      console.log('🔍 Testing submit button...');
      const button = document.querySelector('.submit-button');
      const form = document.getElementById('add-card-form');
      
      console.log('Submit button found:', !!button);
      console.log('Form found:', !!form);
      
      if (button) {
        console.log('Button properties:', {
          disabled: button.disabled,
          type: button.type,
          form: button.form === form,
          classList: button.classList.toString(),
          styleDisplay: button.style.display,
          offsetParent: !!button.offsetParent,
          clientWidth: button.clientWidth,
          clientHeight: button.clientHeight,
          textContent: button.textContent.trim()
        });
        
        const computedStyle = getComputedStyle(button);
        console.log('Computed styles:', {
          display: computedStyle.display,
          visibility: computedStyle.visibility,
          opacity: computedStyle.opacity,
          pointerEvents: computedStyle.pointerEvents,
          zIndex: computedStyle.zIndex,
          position: computedStyle.position
        });
        
        console.log('Attempting direct click...');
        button.click();
        
        // Also try triggering click event manually
        console.log('Triggering manual click event...');
        button.dispatchEvent(new MouseEvent('click', {
          bubbles: true,
          cancelable: true,
          view: window
        }));
      }
    };
    
    // Hide loading screen
    this.hideLoadingScreen();
  }

  setupEventListeners() {
    console.log('=== Setting up event listeners ===');
    console.log('Document readyState:', document.readyState);
    console.log('Add panel visible:', document.getElementById('add-panel')?.classList.contains('active'));
    console.log('Add panel display:', getComputedStyle(document.getElementById('add-panel')).display);
    
    // Add test to switch to add tab
    window.switchToAddTab = () => {
      console.log('🔄 Switching to add tab...');
      this.switchTab('add');
      setTimeout(() => {
        window.testButton();
      }, 500);
    };
    
    // Navigation
    document.querySelectorAll('[data-tab]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const tab = e.currentTarget.dataset.tab;
        console.log(`📱 Navigation click: ${tab}`);
        this.switchTab(tab);
      });
    });

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

    // Card actions - DETAILED DIAGNOSTICS
    const addCardForm = document.getElementById('add-card-form');
    console.log('🔍 FORM DIAGNOSTICS:');
    console.log('- Add card form found:', !!addCardForm);
    console.log('- Form ID:', addCardForm?.id);
    console.log('- Form class:', addCardForm?.className);
    console.log('- Form parent:', addCardForm?.parentElement?.tagName);
    
    if (addCardForm) {
      console.log('Form found, will setup button handler...');
      
      // Find ALL submit buttons
      const submitButtons = addCardForm.querySelectorAll('button[type="submit"], .submit-button, button');
      console.log('🔍 BUTTON DIAGNOSTICS:');
      console.log('- Total buttons found:', submitButtons.length);
      
      submitButtons.forEach((btn, index) => {
        console.log(`- Button ${index + 1}:`, {
          tagName: btn.tagName,
          type: btn.type,
          className: btn.className,
          disabled: btn.disabled,
          textContent: btn.textContent.trim(),
          offsetParent: !!btn.offsetParent
        });
      });
      
      // Try to find submit button by different selectors
      const submitButton1 = addCardForm.querySelector('button[type="submit"]');
      const submitButton2 = addCardForm.querySelector('.submit-button');
      const submitButton3 = document.querySelector('.submit-button');
      
      console.log('Submit button by type="submit":', !!submitButton1);
      console.log('Submit button by .submit-button in form:', !!submitButton2);
      console.log('Submit button by .submit-button globally:', !!submitButton3);
      
      const submitButton = submitButton1 || submitButton2 || submitButton3;
      
      if (submitButton) {
        console.log('Using submit button:', submitButton);
        
        // CLEAR ALL EXISTING HANDLERS
        submitButton.onclick = null;
        submitButton.removeEventListener('click', () => {});
        
        // ADD SINGLE, SIMPLE HANDLER
        console.log('🔧 Adding MAIN click handler...');
        submitButton.addEventListener('click', (e) => {
          console.log('🎯 MAIN SUBMIT BUTTON CLICKED!');
          e.preventDefault(); // Prevent default form submission
          
          // Create proper form event
          const formEvent = {
            preventDefault: () => {},
            target: addCardForm,
            type: 'submit'
          };
          
          console.log('Calling handleAddCard...');
          this.handleAddCard(formEvent);
        }, { once: false, passive: false });
        
        // Also prevent the form from submitting traditionally
        addCardForm.addEventListener('submit', (e) => {
          console.log('🚫 Form submit prevented (handled by button)');
          e.preventDefault();
        });
        
        console.log('✅ Button handler setup complete');
        
        // Set initial validation state
        console.log('🔧 Setting initial validation state...');
        this.updateFormValidation();
        
        // Test the handler after a short delay
        setTimeout(() => {
          console.log('🧪 Testing button handler after setup...');
          console.log('Button still in DOM:', document.contains(submitButton));
          console.log('Button disabled:', submitButton.disabled);
          console.log('Button onclick:', submitButton.onclick);
        }, 100);
        
      } else {
        console.error('❌ NO SUBMIT BUTTON FOUND!');
      }
    }
    
    document.getElementById('scan-button')?.addEventListener('click', this.openScanner.bind(this));
    document.getElementById('cards-search')?.addEventListener('input', this.handleCardsSearch.bind(this));

    // Scanner modal
    document.getElementById('scanner-close')?.addEventListener('click', this.closeScanner.bind(this));

    // Card modal
    document.getElementById('modal-close')?.addEventListener('click', this.closeCardModal.bind(this));
    document.getElementById('copy-code-btn')?.addEventListener('click', this.copyCardCode.bind(this));
    document.getElementById('delete-card-btn')?.addEventListener('click', this.deleteCard.bind(this));

    // Settings
    document.querySelectorAll('input[name="theme"]').forEach(input => {
      input.addEventListener('change', this.handleThemeChange.bind(this));
    });
    
    const languageInputs = document.querySelectorAll('input[name="language"]');
    console.log('Found language inputs:', languageInputs.length);
    languageInputs.forEach(input => {
      console.log('Adding language listener to:', input.value);
      input.addEventListener('change', this.handleLanguageChange.bind(this));
    });

    // Theme toggle
    document.getElementById('theme-toggle')?.addEventListener('click', this.toggleTheme.bind(this));

    // Code type selector
    document.querySelectorAll('input[name="codeType"]').forEach(input => {
      input.addEventListener('change', this.handleCodeTypeChange.bind(this));
    });

    // Code input for preview and validation
    document.getElementById('card-code')?.addEventListener('input', (e) => {
      this.updateCodePreview();
      this.updateFormValidation();
    });
    document.getElementById('card-name')?.addEventListener('input', this.updateFormValidation.bind(this));

    // Online/offline handling
    window.addEventListener('online', () => {
      AppState.isOnline = true;
      this.handleOnlineStatus();
    });

    window.addEventListener('offline', () => {
      AppState.isOnline = false;
      this.handleOfflineStatus();
    });

    // App focus/resume handling - check authentication and refresh data
    window.addEventListener('focus', () => {
      this.handleAppResume();
    });

    // Handle page visibility change (mobile browser focus)
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) {
        this.handleAppResume();
      }
    });

    // Handle page show event (when navigating back)
    window.addEventListener('pageshow', (event) => {
      if (event.persisted) {
        this.handleAppResume();
      }
    });
  }

  async setupServiceWorker() {
    if ('serviceWorker' in navigator) {
      try {
        const registration = await navigator.serviceWorker.register('/sw.js');
        console.log('Service Worker registered:', registration);
        
        // Listen for Service Worker messages
        navigator.serviceWorker.addEventListener('message', (event) => {
          if (event.data && event.data.type === 'SW_UPDATED') {
            console.log('Service Worker updated, preserving user data');
            // Save current data before any potential reload
            this.saveLocalData();
          }
        });
        
        // Listen for updates
        registration.addEventListener('updatefound', () => {
          const newWorker = registration.installing;
          newWorker.addEventListener('statechange', () => {
            if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
              console.log('New Service Worker installed, saving data');
              // Save data before showing update notification
              this.saveLocalData();
              this.showUpdateNotification();
            }
          });
        });
      } catch (error) {
        console.error('Service Worker registration failed:', error);
      }
    }
  }

  setupOfflineHandling() {
    // Setup background sync for offline actions
    if ('serviceWorker' in navigator && 'sync' in window.ServiceWorkerRegistration.prototype) {
      // Register for background sync
    }
  }

  setupPullToRefresh() {
    console.log('🔄 Setting up pull-to-refresh...');
    
    // Initialize pull-to-refresh state
    this.ptrState = {
      pulling: false,
      startY: 0,
      currentY: 0,
      threshold: 80,
      maxDistance: 120,
      refreshing: false
    };

    // Get elements
    this.ptrIndicator = document.getElementById('ptr-indicator');
    this.ptrIcon = document.getElementById('ptr-icon');
    this.ptrText = document.getElementById('ptr-text');
    this.appContainer = document.getElementById('app-container');

    if (!this.ptrIndicator || !this.appContainer) {
      console.warn('Pull-to-refresh elements not found');
      return;
    }

    // Touch event handlers
    this.appContainer.addEventListener('touchstart', this.handleTouchStart.bind(this), { passive: false });
    this.appContainer.addEventListener('touchmove', this.handleTouchMove.bind(this), { passive: false });
    this.appContainer.addEventListener('touchend', this.handleTouchEnd.bind(this), { passive: false });

    // Mouse events for desktop testing
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
      this.appContainer.addEventListener('mousedown', this.handleMouseDown.bind(this));
      this.appContainer.addEventListener('mousemove', this.handleMouseMove.bind(this));
      this.appContainer.addEventListener('mouseup', this.handleMouseUp.bind(this));
    }

    console.log('✅ Pull-to-refresh initialized');
  }

  handleTouchStart(e) {
    // Only handle if at top of scroll AND user is not authenticated
    if (this.appContainer.scrollTop > 0 || !AppState.user) return;
    
    this.ptrState.startY = e.touches[0].clientY;
    this.ptrState.pulling = false; // Don't activate yet, wait for move
    this.ptrState.hasMoved = false;
  }

  handleTouchMove(e) {
    if (this.ptrState.refreshing) return;
    
    // Check if we should start pull-to-refresh
    if (this.ptrState.startY && !this.ptrState.hasMoved) {
      this.ptrState.currentY = e.touches[0].clientY;
      const deltaY = this.ptrState.currentY - this.ptrState.startY;
      
      // Only activate if user is pulling down significantly (>10px) and still at top
      if (deltaY > 10 && this.appContainer.scrollTop === 0) {
        this.ptrState.pulling = true;
        this.ptrState.hasMoved = true;
        this.appContainer.classList.add('ptr-active');
        document.body.classList.add('ptr-active');
      } else if (deltaY <= 0) {
        // Reset if user starts scrolling up
        this.resetPtrState();
        return;
      }
    }

    if (!this.ptrState.pulling) return;

    this.ptrState.currentY = e.touches[0].clientY;
    const deltaY = this.ptrState.currentY - this.ptrState.startY;

    // Only handle downward pulls
    if (deltaY <= 10) {
      this.resetPtrState();
      return;
    }

    // Prevent default scrolling when actively pulling
    e.preventDefault();

    // Limit pull distance
    const pullDistance = Math.min(deltaY - 10, this.ptrState.maxDistance);
    const pullProgress = pullDistance / this.ptrState.threshold;

    this.updatePullIndicator(pullDistance, pullProgress >= 1);
  }

  handleTouchEnd(e) {
    if (!this.ptrState.pulling && !this.ptrState.startY) return;

    const deltaY = this.ptrState.currentY - this.ptrState.startY;
    const shouldRefresh = deltaY >= (this.ptrState.threshold + 10);

    if (shouldRefresh && !this.ptrState.refreshing) {
      this.triggerRefresh();
    } else {
      this.resetPullIndicator();
    }

    this.resetPtrState();
  }

  resetPtrState() {
    this.ptrState.pulling = false;
    this.ptrState.startY = 0;
    this.ptrState.currentY = 0;
    this.ptrState.hasMoved = false;
    this.appContainer.classList.remove('ptr-active');
    document.body.classList.remove('ptr-active');
  }

  // Mouse handlers for desktop testing
  handleMouseDown(e) {
    if (this.appContainer.scrollTop > 0) return;
    this.ptrState.startY = e.clientY;
    this.ptrState.pulling = true;
    this.ptrState.mouseDown = true;
    document.body.classList.add('ptr-active');
  }

  handleMouseMove(e) {
    if (!this.ptrState.pulling || !this.ptrState.mouseDown || this.ptrState.refreshing) return;

    this.ptrState.currentY = e.clientY;
    const deltaY = this.ptrState.currentY - this.ptrState.startY;

    if (deltaY <= 0) return;

    e.preventDefault();
    const pullDistance = Math.min(deltaY, this.ptrState.maxDistance);
    const pullProgress = pullDistance / this.ptrState.threshold;

    this.updatePullIndicator(pullDistance, pullProgress >= 1);
  }

  handleMouseUp(e) {
    if (!this.ptrState.pulling) return;

    const deltaY = this.ptrState.currentY - this.ptrState.startY;
    const shouldRefresh = deltaY >= this.ptrState.threshold;

    if (shouldRefresh && !this.ptrState.refreshing) {
      this.triggerRefresh();
    } else {
      this.resetPullIndicator();
    }

    this.ptrState.pulling = false;
    this.ptrState.mouseDown = false;
    document.body.classList.remove('ptr-active');
  }

  updatePullIndicator(distance, canRefresh) {
    // Show indicator
    this.ptrIndicator.classList.add('visible');

    // Update transform
    const translateY = Math.min(distance, this.ptrState.threshold);
    this.ptrIndicator.style.transform = `translateY(${translateY}px)`;

    // Update icon and text
    if (canRefresh) {
      this.ptrIcon.classList.add('rotated');
      this.ptrText.textContent = this.safeT('messages.releaseToRefresh', 'Відпустіть для оновлення');
    } else {
      this.ptrIcon.classList.remove('rotated');
      this.ptrText.textContent = this.safeT('messages.pullToRefresh', 'Потягніть для оновлення');
    }
  }

  async triggerRefresh() {
    console.log('🔄 Triggering pull-to-refresh...');
    
    this.ptrState.refreshing = true;
    this.ptrIndicator.classList.add('refreshing');
    this.ptrIcon.classList.remove('rotated');
    this.ptrIcon.classList.add('spinning');
    
    // Change icon to loading spinner
    this.ptrIcon.innerHTML = `
      <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2" fill="none"/>
      <path d="M12 6v6l4 2" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
    `;
    
    this.ptrText.textContent = this.safeT('messages.refreshing', 'Оновлення...');

    try {
      // Perform refresh actions
      await this.performRefresh();
      
      // Show success
      this.ptrText.textContent = this.safeT('messages.refreshed', 'Оновлено!');
      
      // Wait a bit before hiding
      setTimeout(() => {
        this.resetPullIndicator();
      }, 1000);
      
    } catch (error) {
      console.error('Refresh error:', error);
      this.ptrText.textContent = this.safeT('messages.refreshError', 'Помилка оновлення');
      
      setTimeout(() => {
        this.resetPullIndicator();
      }, 2000);
    }
  }

  async performRefresh() {
    console.log('📱 Performing data refresh...');
    
    // Check authentication first
    if (!AppState.user) {
      console.log('User not authenticated, skipping refresh');
      return;
    }

    try {
      // Refresh user profile and cards
      const response = await this.apiCall('/auth/me');
      
      if (response && response.user) {
        console.log('✅ Data refreshed via pull-to-refresh');
        
        // Update app state
        AppState.user = response.user;
        AppState.cards = response.cards || [];
        
        // Update UI
        this.updateProfile();
        this.renderCards();
        
        // Sync data to localStorage
        this.saveLocalData();
        
        console.log('✅ Pull-to-refresh completed successfully');
      }
    } catch (error) {
      console.error('Refresh failed:', error);
      throw error;
    }
  }

  resetPullIndicator() {
    this.ptrState.refreshing = false;
    
    // Reset classes
    this.ptrIndicator.classList.remove('visible', 'refreshing');
    this.ptrIcon.classList.remove('rotated', 'spinning');
    
    // Reset icon
    this.ptrIcon.innerHTML = `<path d="M12 1v6m0 0l4-4m-4 4L8 3"/>`;
    
    // Reset text
    this.ptrText.textContent = this.safeT('messages.pullToRefresh', 'Потягніть для оновлення');
    
    // Reset transform
    this.ptrIndicator.style.transform = '';
    
    console.log('Pull-to-refresh reset');
  }

  initializeTheme() {
    const savedTheme = localStorage.getItem('theme');
    const systemTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    
    AppState.theme = savedTheme || systemTheme;
    this.applyTheme(AppState.theme);
    
    // Initialize lastActiveTime for app resume detection
    this.lastActiveTime = Date.now();
    
    // Update theme selector
    const themeInput = document.querySelector(`input[name="theme"][value="${AppState.theme}"]`);
    if (themeInput) themeInput.checked = true;

    // Listen for system theme changes
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
      if (!localStorage.getItem('theme')) {
        const newTheme = e.matches ? 'dark' : 'light';
        this.applyTheme(newTheme);
      }
    });
  }

  async checkAuthentication() {
    // Check if we have a token in localStorage and set it in API client
    const token = localStorage.getItem('authToken') || localStorage.getItem('token');
    
    if (token) {
      window.api.setToken(token);
      // Migrate old token key to new one
      if (localStorage.getItem('token')) {
        localStorage.setItem('authToken', token);
        localStorage.removeItem('token');
      }
    }
    
    if (!token) {
      // Try to load from localStorage for offline mode
      this.loadLocalData();
      this.showAuthScreen();
      return;
    }

    try {
      const response = await this.apiCall('/auth/me');
      
      if (response.user) {
        AppState.user = response.user;
        AppState.cards = response.cards || [];
        
        // Save data to localStorage immediately
        this.saveLocalData();
        
        // Sync data between server and localStorage
        await this.syncData();
        
        // Update language from user profile
        if (response.user.language) {
          console.log('Setting user language:', response.user.language);
          window.i18n.setLanguage(response.user.language);
          window.i18n.updatePageTexts();
        }
        
        this.showAppScreen();
        this.updateProfile();
        this.renderCards();
      } else {
        throw new Error('Invalid response');
      }
    } catch (error) {
      console.error('Auth check failed:', error);
      localStorage.removeItem('token');
      localStorage.removeItem('authToken');
      window.api.setToken(null);
      this.showAuthScreen();
    }
  }

  // Authentication Methods
  async handleLogin(e) {
    e.preventDefault();
    
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    
    if (!email || !password) {
      this.showToast('error', this.safeT('messages.fillAllFields', 'Заповніть всі поля'));
      return;
    }

    const submitBtn = e.target.querySelector('button[type="submit"]');
    this.setButtonLoading(submitBtn, true);

    try {
      const response = await this.apiCall('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password })
      });

      if (response.token) {
        // API client handles token storage
        AppState.user = response.user;
        AppState.cards = response.cards || [];
        
        // Update language
        if (response.user.language) {
          console.log('Setting login user language:', response.user.language);
          window.i18n.setLanguage(response.user.language);
          window.i18n.updatePageTexts();
        }
        
        this.showToast('success', this.safeT('messages.loginSuccess', 'Успішний вхід'));
        this.showAppScreen();
        this.updateProfile();
        this.renderCards();
      } else {
        throw new Error('No token received');
      }
    } catch (error) {
      console.error('Login error:', error);
      this.showToast('error', error.message || this.safeT('messages.invalidCredentials', 'Невірні дані для входу'));
    } finally {
      this.setButtonLoading(submitBtn, false);
    }
  }

  async handleRegister(e) {
    e.preventDefault();
    
    console.log('Registration form submitted');
    
    const name = document.getElementById('register-name').value;
    const email = document.getElementById('register-email').value;
    const password = document.getElementById('register-password').value;
    
    console.log('Form data:', { name, email, password: '***' });
    
    if (!name || !email || !password) {
      console.log('Missing fields');
      this.showToast('error', this.safeT('messages.fillAllFields', 'Заповніть всі поля'));
      return;
    }

    if (password.length < 6) {
      console.log('Password too short');
      this.showToast('error', this.safeT('messages.passwordTooShort', 'Пароль повинен містити мінімум 6 символів'));
      return;
    }

    const submitBtn = e.target.querySelector('button[type="submit"]');
    this.setButtonLoading(submitBtn, true);

    try {
      console.log('Starting API call to /auth/register');
      const response = await this.apiCall('/auth/register', {
        method: 'POST',
        body: JSON.stringify({ 
          name, 
          email, 
          password,
          language: window.i18n.getCurrentLanguage()
        })
      });
      
      console.log('Registration response:', response);

      if (response.token) {
        // API client handles token storage
        AppState.user = response.user;
        AppState.cards = response.cards || [];
        
        this.showToast('success', this.safeT('messages.registerSuccess', 'Акаунт створено'));
        this.showAppScreen();
        this.updateProfile();
        this.renderCards();
      } else {
        throw new Error('No token received');
      }
    } catch (error) {
      console.error('Register error:', error);
      this.showToast('error', error.message || this.safeT('messages.serverError', 'Помилка сервера'));
    } finally {
      this.setButtonLoading(submitBtn, false);
    }
  }

  handleLogout() {
    window.api.logout();
    AppState.user = null;
    AppState.cards = [];
    
    this.showToast('success', this.safeT('messages.logoutSuccess', 'Вихід виконано'));
    this.showAuthScreen();
  }

  async handleChangePassword(e) {
    e.preventDefault();
    
    const currentPassword = document.getElementById('current-password').value;
    const newPassword = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-password').value;
    
    if (!currentPassword || !newPassword || !confirmPassword) {
      this.showToast('error', this.safeT('messages.fillAllFields', 'Заповніть всі поля'));
      return;
    }

    if (newPassword !== confirmPassword) {
      this.showToast('error', this.safeT('messages.passwordsDontMatch', 'Паролі не збігаються'));
      return;
    }

    if (newPassword.length < 6) {
      this.showToast('error', this.safeT('messages.passwordTooShort', 'Пароль занадто короткий'));
      return;
    }

    const submitBtn = e.target.querySelector('button[type="submit"]');
    this.setButtonLoading(submitBtn, true);

    try {
      await this.apiCall('/auth/password', {
        method: 'PUT',
        body: JSON.stringify({ currentPassword, newPassword })
      });

      this.showToast('success', this.safeT('messages.passwordChanged', 'Пароль змінено'));
      e.target.reset();
    } catch (error) {
      console.error('Change password error:', error);
      this.showToast('error', error.message || this.safeT('messages.serverError', 'Помилка сервера'));
    } finally {
      this.setButtonLoading(submitBtn, false);
    }
  }

  async handleEditName() {
    const nameSpan = document.getElementById('user-name');
    const currentName = nameSpan.textContent;
    
    const newName = await this.showPrompt(this.safeT('auth.name', 'Ім\'я'), currentName);
    if (newName && newName !== currentName) {
      try {
        const response = await this.apiCall('/auth/profile', {
          method: 'PUT',
          body: JSON.stringify({ name: newName })
        });

        AppState.user = response.user;
        this.updateProfile();
        this.showToast('success', this.safeT('messages.profileUpdated', 'Профіль оновлено'));
      } catch (error) {
        console.error('Update name error:', error);
        this.showToast('error', error.message || this.safeT('messages.serverError', 'Помилка сервера'));
      }
    }
  }

  // Card Management Methods
  async loadUserCards() {
    try {
      console.log('Loading user cards...');
      const response = await this.apiCall('/auth/me');
      
      if (response && response.cards) {
        AppState.cards = response.cards;
        this.renderCards();
        console.log('Loaded', AppState.cards.length, 'cards');
      }
    } catch (error) {
      console.error('Load cards error:', error);
      // Don't show error toast for card loading, just log it
    }
  }

  async handleAddCard(e) {
    console.log('=== handleAddCard called ===');
    console.log('Event object:', e);
    console.log('Event type:', e.type);
    console.log('Form element:', e.target);
    
    e.preventDefault();
    console.log('Default prevented');
    
    // Check if user is authenticated
    if (!AppState.user || !localStorage.getItem('token')) {
      console.error('User not authenticated');
      this.showToast('error', 'Необхідно авторизуватися');
      this.showAuthScreen();
      return;
    }
    
    console.log('User authenticated:', AppState.user.email);
    
    const name = document.getElementById('card-name').value;
    const code = document.getElementById('card-code').value;
    const codeTypeElement = document.querySelector('input[name="codeType"]:checked');
    
    console.log('Form data:', { name, code, codeTypeElement });
    
    if (!codeTypeElement) {
      console.error('No code type selected');
      this.showToast('error', 'Оберіть тип коду');
      return;
    }
    
    const codeType = codeTypeElement.value;
    console.log('Code type:', codeType);
    
    if (!name || !code) {
      console.log('Missing required fields:', { name: !!name, code: !!code });
      const message = this.safeT('messages.fillAllFields', 'Заповніть всі поля');
      this.showToast('error', message);
      return;
    }

    const submitBtn = e.target.querySelector('button[type="submit"]');
    this.setButtonLoading(submitBtn, true);

    try {
      console.log('Making API call to add card...');
      const response = await this.apiCall('/cards', {
        method: 'POST',
        body: JSON.stringify({ name, code, codeType })
      });
      
      console.log('API response:', response);

      if (response && response.cards) {
        AppState.cards = response.cards;
        console.log('Updated AppState.cards:', AppState.cards.length, 'cards');
        this.renderCards();
        
        const successMessage = this.safeT('messages.cardAdded', 'Картку додано');
        this.showToast('success', successMessage);
        
        // Reset form
        const form = document.getElementById('add-card-form');
        if (form && typeof form.reset === 'function') {
          form.reset();
        } else {
          console.warn('Cannot reset form - form not found or reset method not available');
          // Manual reset as fallback
          document.getElementById('card-name').value = '';
          document.getElementById('card-code').value = '';
          const defaultCodeType = document.querySelector('input[name="codeType"][value="barcode"]');
          if (defaultCodeType) defaultCodeType.checked = true;
        }
        this.clearCodePreview();
        
        // Switch to cards tab
        console.log('Switching to cards tab');
        this.switchTab('cards');
      } else {
        console.error('Invalid response format:', response);
        this.showToast('error', 'Некоректна відповідь сервера');
      }
    } catch (error) {
      console.error('Add card error:', error);
      const errorMessage = error.message || this.safeT('messages.serverError', 'Помилка сервера');
      this.showToast('error', errorMessage);
    } finally {
      this.setButtonLoading(submitBtn, false);
    }
  }

  handleCardsSearch(e) {
    const query = e.target.value.toLowerCase();
    const cards = document.querySelectorAll('.card-item');
    
    cards.forEach(card => {
      const name = card.querySelector('.card-name').textContent.toLowerCase();
      const isVisible = name.includes(query);
      card.style.display = isVisible ? '' : 'none';
    });

    // Show/hide empty state
    const visibleCards = Array.from(cards).filter(card => card.style.display !== 'none');
    const emptyState = document.getElementById('cards-empty');
    
    if (visibleCards.length === 0 && AppState.cards.length > 0) {
      emptyState.classList.remove('hidden');
      emptyState.querySelector('.empty-title').textContent = `Нічого не знайдено за запитом "${e.target.value}"`;
    } else if (AppState.cards.length === 0) {
      emptyState.classList.remove('hidden');
    } else {
      emptyState.classList.add('hidden');
    }
  }

  async deleteCard() {
    console.log('🗑️ deleteCard called');
    const cardId = this.currentCard?._id;
    console.log('Card ID to delete:', cardId);
    if (!cardId) {
      console.error('No card ID found');
      return;
    }

    const confirmMessage = this.safeT('messages.confirmDelete', 'Ви впевнені, що хочете видалити цю картку?');
    console.log('Showing confirmation dialog with message:', confirmMessage);
    const confirmed = await this.showConfirm(confirmMessage);
    console.log('User confirmed deletion:', confirmed);
    if (!confirmed) return;

    try {
      const response = await this.apiCall(`/cards/${cardId}`, {
        method: 'DELETE'
      });

      AppState.cards = response.cards;
      this.renderCards();
      this.closeCardModal();
      this.showToast('success', this.safeT('messages.cardDeleted', 'Картку видалено'));
    } catch (error) {
      console.error('Delete card error:', error);
      this.showToast('error', error.message || this.safeT('messages.serverError', 'Помилка сервера'));
    }
  }

  // Continue with more methods...
  // [The file continues with more methods - I'll split it for readability]

  // UI Methods
  switchTab(tabName) {
    console.log(`🔄 Switching to tab: ${tabName}`);
    
    // Update navigation
    document.querySelectorAll('.nav-item').forEach(item => {
      item.classList.remove('active');
    });
    
    const targetNavItem = document.querySelector(`[data-tab="${tabName}"]`);
    if (targetNavItem) {
      targetNavItem.classList.add('active');
      console.log(`✅ Added active class to nav item: ${tabName}`);
    } else {
      console.error(`❌ Could not find nav item with data-tab="${tabName}"`);
      // Try alternative selector as fallback
      const altNavItem = document.querySelector(`.nav-item[data-tab="${tabName}"]`);
      if (altNavItem) {
        altNavItem.classList.add('active');
        console.log(`✅ Added active class using alternative selector: ${tabName}`);
      }
    }

    // Update panels
    document.querySelectorAll('.tab-panel').forEach(panel => {
      panel.classList.remove('active');
    });
    
    const targetPanel = document.getElementById(`${tabName}-panel`);
    if (targetPanel) {
      targetPanel.classList.add('active');
      console.log(`✅ Added active class to panel: ${tabName}-panel`);
    } else {
      console.error(`❌ Could not find panel with id="${tabName}-panel"`);
    }

    AppState.currentTab = tabName;

    // Scroll to top of the page when switching tabs
    window.scrollTo({
      top: 0,
      behavior: 'smooth'
    });

    // Load data if needed
    if (tabName === 'cards' && AppState.cards.length === 0 && AppState.user) {
      this.loadUserCards();
    }
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
      this.switchTab('cards');
    }
    
    // Close any open modals
    this.closeAllModals();
  }
  
  closeAllModals() {
    // Close modal system modals
    document.querySelectorAll('.modal-overlay').forEach(modal => {
      modal.classList.remove('show');
    });
    
    // Restore body scroll
    document.body.style.overflow = '';
    
    console.log('All modals closed');
  }

  hideLoadingScreen() {
    setTimeout(() => {
      document.getElementById('loading-screen').classList.add('hidden');
    }, 1000);
  }

  showLoginForm() {
    document.getElementById('register-form').classList.add('hidden');
    document.getElementById('login-form').classList.remove('hidden');
  }

  showRegisterForm() {
    document.getElementById('login-form').classList.add('hidden');
    document.getElementById('register-form').classList.remove('hidden');
  }

  // Theme Methods
  applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    AppState.theme = theme;
    localStorage.setItem('theme', theme);
    
    console.log(`🎨 Theme changed to: ${theme}`);
    
    // Update theme toggle icon
    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
      const icon = themeToggle.querySelector('.theme-icon');
      if (theme === 'dark') {
        icon.innerHTML = '<path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z" fill="currentColor"/>';
      } else {
        icon.innerHTML = '<path d="M12 2.25a.75.75 0 01.75.75v2.25a.75.75 0 01-1.5 0V3a.75.75 0 01.75-.75zM7.5 12a4.5 4.5 0 119 0 4.5 4.5 0 01-9 0zM18.894 6.166a.75.75 0 00-1.06-1.06l-1.591 1.59a.75.75 0 101.06 1.061l1.591-1.59zM21.75 12a.75.75 0 01-.75.75h-2.25a.75.75 0 010-1.5H21a.75.75 0 01.75.75zM17.834 18.894a.75.75 0 001.06-1.06l-1.59-1.591a.75.75 0 10-1.061 1.06l1.59 1.591zM12 18a.75.75 0 01.75.75V21a.75.75 0 01-1.5 0v-2.25A.75.75 0 0112 18zM7.758 17.303a.75.75 0 00-1.061-1.06l-1.591 1.59a.75.75 0 001.06 1.061l1.591-1.59zM6 12a.75.75 0 01-.75.75H3a.75.75 0 010-1.5h2.25A.75.75 0 016 12zM6.697 7.757a.75.75 0 001.06-1.06l-1.59-1.591a.75.75 0 00-1.061 1.06l1.59 1.591z" fill="currentColor"/>';
      }
    }
    
    // Regenerate all codes with new theme colors after a small delay
    // This allows CSS transitions to complete first
    setTimeout(() => {
      this.updateCodesForTheme();
    }, 100);
  }

  updateCodesForTheme() {
    console.log('🎨 Updating all codes for new theme...');
    // Note: All codes are now always black on white background for better readability
    
    // Set flag to reduce logging during theme updates
    this.isThemeUpdate = true;
    
    try {
      // 1. Update code preview in add form (if visible and has content)
      const codeInput = document.getElementById('card-code');
      const preview = document.getElementById('code-preview');
      if (codeInput && preview && codeInput.value && !preview.classList.contains('hidden')) {
        console.log('🔄 Updating add form preview...');
        this.updateCodePreview();
      }
      
      // 2. Update all card previews in grid
      const cardItems = document.querySelectorAll('.card-item');
      cardItems.forEach((cardElement, index) => {
        if (index < AppState.cards.length) {
          const card = AppState.cards[index];
          this.generateCardPreview(card, cardElement);
        }
      });
      console.log(`🔄 Updated ${cardItems.length} card previews`);
      
      // 3. Update modal code if modal is open
      const cardModal = document.getElementById('card-modal');
      if (cardModal && cardModal.classList.contains('show') && this.currentCard) {
        console.log('🔄 Updating modal code...');
        this.regenerateModalCode();
      }
      
      console.log('✅ All codes updated for new theme');
    } finally {
      // Always reset flag
      this.isThemeUpdate = false;
    }
  }

  regenerateModalCode() {
    if (!this.currentCard) {
      console.warn('No current card to regenerate modal code');
      return;
    }

    const canvas = document.getElementById('modal-canvas');
    if (!canvas) {
      console.warn('Modal canvas not found');
      return;
    }

    const card = this.currentCard;
    console.log(`🎨 Regenerating modal code for: ${card.name} (${card.codeType})`);

    try {
      if (card.codeType === 'qrcode') {
        if (typeof QRCode === 'undefined') {
          throw new Error('QRCode library not loaded');
        }
        
        // Set canvas class for QR code styling
        canvas.className = 'qr-canvas';
        
        // Clear canvas before generating new QR code
        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        QRCode.toCanvas(canvas, card.code, {
          width: 300,
          margin: 4,
          color: {
            dark: '#000000',  // Always black
            light: '#FFFFFF'  // Always white
          }
        });
        console.log('✅ Modal QR code regenerated with new theme');
      } else {
        if (typeof JsBarcode === 'undefined') {
          throw new Error('JsBarcode library not loaded');
        }
        
        // Set canvas class for barcode styling
        canvas.className = 'barcode-canvas';
        
        JsBarcode(canvas, card.code, {
          width: 3,
          height: 150,
          fontSize: 18,
          background: '#FFFFFF',  // Always white background
          lineColor: '#000000'    // Always black lines
        });
        console.log('✅ Modal barcode regenerated with new theme');
      }
    } catch (error) {
      console.error('❌ Modal code regeneration error:', error);
    }
  }

  toggleTheme() {
    const newTheme = AppState.theme === 'light' ? 'dark' : 'light';
    this.applyTheme(newTheme);
    
    // Update settings radio
    const themeInput = document.querySelector(`input[name="theme"][value="${newTheme}"]`);
    if (themeInput) themeInput.checked = true;
  }

  handleThemeChange(e) {
    this.applyTheme(e.target.value);
  }

  async handleLanguageChange(e) {
    const newLanguage = e.target.value;
    console.log('Changing language to:', newLanguage);
    
    const success = window.i18n.setLanguage(newLanguage);
    if (success) {
      console.log('Language changed successfully');
      // Force update page texts
      window.i18n.updatePageTexts();
    } else {
      console.error('Failed to change language');
    }
    
    // Update on server if user is logged in
    if (AppState.user) {
      try {
        await this.apiCall('/auth/profile', {
          method: 'PUT',
          body: JSON.stringify({ language: newLanguage })
        });
        console.log('Language updated on server');
      } catch (error) {
        console.error('Language update error:', error);
      }
    }
  }

  // Scanner Methods
  async openScanner() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      this.showToast('error', this.safeT('messages.cameraNotSupported', 'Камера не підтримується'));
      return;
    }

    const modal = document.getElementById('scanner-modal');
    const video = document.getElementById('scanner-video');
    const instructions = modal.querySelector('.scanner-instructions');
    
    // Update instructions based on selected code type
    const selectedCodeType = document.querySelector('input[name="codeType"]:checked')?.value || 'qrcode';
    const instructionText = selectedCodeType === 'qrcode' ? 
      'Наведіть камеру на QR-код для сканування' : 
      'Наведіть камеру на штрих-код для сканування';
    
    instructions.textContent = instructionText;
    
    modal.classList.add('show');

    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { 
          facingMode: 'environment',
          width: { ideal: 1280 },
          height: { ideal: 720 }
        }
      });

      video.srcObject = stream;
      this.currentStream = stream;
      
      // Start scanning
      this.startScanning(video);
      
      console.log(`📱 Scanner opened for ${selectedCodeType} scanning`);
    } catch (error) {
      console.error('Camera error:', error);
      this.showToast('error', this.safeT('scanner.permissionDenied', 'Доступ до камери заборонено'));
      this.closeScanner();
    }
  }

  closeScanner() {
    const modal = document.getElementById('scanner-modal');
    modal.classList.remove('show');

    if (this.currentStream) {
      this.currentStream.getTracks().forEach(track => track.stop());
      this.currentStream = null;
    }

    if (this.scannerInterval) {
      clearInterval(this.scannerInterval);
      this.scannerInterval = null;
    }
    
    // Reset scan attempts counter
    this.scanAttempts = 0;
    console.log('📱 Scanner closed');
  }

  startScanning(video) {
    console.log('🚀 Starting scanning process...');
    
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('2d');

    // Get currently selected code type
    const getSelectedCodeType = () => {
      const selectedType = document.querySelector('input[name="codeType"]:checked');
      return selectedType ? selectedType.value : 'qrcode';
    };

    this.scannerInterval = setInterval(() => {
      if (video.readyState === video.HAVE_ENOUGH_DATA) {
        canvas.height = video.videoHeight;
        canvas.width = video.videoWidth;
        context.drawImage(video, 0, 0, canvas.width, canvas.height);
        
        const selectedCodeType = getSelectedCodeType();
        // Reduced logging frequency for better performance
        if (this.scanAttempts % 10 === 0) {
          console.log('🔍 Scanning for:', selectedCodeType, `(attempt ${this.scanAttempts})`);
        }
        this.scanAttempts = (this.scanAttempts || 0) + 1;
        
        if (selectedCodeType === 'qrcode') {
          // QR Code scanning
          this.scanQRCode(context, canvas);
        } else if (selectedCodeType === 'barcode') {
          // Barcode scanning
          this.scanBarcode(canvas);
        }
      }
    }, 200); // Reduced frequency for better performance
  }

  // QR Code scanning method
  scanQRCode(context, canvas) {
    try {
      const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(imageData.data, imageData.width, imageData.height);
      
      if (code) {
        console.log('✅ QR Code detected:', code.data);
        this.onCodeScanned(code.data, 'qrcode');
        return true;
      }
    } catch (error) {
      console.warn('QR scanning error:', error);
    }
    return false;
  }

  // Barcode scanning method
  scanBarcode(canvas) {
    if (typeof Quagga === 'undefined') {
      console.error('❌ Quagga library not loaded');
      return false;
    }

    try {
      Quagga.decodeSingle({
        decoder: {
          readers: [
            "code_128_reader",    // Code 128
            "ean_reader",         // EAN-13
            "ean_8_reader",       // EAN-8
            "code_39_reader",     // Code 39
            "code_39_vin_reader", // Code 39 VIN
            "codabar_reader",     // Codabar
            "upc_reader",         // UPC-A
            "upc_e_reader",       // UPC-E
            "i2of5_reader"        // Interleaved 2 of 5
          ]
        },
        locate: true,
        src: canvas.toDataURL('image/png')
      }, (result) => {
        if (result && result.codeResult && result.codeResult.code) {
          console.log('✅ Barcode detected:', result.codeResult.code);
          console.log('📊 Barcode format:', result.codeResult.format);
          this.onCodeScanned(result.codeResult.code, 'barcode');
        }
      });
    } catch (error) {
      console.warn('Barcode scanning error:', error);
    }
    return false;
  }

  onCodeScanned(code, type) {
    console.log('🎉 Code successfully scanned!');
    console.log(`📝 Type: ${type}`);
    console.log(`🔢 Code: ${code}`);
    
    this.closeScanner();
    
    // Fill the form
    const codeInput = document.getElementById('card-code');
    codeInput.value = code;
    
    // Select the correct code type if it doesn't match
    const currentCodeType = document.querySelector('input[name="codeType"]:checked')?.value;
    if (currentCodeType !== type) {
      const codeTypeInput = document.querySelector(`input[name="codeType"][value="${type}"]`);
      if (codeTypeInput) {
        codeTypeInput.checked = true;
        this.handleCodeTypeChange({ target: codeTypeInput });
      }
    }
    
    // Update preview
    this.updateCodePreview();
    
    // Update form validation
    this.updateFormValidation();
    
    // Show success message with code type
    const typeText = type === 'qrcode' ? 'QR-код' : 'штрих-код';
    this.showToast('success', `✅ ${typeText} успішно відсканований!`);
    
    // Focus on the name field if it's empty
    const nameInput = document.getElementById('card-name');
    if (!nameInput.value.trim()) {
      setTimeout(() => {
        nameInput.focus();
      }, 500);
    }
  }

  // Code Preview Methods
  handleCodeTypeChange(e) {
    const codeType = e.target.value;
    this.updateCodePreview(codeType);
  }

  updateCodePreview(codeType) {
    console.log('🔍 updateCodePreview called with:', codeType);
    
    const code = document.getElementById('card-code').value;
    const preview = document.getElementById('code-preview');
    const canvas = document.getElementById('preview-canvas');
    
    console.log('Code:', code);
    console.log('Preview element:', !!preview);
    console.log('Canvas element:', !!canvas);
    
    if (!code) {
      preview.style.display = 'none';
      return;
    }

    const selectedCodeType = codeType || document.querySelector('input[name="codeType"]:checked')?.value;
    console.log('Selected code type:', selectedCodeType);
    
    preview.style.display = 'block';

    try {
      if (selectedCodeType === 'qrcode') {
        console.log('🔄 Generating QR code...');
        console.log('QRCode library available:', typeof QRCode !== 'undefined');
        
        if (typeof QRCode === 'undefined') {
          throw new Error('QRCode library not loaded');
        }
        
        console.log('🔄 Generating QR code for preview with code:', code);
        
        // Clear canvas before generating new QR code
        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        QRCode.toCanvas(canvas, code, {
          width: 200,
          margin: 2,
          color: {
            dark: '#000000',  // Always black
            light: '#FFFFFF'  // Always white
          }
        });
        console.log('✅ QR code generated successfully');
      } else {
        console.log('🔄 Generating barcode...');
        console.log('JsBarcode library available:', typeof JsBarcode !== 'undefined');
        
        if (typeof JsBarcode === 'undefined') {
          throw new Error('JsBarcode library not loaded');
        }
        
        JsBarcode(canvas, code, {
          width: 2,
          height: 100,
          fontSize: 16,
          textMargin: 0,
          background: '#FFFFFF',  // Always white background
          lineColor: '#000000'    // Always black lines
        });
        console.log('✅ Barcode generated successfully');
      }
    } catch (error) {
      console.error('❌ Code generation error:', error);
      this.showToast('error', this.safeT('messages.invalidCode', 'Помилка генерації коду'));
    }
  }

  clearCodePreview() {
    document.getElementById('code-preview').style.display = 'none';
    document.querySelector('input[name="codeType"][value="barcode"]').checked = true;
  }

  updateFormValidation() {
    const name = document.getElementById('card-name')?.value || '';
    const code = document.getElementById('card-code')?.value || '';
    const submitBtn = document.querySelector('#add-card-form button[type="submit"]');
    
    if (submitBtn) {
      const shouldDisable = !name.trim() || !code.trim();
      console.log('Form validation:', { name: name.trim(), code: code.trim(), shouldDisable });
      submitBtn.disabled = shouldDisable;
    }
  }

  // Card Rendering
  renderCards() {
    console.log('🎴 Rendering cards...');
    console.log('📊 Cards data:', AppState.cards.map(card => ({
      name: card.name,
      code: card.code,
      codeType: card.codeType,
      id: card._id
    })));
    
    const grid = document.getElementById('cards-grid');
    const emptyState = document.getElementById('cards-empty');
    
    if (AppState.cards.length === 0) {
      grid.innerHTML = '';
      emptyState.classList.remove('hidden');
      return;
    }

    emptyState.classList.add('hidden');
    grid.innerHTML = AppState.cards.map(card => this.createCardHTML(card)).join('');
    
    // Add click handlers and generate codes
    grid.querySelectorAll('.card-item').forEach((cardEl, index) => {
      const card = AppState.cards[index];
      
      cardEl.addEventListener('click', () => {
        this.showCardModal(card);
      });
      
      // Generate code for card preview
      this.generateCardPreview(card, cardEl);
    });

    // Update cards count in profile
    const cardsCount = document.getElementById('cards-count');
    if (cardsCount) {
      cardsCount.textContent = AppState.cards.length;
    }
  }

  createCardHTML(card) {
    const createdDate = window.i18n.formatTime(card.createdAt);
    const cardTypeText = card.codeType === 'qrcode' ? 'QR' : this.safeT('cards.barcode', 'Штрих-код');
    const createdText = this.safeT('cards.created', 'Створено');
    
    return `
      <div class="card-item" data-card-id="${card._id}">
        <div class="card-header">
          <div class="card-name">${this.escapeHtml(card.name)}</div>
          <div class="card-type">${cardTypeText}</div>
        </div>
        <div class="card-code-preview">
          <canvas id="card-canvas-${card._id}" width="160" height="160"></canvas>
        </div>
        <div class="card-info">
          <span>${createdText}: ${createdDate}</span>
        </div>
      </div>
    `;
  }

  generateCardPreview(card, cardElement) {
    const canvas = cardElement.querySelector(`#card-canvas-${card._id}`);
    if (!canvas) {
      console.warn('Canvas not found for card:', card._id);
      return;
    }

    try {
      if (card.codeType === 'qrcode') {
        if (typeof QRCode === 'undefined') {
          console.warn('QRCode library not available for card preview');
          return;
        }
        
        // Reduced logging for theme changes
        if (!this.isThemeUpdate) {
          console.log('🔄 Generating QR code for card preview:', card.name, 'with code:', card.code);
        }
        
        // Clear canvas before generating new QR code
        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        QRCode.toCanvas(canvas, card.code, {
          width: 160,
          margin: 1,
          color: {
            dark: '#000000',  // Always black
            light: '#FFFFFF'  // Always white
          }
        }, (error) => {
          if (error) {
            console.error('QR generation error for card preview:', error);
          } else {
            console.log('✅ QR code generated successfully for card:', card.name);
          }
        });
      } else {
        if (typeof JsBarcode === 'undefined') {
          console.warn('JsBarcode library not available for card preview');
          return;
        }
        
        JsBarcode(canvas, card.code, {
          width: 1.5,
          height: 80,
          fontSize: 10,
          textMargin: 2,
          background: '#FFFFFF',  // Always white background
          lineColor: '#000000'    // Always black lines
        });
      }
    } catch (error) {
      console.error('Card preview generation error:', error);
      // Show fallback text instead of code
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--text-muted').trim() || '#6C757D';
      ctx.font = '14px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(card.codeType === 'qrcode' ? 'QR код' : 'Штрих-код', canvas.width / 2, canvas.height / 2);
    }
  }

  // Card Modal
  showCardModal(card) {
    console.log('🔍 showCardModal called for card:', card.name, card.codeType);
    
    this.currentCard = card;
    const modal = document.getElementById('card-modal');
    const title = document.getElementById('modal-card-name');
    const canvas = document.getElementById('modal-canvas');
    const codeText = document.getElementById('modal-code-text');
    
    if (!modal || !title || !canvas || !codeText) {
      console.error('❌ Modal elements not found');
      return;
    }
    
    title.textContent = card.name;
    codeText.textContent = card.code;
    
    // Generate code
    try {
      if (card.codeType === 'qrcode') {
        console.log('🔄 Generating QR code for modal...');
        
        if (typeof QRCode === 'undefined') {
          throw new Error('QRCode library not loaded');
        }
        
        console.log('🔄 Generating QR code for modal:', card.name, 'with code:', card.code);
        
        // Set canvas class for QR code styling
        canvas.className = 'qr-canvas';
        
        // Clear canvas before generating new QR code
        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        QRCode.toCanvas(canvas, card.code, {
          width: 300,
          margin: 4,
          color: {
            dark: '#000000',  // Always black
            light: '#FFFFFF'  // Always white
          }
        });
        console.log('✅ QR code generated for modal');
      } else {
        console.log('🔄 Generating barcode for modal...');
        
        if (typeof JsBarcode === 'undefined') {
          throw new Error('JsBarcode library not loaded');
        }
        
        // Set canvas class for barcode styling
        canvas.className = 'barcode-canvas';
        
        JsBarcode(canvas, card.code, {
          width: 3,
          height: 150,
          fontSize: 18,
          background: '#FFFFFF',  // Always white background
          lineColor: '#000000'    // Always black lines
        });
        console.log('✅ Barcode generated for modal');
      }
    } catch (error) {
      console.error('❌ Modal code generation error:', error);
      
      // Show error message in modal
      const errorMsg = document.createElement('div');
      errorMsg.style.cssText = 'text-align: center; padding: 20px; color: var(--error, #EF4444);';
      errorMsg.textContent = `Помилка генерації ${card.codeType === 'qrcode' ? 'QR-коду' : 'штрих-коду'}: ${error.message}`;
      
      // Replace canvas with error message
      if (canvas.parentNode) {
        canvas.parentNode.insertBefore(errorMsg, canvas);
        canvas.style.display = 'none';
      }
    }
    
    modal.classList.add('show');
  }

  closeCardModal() {
    document.getElementById('card-modal').classList.remove('show');
    this.currentCard = null;
  }

  async copyCardCode() {
    if (!this.currentCard) return;

    try {
      await navigator.clipboard.writeText(this.currentCard.code);
      this.showToast('success', this.safeT('messages.copied', 'Скопійовано'));
    } catch (error) {
      console.error('Copy error:', error);
      this.showToast('error', this.safeT('messages.copyFailed', 'Помилка копіювання'));
    }
  }

  // Profile Methods
  updateProfile() {
    if (!AppState.user) return;

    document.getElementById('user-id').textContent = AppState.user.id;
    document.getElementById('user-name').textContent = AppState.user.name;
    document.getElementById('user-email').textContent = AppState.user.email;
    document.getElementById('cards-count').textContent = AppState.cards.length;
    
    // Set join date
    const joinDate = document.getElementById('join-date');
    if (AppState.user.createdAt) {
      joinDate.textContent = window.i18n.formatDate(AppState.user.createdAt);
    } else {
      joinDate.textContent = this.safeT('profile.noDateAvailable', 'Дата недоступна');
    }

    // Update language selector
    const languageInput = document.querySelector(`input[name="language"][value="${AppState.user.language || 'uk'}"]`);
    console.log('Looking for language input:', AppState.user.language, 'Found:', !!languageInput);
    if (languageInput) {
      languageInput.checked = true;
    } else {
      // Fallback to Ukrainian if user language not found
      const fallbackInput = document.querySelector(`input[name="language"][value="uk"]`);
      if (fallbackInput) {
        fallbackInput.checked = true;
      }
    }
  }

  // API Methods - Use API client directly
  async apiCall(endpoint, options = {}) {
    try {
      // Map old API calls to new API client methods
      const method = options.method || 'GET';
      const body = options.body ? JSON.parse(options.body) : undefined;

      // Handle auth endpoints
      if (endpoint === '/auth/login') {
        return await window.api.login(body);
      }
      if (endpoint === '/auth/register') {
        return await window.api.register(body);
      }
      if (endpoint === '/auth/me') {
        const profile = await window.api.getProfile();
        return { user: profile.user, cards: profile.user.cards || [] };
      }
      if (endpoint === '/auth/profile') {
        return await window.api.updateProfile(body);
      }
      if (endpoint === '/auth/password') {
        return await window.api.changePassword(body);
      }
      
      // Handle card endpoints
      if (endpoint === '/cards' && method === 'POST') {
        await window.api.createCard(body);
        // Return updated cards list
        const updatedProfile = await window.api.getProfile();
        return { cards: updatedProfile.user.cards || [] };
      }
      if (endpoint.startsWith('/cards/') && method === 'DELETE') {
        const cardId = endpoint.replace('/cards/', '');
        await window.api.deleteCard(cardId);
        // Return updated cards list
        const updatedProfile = await window.api.getProfile();
        return { cards: updatedProfile.user.cards || [] };
      }
      
      // Fallback to direct API client request
      return await window.api.request(endpoint, options);

    } catch (error) {
      if (error.message.includes('Unauthorized') || error.message.includes('401')) {
        window.api.setToken(null);
        this.showAuthScreen();
      }
      throw error;
    }
  }

  // Data Synchronization Methods
  loadLocalData() {
    console.log('📂 Loading local data for offline mode...');
    
    try {
      const localCards = localStorage.getItem('cards');
      const localUser = localStorage.getItem('user');
      
      if (localCards) {
        AppState.cards = JSON.parse(localCards);
        console.log(`Loaded ${AppState.cards.length} cards from localStorage`);
      }
      
      if (localUser) {
        AppState.user = JSON.parse(localUser);
        console.log('Loaded user data from localStorage');
      }
    } catch (error) {
      console.error('Error loading local data:', error);
      AppState.cards = [];
      AppState.user = null;
    }
  }

  saveLocalData() {
    console.log('💾 Saving data to localStorage...');
    
    try {
      if (AppState.cards) {
        localStorage.setItem('cards', JSON.stringify(AppState.cards));
      }
      
      if (AppState.user) {
        localStorage.setItem('user', JSON.stringify(AppState.user));
      }
    } catch (error) {
      console.error('Error saving local data:', error);
    }
  }

  async syncData() {
    if (!window.api.isOnline() || !window.api.isAuthenticated()) {
      console.log('⚠️ Cannot sync: offline or not authenticated');
      return false;
    }

    try {
      console.log('🔄 Starting data synchronization...');
      
      const success = await window.api.syncData();
      
      if (success) {
        // Update AppState with synced data
        const localCards = localStorage.getItem('cards');
        if (localCards) {
          AppState.cards = JSON.parse(localCards);
        }
        
        // Save to localStorage as backup
        this.saveLocalData();
        
        console.log('✅ Data synchronized successfully');
        return true;
      } else {
        console.log('❌ Sync failed, continuing with local data');
        return false;
      }
    } catch (error) {
      console.error('❌ Sync error:', error);
      return false;
    }
  }

  // Utility Methods
  setButtonLoading(button, isLoading) {
    if (!button) {
      console.warn('Button not found for loading state');
      return;
    }
    
    if (isLoading) {
      button.disabled = true;
      button.dataset.originalText = button.textContent;
      button.textContent = this.safeT('messages.loading', 'Завантаження...');
    } else {
      button.disabled = false;
      button.textContent = button.dataset.originalText || button.textContent;
    }
  }

  showToast(type, message, duration = 3000) {
    const container = document.getElementById('toast-container');
    if (!container) {
      console.warn('Toast container not found, falling back to alert');
      alert(message);
      return;
    }
    
    const toast = document.createElement('div');
    
    toast.className = `toast ${type}`;
    toast.innerHTML = `
      <div class="toast-content">
        <div class="toast-message">${this.escapeHtml(message)}</div>
      </div>
    `;
    
    container.appendChild(toast);
    
    // Auto-remove toast
    setTimeout(() => {
      if (toast.parentNode) {
        toast.remove();
      }
    }, duration);
  }

  showUpdateNotification() {
    this.showToast('info', 'App update available. Please refresh.', 5000);
  }

  handleOnlineStatus() {
    this.showToast('success', this.safeT('messages.connectionRestored', 'З\'єднання відновлено'));
    // Sync any pending offline actions
  }

  handleOfflineStatus() {
    this.showToast('warning', this.safeT('messages.offlineMode', 'Офлайн режим'));
  }

  // Handle app resume/focus - validate token and refresh data
  async handleAppResume() {
    console.log('🔄 App resumed/focused');
    
    // Don't check if user is not authenticated
    if (!AppState.user) {
      console.log('User not authenticated, skipping resume check');
      return;
    }

    // Check if we have a token
    const token = localStorage.getItem('authToken') || localStorage.getItem('token');
    if (!token) {
      console.log('No token found, redirecting to auth');
      this.handleLogout();
      return;
    }

    // Only check token validity if app was in background for more than 30 seconds
    if (!this.lastActiveTime || Date.now() - this.lastActiveTime > 30000) {
      try {
        console.log('🔐 Validating token after app resume...');
        const response = await this.apiCall('/auth/me');
        
        if (response && response.user) {
          console.log('✅ Token still valid, refreshing data...');
          
          // Update app state with fresh data
          AppState.user = response.user;
          AppState.cards = response.cards || [];
          
          // Save data immediately
          this.saveLocalData();
          
          // Update language if changed
          if (response.user.language && response.user.language !== window.i18n.getCurrentLanguage()) {
            window.i18n.setLanguage(response.user.language);
            window.i18n.updatePageTexts();
          }
          
          // Refresh UI
          this.updateProfile();
          this.renderCards();
          
          console.log('✅ Data refreshed successfully');
        }
      } catch (error) {
        console.error('Token validation failed:', error);
        // Token is invalid, logout user
        this.handleLogout();
        this.showToast('error', this.safeT('messages.sessionExpired', 'Сесія закінчилася, увійдіть знову'));
      }
    }
    
    this.lastActiveTime = Date.now();
  }

  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  // Safe translation function with fallback
  safeT(key, fallback = key) {
    try {
      if (window.t && typeof window.t === 'function') {
        return window.t(key);
      }
      return fallback;
    } catch (error) {
      console.warn('Translation error for key:', key, error);
      return fallback;
    }
  }

  // Modal System Methods
  showModal(options = {}) {
    const {
      title = 'Повідомлення',
      message = '',
      confirmText = 'OK',
      cancelText = 'Скасувати',
      showCancel = false,
      type = 'info'
    } = options;

    console.log('🔍 showModal called with:', { title, message, confirmText, cancelText, showCancel, type });

    return new Promise((resolve) => {
      // Create modal if it doesn't exist
      let modal = document.getElementById('app-modal');
      if (!modal) {
        console.log('📝 Creating new modal');
        modal = this.createModal();
        document.body.appendChild(modal);
      } else {
        console.log('♻️ Using existing modal');
      }

      const overlay = modal;
      const modalContent = modal.querySelector('.modal');
      const modalTitle = modal.querySelector('.modal-title');
      const modalMessage = modal.querySelector('.modal-message');
      const confirmBtn = modal.querySelector('.modal-btn-primary');
      const cancelBtn = modal.querySelector('.modal-btn-secondary');
      const closeBtn = modal.querySelector('.modal-close');

      // Set content
      modalTitle.textContent = title;
      modalMessage.textContent = message;
      confirmBtn.textContent = confirmText;
      cancelBtn.textContent = cancelText;

      // Show/hide cancel button
      cancelBtn.style.display = showCancel ? 'inline-flex' : 'none';

      // Add type class for styling
      modalContent.className = `modal modal-${type}`;

      // Remove old listeners
      const newConfirmBtn = confirmBtn.cloneNode(true);
      const newCancelBtn = cancelBtn.cloneNode(true);
      const newCloseBtn = closeBtn.cloneNode(true);
      
      confirmBtn.parentNode.replaceChild(newConfirmBtn, confirmBtn);
      cancelBtn.parentNode.replaceChild(newCancelBtn, cancelBtn);
      closeBtn.parentNode.replaceChild(newCloseBtn, closeBtn);

      // Add new listeners
      const hideModal = () => {
        overlay.classList.remove('show');
        document.body.style.overflow = '';
      };

      newConfirmBtn.addEventListener('click', () => {
        hideModal();
        resolve(true);
      });

      newCancelBtn.addEventListener('click', () => {
        hideModal();
        resolve(false);
      });

      newCloseBtn.addEventListener('click', () => {
        hideModal();
        resolve(false);
      });

      overlay.addEventListener('click', (e) => {
        if (e.target === overlay) {
          hideModal();
          resolve(false);
        }
      });

      // ESC key handler
      const escHandler = (e) => {
        if (e.key === 'Escape') {
          hideModal();
          resolve(false);
          document.removeEventListener('keydown', escHandler);
        }
      };
      document.addEventListener('keydown', escHandler);

      // Show modal
      console.log('🎭 Showing modal...');
      console.log('Modal element before show:', overlay);
      console.log('Modal classes before show:', overlay.className);
      console.log('Modal in DOM before show:', document.contains(overlay));
      console.log('Modal computed visibility before show:', getComputedStyle(overlay).visibility);
      console.log('Modal computed opacity before show:', getComputedStyle(overlay).opacity);
      
      overlay.classList.add('show');
      document.body.style.overflow = 'hidden';
      
      console.log('Modal classes after show:', overlay.className);
      console.log('Modal computed visibility after show:', getComputedStyle(overlay).visibility);
      console.log('Modal computed opacity after show:', getComputedStyle(overlay).opacity);
      console.log('✅ Modal should now be visible');
      
      // Focus on confirm button
      setTimeout(() => {
        newConfirmBtn.focus();
      }, 100);
    });
  }

  createModal() {
    const modalHTML = `
      <div class="modal-overlay app-modal-system" id="app-modal">
        <div class="modal app-modal-content">
          <div class="modal-header">
            <h3 class="modal-title">Заголовок</h3>
            <button class="modal-close">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
                <path d="M18 6L6 18M6 6L18 18" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
              </svg>
            </button>
          </div>
          <div class="modal-body">
            <p class="modal-message">Повідомлення</p>
          </div>
          <div class="modal-actions">
            <button class="modal-btn modal-btn-primary">OK</button>
            <button class="modal-btn modal-btn-secondary">Скасувати</button>
          </div>
        </div>
      </div>
    `;
    
    const div = document.createElement('div');
    div.innerHTML = modalHTML;
    const modal = div.firstElementChild;
    
    // Debug logging
    console.log('🔧 Created modal element:', modal);
    console.log('Modal classes:', modal.className);
    console.log('Modal ID:', modal.id);
    console.log('Modal inner content:', modal.querySelector('.app-modal-content'));
    
    return modal;
  }

  showAlert(message, title = 'Повідомлення') {
    try {
      return this.showModal({
        title,
        message,
        confirmText: 'OK',
        type: 'alert'
      });
    } catch (error) {
      console.error('Modal error:', error);
      // Fallback to native alert
      alert(title + ': ' + message);
      return Promise.resolve(true);
    }
  }

  showConfirm(message, title = 'Підтвердження') {
    return this.showModal({
      title,
      message,
      confirmText: 'Так',
      cancelText: 'Ні',
      showCancel: true,
      type: 'confirm'
    });
  }

  showPrompt(message, defaultValue = '', title = 'Введіть значення') {
    return new Promise((resolve) => {
      // Create prompt modal
      let modal = document.getElementById('app-prompt-modal');
      if (!modal) {
        modal = this.createPromptModal();
        document.body.appendChild(modal);
      }

      const overlay = modal;
      const modalTitle = modal.querySelector('.modal-title');
      const modalMessage = modal.querySelector('.modal-message');
      const input = modal.querySelector('.modal-input');
      const confirmBtn = modal.querySelector('.modal-btn-primary');
      const cancelBtn = modal.querySelector('.modal-btn-secondary');
      const closeBtn = modal.querySelector('.modal-close');

      // Set content
      modalTitle.textContent = title;
      modalMessage.textContent = message;
      input.value = defaultValue;

      // Remove old listeners
      const newConfirmBtn = confirmBtn.cloneNode(true);
      const newCancelBtn = cancelBtn.cloneNode(true);
      const newCloseBtn = closeBtn.cloneNode(true);
      
      confirmBtn.parentNode.replaceChild(newConfirmBtn, confirmBtn);
      cancelBtn.parentNode.replaceChild(newCancelBtn, cancelBtn);
      closeBtn.parentNode.replaceChild(newCloseBtn, closeBtn);

      const hideModal = () => {
        overlay.classList.remove('show');
        document.body.style.overflow = '';
      };

      const handleConfirm = () => {
        const value = input.value.trim();
        hideModal();
        resolve(value || null);
      };

      const handleCancel = () => {
        hideModal();
        resolve(null);
      };

      newConfirmBtn.addEventListener('click', handleConfirm);
      newCancelBtn.addEventListener('click', handleCancel);
      newCloseBtn.addEventListener('click', handleCancel);

      overlay.addEventListener('click', (e) => {
        if (e.target === overlay) handleCancel();
      });

      input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          handleConfirm();
        } else if (e.key === 'Escape') {
          e.preventDefault();
          handleCancel();
        }
      });

      // Show modal
      overlay.classList.add('show');
      document.body.style.overflow = 'hidden';
      
      // Focus on input
      setTimeout(() => {
        input.focus();
        input.select();
      }, 100);
    });
  }

  createPromptModal() {
    const modalHTML = `
      <div class="modal-overlay" id="app-prompt-modal">
        <div class="modal modal-prompt">
          <div class="modal-header">
            <h3 class="modal-title">Введіть значення</h3>
            <button class="modal-close">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
                <path d="M18 6L6 18M6 6L18 18" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
              </svg>
            </button>
          </div>
          <div class="modal-body">
            <p class="modal-message">Введіть нове значення:</p>
            <input type="text" class="modal-input" placeholder="Введіть значення...">
          </div>
          <div class="modal-actions">
            <button class="modal-btn modal-btn-primary">OK</button>
            <button class="modal-btn modal-btn-secondary">Скасувати</button>
          </div>
        </div>
      </div>
    `;
    
    const div = document.createElement('div');
    div.innerHTML = modalHTML;
    return div.firstElementChild;
  }
}

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  window.app = new LoyaltyCardsApp();
});

// Error handling
window.addEventListener('error', (e) => {
  console.error('App error:', e.error);
});

window.addEventListener('unhandledrejection', (e) => {
  console.error('Unhandled promise rejection:', e.reason);
});