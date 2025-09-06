// ThemeManager.js - Theme management functionality
class ThemeManager {
  constructor(app) {
    this.app = app;
    this.isThemeUpdate = false;
  }

  initializeTheme() {
    const savedTheme = localStorage.getItem('theme');
    const systemTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    
    AppState.theme = savedTheme || systemTheme;
    this.applyTheme(AppState.theme);
    
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

  applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    AppState.theme = theme;
    localStorage.setItem('theme', theme);
    
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
    setTimeout(() => {
      this.updateCodesForTheme();
    }, 100);
  }

  updateCodesForTheme() {
    // Set flag to reduce logging during theme updates
    this.isThemeUpdate = true;
    
    try {
      // 1. Update code preview in add form (if visible and has content)
      const codeInput = document.getElementById('card-code');
      const preview = document.getElementById('code-preview');
      if (codeInput && preview && codeInput.value && !preview.classList.contains('hidden')) {
        this.app.updateCodePreview();
      }
      
      // 2. Update all card previews in grid
      const cardItems = document.querySelectorAll('.card-item');
      cardItems.forEach((cardElement, index) => {
        if (index < AppState.cards.length) {
          const card = AppState.cards[index];
          this.app.generateCardPreview(card, cardElement);
        }
      });
      
      // 3. Update modal code if modal is open
      const cardModal = document.getElementById('card-modal');
      if (cardModal && cardModal.classList.contains('show') && this.app.currentCard) {
        this.regenerateModalCode();
      }
    } finally {
      // Always reset flag
      this.isThemeUpdate = false;
    }
  }

  regenerateModalCode() {
    if (!this.app.currentCard) {
      console.warn('No current card to regenerate modal code');
      return;
    }

    const canvas = document.getElementById('modal-canvas');
    if (!canvas) {
      console.warn('Modal canvas not found');
      return;
    }

    const card = this.app.currentCard;

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

  // Setup theme event listeners
  setupThemeEventListeners() {
    // Settings theme radio buttons
    document.querySelectorAll('input[name="theme"]').forEach(input => {
      input.addEventListener('change', this.handleThemeChange.bind(this));
    });

    // Theme toggle button
    document.getElementById('theme-toggle')?.addEventListener('click', this.toggleTheme.bind(this));
  }
}

// Export for use in other modules
window.ThemeManager = ThemeManager;