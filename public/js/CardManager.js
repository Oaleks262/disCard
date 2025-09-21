// CardManager.js - Card management functionality
class CardManager {
  constructor(app) {
    this.app = app;
    this.currentCard = null;
    this.isThemeUpdate = false;
  }

  async handleAddCard(e) {
    e.preventDefault();
    
    // Check if user is authenticated
    if (!AppState.user || !localStorage.getItem('authToken')) {
      console.error('User not authenticated');
      UIUtils.showToast('error', 'Необхідно авторизуватися');
      this.app.auth.showAuthScreen();
      return;
    }
    
    const name = document.getElementById('card-name').value;
    const code = document.getElementById('card-code').value;
    const codeTypeElement = document.querySelector('input[name="codeType"]:checked');
    
    if (!codeTypeElement) {
      UIUtils.showToast('error', 'Оберіть тип коду');
      return;
    }
    
    const codeType = codeTypeElement.value;
    
    if (!name || !code) {
      const message = UIUtils.safeT('messages.fillAllFields', 'Заповніть всі поля');
      UIUtils.showToast('error', message);
      return;
    }

    // Find submit button properly
    const submitBtn = e.target.querySelector('button[type="submit"]') || 
                     e.target.querySelector('.submit-button') ||
                     document.querySelector('#add-card-form button[type="submit"]') ||
                     document.querySelector('#add-card-form .submit-button');
    
    if (submitBtn) {
      UIUtils.setButtonLoading(submitBtn, true);
    }

    try {
      // Send plain code to server - server will handle encryption
      const response = await this.app.apiCall('/cards', {
        method: 'POST',
        body: JSON.stringify({ 
          name, 
          code,
          codeType
        })
      });

      if (response && response.cards) {
        // Server returns decrypted cards ready for display
        AppState.cards = response.cards;
        this.renderCards();
        
        const successMessage = UIUtils.safeT('messages.cardAdded', 'Картку додано');
        UIUtils.showToast('success', successMessage);
        
        // Reset form
        const form = document.getElementById('add-card-form');
        if (form && typeof form.reset === 'function') {
          form.reset();
        } else {
          // Manual reset as fallback
          document.getElementById('card-name').value = '';
          document.getElementById('card-code').value = '';
          const defaultCodeType = document.querySelector('input[name="codeType"][value="barcode"]');
          if (defaultCodeType) defaultCodeType.checked = true;
        }
        this.clearCodePreview();
        
        // Switch to cards tab
        this.app.switchTab('cards');
      } else {
        console.error('Invalid response format:', response);
        UIUtils.showToast('error', 'Некоректна відповідь сервера');
      }
    } catch (error) {
      console.error('Add card error:', error);
      const errorMessage = error.message || UIUtils.safeT('messages.serverError', 'Помилка сервера');
      UIUtils.showToast('error', errorMessage);
    } finally {
      if (submitBtn) {
        UIUtils.setButtonLoading(submitBtn, false);
      }
    }
  }

  renderCards() {
    try {
      const grid = document.getElementById('cards-grid');
      const emptyState = document.getElementById('cards-empty');
      
      if (!grid || !emptyState) {
        return;
      }
    
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
    } catch (error) {
      console.error('Error rendering cards:', error);
    }
  }

  createCardHTML(card) {
    const createdDate = window.i18n.formatTime(card.createdAt);
    const cardTypeText = card.codeType === 'qrcode' ? 'QR' : UIUtils.safeT('cards.barcode', 'Штрих-код');
    const createdText = UIUtils.safeT('cards.created', 'Створено');
    
    return `
      <div class="card-item" data-card-id="${card._id}">
        <div class="card-header">
          <div class="card-name">${UIUtils.escapeHtml(card.name)}</div>
          <div class="card-type">${cardTypeText}</div>
        </div>
        <div class="card-code-preview">
          <div class="code-loading" id="loading-${card._id}">
            <div class="loading-spinner"></div>
            <span>Генерування коду...</span>
          </div>
          <canvas id="card-canvas-${card._id}" width="160" height="160" style="display: none;"></canvas>
        </div>
        <div class="card-info">
          <span>${createdText}: ${createdDate}</span>
        </div>
      </div>
    `;
  }

  generateCardPreview(card, cardElement) {
    const canvas = cardElement.querySelector(`#card-canvas-${card._id}`);
    const loading = cardElement.querySelector(`#loading-${card._id}`);
    
    if (!canvas) {
      return;
    }

    // Show loading, hide canvas
    if (loading) loading.style.display = 'flex';
    canvas.style.display = 'none';

    try {
      if (card.codeType === 'qrcode') {
        if (typeof QRCode === 'undefined') {
          this.hideLoadingShowError(loading, canvas, 'QRCode library not loaded');
          return;
        }
        
        // Clear canvas before generating new QR code
        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        // Check if card has valid code
        const codeValue = card.code || card.encryptedCode || 'NO_CODE';
        
        QRCode.toCanvas(canvas, codeValue, {
          width: 160,
          margin: 1,
          color: {
            dark: '#000000',  // Always black
            light: '#FFFFFF'  // Always white
          }
        }, (error) => {
          if (error) {
            this.hideLoadingShowError(loading, canvas, 'Error generating QR code');
          } else {
            // Success - hide loading, show canvas
            if (loading) loading.style.display = 'none';
            canvas.style.display = 'block';
          }
        });
      } else {
        if (typeof JsBarcode === 'undefined') {
          this.hideLoadingShowError(loading, canvas, 'JsBarcode library not loaded');
          return;
        }

        // Check if card has valid code
        const codeValue = card.code || card.encryptedCode || 'NO_CODE';
        
        JsBarcode(canvas, codeValue, {
          format: "CODE128",
          width: 2,
          height: 60,
          displayValue: false,
          background: "#FFFFFF",
          lineColor: "#000000"
        });
        
        // Success - hide loading, show canvas
        if (loading) loading.style.display = 'none';
        canvas.style.display = 'block';
      }
    } catch (error) {
      this.hideLoadingShowError(loading, canvas, 'Code generation failed');
    }
  }

  hideLoadingShowError(loading, canvas, errorMessage) {
    if (loading) {
      loading.innerHTML = `<span style="color: #ff6b6b;">⚠️ ${errorMessage}</span>`;
    }
    canvas.style.display = 'none';
  }

  showCardModal(card) {
    this.currentCard = card;
    const modal = document.getElementById('card-modal');
    const title = document.getElementById('modal-card-name');
    const canvas = document.getElementById('modal-canvas');
    const codeText = document.getElementById('modal-code-text');
    
    if (!modal || !title || !canvas || !codeText) {
      console.error('Modal elements not found');
      return;
    }
    
    title.textContent = card.name;
    codeText.textContent = card.code || 'No code available';
    
    // Generate code
    try {
      if (card.codeType === 'qrcode') {
        if (typeof QRCode === 'undefined') {
          throw new Error('QRCode library not loaded');
        }
        
        // Validate card code data
        if (!card.code || typeof card.code !== 'string' || card.code.trim() === '') {
          throw new Error('Invalid card code data');
        }
        
        // Set canvas class for QR code styling
        canvas.className = 'qr-canvas';
        
        // Clear canvas before generating new QR code
        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        QRCode.toCanvas(canvas, card.code.trim(), {
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
      console.error('Modal code generation error:', error);
      
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
    
    // Add backdrop click listener (only once)
    if (!modal.hasAttribute('data-backdrop-listener')) {
      modal.addEventListener('click', (e) => {
        if (e.target === modal) {
          this.closeCardModal();
        }
      });
      modal.setAttribute('data-backdrop-listener', 'true');
    }
    
    // Add ESC key listener
    this.handleEscKey = (e) => {
      if (e.key === 'Escape' && modal.classList.contains('show')) {
        this.closeCardModal();
      }
    };
    document.addEventListener('keydown', this.handleEscKey);
  }

  closeCardModal() {
    document.getElementById('card-modal').classList.remove('show');
    this.currentCard = null;
    
    // Remove ESC key listener
    if (this.handleEscKey) {
      document.removeEventListener('keydown', this.handleEscKey);
      this.handleEscKey = null;
    }
  }

  async deleteCard() {
    const cardId = this.currentCard?._id;
    if (!cardId) {
      console.error('No card ID found');
      return;
    }

    const confirmMessage = UIUtils.safeT('messages.confirmDelete', 'Ви впевнені, що хочете видалити цю картку?');
    const confirmed = await UIUtils.showConfirm(confirmMessage);
    if (!confirmed) return;

    try {
      const response = await this.app.apiCall(`/cards/${cardId}`, {
        method: 'DELETE'
      });

      AppState.cards = response.cards;
      this.renderCards();
      this.closeCardModal();
      UIUtils.showToast('success', UIUtils.safeT('messages.cardDeleted', 'Картку видалено'));
    } catch (error) {
      console.error('Delete card error:', error);
      UIUtils.showToast('error', error.message || UIUtils.safeT('messages.serverError', 'Помилка сервера'));
    }
  }

  async copyCardCode() {
    if (!this.currentCard) return;

    try {
      await navigator.clipboard.writeText(this.currentCard.code);
      UIUtils.showToast('success', UIUtils.safeT('messages.copied', 'Скопійовано'));
    } catch (error) {
      console.error('Copy error:', error);
      UIUtils.showToast('error', UIUtils.safeT('messages.copyFailed', 'Помилка копіювання'));
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

  updateFormValidation() {
    const name = document.getElementById('card-name')?.value || '';
    const code = document.getElementById('card-code')?.value || '';
    const submitBtn = document.querySelector('#add-card-form button[type="submit"]');
    
    if (submitBtn) {
      const shouldDisable = !name.trim() || !code.trim();
      submitBtn.disabled = shouldDisable;
    }
  }

  updateCodePreview(codeType) {
    const code = document.getElementById('card-code').value;
    const preview = document.getElementById('code-preview');
    const canvas = document.getElementById('preview-canvas');
    
    if (!code) {
      preview.style.display = 'none';
      return;
    }

    const selectedCodeType = codeType || document.querySelector('input[name="codeType"]:checked')?.value;
    
    preview.style.display = 'block';

    try {
      if (selectedCodeType === 'qrcode') {
        if (typeof QRCode === 'undefined') {
          throw new Error('QRCode library not loaded');
        }
        
        // Clear canvas before generating new QR code
        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        window.QRCode.toCanvas(canvas, code, {
          width: 200,
          margin: 2,
          color: {
            dark: '#000000',  // Always black
            light: '#FFFFFF'  // Always white
          }
        });
      } else {
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
      }
    } catch (error) {
      console.error('Code generation error:', error);
      UIUtils.showToast('error', UIUtils.safeT('messages.invalidCode', 'Помилка генерації коду'));
    }
  }

  clearCodePreview() {
    document.getElementById('code-preview').style.display = 'none';
    document.querySelector('input[name="codeType"][value="barcode"]').checked = true;
  }

  regenerateModalCode() {
    if (!this.currentCard) {
      return;
    }

    const canvas = document.getElementById('modal-canvas');
    if (!canvas) {
      return;
    }

    const card = this.currentCard;

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
      console.error('Modal code regeneration error:', error);
    }
  }

  // Setup card event listeners
  setupCardEventListeners() {
    // Card form handling
    const addCardForm = document.getElementById('add-card-form');
    if (addCardForm) {
      const submitButton = addCardForm.querySelector('button[type="submit"]') || 
                          addCardForm.querySelector('.submit-button') || 
                          document.querySelector('.submit-button');
      
      if (submitButton) {
        // Remove any existing listeners
        const newSubmitButton = submitButton.cloneNode(true);
        submitButton.parentNode.replaceChild(newSubmitButton, submitButton);
        
        newSubmitButton.addEventListener('click', (e) => {
          e.preventDefault();
          
          // Create proper form event
          const formEvent = {
            preventDefault: () => {},
            target: addCardForm,
            type: 'submit'
          };
          
          this.handleAddCard(formEvent);
        });
        
        // Also handle form submission directly
        addCardForm.addEventListener('submit', (e) => {
          e.preventDefault();
          this.handleAddCard(e);
        });
        
        this.updateFormValidation();
      }
    }
    
    // Cards search
    document.getElementById('cards-search')?.addEventListener('input', this.handleCardsSearch.bind(this));

    // Card modal
    document.getElementById('modal-close')?.addEventListener('click', this.closeCardModal.bind(this));
    document.getElementById('copy-code-btn')?.addEventListener('click', this.copyCardCode.bind(this));
    document.getElementById('delete-card-btn')?.addEventListener('click', this.deleteCard.bind(this));
    
    // Cancel add card button
    document.getElementById('cancel-add-card')?.addEventListener('click', this.cancelAddCard.bind(this));

    // Form validation on input changes
    document.getElementById('card-name')?.addEventListener('input', this.updateFormValidation.bind(this));
    document.getElementById('card-code')?.addEventListener('input', (e) => {
      // Validate and filter input to only allow English letters, numbers, hyphens, and spaces
      const input = e.target;
      const value = input.value;
      const filteredValue = value.replace(/[^A-Za-z0-9\-\s]/g, '');
      
      if (value !== filteredValue) {
        input.value = filteredValue;
        UIUtils.showToast('warning', 'Дозволені тільки англійські літери, цифри, дефіси та пробіли');
      }
      
      this.updateFormValidation();
      this.updateCodePreview();
    });

    // Code type change
    document.querySelectorAll('input[name="codeType"]').forEach(radio => {
      radio.addEventListener('change', () => {
        this.updateCodePreview();
      });
    });
  }

  cancelAddCard() {
    // Clear form fields
    document.getElementById('card-name').value = '';
    document.getElementById('card-code').value = '';
    
    // Reset code type to default (barcode)
    document.querySelector('input[name="codeType"][value="barcode"]').checked = true;
    
    // Clear code preview
    this.clearCodePreview();
    
    // Switch to cards tab
    if (window.app && window.app.switchTab) {
      window.app.switchTab('cards');
    }
    
    UIUtils.showToast('info', 'Додавання картки скасовано');
  }
}

// Export for use in other modules
window.CardManager = CardManager;