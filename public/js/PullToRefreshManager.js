// PullToRefreshManager.js - Pull-to-refresh functionality
class PullToRefreshManager {
  constructor(app) {
    this.app = app;
    this.ptrState = {
      pulling: false,
      refreshing: false,
      startY: 0,
      currentY: 0,
      threshold: 80
    };
    this.ptrIndicator = null;
    this.ptrIcon = null;
    this.ptrText = null;
    this.appContainer = null;
  }

  setupPullToRefresh() {
    // Initialize pull-to-refresh state
    this.ptrState = {
      pulling: false,
      refreshing: false,
      startY: 0,
      currentY: 0,
      threshold: 80
    };

    // Create pull-to-refresh indicator
    this.ptrIndicator = document.createElement('div');
    this.ptrIndicator.className = 'ptr-indicator';
    this.ptrIndicator.innerHTML = `
      <div class="ptr-content">
        <div class="ptr-icon">↓</div>
        <div class="ptr-text">Потягніть для оновлення</div>
      </div>
    `;

    this.ptrIcon = this.ptrIndicator.querySelector('.ptr-icon');
    this.ptrText = this.ptrIndicator.querySelector('.ptr-text');

    // Insert at the beginning of app container
    this.appContainer = document.getElementById('app-container');
    if (this.appContainer) {
      this.appContainer.insertBefore(this.ptrIndicator, this.appContainer.firstChild);

      // Touch events
      this.appContainer.addEventListener('touchstart', this.handleTouchStart.bind(this), { passive: true });
      this.appContainer.addEventListener('touchmove', this.handleTouchMove.bind(this), { passive: false });
      this.appContainer.addEventListener('touchend', this.handleTouchEnd.bind(this), { passive: true });

      // Mouse events for desktop testing
      this.appContainer.addEventListener('mousedown', this.handleMouseDown.bind(this));
      this.appContainer.addEventListener('mousemove', this.handleMouseMove.bind(this));
      this.appContainer.addEventListener('mouseup', this.handleMouseUp.bind(this));
    }
  }

  handleTouchStart(e) {
    // Only handle if at top of scroll AND user is not authenticated
    if (this.appContainer.scrollTop > 0 || !AppState.user) return;

    this.ptrState.startY = e.touches[0].clientY;
    this.ptrState.pulling = false;
  }

  handleTouchMove(e) {
    if (!AppState.user || this.ptrState.refreshing) return;

    const currentY = e.touches[0].clientY;
    const deltaY = currentY - this.ptrState.startY;

    // Only activate if pulling down from top
    if (deltaY > 0 && this.appContainer.scrollTop === 0) {
      e.preventDefault(); // Prevent scrolling

      this.ptrState.pulling = true;
      this.ptrState.currentY = deltaY;

      this.updatePullIndicator(deltaY);
    }
  }

  handleTouchEnd() {
    if (!this.ptrState.pulling || this.ptrState.refreshing) return;

    const deltaY = this.ptrState.currentY;

    if (deltaY >= this.ptrState.threshold) {
      this.triggerRefresh();
    } else {
      this.resetPtrState();
    }

    this.ptrState.pulling = false;
  }

  // Mouse events for desktop testing
  handleMouseDown(e) {
    if (this.appContainer.scrollTop > 0 || !AppState.user) return;
    this.ptrState.startY = e.clientY;
    this.ptrState.pulling = false;
  }

  handleMouseMove(e) {
    if (!AppState.user || this.ptrState.refreshing || !this.ptrState.startY) return;

    const currentY = e.clientY;
    const deltaY = currentY - this.ptrState.startY;

    if (deltaY > 0 && this.appContainer.scrollTop === 0) {
      this.ptrState.pulling = true;
      this.ptrState.currentY = deltaY;
      this.updatePullIndicator(deltaY);
    }
  }

  handleMouseUp() {
    if (!this.ptrState.pulling || this.ptrState.refreshing) return;

    const deltaY = this.ptrState.currentY;
    if (deltaY >= this.ptrState.threshold) {
      this.triggerRefresh();
    } else {
      this.resetPtrState();
    }

    this.ptrState.pulling = false;
    this.ptrState.startY = 0;
  }

  updatePullIndicator(deltaY) {
    const maxPull = this.ptrState.threshold * 1.5;
    const pullRatio = Math.min(deltaY / maxPull, 1);
    const pullDistance = Math.min(deltaY * 0.3, this.ptrState.threshold * 0.8);

    this.ptrIndicator.style.transform = `translateY(${pullDistance}px)`;
    this.ptrIndicator.style.opacity = pullRatio;

    if (deltaY >= this.ptrState.threshold) {
      this.ptrIcon.classList.add('rotated');
      this.ptrText.textContent = 'Відпустіть для оновлення';
    } else {
      this.ptrIcon.classList.remove('rotated');
      this.ptrText.textContent = 'Потягніть для оновлення';
    }
  }

  async triggerRefresh() {
    this.ptrState.refreshing = true;
    this.ptrIndicator.classList.add('refreshing');
    this.ptrIcon.classList.remove('rotated');
    this.ptrIcon.classList.add('spinning');
    this.ptrText.textContent = 'Оновлення...';

    try {
      // Call the data manager's refresh method
      await this.app.data.performRefresh();
      
      // Update UI
      this.app.data.updateProfile();
      this.app.cards.renderCards();
      
    } catch (error) {
      console.error('Refresh failed:', error);
      if (error.message === 'Session expired') {
        // Auth manager will handle session expiration
        return;
      } else {
        UIUtils.showToast('error', 'Помилка оновлення');
      }
    }

    // Reset state after delay
    setTimeout(() => {
      this.resetPtrState();
    }, 1000);
  }

  resetPtrState() {
    this.ptrState.refreshing = false;
    this.ptrState.pulling = false;
    this.ptrState.currentY = 0;
    
    this.ptrIndicator.classList.remove('refreshing');
    this.ptrIcon.classList.remove('spinning', 'rotated');
    this.ptrText.textContent = 'Потягніть для оновлення';
    
    // Reset transform
    this.ptrIndicator.style.transform = '';
  }
}

// Export for use in other modules
window.PullToRefreshManager = PullToRefreshManager;