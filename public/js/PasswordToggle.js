// PasswordToggle.js - Password visibility toggle functionality
class PasswordToggle {
  constructor() {
    this.init();
  }

  init() {
    // Setup event listeners for all password toggle buttons
    document.addEventListener('click', (e) => {
      if (e.target.closest('.password-toggle')) {
        e.preventDefault();
        const button = e.target.closest('.password-toggle');
        this.togglePassword(button);
      }
    });
  }

  togglePassword(button) {
    const targetId = button.getAttribute('data-target');
    const input = document.getElementById(targetId);
    
    if (!input) {
      console.error(`Password input with id "${targetId}" not found`);
      return;
    }

    const eyeOpen = button.querySelector('.eye-open');
    const eyeClosed = button.querySelector('.eye-closed');

    if (input.type === 'password') {
      // Show password
      input.type = 'text';
      eyeOpen.style.display = 'none';
      eyeClosed.style.display = 'block';
      button.setAttribute('aria-label', 'Приховати пароль');
    } else {
      // Hide password
      input.type = 'password';
      eyeOpen.style.display = 'block';
      eyeClosed.style.display = 'none';
      button.setAttribute('aria-label', 'Показати пароль');
    }
  }

  // Initialize all password toggles with proper accessibility
  setupAccessibility() {
    const toggleButtons = document.querySelectorAll('.password-toggle');
    toggleButtons.forEach(button => {
      button.setAttribute('aria-label', 'Показати пароль');
      button.setAttribute('type', 'button');
      button.setAttribute('tabindex', '0');
      
      // Add keyboard support
      button.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          this.togglePassword(button);
        }
      });
    });
  }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  const passwordToggle = new PasswordToggle();
  passwordToggle.setupAccessibility();
});

// Export for use in other modules
window.PasswordToggle = PasswordToggle;