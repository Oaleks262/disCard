// Landing Page JavaScript

class LandingPage {
  constructor() {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => this.init());
    } else {
      this.init();
    }
  }

  init() {
    this.setupLanguageSwitcher();
    this.setupCTAButton();
    this.setupScrollAnimations();
    this.setupThemeDetection();
    
    // Update texts after language is loaded
    setTimeout(() => {
      if (window.i18n) {
        window.i18n.updatePageTexts();
      }
    }, 100);
  }

  setupLanguageSwitcher() {
    const languageBtns = document.querySelectorAll('.lang-btn');
    
    languageBtns.forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        
        const selectedLang = btn.dataset.lang;
        const currentLang = window.i18n ? window.i18n.getCurrentLanguage() : 'uk';
        
        if (selectedLang !== currentLang) {
          // Update active state
          languageBtns.forEach(b => b.classList.remove('active'));
          btn.classList.add('active');
          
          // Change language
          if (window.i18n) {
            window.i18n.setLanguage(selectedLang);
          }
          
          // Add animation effect
          btn.style.transform = 'scale(0.95)';
          setTimeout(() => {
            btn.style.transform = '';
          }, 150);
        }
      });
    });

    // Set initial active state
    setTimeout(() => {
      if (window.i18n) {
        const currentLang = window.i18n.getCurrentLanguage();
        const activeLangBtn = document.querySelector(`[data-lang="${currentLang}"]`);
        if (activeLangBtn) {
          document.querySelectorAll('.lang-btn').forEach(btn => btn.classList.remove('active'));
          activeLangBtn.classList.add('active');
        }
      } else {
        // Default to Ukrainian if i18n not loaded
        const ukBtn = document.querySelector('[data-lang="uk"]');
        if (ukBtn) {
          ukBtn.classList.add('active');
        }
      }
    }, 100);
  }

  setupCTAButton() {
    const ctaButton = document.getElementById('cta-button');
    
    if (ctaButton) {
      ctaButton.addEventListener('click', (e) => {
        e.preventDefault();
        
        // Add click animation
        ctaButton.style.transform = 'translateY(-2px) scale(0.98)';
        
        setTimeout(() => {
          ctaButton.style.transform = '';
          // Redirect to app
          this.navigateToApp();
        }, 200);
      });

      // Add hover effect
      ctaButton.addEventListener('mouseenter', () => {
        this.animatePhoneMockup();
      });
    }
  }

  navigateToApp() {
    // Redirect directly to app
    window.location.href = '/app.html';
  }

  animatePhoneMockup() {
    const mockup = document.querySelector('.phone-mockup');
    if (mockup) {
      mockup.style.animation = 'none';
      setTimeout(() => {
        mockup.style.animation = 'float 6s ease-in-out infinite';
      }, 10);
    }
  }

  setupScrollAnimations() {
    // Intersection Observer for animations
    const observerOptions = {
      threshold: 0.1,
      rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.style.opacity = '1';
          entry.target.style.transform = 'translateY(0)';
          
          // Animate feature cards with delay
          if (entry.target.classList.contains('feature-card')) {
            const index = Array.from(entry.target.parentNode.children).indexOf(entry.target);
            entry.target.style.transitionDelay = `${index * 0.1}s`;
          }
          
          // Animate screenshot cards
          if (entry.target.classList.contains('screenshot-card')) {
            const index = Array.from(entry.target.parentNode.children).indexOf(entry.target);
            entry.target.style.transitionDelay = `${index * 0.15}s`;
          }
        }
      });
    }, observerOptions);

    // Observe elements for animation
    document.querySelectorAll('.feature-card, .screenshot-card').forEach(el => {
      el.style.opacity = '0';
      el.style.transform = 'translateY(30px)';
      el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
      observer.observe(el);
    });
  }

  setupThemeDetection() {
    // Detect system theme preference
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      document.body.classList.add('dark-theme-preferred');
    }

    // Listen for theme changes
    if (window.matchMedia) {
      window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => {
        if (e.matches) {
          document.body.classList.add('dark-theme-preferred');
        } else {
          document.body.classList.remove('dark-theme-preferred');
        }
      });
    }
  }

  // Utility methods
  smoothScrollTo(target) {
    const element = document.querySelector(target);
    if (element) {
      element.scrollIntoView({
        behavior: 'smooth',
        block: 'start'
      });
    }
  }

  // Analytics and tracking (placeholder)
  trackEvent(event, data = {}) {
    // Implementation for analytics
  }
}

// Additional animations and effects
class LandingAnimations {
  constructor() {
    this.initCodeAnimations();
    this.initParallaxEffect();
  }

  initCodeAnimations() {
    // Animate the barcode and QR codes in the phone mockup
    const barcodes = document.querySelectorAll('.barcode.animated');
    const qrcodes = document.querySelectorAll('.qrcode.animated');

    // Stagger animations
    barcodes.forEach((barcode, index) => {
      barcode.style.animationDelay = `${index * 0.5}s`;
    });

    qrcodes.forEach((qrcode, index) => {
      qrcode.style.animationDelay = `${index * 0.7}s`;
    });
  }

  initParallaxEffect() {
    // Simple parallax effect for hero section - disabled on mobile
    if (window.innerWidth <= 768) {
      return; // Skip parallax on mobile devices
    }
    
    window.addEventListener('scroll', () => {
      const scrolled = window.pageYOffset;
      const rate = scrolled * -0.3;
      
      const heroVisual = document.querySelector('.hero-visual');
      if (heroVisual) {
        heroVisual.style.transform = `translateY(${rate}px)`;
      }
    });
  }

}

// Performance optimization
class LandingPerformance {
  constructor() {
    this.optimizeImages();
    this.preloadCriticalResources();
  }

  optimizeImages() {
    // Lazy load images when they come into viewport
    const images = document.querySelectorAll('img[data-src]');
    
    const imageObserver = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const img = entry.target;
          img.src = img.dataset.src;
          img.classList.remove('lazy');
          imageObserver.unobserve(img);
        }
      });
    });

    images.forEach(img => imageObserver.observe(img));
  }

  preloadCriticalResources() {
    // Preload app.html for faster navigation
    const link = document.createElement('link');
    link.rel = 'prefetch';
    link.href = '/app.html';
    document.head.appendChild(link);

    // Preload critical app CSS
    const cssLink = document.createElement('link');
    cssLink.rel = 'prefetch';
    cssLink.href = '/css/app.css';
    document.head.appendChild(cssLink);
  }
}

// Mobile optimizations
class LandingMobile {
  constructor() {
    this.setupTouchGestures();
    this.optimizeForMobile();
  }

  setupTouchGestures() {
    // Add touch feedback for interactive elements
    const interactiveElements = document.querySelectorAll('button, .card-item, .feature-card');
    
    interactiveElements.forEach(element => {
      element.addEventListener('touchstart', () => {
        element.style.transform = 'scale(0.98)';
      });

      element.addEventListener('touchend', () => {
        setTimeout(() => {
          element.style.transform = '';
        }, 150);
      });
    });
  }

  optimizeForMobile() {
    // Optimize animations for mobile
    if (window.DeviceMotionEvent) {
      // Reduce animations on mobile for better performance
      document.documentElement.style.setProperty('--transition-duration', '0.2s');
    }

    // Handle orientation change
    window.addEventListener('orientationchange', () => {
      setTimeout(() => {
        // Recalculate layout after orientation change
        window.dispatchEvent(new Event('resize'));
      }, 100);
    });
  }
}

// Initialize classes
new LandingPage();

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  new LandingAnimations();
  new LandingPerformance();
  
  // Initialize mobile optimizations only on mobile devices
  if (window.innerWidth <= 768) {
    new LandingMobile();
  }
});

// Handle page visibility for performance
document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    // Pause animations when page is not visible
    document.documentElement.style.setProperty('animation-play-state', 'paused');
  } else {
    // Resume animations
    document.documentElement.style.setProperty('animation-play-state', 'running');
  }
});

// Error handling
window.addEventListener('error', (e) => {
  console.error('Landing page error:', e.error);
  // Implement error reporting if needed
});

// Service Worker registration for PWA features
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js')
      .then(registration => {
        // Service Worker registered successfully
      })
      .catch(registrationError => {
        console.error('SW registration failed: ', registrationError);
      });
  });
}