// Internationalization (i18n) Module

const translations = {
  uk: {
    // Landing Page
    heroTitle: "Всі карти лояльності в одному місці",
    heroSubtitle: "Скануй, зберігай та використовуй картки магазинів у зручному PWA додатку",
    features: {
      scan: "Сканування камерою",
      scanDescription: "Легко додавайте нові карти простим скануванням штрих-коду або QR-коду",
      store: "Безпечне зберігання",
      storeDescription: "Ваші карти зберігаються в зашифрованому вигляді з доступом лише для вас",
      access: "Швидкий доступ",
      accessDescription: "Миттєвий доступ до всіх ваших карт навіть офлайн завдяки PWA технології"
    },
    cta: "Спробувати безкоштовно",
    screenshots: {
      title: "Простий у використанні інтерфейс",
      allCards: "Всі карти в одному місці",
      easyScanning: "Легке сканування",
      personalization: "Персоналізація"
    },
    mockupCards: {
      tabs: {
        cards: "📱 Карти",
        add: "➕ Додати", 
        settings: "⚙️ Налаштування"
      },
      stores: {
        atb: "АТБ",
        silpo: "Сільпо",
        eva: "EVA"
      },
      scanner: {
        instruction: "Наведіть камеру на код"
      },
      settings: {
        darkTheme: "🌙 Темна тема",
        language: "🌍 Мова: Українська"
      }
    },
    installation: {
      title: "Як встановити додаток на телефон",
      android: {
        step1: {
          title: "Відкрийте додаток у браузері",
          desc: "Перейдіть на сайт через Chrome або будь-який інший браузер"
        },
        step2: {
          title: "Знайдіть меню браузера",
          desc: "Натисніть на три крапки (<img src='/icons/share-android.png' alt='меню' style='display:inline; width:16px; height:16px; vertical-align:middle;'>) у верхньому правому куті браузера"
        },
        step3: {
          title: "Виберіть \"Додати на головний екран\"",
          desc: "Або \"Install app\" / \"Встановити додаток\" залежно від браузера"
        },
        step4: {
          title: "Підтвердіть встановлення",
          desc: "Натисніть \"Додати\" і додаток з'явиться на головному екрані"
        }
      },
      ios: {
        step1: {
          title: "Відкрийте Safari",
          desc: "Важливо використовувати саме Safari браузер на iOS пристроях"
        },
        step2: {
          title: "Перейдіть на сайт",
          desc: "Введіть адресу сайту в адресний рядок Safari"
        },
        step3: {
          title: "Натисніть кнопку \"Поділитися\"",
          desc: "Знайдіть значок поділитися (<img src='/icons/share-apple.png' alt='поділитися' style='display:inline; width:16px; height:16px; vertical-align:middle;'>) внизу екрану Safari"
        },
        step4: {
          title: "Виберіть \"На головний екран\"",
          desc: "Прокрутіть вниз і знайдіть опцію \"На головний екран\" або \"Add to Home Screen\""
        },
        step5: {
          title: "Додайте додаток",
          desc: "Натисніть \"Додати\" і піктограма з'явиться на домашньому екрані"
        }
      },
      note: {
        title: "Чому це працює без App Store/Play market?",
        desc: "disCard - це PWA (Progressive Web App), сучасна технологія, що дозволяє веб-додаткам працювати як нативні програми з офлайн доступом і push-сповіщеннями."
      }
    },
    footer: {
      description: "Сучасний додаток для управління картами лояльності",
      rights: "Всі права захищені.",
      features: {
        title: "Особливості",
        pwa: "PWA додаток",
        offline: "Робота офлайн",
        secure: "Безпечне зберігання",
        free: "Безкоштовно"
      },
      support: {
        title: "Підтримка",
        install: "Як встановити",
        features: "Можливості",
        guide: "Інструкція"
      }
    },
    
    // App Navigation
    tabs: {
      cards: "Карти",
      add: "Додати",
      profile: "Профіль",
      settings: "Налаштування"
    },
    
    // Authentication
    auth: {
      login: "Увійти",
      register: "Реєстрація",
      email: "Email",
      password: "Пароль",
      name: "Ім'я",
      loginTitle: "Вхід до акаунту",
      registerTitle: "Створення акаунту",
      noAccount: "Немає акаунту?",
      hasAccount: "Вже є акаунт?",
      forgotPassword: "Забули пароль?"
    },
    
    // Profile
    profile: {
      userId: "ID користувача",
      changePassword: "Зміна пароля",
      currentPassword: "Поточний пароль",
      newPassword: "Новий пароль",
      confirmPassword: "Підтвердити пароль",
      userInfo: "Інформація користувача",
      statistics: "Статистика",
      cardsCount: "Збережено карт",
      joinDate: "Дата реєстрації",
      logout: "Вийти",
      changePasswordBtn: "Змінити пароль",
      noDateAvailable: "Дата недоступна"
    },
    
    // Settings
    settings: {
      theme: "Тема",
      light: "Світла",
      dark: "Темна",
      language: "Мова",
      appearance: "Вигляд додатку",
      interfaceLanguage: "Мова інтерфейсу",
      themeDescription: "Оберіть світлу або темну тему",
      languageDescription: "Оберіть мову додатку"
    },
    
    // Cards
    cards: {
      searchPlaceholder: "Пошук карт...",
      noCards: "У вас поки немає збережених карт",
      noCardsSubtitle: "Додайте вашу першу картку лояльності",
      addCard: "Додати картку",
      cardName: "Назва картки",
      cardNamePlaceholder: "Наприклад: АТБ",
      cardCode: "Код картки",
      codeType: "Тип коду",
      barcode: "Штрих-код",
      qrcode: "QR-код",
      preview: "Превью коду",
      saveCard: "Зберегти картку",
      editCard: "Редагувати картку",
      deleteCard: "Видалити картку",
      copyCode: "Копіювати код",
      scanCode: "Сканувати код",
      manualEntry: "Введіть код або скануйте",
      scanInstructions: "Наведіть камеру на код для сканування",
      created: "Створено",
      codeWillAppear: "Код з'явиться тут"
    },
    
    // Scanner
    scanner: {
      title: "Сканування коду",
      instructions: "Наведіть камеру на код для сканування",
      permissionDenied: "Доступ до камери заборонено",
      notFound: "Камера не знайдена",
      scanning: "Сканування...",
      success: "Код успішно відсканований!",
      error: "Помилка сканування",
      barcodeUnavailable: "Штрих-код недоступний"
    },
    
    // Messages
    messages: {
      loading: "Завантаження...",
      saving: "Збереження...",
      saved: "Збережено!",
      error: "Помилка",
      success: "Успіх",
      pullToRefresh: "Потягніть для оновлення",
      confirm: "Підтвердити",
      cancel: "Скасувати",
      delete: "Видалити",
      edit: "Редагувати",
      close: "Закрити",
      copy: "Копіювати",
      copied: "Скопійовано!",
      copyFailed: "Помилка копіювання",
      loginSuccess: "Успішний вхід",
      registerSuccess: "Акаунт створено",
      logoutSuccess: "Ви вийшли з акаунту",
      passwordChanged: "Пароль змінено",
      profileUpdated: "Профіль оновлено",
      cardAdded: "Картку додано",
      cardUpdated: "Картку оновлено",
      cardDeleted: "Картку видалено",
      invalidCredentials: "Невірні дані для входу",
      emailExists: "Користувач з таким email вже існує",
      passwordTooShort: "Пароль повинен містити мінімум 6 символів",
      passwordsDontMatch: "Паролі не співпадають",
      fillAllFields: "Заповніть всі поля",
      networkError: "Помилка мережі",
      serverError: "Помилка сервера",
      cameraNotSupported: "Камера не підтримується",
      invalidCode: "Невірний код",
      confirmDelete: "Ви впевнені, що хочете видалити цю картку?",
      offlineMode: "Режим офлайн"
    },
    
    // Time formats
    time: {
      now: "зараз",
      minuteAgo: "хвилину тому",
      minutesAgo: "хвилин тому",
      hourAgo: "годину тому",
      hoursAgo: "годин тому",
      dayAgo: "день тому",
      daysAgo: "днів тому",
      monthAgo: "місяць тому",
      monthsAgo: "місяців тому",
      yearAgo: "рік тому",
      yearsAgo: "років тому"
    }
  },
  
  en: {
    // Landing Page
    heroTitle: "All loyalty cards in one place",
    heroSubtitle: "Scan, store and use your store cards in a convenient PWA app",
    features: {
      scan: "Camera scanning",
      scanDescription: "Easily add new cards by simply scanning barcodes or QR codes",
      store: "Secure storage",
      storeDescription: "Your cards are stored encrypted with access only for you",
      access: "Quick access",
      accessDescription: "Instant access to all your cards even offline thanks to PWA technology"
    },
    cta: "Try for free",
    screenshots: {
      title: "Easy to use interface",
      allCards: "All cards in one place",
      easyScanning: "Easy scanning",
      personalization: "Personalization"
    },
    mockupCards: {
      tabs: {
        cards: "📱 Cards",
        add: "➕ Add",
        settings: "⚙️ Settings"
      },
      stores: {
        atb: "ATB",
        silpo: "Silpo", 
        eva: "EVA"
      },
      scanner: {
        instruction: "Point your camera at the code"
      },
      settings: {
        darkTheme: "🌙 Dark theme",
        language: "🌍 Language: English"
      }
    },
    installation: {
      title: "How to install the app on your phone",
      android: {
        step1: {
          title: "Open the app in browser",
          desc: "Go to the website through Chrome or any other browser"
        },
        step2: {
          title: "Find browser menu",
          desc: "Tap on three dots (<img src='/icons/share-android.png' alt='menu' style='display:inline; width:16px; height:16px; vertical-align:middle;'>) in the top right corner of the browser"
        },
        step3: {
          title: "Select \"Add to Home screen\"",
          desc: "Or \"Install app\" depending on your browser"
        },
        step4: {
          title: "Confirm installation",
          desc: "Tap \"Add\" and the app will appear on your home screen"
        }
      },
      ios: {
        step1: {
          title: "Open Safari",
          desc: "It's important to use Safari browser on iOS devices"
        },
        step2: {
          title: "Go to the website",
          desc: "Enter the website address in Safari's address bar"
        },
        step3: {
          title: "Tap the \"Share\" button",
          desc: "Find the share icon (<img src='/icons/share-apple.png' alt='share' style='display:inline; width:16px; height:16px; vertical-align:middle;'>) at the bottom of Safari screen"
        },
        step4: {
          title: "Select \"Add to Home Screen\"",
          desc: "Scroll down and find the \"Add to Home Screen\" option"
        },
        step5: {
          title: "Add the app",
          desc: "Tap \"Add\" and the icon will appear on your home screen"
        }
      },
      note: {
        title: "Why does it work without App Store?",
        desc: "disCard is a PWA (Progressive Web App), a modern technology that allows web apps to work like native programs with offline access and push notifications."
      }
    },
    footer: {
      description: "Modern app for managing loyalty cards",
      rights: "All rights reserved.",
      features: {
        title: "Features",
        pwa: "PWA App",
        offline: "Works Offline",
        secure: "Secure Storage",
        free: "Free"
      },
      support: {
        title: "Support",
        install: "How to Install",
        features: "Features",
        guide: "Guide"
      }
    },
    
    // App Navigation
    tabs: {
      cards: "Cards",
      add: "Add",
      profile: "Profile",
      settings: "Settings"
    },
    
    // Authentication
    auth: {
      login: "Login",
      register: "Register",
      email: "Email",
      password: "Password",
      name: "Name",
      loginTitle: "Sign in to your account",
      registerTitle: "Create your account",
      noAccount: "Don't have an account?",
      hasAccount: "Already have an account?",
      forgotPassword: "Forgot password?"
    },
    
    // Profile
    profile: {
      userId: "User ID",
      changePassword: "Change password",
      currentPassword: "Current password",
      newPassword: "New password",
      confirmPassword: "Confirm password",
      userInfo: "User information",
      statistics: "Statistics",
      cardsCount: "Saved cards",
      joinDate: "Join date",
      logout: "Logout",
      changePasswordBtn: "Change password",
      noDateAvailable: "No date available"
    },
    
    // Settings
    settings: {
      theme: "Theme",
      light: "Light",
      dark: "Dark",
      language: "Language",
      appearance: "App appearance",
      interfaceLanguage: "Interface language",
      themeDescription: "Choose light or dark theme",
      languageDescription: "Choose app language"
    },
    
    // Cards
    cards: {
      searchPlaceholder: "Search cards...",
      noCards: "You don't have any saved cards yet",
      noCardsSubtitle: "Add your first loyalty card",
      addCard: "Add card",
      cardName: "Card name",
      cardNamePlaceholder: "e.g.: Starbucks",
      cardCode: "Card code",
      codeType: "Code type",
      barcode: "Barcode",
      qrcode: "QR code",
      preview: "Code preview",
      saveCard: "Save card",
      editCard: "Edit card",
      deleteCard: "Delete card",
      copyCode: "Copy code",
      scanCode: "Scan code",
      manualEntry: "Enter code or scan",
      scanInstructions: "Point your camera at the code to scan",
      created: "Created",
      codeWillAppear: "Code will appear here"
    },
    
    // Scanner
    scanner: {
      title: "Code scanning",
      instructions: "Point your camera at the code to scan",
      permissionDenied: "Camera access denied",
      notFound: "Camera not found",
      scanning: "Scanning...",
      success: "Code scanned successfully!",
      error: "Scanning error",
      barcodeUnavailable: "Barcode unavailable"
    },
    
    // Messages
    messages: {
      loading: "Loading...",
      saving: "Saving...",
      saved: "Saved!",
      error: "Error",
      success: "Success",
      pullToRefresh: "Pull to refresh",
      confirm: "Confirm",
      cancel: "Cancel",
      delete: "Delete",
      edit: "Edit",
      close: "Close",
      copy: "Copy",
      copied: "Copied!",
      copyFailed: "Copy failed",
      loginSuccess: "Login successful",
      registerSuccess: "Account created",
      logoutSuccess: "You have been logged out",
      passwordChanged: "Password changed",
      profileUpdated: "Profile updated",
      cardAdded: "Card added",
      cardUpdated: "Card updated",
      cardDeleted: "Card deleted",
      invalidCredentials: "Invalid login credentials",
      emailExists: "User with this email already exists",
      passwordTooShort: "Password must be at least 6 characters",
      passwordsDontMatch: "Passwords don't match",
      fillAllFields: "Please fill all fields",
      networkError: "Network error",
      serverError: "Server error",
      cameraNotSupported: "Camera not supported",
      invalidCode: "Invalid code",
      confirmDelete: "Are you sure you want to delete this card?",
      offlineMode: "Offline mode"
    },
    
    // Time formats
    time: {
      now: "now",
      minuteAgo: "a minute ago",
      minutesAgo: "minutes ago",
      hourAgo: "an hour ago",
      hoursAgo: "hours ago",
      dayAgo: "a day ago",
      daysAgo: "days ago",
      monthAgo: "a month ago",
      monthsAgo: "months ago",
      yearAgo: "a year ago",
      yearsAgo: "years ago"
    }
  }
};

// i18n utility functions
class I18n {
  constructor() {
    this.translations = translations;
    this.currentLanguage = this.detectLanguage();
    this.init();
  }

  init() {
    // Listen for language changes
    document.addEventListener('languageChanged', (e) => {
      this.currentLanguage = e.detail.language;
      this.updatePageTexts();
    });
  }

  detectLanguage() {
    // Check localStorage first
    const savedLanguage = localStorage.getItem('language');
    if (savedLanguage && this.translations[savedLanguage]) {
      return savedLanguage;
    }

    // Check browser language
    const browserLanguage = navigator.language.split('-')[0];
    if (this.translations[browserLanguage]) {
      return browserLanguage;
    }

    // Default to Ukrainian
    return 'uk';
  }

  setLanguage(language) {
    console.log('i18n.setLanguage called with:', language);
    
    if (!this.translations[language]) {
      console.warn(`Language '${language}' not supported`);
      return false;
    }

    this.currentLanguage = language;
    localStorage.setItem('language', language);
    
    // Update HTML lang attribute
    document.documentElement.lang = language;
    
    console.log('Language changed to:', language, 'Updating page texts...');
    
    // Update page texts immediately
    this.updatePageTexts();
    
    // Dispatch language change event
    document.dispatchEvent(new CustomEvent('languageChanged', {
      detail: { language }
    }));

    return true;
  }

  getCurrentLanguage() {
    return this.currentLanguage;
  }

  t(key, params = {}) {
    const keys = key.split('.');
    let value = this.translations[this.currentLanguage];
    
    // Navigate through nested keys
    for (const k of keys) {
      if (value && typeof value === 'object' && k in value) {
        value = value[k];
      } else {
        // Fallback to default language
        value = this.translations['uk'];
        for (const k of keys) {
          if (value && typeof value === 'object' && k in value) {
            value = value[k];
          } else {
            console.warn(`Translation key '${key}' not found`);
            return key;
          }
        }
        break;
      }
    }

    if (typeof value !== 'string') {
      console.warn(`Translation key '${key}' is not a string`);
      return key;
    }

    // Replace parameters
    return value.replace(/\{\{(\w+)\}\}/g, (match, param) => {
      return params[param] || match;
    });
  }

  updatePageTexts() {
    console.log('Updating page texts for language:', this.currentLanguage);
    
    // Update all elements with data-i18n attribute
    const elements = document.querySelectorAll('[data-i18n]');
    console.log('Found', elements.length, 'elements with data-i18n');
    
    elements.forEach(element => {
      const key = element.getAttribute('data-i18n');
      const translation = this.t(key);
      
      if (element.tagName === 'INPUT' && element.type !== 'button') {
        element.placeholder = translation;
      } else {
        // Check if translation contains HTML tags
        if (translation.includes('<img') || translation.includes('<')) {
          element.innerHTML = translation;
        } else {
          element.textContent = translation;
        }
      }
    });

    // Update placeholder attributes
    document.querySelectorAll('[data-i18n-placeholder]').forEach(element => {
      const key = element.getAttribute('data-i18n-placeholder');
      element.placeholder = this.t(key);
    });

    // Update title attributes
    document.querySelectorAll('[data-i18n-title]').forEach(element => {
      const key = element.getAttribute('data-i18n-title');
      element.title = this.t(key);
    });

    // Update page title
    const titleElement = document.querySelector('title[data-i18n]');
    if (titleElement) {
      const key = titleElement.getAttribute('data-i18n');
      document.title = this.t(key);
    }
  }

  formatTime(date) {
    const now = new Date();
    const diff = now - new Date(date);
    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    const months = Math.floor(days / 30);
    const years = Math.floor(days / 365);

    if (seconds < 60) {
      return this.t('time.now');
    } else if (minutes < 2) {
      return this.t('time.minuteAgo');
    } else if (minutes < 60) {
      return `${minutes} ${this.t('time.minutesAgo')}`;
    } else if (hours < 2) {
      return this.t('time.hourAgo');
    } else if (hours < 24) {
      return `${hours} ${this.t('time.hoursAgo')}`;
    } else if (days < 2) {
      return this.t('time.dayAgo');
    } else if (days < 30) {
      return `${days} ${this.t('time.daysAgo')}`;
    } else if (months < 2) {
      return this.t('time.monthAgo');
    } else if (months < 12) {
      return `${months} ${this.t('time.monthsAgo')}`;
    } else if (years < 2) {
      return this.t('time.yearAgo');
    } else {
      return `${years} ${this.t('time.yearsAgo')}`;
    }
  }

  formatDate(date) {
    const d = new Date(date);
    const options = {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    };
    
    return d.toLocaleDateString(this.currentLanguage === 'uk' ? 'uk-UA' : 'en-US', options);
  }

  pluralize(count, singular, few, many) {
    if (this.currentLanguage === 'uk') {
      if (count % 10 === 1 && count % 100 !== 11) {
        return singular;
      } else if ([2, 3, 4].includes(count % 10) && ![12, 13, 14].includes(count % 100)) {
        return few;
      } else {
        return many;
      }
    } else {
      return count === 1 ? singular : few;
    }
  }
}

// Initialize when ready
function initializeI18n() {
  try {
    // Create global instance
    window.i18n = new I18n();
    
    // Global shortcut function
    window.t = (key, params) => window.i18n.t(key, params);
    
    // Update texts
    window.i18n.updatePageTexts();
    
    console.log('i18n initialized successfully');
  } catch (error) {
    console.error('Failed to initialize i18n:', error);
    
    // Create fallback functions
    window.t = (key) => key;
    window.i18n = {
      setLanguage: () => true,
      getCurrentLanguage: () => 'uk',
      updatePageTexts: () => {},
      t: (key) => key,
      formatDate: (date) => new Date(date).toLocaleDateString(),
      formatTime: (date) => new Date(date).toLocaleString()
    };
  }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initializeI18n);
} else {
  initializeI18n();
}