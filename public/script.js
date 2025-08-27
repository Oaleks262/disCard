// Application State
let currentUser = null;
let currentPage = 'loading';
let currentTab = 'cards';
let userCards = [];
let shoppingLists = [];
let currentList = null;
let friends = [];
let friendRequests = { sent: [], received: [] };
let scanner = null;
let currentStream = null;
let currentLanguage = 'uk'; // Default to Ukrainian

// API Configuration
const API_BASE = window.location.origin + '/api';

// Translations
const translations = {
    uk: {
        app: {
            title: "💳 Карти Лояльності"
        },
        common: {
            email: "Email",
            password: "Пароль",
            back: "Назад",
            cancel: "Скасувати",
            loading: "Завантаження...",
            copy: "Копіювати",
            edit: "Редагувати",
            delete: "Видалити"
        },
        login: {
            title: "Вхід до системи",
            submit: "Увійти",
            no_account: "Немає акаунту?",
            register_link: "Зареєструватися",
            remember_me: "Запам'ятати мене"
        },
        register: {
            title: "Реєстрація",
            confirm_password: "Підтвердити пароль",
            submit: "Зареєструватися",
            have_account: "Вже є акаунт?",
            login_link: "Увійти"
        },
        tabs: {
            cards: "Карти",
            shopping: "Покупки",
            friends: "Друзі",
            profile: "Профіль"
        },
        cards: {
            my_cards: "Мої карти",
            add_card: "Додати картку",
            search: "Пошук карт...",
            no_cards: "Немає карт",
            add_first_card: "Додайте свою першу карту лояльності",
            security: "Безпека"
        },
        shopping: {
            my_lists: "Мої списки покупок",
            add_list: "Новий список",
            add_list_title: "Новий список покупок",
            search: "Пошук списків...",
            no_lists: "Немає списків покупок",
            add_first_list: "Створіть свій перший список покупок",
            list_name: "Назва списку",
            list_name_placeholder: "Наприклад: Тижневі покупки",
            list_description: "Опис (опціонально)",
            list_description_placeholder: "Короткий опис списку...",
            list_budget: "Бюджет (грн, опціонально)",
            list_budget_placeholder: "0.00",
            list_color: "Колір",
            create_list: "Створити список",
            total_items: "Всього товарів:",
            completed_items: "Куплено:",
            total_budget: "Бюджет:",
            add_item: "Додати товар",
            item_name_placeholder: "Назва товару",
            quantity_placeholder: "1 кг",
            price_placeholder: "Ціна (грн)",
            share_list: "Поділитися",
            share_with_friends: "Поділитися з друзями",
            permission_label: "Дозвіл:",
            permission_view: "Тільки переглядати",
            permission_edit: "Редагувати",
            already_shared_with: "Вже поділено з:"
        },
        friends: {
            title: "Друзі",
            add_friend: "Додати друга",
            search_title: "Пошук друга",
            user_id_label: "ID користувача",
            user_id_placeholder: "Введіть ID користувача",
            search_user: "Знайти користувача",
            requests_title: "Запити на дружбу",
            received_requests: "Отримані",
            sent_requests: "Надіслані",
            my_friends: "Мої друзі",
            search_friends: "Пошук друзів...",
            send_request: "Надіслати запит",
            accept_request: "Прийняти",
            reject_request: "Відхилити",
            remove_friend: "Видалити друга",
            already_friends: "Ви вже друзі",
            request_sent: "Запит надіслано",
            request_pending: "Запит очікує",
            user_not_found: "Користувач не знайдений",
            friends_since: "Друзі з",
            no_friends: "У вас поки немає друзів",
            no_requests: "Немає запитів"
        },
        profile: {
            title: "Профіль користувача",
            user_id: "ID користувача:",
            change_name: "Змінити ім'я",
            change_name_desc: "Оновіть своє відображуване ім'я",
            new_name: "Нове ім'я",
            new_name_placeholder: "Введіть ваше ім'я",
            update_name: "Оновити ім'я",
            change_password: "Змінити пароль",
            change_password_desc: "Оновіть пароль для підвищення безпеки",
            current_password: "Поточний пароль",
            new_password: "Новий пароль",
            confirm_new_password: "Підтвердити новий пароль",
            update_password: "Оновити пароль",
            account_stats: "Статистика акаунту",
            total_cards: "Всього карт",
            total_lists: "Всього списків",
            account_age: "Днів з нами",
            security: "Безпека",
            manage_2fa: "Керувати 2FA"
        },
        add_card: {
            title: "Додати картку",
            name: "Назва картки",
            name_placeholder: "Наприклад: АТБ, Сільпо, Rozetka",
            code: "Номер картки",
            code_placeholder: "Введіть номер або скануйте",
            code_type: "Тип коду",
            barcode: "Штрих-код",
            qr_code: "QR-код",
            scan: "Сканувати",
            save: "Зберегти картку"
        },
        scanner: {
            title: "Сканування коду",
            switch_camera: "Перемкнути камеру",
            flash: "Спалах"
        },
        card_modal: {
            title: "Картка",
            delete: "Видалити"
        },
        messages: {
            fill_all_fields: "Заповніть всі поля",
            passwords_not_match: "Паролі не співпадають",
            password_min_length: "Пароль повинен містити мінімум 6 символів",
            registration_success: "Реєстрація успішна!",
            login_success: "Успішний вхід",
            logout_success: "Ви вийшли з системи",
            card_added: "Картка додана!",
            card_deleted: "Картка видалена",
            code_scanned: "Код успішно відсканований!",
            connection_restored: "З'єднання відновлено",
            connection_lost: "Втрачено з'єднання з інтернетом",
            camera_error: "Не вдалося отримати доступ до камери",
            camera_switch_error: "Не вдалося перемкнути камеру",
            flash_not_supported: "Спалах не підтримується цим пристроєм",
            flash_error: "Помилка керування спалахом",
            server_error: "Помилка з'єднання з сервером",
            unexpected_error: "Виникла неочікувана помилка",
            request_error: "Помилка обробки запиту",
            session_expired: "Сесія закінчена через неактивність",
            confirm_delete: "Ви впевнені, що хочете видалити цю картку?",
            copied: "Скопійовано!",
            name_updated: "Ім'я оновлено",
            password_updated: "Пароль оновлено",
            fill_all_fields_profile: "Заповніть всі поля",
            passwords_not_match_new: "Нові паролі не співпадають",
            enter_new_name: "Введіть нове ім'я",
            password_update_error: "Помилка оновлення пароля",
            name_update_error: "Помилка оновлення імені",
            profile_load_error: "Помилка завантаження профілю"
        },
        theme: {
            toggle_light: "Світла тема",
            toggle_dark: "Темна тема"
        },
        security: {
            title: "Налаштування безпеки",
            twofa_section: "Двофакторна автентифікація (2FA)",
            twofa_description: "Додайте додатковий рівень захисту для вашого акаунту",
            twofa_enabled: "2FA увімкнена",
            twofa_disabled: "2FA вимкнена",
            enable_twofa: "Увімкнути 2FA",
            disable_twofa: "Вимкнути 2FA",
            setup_twofa: "Налаштування 2FA",
            disable_twofa_title: "Вимкнути 2FA",
            disable_warning: "Ви впевнені, що хочете вимкнути двофакторну автентифікацію? Це знизить безпеку вашого акаунту.",
            step1: "Крок 1: Скануйте QR-код",
            step2: "Крок 2: Введіть код підтвердження",
            scan_instructions: "Скануйте цей QR-код у вашому додатку автентифікатора (Google Authenticator, Authy тощо):",
            verify_instructions: "Введіть 6-значний код з вашого додатку:",
            manual_entry: "Або введіть код вручну:",
            current_code: "Поточний код 2FA:",
            complete_setup: "Завершити налаштування",
            confirm_disable: "Підтвердити вимкнення"
        },
        twofa: {
            login_title: "Двофакторна автентифікація",
            enter_code: "Введіть код з додатку автентифікатора:",
            verify: "Підтвердити",
            setup_success: "2FA успішно налаштована!",
            disabled_success: "2FA вимкнена",
            invalid_code: "Невірний код підтвердження",
            setup_required: "Спочатку налаштуйте 2FA"
        }
    },
    en: {
        app: {
            title: "💳 Loyalty Cards"
        },
        common: {
            email: "Email",
            password: "Password",
            back: "Back",
            cancel: "Cancel",
            loading: "Loading...",
            copy: "Copy",
            edit: "Edit",
            delete: "Delete"
        },
        login: {
            title: "Sign In",
            submit: "Sign In",
            no_account: "Don't have an account?",
            register_link: "Sign Up"
        },
        tabs: {
            cards: "Cards",
            shopping: "Shopping",
            friends: "Friends",
            profile: "Profile"
        },
        shopping: {
            // Add English translations for shopping if needed
            share_list: "Share",
            share_with_friends: "Share with Friends",
            permission_label: "Permission:",
            permission_view: "View Only",
            permission_edit: "Edit",
            already_shared_with: "Already shared with:"
        },
        friends: {
            title: "Friends",
            add_friend: "Add Friend",
            search_title: "Search Friend",
            user_id_label: "User ID",
            user_id_placeholder: "Enter user ID",
            search_user: "Find User",
            requests_title: "Friend Requests",
            received_requests: "Received",
            sent_requests: "Sent",
            my_friends: "My Friends",
            search_friends: "Search friends...",
            send_request: "Send Request",
            accept_request: "Accept",
            reject_request: "Reject",
            remove_friend: "Remove Friend",
            already_friends: "Already friends",
            request_sent: "Request sent",
            request_pending: "Request pending",
            user_not_found: "User not found",
            friends_since: "Friends since",
            no_friends: "You don't have friends yet",
            no_requests: "No requests"
        },
        profile: {
            title: "User Profile",
            user_id: "User ID:",
            change_name: "Change Name",
            change_name_desc: "Update your display name",
            new_name: "New Name",
            new_name_placeholder: "Enter your name",
            update_name: "Update Name",
            change_password: "Change Password",
            change_password_desc: "Update your password for better security",
            current_password: "Current Password",
            new_password: "New Password",
            confirm_new_password: "Confirm New Password",
            update_password: "Update Password",
            account_stats: "Account Statistics",
            total_cards: "Total Cards",
            total_lists: "Total Lists",
            account_age: "Days with us",
            security: "Security",
            manage_2fa: "Manage 2FA"
        },
        register: {
            title: "Sign Up",
            confirm_password: "Confirm Password",
            submit: "Sign Up",
            have_account: "Already have an account?",
            login_link: "Sign In"
        },
        cards: {
            my_cards: "My Cards",
            add_card: "Add Card",
            search: "Search cards...",
            no_cards: "No Cards",
            add_first_card: "Add your first loyalty card",
            security: "Security"
        },
        add_card: {
            title: "Add Card",
            name: "Card Name",
            name_placeholder: "e.g.: Walmart, Target, Amazon",
            code: "Card Number",
            code_placeholder: "Enter number or scan",
            code_type: "Code Type",
            barcode: "Barcode",
            qr_code: "QR Code",
            scan: "Scan",
            save: "Save Card"
        },
        scanner: {
            title: "Code Scanner",
            switch_camera: "Switch Camera",
            flash: "Flash"
        },
        card_modal: {
            title: "Card",
            delete: "Delete"
        },
        messages: {
            fill_all_fields: "Please fill all fields",
            passwords_not_match: "Passwords don't match",
            password_min_length: "Password must contain at least 6 characters",
            registration_success: "Registration successful!",
            login_success: "Successfully signed in",
            logout_success: "You have been signed out",
            card_added: "Card added!",
            card_deleted: "Card deleted",
            code_scanned: "Code scanned successfully!",
            connection_restored: "Connection restored",
            connection_lost: "Internet connection lost",
            camera_error: "Failed to access camera",
            camera_switch_error: "Failed to switch camera",
            flash_not_supported: "Flash not supported by this device",
            flash_error: "Flash control error",
            server_error: "Server connection error",
            unexpected_error: "An unexpected error occurred",
            request_error: "Request processing error",
            session_expired: "Session expired due to inactivity",
            confirm_delete: "Are you sure you want to delete this card?",
            copied: "Copied!"
        },
        theme: {
            toggle_light: "Light theme",
            toggle_dark: "Dark theme"
        },
        security: {
            title: "Security Settings",
            twofa_section: "Two-Factor Authentication (2FA)",
            twofa_description: "Add an extra layer of protection to your account",
            twofa_enabled: "2FA enabled",
            twofa_disabled: "2FA disabled",
            enable_twofa: "Enable 2FA",
            disable_twofa: "Disable 2FA",
            setup_twofa: "Setup 2FA",
            disable_twofa_title: "Disable 2FA",
            disable_warning: "Are you sure you want to disable two-factor authentication? This will reduce your account security.",
            step1: "Step 1: Scan QR Code",
            step2: "Step 2: Enter Verification Code",
            scan_instructions: "Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.):",
            verify_instructions: "Enter the 6-digit code from your app:",
            manual_entry: "Or enter the code manually:",
            current_code: "Current 2FA code:",
            complete_setup: "Complete Setup",
            confirm_disable: "Confirm Disable"
        },
        twofa: {
            login_title: "Two-Factor Authentication",
            enter_code: "Enter code from your authenticator app:",
            verify: "Verify",
            setup_success: "2FA successfully configured!",
            disabled_success: "2FA disabled",
            invalid_code: "Invalid verification code",
            setup_required: "Please setup 2FA first"
        }
    }
};

// Translation Functions
function getTranslation(key, lang = currentLanguage) {
    const keys = key.split('.');
    let translation = translations[lang];
    
    for (const k of keys) {
        if (translation && translation[k]) {
            translation = translation[k];
        } else {
            // Fallback to Ukrainian if translation not found
            translation = translations['uk'];
            for (const fallbackKey of keys) {
                if (translation && translation[fallbackKey]) {
                    translation = translation[fallbackKey];
                } else {
                    return key; // Return key if no translation found
                }
            }
            break;
        }
    }
    
    return translation || key;
}

function updatePageTranslations() {
    // Update all elements with data-translate attribute
    document.querySelectorAll('[data-translate]').forEach(element => {
        const key = element.getAttribute('data-translate');
        element.textContent = getTranslation(key);
    });
    
    // Update placeholders
    document.querySelectorAll('[data-translate-placeholder]').forEach(element => {
        const key = element.getAttribute('data-translate-placeholder');
        element.placeholder = getTranslation(key);
    });
    
    // Update titles
    document.querySelectorAll('[data-translate-title]').forEach(element => {
        const key = element.getAttribute('data-translate-title');
        element.title = getTranslation(key);
    });
}

function toggleLanguage() {
    currentLanguage = currentLanguage === 'uk' ? 'en' : 'uk';
    localStorage.setItem('language', currentLanguage);
    updatePageTranslations();
    updateLanguageToggle();
    
    // Show notification
    const message = currentLanguage === 'en' ? 'Language switched to English' : 'Мову змінено на українську';
    showNotification(message, 'info');
}

function updateLanguageToggle() {
    const langToggle = document.getElementById('language-toggle');
    if (langToggle) {
        langToggle.textContent = currentLanguage === 'uk' ? '🇺🇸' : '🇺🇦';
        langToggle.title = currentLanguage === 'uk' ? 'Switch to English' : 'Переключити на українську';
    }
}

function initializeLanguage() {
    const savedLanguage = localStorage.getItem('language');
    const browserLanguage = navigator.language.startsWith('uk') ? 'uk' : 'en';
    
    currentLanguage = savedLanguage || browserLanguage;
    updatePageTranslations();
    updateLanguageToggle();
}

// Initialize Application
document.addEventListener('DOMContentLoaded', async () => {
    await initializeApp();
});

// App Initialization
async function initializeApp() {
    console.log('🚀 Ініціалізація додатку...');
    
    // Initialize language first
    initializeLanguage();
    
    // Register Service Worker
    if ('serviceWorker' in navigator) {
        try {
            await navigator.serviceWorker.register('/sw.js');
            console.log('✅ Service Worker зареєстровано');
        } catch (error) {
            console.warn('⚠️ Помилка реєстрації Service Worker:', error);
        }
    }

    // Initialize theme
    initializeTheme();
    
    // Setup event listeners
    setupEventListeners();
    
    // Check authentication (now uses secure cookies instead of localStorage)
    try {
        const response = await fetch(`${API_BASE}/cards`, {
            credentials: 'include' // Include cookies
        });
        
        if (response.ok) {
            const data = await response.json();
            userCards = data.cards;
            await showPage('cards');
            return;
        } else if (response.status === 423) {
            // Account locked
            const errorData = await response.json();
            showNotification(errorData.error, 'error');
            await showPage('login');
            return;
        }
    } catch (error) {
        console.warn('⚠️ Помилка перевірки автентифікації:', error);
    }
    
    // Show login page
    await showPage('login');
}

// Theme Management
function initializeTheme() {
    const savedTheme = localStorage.getItem('theme');
    const systemTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    const theme = savedTheme || systemTheme;
    
    document.documentElement.setAttribute('data-theme', theme);
    updateThemeToggle();
    
    // Listen for system theme changes
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
        if (!localStorage.getItem('theme')) {
            document.documentElement.setAttribute('data-theme', e.matches ? 'dark' : 'light');
            updateThemeToggle();
        }
    });
}

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    updateThemeToggle();
}

function updateThemeToggle() {
    const themeToggle = document.getElementById('theme-toggle');
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    if (themeToggle) {
        themeToggle.textContent = isDark ? '☀️' : '🌙';
        themeToggle.title = isDark ? getTranslation('theme.toggle_light') : getTranslation('theme.toggle_dark');
    }
}

// Event Listeners Setup
function setupEventListeners() {
    // Language toggle
    document.getElementById('language-toggle')?.addEventListener('click', toggleLanguage);
    
    // Theme toggle
    document.getElementById('theme-toggle')?.addEventListener('click', toggleTheme);
    
    // Logout
    document.getElementById('logout-btn')?.addEventListener('click', logout);
    
    // Tab navigation
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    });
    
    // Auth forms
    document.getElementById('login-form')?.addEventListener('submit', login);
    document.getElementById('register-form')?.addEventListener('submit', handleRegister);
    document.getElementById('show-register')?.addEventListener('click', (e) => {
        e.preventDefault();
        showPage('register');
    });
    document.getElementById('show-login')?.addEventListener('click', (e) => {
        e.preventDefault();
        showPage('login');
    });
    
    // Shopping list buttons
    document.getElementById('add-shopping-list-btn')?.addEventListener('click', showAddShoppingList);
    document.getElementById('back-to-shopping')?.addEventListener('click', goToShopping);
    document.getElementById('back-to-shopping-lists')?.addEventListener('click', goToShopping);
    document.getElementById('edit-list-btn')?.addEventListener('click', editCurrentList);
    document.getElementById('delete-list-btn')?.addEventListener('click', deleteCurrentList);
    
    // Shopping list forms and search
    document.getElementById('add-shopping-list-form')?.addEventListener('submit', createShoppingList);
    document.getElementById('add-item-form')?.addEventListener('submit', addShoppingItem);
    document.getElementById('search-lists')?.addEventListener('input', searchShoppingLists);
    
    // Profile forms and actions
    document.getElementById('change-name-form')?.addEventListener('submit', updateUserName);
    document.getElementById('change-password-form')?.addEventListener('submit', updateUserPassword);
    document.getElementById('copy-user-id')?.addEventListener('click', copyUserId);
    document.getElementById('profile-security-btn')?.addEventListener('click', showSecuritySettings);
    
    // Friends functionality
    document.getElementById('add-friend-btn')?.addEventListener('click', () => {
        document.getElementById('friend-search-modal').style.display = 'block';
    });
    
    document.getElementById('friend-search-form')?.addEventListener('submit', (e) => {
        e.preventDefault();
        const userId = document.getElementById('friend-search-id').value.trim();
        if (userId) {
            searchUserById(userId);
        }
    });
    
    // Friend request tabs
    document.querySelectorAll('[data-request-tab]').forEach(tab => {
        tab.addEventListener('click', (e) => {
            const tabType = e.target.closest('[data-request-tab]').dataset.requestTab;
            
            // Update active tab
            document.querySelectorAll('[data-request-tab]').forEach(t => t.classList.remove('active'));
            e.target.closest('[data-request-tab]').classList.add('active');
            
            // Show corresponding request list
            document.getElementById('received-requests').style.display = tabType === 'received' ? 'block' : 'none';
            document.getElementById('sent-requests').style.display = tabType === 'sent' ? 'block' : 'none';
        });
    });
    
    // Share list functionality
    document.getElementById('share-list-btn')?.addEventListener('click', () => {
        if (currentList) {
            showShareListModal();
        }
    });
    
    // Search friends
    document.getElementById('friends-search-input')?.addEventListener('input', (e) => {
        const searchTerm = e.target.value.toLowerCase();
        const friendItems = document.querySelectorAll('.friend-item');
        
        friendItems.forEach(item => {
            const name = item.querySelector('h4').textContent.toLowerCase();
            const email = item.querySelector('p').textContent.toLowerCase();
            const matches = name.includes(searchTerm) || email.includes(searchTerm);
            item.style.display = matches ? 'flex' : 'none';
        });
    });
    
    // Color picker preview update
    document.getElementById('list-color')?.addEventListener('change', (e) => {
        const preview = document.querySelector('.color-preview');
        if (preview) preview.style.backgroundColor = e.target.value;
    });
    
    // Cards page
    document.getElementById('add-card-btn')?.addEventListener('click', showAddCard);
    document.getElementById('search-cards')?.addEventListener('input', searchCards);
    document.getElementById('security-settings-btn')?.addEventListener('click', showSecuritySettings);
    
    // Add card page
    document.getElementById('add-card-form')?.addEventListener('submit', handleAddCard);
    document.getElementById('back-to-cards')?.addEventListener('click', () => showPage('cards'));
    document.getElementById('cancel-add-card')?.addEventListener('click', () => showPage('cards'));
    document.getElementById('scan-barcode-btn')?.addEventListener('click', showScanner);
    
    // Scanner modal
    document.getElementById('close-scanner')?.addEventListener('click', closeScanner);
    document.getElementById('toggle-camera')?.addEventListener('click', toggleCamera);
    document.getElementById('toggle-flash')?.addEventListener('click', toggleFlash);
    
    // Card modal
    document.getElementById('close-card-modal')?.addEventListener('click', closeCardModal);
    document.getElementById('delete-card')?.addEventListener('click', handleDeleteCard);
    
    // Notification
    document.getElementById('close-notification')?.addEventListener('click', hideNotification);
    
    // 2FA Security Settings
    document.getElementById('close-security-modal')?.addEventListener('click', () => {
        document.getElementById('security-modal').style.display = 'none';
    });
    document.getElementById('setup-twofa-btn')?.addEventListener('click', setup2FA);
    document.getElementById('disable-twofa-btn')?.addEventListener('click', disable2FA);
    
    // 2FA Setup Modal
    document.getElementById('close-twofa-setup')?.addEventListener('click', () => {
        document.getElementById('twofa-setup-modal').style.display = 'none';
    });
    document.getElementById('cancel-twofa-setup')?.addEventListener('click', () => {
        document.getElementById('twofa-setup-modal').style.display = 'none';
    });
    document.getElementById('twofa-setup-form')?.addEventListener('submit', (e) => {
        e.preventDefault();
        verify2FASetup();
    });
    document.getElementById('copy-key')?.addEventListener('click', () => {
        const key = document.getElementById('manual-entry-key').textContent;
        copyToClipboard(key);
    });
    
    // 2FA Disable Modal
    document.getElementById('close-twofa-disable')?.addEventListener('click', () => {
        document.getElementById('twofa-disable-modal').style.display = 'none';
    });
    document.getElementById('cancel-twofa-disable')?.addEventListener('click', () => {
        document.getElementById('twofa-disable-modal').style.display = 'none';
    });
    document.getElementById('twofa-disable-form')?.addEventListener('submit', (e) => {
        e.preventDefault();
        confirmDisable2FA();
    });
    
    // 2FA Login Modal
    document.getElementById('cancel-twofa-login')?.addEventListener('click', cancel2FALogin);
    document.getElementById('twofa-login-form')?.addEventListener('submit', (e) => {
        e.preventDefault();
        submit2FALogin();
    });
    
    // Auto-focus and formatting for 2FA inputs
    const twofaInputs = document.querySelectorAll('.twofa-input');
    twofaInputs.forEach(input => {
        // Only allow numbers
        input.addEventListener('input', (e) => {
            e.target.value = e.target.value.replace(/[^0-9]/g, '').substring(0, 6);
        });
        
        // Auto-submit on complete
        input.addEventListener('input', (e) => {
            if (e.target.value.length === 6) {
                // Small delay to ensure user sees the full code
                setTimeout(() => {
                    const form = e.target.closest('form');
                    if (form) {
                        form.dispatchEvent(new Event('submit'));
                    }
                }, 300);
            }
        });
    });
    
    // Click outside modals to close
    document.addEventListener('click', (e) => {
        if (e.target.classList.contains('modal')) {
            closeScanner();
            closeCardModal();
            // Close 2FA modals
            document.getElementById('security-modal').style.display = 'none';
            document.getElementById('twofa-setup-modal').style.display = 'none';
            document.getElementById('twofa-disable-modal').style.display = 'none';
            document.getElementById('twofa-login-modal').style.display = 'none';
        }
    });
    
    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeScanner();
            closeCardModal();
            hideNotification();
            // Close 2FA modals on Escape
            document.getElementById('security-modal').style.display = 'none';
            document.getElementById('twofa-setup-modal').style.display = 'none';
            document.getElementById('twofa-disable-modal').style.display = 'none';
            document.getElementById('twofa-login-modal').style.display = 'none';
        }
        
        if (currentPage === 'cards' && (e.ctrlKey || e.metaKey)) {
            if (e.key === 'k' || e.key === '/') {
                e.preventDefault();
                document.getElementById('search-cards')?.focus();
            }
            if (e.key === 'n') {
                e.preventDefault();
                showAddCard();
            }
        }
    });
    
    // Enhanced session management - tokens now expire after 1 hour
    // If user gets 401, they'll be redirected to login automatically
}

// Page Management
async function showPage(page) {
    console.log(`📄 Показую сторінку: ${page}`);
    
    // Hide all pages
    document.querySelectorAll('.page').forEach(p => p.style.display = 'none');
    document.getElementById('loading-screen').style.display = 'none';
    
    // Update current page
    currentPage = page;
    
    // Show/hide navbar and tabs
    const navbar = document.getElementById('navbar');
    const mainTabs = document.getElementById('main-tabs');
    
    if (page === 'login' || page === 'register') {
        navbar.style.display = 'none';
        if (mainTabs) mainTabs.style.display = 'none';
    } else {
        navbar.style.display = 'flex';
        if (mainTabs) {
            mainTabs.style.display = (page === 'cards' || page === 'shopping' || page === 'profile' || 
                                      page === 'add-shopping-list' || page === 'shopping-list-detail') ? 'flex' : 'none';
        }
    }
    
    // Show target page
    const targetPage = document.getElementById(`${page}-page`);
    if (targetPage) {
        targetPage.style.display = 'block';
        
        // Page-specific initialization
        if (page === 'cards') {
            currentTab = 'cards';
            updateTabButtons();
            await loadCards();
        } else if (page === 'shopping') {
            currentTab = 'shopping';
            updateTabButtons();
            await loadShoppingLists();
        } else if (page === 'profile') {
            currentTab = 'profile';
            updateTabButtons();
            await loadProfile();
        }
        
        // Add fade-in animation
        targetPage.style.opacity = '0';
        targetPage.style.transform = 'translateY(20px)';
        
        setTimeout(() => {
            targetPage.style.transition = 'all 0.3s ease-out';
            targetPage.style.opacity = '1';
            targetPage.style.transform = 'translateY(0)';
        }, 50);
    }
}

function updateTabButtons() {
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.dataset.tab === currentTab) {
            btn.classList.add('active');
        }
    });
}

// Authentication
async function handleLogin(e) {
    e.preventDefault();
    
    const email = document.getElementById('login-email').value.trim();
    const password = document.getElementById('login-password').value;
    
    if (!email || !password) {
        showNotification(getTranslation('messages.fill_all_fields'), 'error');
        return;
    }
    
    // Use the new 2FA-enabled login
    await loginWith2FA(email, password);
}

async function handleRegister(e) {
    e.preventDefault();
    
    const email = document.getElementById('register-email').value.trim();
    const password = document.getElementById('register-password').value;
    const confirmPassword = document.getElementById('register-confirm-password').value;
    
    if (!email || !password || !confirmPassword) {
        showNotification(getTranslation('messages.fill_all_fields'), 'error');
        return;
    }
    
    if (password !== confirmPassword) {
        showNotification(getTranslation('messages.passwords_not_match'), 'error');
        return;
    }
    
    if (password.length < 6) {
        showNotification(getTranslation('messages.password_min_length'), 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/auth/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include', // Include cookies
            body: JSON.stringify({ email, password }),
        });
        
        const data = await response.json();
        
        if (response.ok) {
            currentUser = data.user;
            showNotification(getTranslation('messages.registration_success'), 'success');
            await showPage('cards');
        } else {
            showNotification(data.error || getTranslation('messages.server_error'), 'error');
            // Show password suggestions if available
            if (data.suggestions && data.suggestions.length > 0) {
                console.log('Password suggestions:', data.suggestions);
            }
        }
    } catch (error) {
        console.error('Register error:', error);
        showNotification(getTranslation('messages.server_error'), 'error');
    }
}

async function logout() {
    try {
        // Call logout endpoint to clear server-side session
        await fetch(`${API_BASE}/auth/logout`, {
            method: 'POST',
            credentials: 'include'
        });
    } catch (error) {
        console.warn('Logout API call failed:', error);
    }
    
    currentUser = null;
    userCards = [];
    
    // Clear forms
    document.querySelectorAll('form').forEach(form => form.reset());
    
    showNotification(getTranslation('messages.logout_success'), 'success');
    showPage('login');
}

// Cards Management
async function loadCards() {
    // Check if user is logged in
    if (!currentUser) {
        showPage('login');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/cards`, {
            credentials: 'include'
        });
        
        if (response.ok) {
            const data = await response.json();
            console.log('Loaded cards for user:', currentUser.id, 'Cards:', data.cards?.length || 0);
            userCards = data.cards || [];
            renderCards(userCards);
        } else if (response.status === 401) {
            console.warn('Unauthorized - redirecting to login');
            currentUser = null;
            showPage('login');
        } else if (response.status === 423) {
            // Account locked
            const errorData = await response.json();
            showNotification(errorData.error, 'error');
            currentUser = null;
            showPage('login');
        } else {
            const errorData = await response.json();
            showNotification(errorData.error || getTranslation('messages.server_error'), 'error');
        }
    } catch (error) {
        console.error('Load cards error:', error);
        showNotification(getTranslation('messages.server_error'), 'error');
    }
}

function renderCards(cards = userCards) {
    const grid = document.getElementById('cards-grid');
    const emptyState = document.getElementById('empty-state');
    
    if (cards.length === 0) {
        grid.style.display = 'none';
        emptyState.style.display = 'block';
        return;
    }
    
    emptyState.style.display = 'none';
    grid.style.display = 'grid';
    
    grid.innerHTML = cards.map(card => `
        <div class="card" onclick="showCard('${card._id}')" data-card-id="${card._id}">
            <div class="card-header">
                <div class="card-title">${escapeHtml(card.name)}</div>
                <div class="card-type">${card.codeType === 'qr' ? 'QR' : 'Штрих-код'}</div>
            </div>
            <div class="card-code">${escapeHtml(card.code)}</div>
            <div class="card-date">
                Додано: ${new Date(card.createdAt).toLocaleDateString('uk-UA')}
            </div>
        </div>
    `).join('');
    
    // Add animation
    const cardElements = grid.querySelectorAll('.card');
    cardElements.forEach((card, index) => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(20px)';
        setTimeout(() => {
            card.style.transition = 'all 0.3s ease-out';
            card.style.opacity = '1';
            card.style.transform = 'translateY(0)';
        }, index * 100);
    });
}

function searchCards() {
    const query = document.getElementById('search-cards').value.toLowerCase().trim();
    
    if (query === '') {
        renderCards(userCards);
        return;
    }
    
    const filtered = userCards.filter(card => 
        card.name.toLowerCase().includes(query) ||
        card.code.toLowerCase().includes(query)
    );
    
    renderCards(filtered);
}

function showAddCard() {
    showPage('add-card');
    
    // Clear form
    document.getElementById('add-card-form').reset();
    
    // Focus first input
    setTimeout(() => {
        document.getElementById('card-name')?.focus();
    }, 300);
}

async function handleAddCard(e) {
    e.preventDefault();
    
    // Check if user is logged in
    if (!currentUser) {
        showNotification('Увійдіть в систему для додавання карток', 'error');
        showPage('login');
        return;
    }
    
    const name = document.getElementById('card-name').value.trim();
    const code = document.getElementById('card-code').value.trim();
    const codeType = document.querySelector('input[name="code-type"]:checked').value;
    
    if (!name || !code) {
        showNotification(getTranslation('messages.fill_all_fields'), 'error');
        return;
    }
    
    if (name.length > 100) {
        showNotification('Назва картки занадто довга (максимум 100 символів)', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/cards`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({ name, code, codeType }),
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showNotification(getTranslation('messages.card_added'), 'success');
            await showPage('cards');
        } else if (response.status === 401) {
            showPage('login');
        } else if (response.status === 423) {
            showNotification(data.error, 'error');
            showPage('login');
        } else {
            showNotification(data.error || getTranslation('messages.server_error'), 'error');
        }
    } catch (error) {
        console.error('Add card error:', error);
        showNotification(getTranslation('messages.server_error'), 'error');
    }
}

async function handleDeleteCard() {
    const cardId = document.getElementById('delete-card').dataset.cardId;
    if (!cardId) return;
    
    if (!confirm(getTranslation('messages.confirm_delete'))) {
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/cards/${cardId}`, {
            method: 'DELETE',
            credentials: 'include'
        });
        
        if (response.ok) {
            showNotification(getTranslation('messages.card_deleted'), 'success');
            closeCardModal();
            await loadCards();
        } else if (response.status === 401) {
            showPage('login');
        } else if (response.status === 423) {
            const errorData = await response.json();
            showNotification(errorData.error, 'error');
            showPage('login');
        } else {
            const data = await response.json();
            showNotification(data.error || getTranslation('messages.server_error'), 'error');
        }
    } catch (error) {
        console.error('Delete card error:', error);
        showNotification(getTranslation('messages.server_error'), 'error');
    }
}

// Card Display
async function showCard(cardId) {
    const card = userCards.find(c => c._id === cardId);
    if (!card) return;
    
    const modal = document.getElementById('card-modal');
    const title = document.getElementById('card-modal-title');
    const display = document.getElementById('card-code-display');
    const number = document.getElementById('card-code-number');
    const deleteBtn = document.getElementById('delete-card');
    
    title.textContent = card.name;
    number.textContent = card.code;
    deleteBtn.dataset.cardId = cardId;
    
    // Clear previous display
    display.innerHTML = '';
    
    try {
        if (card.codeType === 'qr') {
            // Generate QR code
            const canvas = await QRCode.toCanvas(card.code, {
                width: 256,
                height: 256,
                colorDark: '#000000',
                colorLight: '#ffffff',
                correctLevel: QRCode.CorrectLevel.H
            });
            display.appendChild(canvas);
        } else {
            // Generate barcode using simple canvas implementation
            const canvas = generateBarcode(card.code);
            if (canvas) {
                display.appendChild(canvas);
            } else {
                display.innerHTML = `
                    <div style="padding: 2rem; text-align: center; color: var(--text-secondary);">
                        <p>📱 Штрих-код</p>
                        <p style="font-family: monospace; font-size: 1.2rem; margin-top: 1rem;">${escapeHtml(card.code)}</p>
                    </div>
                `;
            }
        }
    } catch (error) {
        console.error('Error generating code:', error);
        display.innerHTML = `
            <div style="padding: 2rem; text-align: center; color: var(--error-color);">
                <p>⚠️ Помилка генерації коду</p>
            </div>
        `;
    }
    
    modal.style.display = 'flex';
    
    // Add close on background click
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            closeCardModal();
        }
    });
}

function closeCardModal() {
    document.getElementById('card-modal').style.display = 'none';
}

// Simple barcode generation (Code 128 simulation)
function generateBarcode(text) {
    try {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        
        canvas.width = 300;
        canvas.height = 100;
        
        // Fill background
        ctx.fillStyle = '#ffffff';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        
        // Draw bars
        ctx.fillStyle = '#000000';
        let x = 20;
        const barWidth = 2;
        const barHeight = 60;
        
        // Simple pattern based on text
        for (let i = 0; i < text.length && x < canvas.width - 20; i++) {
            const charCode = text.charCodeAt(i);
            const pattern = charCode % 10;
            
            for (let j = 0; j < pattern + 1; j++) {
                if (j % 2 === 0) {
                    ctx.fillRect(x, 20, barWidth, barHeight);
                }
                x += barWidth;
            }
            x += barWidth; // space between characters
        }
        
        // Draw text below
        ctx.fillStyle = '#000000';
        ctx.font = '14px monospace';
        ctx.textAlign = 'center';
        ctx.fillText(text, canvas.width / 2, 95);
        
        return canvas;
    } catch (error) {
        console.error('Barcode generation error:', error);
        return null;
    }
}

// Scanner functionality
function showScanner() {
    const modal = document.getElementById('scanner-modal');
    modal.style.display = 'flex';
    initializeScanner();
}

async function initializeScanner() {
    try {
        const video = document.getElementById('scanner-video');
        
        // Get user media
        currentStream = await navigator.mediaDevices.getUserMedia({
            video: {
                facingMode: 'environment', // Back camera
                width: { ideal: 1280 },
                height: { ideal: 720 }
            }
        });
        
        video.srcObject = currentStream;
        video.play();
        
        // Initialize scanner with library check
        video.addEventListener('loadedmetadata', () => {
            const selectedType = document.querySelector('input[name="code-type"]:checked')?.value || 'barcode';
            
            if (selectedType === 'qr' && typeof jsQR === 'undefined') {
                showNotification('QR сканер не доступний. Введіть код вручну.', 'warning');
                return;
            }
            
            if (selectedType === 'barcode' && typeof Quagga === 'undefined') {
                showNotification('Штрих-код сканер не доступний. Введіть код вручну.', 'warning');
                return;
            }
            
            initializeQuagga(video);
        });
        
    } catch (error) {
        console.error('Camera access error:', error);
        showNotification(getTranslation('messages.camera_error'), 'error');
        closeScanner();
    }
}

function initializeQuagga(video) {
    // Get current code type selection
    const selectedType = document.querySelector('input[name="code-type"]:checked')?.value || 'barcode';
    
    if (selectedType === 'qr') {
        initializeQRScanner(video);
        return;
    }
    
    // Enhanced barcode scanning with Quagga
    Quagga.init({
        inputStream: {
            name: "Live",
            type: "LiveStream",
            target: video,
            constraints: {
                width: { min: 480, ideal: 640, max: 800 },
                height: { min: 320, ideal: 480, max: 600 },
                facingMode: "environment"
            }
        },
        locator: {
            patchSize: "medium",
            halfSample: true
        },
        numOfWorkers: 2,
        frequency: 10,
        decoder: {
            readers: [
                "code_128_reader",
                "ean_reader",
                "ean_8_reader", 
                "code_39_reader",
                "code_39_vin_reader",
                "codabar_reader",
                "upc_reader",
                "upc_e_reader",
                "i2of5_reader",
                "2of5_reader"
            ],
            multiple: false
        },
        locate: true
    }, function(err) {
        if (err) {
            console.error('Quagga initialization error:', err);
            showNotification('Помилка сканера: ' + (err.message || 'Невідома помилка'), 'error');
            return;
        }
        console.log("Barcode scanner initialized");
        Quagga.start();
    });
    
    Quagga.onDetected(function(result) {
        const code = result.codeResult.code;
        console.log('Scanned barcode:', code);
        
        // Validate and filter out false positives
        if (code && code.length >= 4 && /^[0-9A-Za-z\-]+$/.test(code)) {
            // Set the scanned code in the form
            document.getElementById('card-code').value = code;
            
            // Close scanner
            closeScanner();
            
            showNotification('Штрих-код успішно відсканований!', 'success');
        }
    });
}

function initializeQRScanner(video) {
    // Create canvas for QR code processing
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('2d');
    let isScanning = true;
    
    function scanFrame() {
        if (!isScanning || !video.videoWidth || !video.videoHeight) {
            if (isScanning) {
                requestAnimationFrame(scanFrame);
            }
            return;
        }
        
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        context.drawImage(video, 0, 0, canvas.width, canvas.height);
        
        try {
            const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
            
            // Use jsQR library to decode QR codes
            if (typeof jsQR !== 'undefined') {
                const qrCode = jsQR(imageData.data, imageData.width, imageData.height, {
                    inversionAttempts: "dontInvert"
                });
                
                if (qrCode && qrCode.data) {
                    console.log('Scanned QR code:', qrCode.data);
                    
                    // Set the scanned code in the form
                    document.getElementById('card-code').value = qrCode.data;
                    
                    // Close scanner
                    closeScanner();
                    
                    showNotification('QR-код успішно відсканований!', 'success');
                    return;
                }
            }
            
            // Continue scanning
            if (isScanning) {
                requestAnimationFrame(scanFrame);
            }
        } catch (error) {
            console.error('QR scan error:', error);
            if (isScanning) {
                setTimeout(scanFrame, 200);
            }
        }
    }
    
    // Store scanning state for cleanup
    video.qrScanning = true;
    video.stopQRScan = () => { isScanning = false; };
    
    // Start scanning loop
    requestAnimationFrame(scanFrame);
    
    // Show message about QR scanning
    showNotification('QR сканер активний. Наведіть камеру на QR-код...', 'info');
}

async function toggleCamera() {
    try {
        if (currentStream) {
            currentStream.getTracks().forEach(track => track.stop());
        }
        
        // Try to get opposite camera
        const video = document.getElementById('scanner-video');
        const constraints = {
            video: {
                facingMode: video.facingMode === 'environment' ? 'user' : 'environment',
                width: { ideal: 1280 },
                height: { ideal: 720 }
            }
        };
        
        currentStream = await navigator.mediaDevices.getUserMedia(constraints);
        video.srcObject = currentStream;
        video.facingMode = constraints.video.facingMode;
        
        // Reinitialize Quagga
        Quagga.stop();
        setTimeout(() => initializeQuagga(video), 500);
        
    } catch (error) {
        console.error('Camera toggle error:', error);
        showNotification(getTranslation('messages.camera_switch_error'), 'error');
    }
}

async function toggleFlash() {
    try {
        if (currentStream) {
            const track = currentStream.getVideoTracks()[0];
            const capabilities = track.getCapabilities();
            
            if (capabilities.torch) {
                const constraints = { advanced: [{ torch: !track.torchEnabled }] };
                await track.applyConstraints(constraints);
                track.torchEnabled = !track.torchEnabled;
                
                const flashBtn = document.getElementById('toggle-flash');
                flashBtn.textContent = track.torchEnabled ? '🔆 Вимкнути спалах' : '💡 Спалах';
            } else {
                showNotification(getTranslation('messages.flash_not_supported'), 'warning');
            }
        }
    } catch (error) {
        console.error('Flash toggle error:', error);
        showNotification(getTranslation('messages.flash_error'), 'error');
    }
}

function closeScanner() {
    const modal = document.getElementById('scanner-modal');
    modal.style.display = 'none';
    
    // Stop Quagga
    if (typeof Quagga !== 'undefined') {
        Quagga.stop();
    }
    
    // Stop QR scanning if active
    const video = document.getElementById('scanner-video');
    if (video && video.stopQRScan) {
        video.stopQRScan();
        video.qrScanning = false;
    }
    
    // Stop camera stream
    if (currentStream) {
        currentStream.getTracks().forEach(track => track.stop());
        currentStream = null;
    }
    
    // Reset flash button
    const flashBtn = document.getElementById('toggle-flash');
    if (flashBtn) {
        flashBtn.textContent = '💡 Спалах';
    }
}

// Notifications
function showNotification(message, type = 'info') {
    const notification = document.getElementById('notification');
    const messageEl = document.getElementById('notification-message');
    
    messageEl.textContent = message;
    notification.className = `notification ${type}`;
    notification.style.display = 'block';
    
    // Auto-hide after 5 seconds
    setTimeout(hideNotification, 5000);
}

function hideNotification() {
    document.getElementById('notification').style.display = 'none';
}

// Utility Functions
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Offline Support
window.addEventListener('online', () => {
    showNotification(getTranslation('messages.connection_restored'), 'success');
    if (currentPage === 'cards') {
        loadCards();
    }
});

window.addEventListener('offline', () => {
    showNotification(getTranslation('messages.connection_lost'), 'warning');
});

// Global error handling
window.addEventListener('error', (error) => {
    console.error('Global error:', error);
    showNotification(getTranslation('messages.unexpected_error'), 'error');
});

window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);
    showNotification(getTranslation('messages.request_error'), 'error');
});

// 2FA Functionality
let twoFactorLoginData = null;

async function showSecuritySettings() {
    const modal = document.getElementById('security-modal');
    const twoFADisabled = document.getElementById('twofa-disabled');
    const twoFAEnabled = document.getElementById('twofa-enabled');
    
    // Check current 2FA status from user data
    if (currentUser && currentUser.twoFactorEnabled) {
        twoFADisabled.style.display = 'none';
        twoFAEnabled.style.display = 'block';
    } else {
        twoFAEnabled.style.display = 'none';
        twoFADisabled.style.display = 'block';
    }
    
    modal.style.display = 'flex';
}

async function setup2FA() {
    try {
        const response = await fetch(`${API_BASE}/auth/2fa/setup`, {
            method: 'POST',
            credentials: 'include'
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to setup 2FA');
        }
        
        const data = await response.json();
        
        // Show setup modal
        document.getElementById('security-modal').style.display = 'none';
        document.getElementById('qr-code-display').innerHTML = `<img src="${data.qrCode}" alt="2FA QR Code" />`;
        document.getElementById('manual-entry-key').textContent = data.secret;
        document.getElementById('twofa-setup-modal').style.display = 'flex';
        
    } catch (error) {
        console.error('2FA setup error:', error);
        showNotification(error.message || getTranslation('messages.server_error'), 'error');
    }
}

async function verify2FASetup() {
    try {
        const token = document.getElementById('twofa-verify-token').value;
        if (!token || token.length !== 6) {
            showNotification('Please enter a 6-digit code', 'error');
            return;
        }
        
        const response = await fetch(`${API_BASE}/auth/2fa/verify`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include',
            body: JSON.stringify({ token })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Verification failed');
        }
        
        const data = await response.json();
        
        // Update user state
        if (currentUser) {
            currentUser.twoFactorEnabled = true;
        }
        
        // Close modal and show success
        document.getElementById('twofa-setup-modal').style.display = 'none';
        showNotification(getTranslation('twofa.setup_success'), 'success');
        
        // Reset form
        document.getElementById('twofa-verify-token').value = '';
        
    } catch (error) {
        console.error('2FA verification error:', error);
        showNotification(error.message || getTranslation('twofa.invalid_code'), 'error');
    }
}

async function disable2FA() {
    const modal = document.getElementById('twofa-disable-modal');
    modal.style.display = 'flex';
}

async function confirmDisable2FA() {
    try {
        const password = document.getElementById('disable-password').value;
        const token = document.getElementById('disable-twofa-token').value;
        
        if (!password || !token || token.length !== 6) {
            showNotification('Please fill in all fields', 'error');
            return;
        }
        
        const response = await fetch(`${API_BASE}/auth/2fa/disable`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include',
            body: JSON.stringify({ password, token })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to disable 2FA');
        }
        
        // Update user state
        if (currentUser) {
            currentUser.twoFactorEnabled = false;
        }
        
        // Close modals
        document.getElementById('twofa-disable-modal').style.display = 'none';
        document.getElementById('security-modal').style.display = 'none';
        
        showNotification(getTranslation('twofa.disabled_success'), 'success');
        
        // Reset form
        document.getElementById('disable-password').value = '';
        document.getElementById('disable-twofa-token').value = '';
        
    } catch (error) {
        console.error('2FA disable error:', error);
        showNotification(error.message || getTranslation('messages.server_error'), 'error');
    }
}

async function loginWith2FA(email, password, twoFactorToken = null) {
    try {
        const response = await fetch(`${API_BASE}/auth/login-2fa`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({ 
                email, 
                password, 
                twoFactorToken 
            })
        });

        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Login failed');
        }
        
        // Check if 2FA is required
        if (data.requires2FA) {
            // Store login data for 2FA step
            twoFactorLoginData = { email, password };
            // Show 2FA modal
            document.getElementById('twofa-login-modal').style.display = 'flex';
            document.getElementById('twofa-token').focus();
            return;
        }
        
        // Successful login
        currentUser = data.user;
        showNotification(getTranslation('messages.login_success'), 'success');
        showPage('cards');
        loadCards();
        
    } catch (error) {
        console.error('Login error:', error);
        showNotification(error.message || getTranslation('messages.server_error'), 'error');
    }
}

async function submit2FALogin() {
    if (!twoFactorLoginData) {
        showNotification(getTranslation('twofa.setup_required'), 'error');
        return;
    }
    
    const token = document.getElementById('twofa-token').value;
    if (!token || token.length !== 6) {
        showNotification('Please enter a 6-digit code', 'error');
        return;
    }
    
    // Try login with 2FA token
    await loginWith2FA(twoFactorLoginData.email, twoFactorLoginData.password, token);
    
    // Clear data and modal
    twoFactorLoginData = null;
    document.getElementById('twofa-login-modal').style.display = 'none';
    document.getElementById('twofa-token').value = '';
}

function cancel2FALogin() {
    twoFactorLoginData = null;
    document.getElementById('twofa-login-modal').style.display = 'none';
    document.getElementById('twofa-token').value = '';
}

function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
            showNotification(getTranslation('messages.copied'), 'success');
        }).catch(() => {
            fallbackCopy(text);
        });
    } else {
        fallbackCopy(text);
    }
}

function fallbackCopy(text) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.left = '-999999px';
    textArea.style.top = '-999999px';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    try {
        document.execCommand('copy');
        showNotification(getTranslation('common.copy') + ' ✓', 'success');
    } catch (err) {
        showNotification('Copy failed', 'error');
    }
    document.body.removeChild(textArea);
}

// Tab Management
function switchTab(tabName) {
    if (currentTab === tabName) return;
    
    // Update tab buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.dataset.tab === tabName) {
            btn.classList.add('active');
        }
    });
    
    currentTab = tabName;
    
    // Show appropriate page
    if (tabName === 'cards') {
        showCardsPage();
    } else if (tabName === 'shopping') {
        showShoppingPage();
    } else if (tabName === 'friends') {
        showFriendsPage();
    } else if (tabName === 'profile') {
        showProfilePage();
    }
}

function showCardsPage() {
    hideAllPages();
    document.getElementById('cards-page').style.display = 'block';
    loadCards();
}

function hideAllPages() {
    document.querySelectorAll('.page').forEach(page => {
        page.style.display = 'none';
    });
}

function showShoppingPage() {
    hideAllPages();
    document.getElementById('shopping-page').style.display = 'block';
    loadShoppingLists();
}

function showFriendsPage() {
    hideAllPages();
    document.getElementById('friends-page').style.display = 'block';
    loadFriends();
    loadFriendRequests();
}

function showProfilePage() {
    hideAllPages();
    document.getElementById('profile-page').style.display = 'block';
    loadProfile();
}

// Shopping Lists Functions
async function loadShoppingLists() {
    try {
        const response = await fetch(`${API_BASE}/shopping-lists`, {
            credentials: 'include'
        });
        
        if (!response.ok) throw new Error('Failed to load shopping lists');
        
        const data = await response.json();
        shoppingLists = data.lists || [];
        renderShoppingLists();
    } catch (error) {
        console.error('Load shopping lists error:', error);
        showNotification('Помилка завантаження списків', 'error');
    }
}

function renderShoppingLists(lists = shoppingLists) {
    const grid = document.getElementById('shopping-lists-grid');
    const emptyState = document.getElementById('shopping-empty-state');
    
    if (lists.length === 0) {
        grid.style.display = 'none';
        emptyState.style.display = 'block';
        return;
    }
    
    grid.style.display = 'grid';
    emptyState.style.display = 'none';
    
    grid.innerHTML = lists.map(list => {
        const completedItems = list.items.filter(item => item.completed).length;
        const totalItems = list.items.length;
        const progress = totalItems > 0 ? (completedItems / totalItems) * 100 : 0;
        
        return `
            <div class="shopping-list-card" onclick="openShoppingListDetail('${list._id}')">
                <div class="list-header">
                    <div>
                        <div class="list-name">${escapeHtml(list.name)}</div>
                        ${list.description ? `<div class="list-description">${escapeHtml(list.description)}</div>` : ''}
                    </div>
                    <div class="list-color-indicator" style="background-color: ${list.color}"></div>
                </div>
                
                <div class="list-progress">
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: ${progress}%"></div>
                    </div>
                    <div class="progress-text">
                        <span>${completedItems}/${totalItems} ${getTranslation('shopping.completed_items')}</span>
                        ${list.totalBudget ? `<span>${list.totalBudget} грн</span>` : ''}
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function searchShoppingLists() {
    const query = document.getElementById('search-lists').value.toLowerCase().trim();
    
    if (query === '') {
        renderShoppingLists(shoppingLists);
        return;
    }
    
    const filtered = shoppingLists.filter(list => 
        list.name.toLowerCase().includes(query) ||
        (list.description && list.description.toLowerCase().includes(query))
    );
    
    renderShoppingLists(filtered);
}

function showAddShoppingList() {
    // Reset form to add mode first
    resetShoppingListForm();
    
    hideAllPages();
    document.getElementById('add-shopping-list-page').style.display = 'block';
    
    // Reset form
    document.getElementById('add-shopping-list-form').reset();
    document.getElementById('list-color').value = '#10B981';
    document.querySelector('.color-preview').style.backgroundColor = '#10B981';
}

function goToShopping() {
    switchTab('shopping');
}

async function createShoppingList(event) {
    event.preventDefault();
    
    const form = event.target;
    const formData = new FormData(form);
    
    const listData = {
        name: formData.get('name'),
        description: formData.get('description'),
        totalBudget: formData.get('budget') ? parseFloat(formData.get('budget')) : undefined,
        color: formData.get('color')
    };
    
    try {
        const response = await fetch(`${API_BASE}/shopping-lists`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify(listData)
        });
        
        if (!response.ok) throw new Error('Failed to create shopping list');
        
        const data = await response.json();
        showNotification(data.message, 'success');
        goToShopping();
    } catch (error) {
        console.error('Create shopping list error:', error);
        showNotification('Помилка створення списку', 'error');
    }
}

function openShoppingListDetail(listId) {
    const list = shoppingLists.find(l => l._id === listId);
    if (!list) return;
    
    currentList = list;
    hideAllPages();
    document.getElementById('shopping-list-detail-page').style.display = 'block';
    
    // Update page title and stats
    document.getElementById('list-detail-title').textContent = list.name;
    updateListStats();
    renderShoppingItems();
}

function updateListStats() {
    if (!currentList) return;
    
    const totalItems = currentList.items.length;
    const completedItems = currentList.items.filter(item => item.completed).length;
    
    document.getElementById('total-items-count').textContent = totalItems;
    document.getElementById('completed-items-count').textContent = completedItems;
    document.getElementById('list-budget-display').textContent = 
        currentList.totalBudget ? `${currentList.totalBudget} грн` : '--';
}

function renderShoppingItems() {
    if (!currentList) return;
    
    const container = document.getElementById('shopping-items-container');
    
    if (currentList.items.length === 0) {
        container.innerHTML = '<p class="empty-text">Немає товарів у списку</p>';
        return;
    }
    
    container.innerHTML = currentList.items.map(item => `
        <div class="shopping-item ${item.completed ? 'completed' : ''}">
            <input type="checkbox" class="item-checkbox" 
                   ${item.completed ? 'checked' : ''} 
                   onchange="toggleItemCompleted('${item._id}')">
            <div class="item-details">
                <div class="item-name">${escapeHtml(item.name)}</div>
                <div class="item-quantity">${escapeHtml(item.quantity)}</div>
                <div class="item-category">${escapeHtml(item.category)}</div>
                <div class="item-price">${item.price ? item.price + ' грн' : '--'}</div>
            </div>
            <div class="item-actions">
                <button class="btn-icon-small" onclick="deleteShoppingItem('${item._id}')" title="Видалити">🗑️</button>
            </div>
        </div>
    `).join('');
}

async function addShoppingItem(event) {
    event.preventDefault();
    
    if (!currentList) return;
    
    const form = event.target;
    const formData = new FormData(form);
    
    const itemData = {
        name: formData.get('name'),
        quantity: formData.get('quantity'),
        category: formData.get('category'),
        price: formData.get('price') ? parseFloat(formData.get('price')) : undefined
    };
    
    try {
        const response = await fetch(`${API_BASE}/shopping-lists/${currentList._id}/items`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify(itemData)
        });
        
        if (!response.ok) throw new Error('Failed to add item');
        
        const data = await response.json();
        currentList = data.list;
        
        // Reset form and update display
        form.reset();
        document.getElementById('item-quantity').value = '1';
        updateListStats();
        renderShoppingItems();
        
        showNotification('Товар додано', 'success');
    } catch (error) {
        console.error('Add item error:', error);
        showNotification('Помилка додавання товару', 'error');
    }
}

async function toggleItemCompleted(itemId) {
    if (!currentList) return;
    
    const item = currentList.items.find(i => i._id === itemId);
    if (!item) return;
    
    const completed = !item.completed;
    
    try {
        const response = await fetch(`${API_BASE}/shopping-lists/${currentList._id}/items/${itemId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ completed })
        });
        
        if (!response.ok) throw new Error('Failed to update item');
        
        const data = await response.json();
        currentList = data.list;
        
        updateListStats();
        renderShoppingItems();
    } catch (error) {
        console.error('Toggle item error:', error);
        showNotification('Помилка оновлення товару', 'error');
    }
}

async function deleteShoppingItem(itemId) {
    if (!currentList || !confirm('Видалити цей товар?')) return;
    
    try {
        const response = await fetch(`${API_BASE}/shopping-lists/${currentList._id}/items/${itemId}`, {
            method: 'DELETE',
            credentials: 'include'
        });
        
        if (!response.ok) throw new Error('Failed to delete item');
        
        const data = await response.json();
        currentList = data.list;
        
        updateListStats();
        renderShoppingItems();
        showNotification('Товар видалено', 'success');
    } catch (error) {
        console.error('Delete item error:', error);
        showNotification('Помилка видалення товару', 'error');
    }
}

async function deleteCurrentList() {
    if (!currentList || !confirm(`Видалити список "${currentList.name}"? Ця дія незворотна.`)) return;
    
    try {
        const response = await fetch(`${API_BASE}/shopping-lists/${currentList._id}`, {
            method: 'DELETE',
            credentials: 'include'
        });
        
        if (!response.ok) throw new Error('Failed to delete list');
        
        showNotification('Список видалено', 'success');
        goToShopping();
        await loadShoppingLists();
    } catch (error) {
        console.error('Delete list error:', error);
        showNotification('Помилка видалення списку', 'error');
    }
}

function editCurrentList() {
    if (!currentList) return;
    
    // Pre-fill form with current list data
    document.getElementById('list-name').value = currentList.name;
    document.getElementById('list-description').value = currentList.description || '';
    document.getElementById('list-budget').value = currentList.totalBudget || '';
    document.getElementById('list-color').value = currentList.color || '#10B981';
    document.querySelector('.color-preview').style.backgroundColor = currentList.color || '#10B981';
    
    // Change form title to edit mode
    const pageTitle = document.querySelector('#add-shopping-list-page .page-header h2');
    if (pageTitle) {
        pageTitle.textContent = `Редагувати список: ${currentList.name}`;
    }
    
    // Update form action
    const form = document.getElementById('add-shopping-list-form');
    form.onsubmit = async (event) => {
        event.preventDefault();
        await updateShoppingList(currentList._id, event);
    };
    
    // Update submit button text
    const submitButton = form.querySelector('button[type="submit"]');
    if (submitButton) {
        submitButton.textContent = 'Зберегти зміни';
    }
    
    // Show edit page
    hideAllPages();
    document.getElementById('add-shopping-list-page').style.display = 'block';
}

async function updateShoppingList(listId, event) {
    const form = event.target;
    const formData = new FormData(form);
    
    const listData = {
        name: formData.get('name'),
        description: formData.get('description'),
        totalBudget: formData.get('budget') ? parseFloat(formData.get('budget')) : undefined,
        color: formData.get('color')
    };
    
    try {
        const response = await fetch(`${API_BASE}/shopping-lists/${listId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify(listData)
        });
        
        if (!response.ok) throw new Error('Failed to update shopping list');
        
        const data = await response.json();
        
        // Update current list if we're editing the currently viewed list
        if (currentList && currentList._id === listId) {
            currentList = data.list;
            document.getElementById('list-detail-title').textContent = currentList.name;
        }
        
        showNotification('Список оновлено', 'success');
        
        // Reset form to add mode
        resetShoppingListForm();
        
        // Go back to list detail or shopping lists
        if (currentList && currentList._id === listId) {
            openShoppingListDetail(listId);
        } else {
            goToShopping();
        }
        
        await loadShoppingLists();
    } catch (error) {
        console.error('Update shopping list error:', error);
        showNotification('Помилка оновлення списку', 'error');
    }
}

function resetShoppingListForm() {
    const form = document.getElementById('add-shopping-list-form');
    const pageTitle = document.querySelector('#add-shopping-list-page .page-header h2');
    const submitButton = form.querySelector('button[type="submit"]');
    
    // Reset form to add mode
    form.onsubmit = createShoppingList;
    
    if (pageTitle) {
        pageTitle.textContent = 'Новий список покупок';
    }
    
    if (submitButton) {
        submitButton.textContent = 'Створити список';
    }
}

// Update login function to support remember me
async function login(event) {
    event.preventDefault();
    
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    const rememberMe = document.getElementById('remember-me').checked;
    
    try {
        const response = await fetch(`${API_BASE}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ email, password, rememberMe })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Login failed');
        }
        
        currentUser = data.user;
        showPage('cards');
        showNotification(data.message, 'success');
    } catch (error) {
        console.error('Login error:', error);
        showNotification(error.message, 'error');
    }
}

// Profile Functions
async function loadProfile() {
    if (!currentUser) return;
    
    try {
        // Fetch fresh profile data from server
        const response = await fetch(`${API_BASE}/user/profile`, {
            credentials: 'include'
        });
        
        if (response.ok) {
            const data = await response.json();
            const user = data.user;
            
            // Update current user with fresh data
            currentUser = { ...currentUser, ...user };
            
            // Update profile display
            document.getElementById('profile-display-name').textContent = user.name || user.email.split('@')[0];
            document.getElementById('profile-display-email').textContent = user.email;
            document.getElementById('profile-display-id').textContent = user.id || 'N/A';
            
            // Update stats with server data
            if (user.statistics) {
                document.getElementById('total-cards-count').textContent = user.statistics.cardCount;
                document.getElementById('total-lists-count').textContent = user.statistics.shoppingListCount;
                document.getElementById('account-age').textContent = user.statistics.accountAge;
            } else {
                // Fallback to local data
                document.getElementById('total-cards-count').textContent = userCards.length;
                document.getElementById('total-lists-count').textContent = shoppingLists.length;
                
                if (user.createdAt) {
                    const createdDate = new Date(user.createdAt);
                    const now = new Date();
                    const ageInDays = Math.floor((now - createdDate) / (1000 * 60 * 60 * 24));
                    document.getElementById('account-age').textContent = ageInDays;
                } else {
                    document.getElementById('account-age').textContent = '--';
                }
            }
            
            // Pre-fill name form with current name
            document.getElementById('new-name').value = user.name || '';
            
        } else {
            throw new Error('Failed to load profile');
        }
        
    } catch (error) {
        console.error('Load profile error:', error);
        showNotification(getTranslation('messages.profile_load_error'), 'error');
        
        // Fallback to existing currentUser data
        if (currentUser) {
            document.getElementById('profile-display-name').textContent = currentUser.name || currentUser.email.split('@')[0];
            document.getElementById('profile-display-email').textContent = currentUser.email;
            document.getElementById('profile-display-id').textContent = currentUser.id || currentUser._id || 'N/A';
            
            // Update stats with local data
            document.getElementById('total-cards-count').textContent = userCards.length;
            document.getElementById('total-lists-count').textContent = shoppingLists.length;
            
            if (currentUser.createdAt) {
                const createdDate = new Date(currentUser.createdAt);
                const now = new Date();
                const ageInDays = Math.floor((now - createdDate) / (1000 * 60 * 60 * 24));
                document.getElementById('account-age').textContent = ageInDays;
            } else {
                document.getElementById('account-age').textContent = '--';
            }
            
            // Pre-fill name form with current name
            document.getElementById('new-name').value = currentUser.name || '';
        }
    }
}

async function updateUserName(event) {
    event.preventDefault();
    
    const newName = document.getElementById('new-name').value.trim();
    
    if (!newName) {
        showNotification(getTranslation('messages.enter_new_name'), 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/user/update-name`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ name: newName })
        });
        
        if (!response.ok) throw new Error('Failed to update name');
        
        const data = await response.json();
        
        // Update current user
        if (currentUser) {
            currentUser.name = newName;
        }
        
        // Update display
        document.getElementById('profile-display-name').textContent = newName;
        
        showNotification(getTranslation('messages.name_updated'), 'success');
    } catch (error) {
        console.error('Update name error:', error);
        showNotification(getTranslation('messages.name_update_error'), 'error');
    }
}

async function updateUserPassword(event) {
    event.preventDefault();
    
    const currentPassword = document.getElementById('current-password').value;
    const newPassword = document.getElementById('new-password').value;
    const confirmNewPassword = document.getElementById('confirm-new-password').value;
    
    if (!currentPassword || !newPassword || !confirmNewPassword) {
        showNotification(getTranslation('messages.fill_all_fields_profile'), 'error');
        return;
    }
    
    if (newPassword !== confirmNewPassword) {
        showNotification(getTranslation('messages.passwords_not_match_new'), 'error');
        return;
    }
    
    if (newPassword.length < 6) {
        showNotification('Новий пароль повинен містити мінімум 6 символів', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/user/update-password`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ currentPassword, newPassword })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to update password');
        }
        
        const data = await response.json();
        
        // Clear form
        document.getElementById('change-password-form').reset();
        
        showNotification(getTranslation('messages.password_updated'), 'success');
        
        // If server requires re-login, redirect to login page
        if (data.requiresReLogin) {
            setTimeout(() => {
                currentUser = null;
                userCards = [];
                shoppingLists = [];
                showPage('login');
                showNotification('Будь ласка, увійдіть знову для безпеки', 'info');
            }, 2000); // Give time to read the success message
        }
    } catch (error) {
        console.error('Update password error:', error);
        showNotification(error.message || getTranslation('messages.password_update_error'), 'error');
    }
}

// Friends Management Functions
async function loadFriends() {
    try {
        const response = await fetch(`${API_BASE}/friends`, {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        if (response.ok) {
            const data = await response.json();
            friends = data.friends || [];
            displayFriends();
        }
    } catch (error) {
        console.error('Error loading friends:', error);
    }
}

async function loadFriendRequests() {
    try {
        const response = await fetch(`${API_BASE}/friends/requests`, {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        if (response.ok) {
            const data = await response.json();
            friendRequests = { sent: data.sent || [], received: data.received || [] };
            displayFriendRequests();
        }
    } catch (error) {
        console.error('Error loading friend requests:', error);
    }
}

function displayFriends() {
    const friendsList = document.getElementById('friends-list');
    const t = translations[currentLanguage];
    
    if (friends.length === 0) {
        friendsList.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">👥</div>
                <p>${t.friends.no_friends}</p>
            </div>
        `;
        return;
    }
    
    friendsList.innerHTML = friends.map(friend => `
        <div class="friend-item">
            <div class="friend-info">
                <div class="friend-avatar">👤</div>
                <div class="friend-details">
                    <h4>${friend.name}</h4>
                    <p>${friend.email}</p>
                    <small>${t.friends.friends_since}: ${new Date(friend.friendsSince).toLocaleDateString()}</small>
                </div>
            </div>
            <div class="friend-actions">
                <button onclick="removeFriend('${friend.friendshipId}')" class="btn btn-danger btn-sm">
                    ${t.friends.remove_friend}
                </button>
            </div>
        </div>
    `).join('');
}

function displayFriendRequests() {
    const receivedRequests = document.getElementById('received-requests');
    const sentRequests = document.getElementById('sent-requests');
    const receivedCount = document.getElementById('received-count');
    const sentCount = document.getElementById('sent-count');
    const t = translations[currentLanguage];
    
    // Update badges
    receivedCount.textContent = friendRequests.received.length;
    sentCount.textContent = friendRequests.sent.length;
    
    // Display received requests
    if (friendRequests.received.length === 0) {
        receivedRequests.innerHTML = `<p class="no-requests">${t.friends.no_requests}</p>`;
    } else {
        receivedRequests.innerHTML = friendRequests.received.map(request => `
            <div class="request-item">
                <div class="request-info">
                    <div class="friend-avatar">👤</div>
                    <div class="friend-details">
                        <h4>${request.user.name}</h4>
                        <p>${request.user.email}</p>
                        <small>${new Date(request.receivedAt).toLocaleDateString()}</small>
                    </div>
                </div>
                <div class="request-actions">
                    <button onclick="acceptFriendRequest('${request.id}')" class="btn btn-success btn-sm">
                        ${t.friends.accept_request}
                    </button>
                    <button onclick="rejectFriendRequest('${request.id}')" class="btn btn-danger btn-sm">
                        ${t.friends.reject_request}
                    </button>
                </div>
            </div>
        `).join('');
    }
    
    // Display sent requests
    if (friendRequests.sent.length === 0) {
        sentRequests.innerHTML = `<p class="no-requests">${t.friends.no_requests}</p>`;
    } else {
        sentRequests.innerHTML = friendRequests.sent.map(request => `
            <div class="request-item">
                <div class="request-info">
                    <div class="friend-avatar">👤</div>
                    <div class="friend-details">
                        <h4>${request.user.name}</h4>
                        <p>${request.user.email}</p>
                        <small>${new Date(request.sentAt).toLocaleDateString()}</small>
                    </div>
                </div>
                <div class="request-status">
                    <span class="status-pending">${translations[currentLanguage].friends.request_pending}</span>
                </div>
            </div>
        `).join('');
    }
}

async function searchUserById(userId) {
    const searchResult = document.getElementById('friend-search-result');
    const t = translations[currentLanguage];
    
    try {
        searchResult.style.display = 'none';
        
        const response = await fetch(`${API_BASE}/friends/search/${userId}`, {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        if (response.ok) {
            const data = await response.json();
            const user = data.user;
            
            let actionButton = '';
            let statusText = '';
            
            switch (user.friendshipStatus) {
                case 'none':
                    actionButton = `<button onclick="sendFriendRequest('${user.id}')" class="btn btn-primary">
                        ${t.friends.send_request}
                    </button>`;
                    break;
                case 'sent':
                    statusText = `<span class="status-pending">${t.friends.request_sent}</span>`;
                    break;
                case 'received':
                    statusText = `<span class="status-info">У вас є запит від цього користувача</span>`;
                    break;
                case 'accepted':
                    statusText = `<span class="status-success">${t.friends.already_friends}</span>`;
                    break;
            }
            
            searchResult.innerHTML = `
                <div class="search-result-item">
                    <div class="friend-info">
                        <div class="friend-avatar">👤</div>
                        <div class="friend-details">
                            <h4>${user.name}</h4>
                            <p>${user.email}</p>
                            <small>ID: ${user.id}</small>
                        </div>
                    </div>
                    <div class="friend-actions">
                        ${actionButton}
                        ${statusText}
                    </div>
                </div>
            `;
            searchResult.style.display = 'block';
        } else {
            const data = await response.json();
            searchResult.innerHTML = `<p class="error">${data.error || t.friends.user_not_found}</p>`;
            searchResult.style.display = 'block';
        }
    } catch (error) {
        console.error('Error searching user:', error);
        searchResult.innerHTML = `<p class="error">${t.messages.server_error}</p>`;
        searchResult.style.display = 'block';
    }
}

async function sendFriendRequest(recipientId) {
    try {
        const response = await fetch(`${API_BASE}/friends/request`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            },
            body: JSON.stringify({ recipientId })
        });
        
        if (response.ok) {
            showMessage(translations[currentLanguage].friends.request_sent);
            document.getElementById('friend-search-modal').style.display = 'none';
            loadFriendRequests();
        } else {
            const data = await response.json();
            showMessage(data.error, 'error');
        }
    } catch (error) {
        console.error('Error sending friend request:', error);
        showMessage(translations[currentLanguage].messages.server_error, 'error');
    }
}

async function acceptFriendRequest(requestId) {
    try {
        const response = await fetch(`${API_BASE}/friends/request/${requestId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            },
            body: JSON.stringify({ action: 'accept' })
        });
        
        if (response.ok) {
            showMessage('Запит на дружбу прийнято');
            loadFriendRequests();
            loadFriends();
        } else {
            const data = await response.json();
            showMessage(data.error, 'error');
        }
    } catch (error) {
        console.error('Error accepting friend request:', error);
        showMessage(translations[currentLanguage].messages.server_error, 'error');
    }
}

async function rejectFriendRequest(requestId) {
    try {
        const response = await fetch(`${API_BASE}/friends/request/${requestId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            },
            body: JSON.stringify({ action: 'reject' })
        });
        
        if (response.ok) {
            showMessage('Запит на дружбу відхилено');
            loadFriendRequests();
        } else {
            const data = await response.json();
            showMessage(data.error, 'error');
        }
    } catch (error) {
        console.error('Error rejecting friend request:', error);
        showMessage(translations[currentLanguage].messages.server_error, 'error');
    }
}

async function removeFriend(friendshipId) {
    if (!confirm('Ви впевнені, що хочете видалити цього друга?')) {
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/friends/${friendshipId}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        });
        
        if (response.ok) {
            showMessage('Друга видалено');
            loadFriends();
        } else {
            const data = await response.json();
            showMessage(data.error, 'error');
        }
    } catch (error) {
        console.error('Error removing friend:', error);
        showMessage(translations[currentLanguage].messages.server_error, 'error');
    }
}

// Shopping list sharing functions
async function shareShoppingList(listId, friendId, permission) {
    try {
        const response = await fetch(`${API_BASE}/shopping-lists/${listId}/share`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            },
            body: JSON.stringify({ friendId, permission })
        });
        
        if (response.ok) {
            const data = await response.json();
            showMessage(data.message);
            document.getElementById('share-list-modal').style.display = 'none';
            loadCurrentSharedInfo();
        } else {
            const data = await response.json();
            showMessage(data.error, 'error');
        }
    } catch (error) {
        console.error('Error sharing list:', error);
        showMessage(translations[currentLanguage].messages.server_error, 'error');
    }
}

async function loadCurrentSharedInfo() {
    if (!currentList) return;
    
    const currentShares = document.getElementById('current-shares');
    if (currentList.sharedWith && currentList.sharedWith.length > 0) {
        // Display current shares - this would need the actual friend data
        // For now, just show that it's shared
        currentShares.innerHTML = `<p>${currentList.sharedWith.length} друзів мають доступ</p>`;
    } else {
        currentShares.innerHTML = `<p>Список не поділено</p>`;
    }
}

function showShareListModal() {
    const modal = document.getElementById('share-list-modal');
    const friendsContainer = document.getElementById('friends-to-share');
    
    // Load friends into the share modal
    if (friends.length === 0) {
        friendsContainer.innerHTML = '<p>У вас немає друзів для поділу</p>';
    } else {
        friendsContainer.innerHTML = friends.map(friend => `
            <div class="friend-share-item">
                <div class="friend-info">
                    <div class="friend-avatar">👤</div>
                    <div class="friend-details">
                        <h4>${friend.name}</h4>
                        <p>${friend.email}</p>
                    </div>
                </div>
                <button onclick="shareWithFriend('${friend.id}')" class="btn btn-primary btn-sm">
                    Поділитися
                </button>
            </div>
        `).join('');
    }
    
    loadCurrentSharedInfo();
    modal.style.display = 'block';
}

function shareWithFriend(friendId) {
    const permission = document.getElementById('share-permission').value;
    if (currentList) {
        shareShoppingList(currentList._id, friendId, permission);
    }
}

function copyUserId() {
    const userId = document.getElementById('profile-display-id').textContent;
    copyToClipboard(userId);
}

// Export for debugging
window.debugApp = {
    currentUser,
    currentPage,
    currentTab,
    userCards,
    shoppingLists,
    currentList,
    showPage,
    switchTab,
    loadCards,
    loadShoppingLists,
    logout
};

// Test function for debugging card API
async function testCardAPI() {
    console.log('Testing card API...');
    console.log('Current user:', currentUser);
    
    if (!currentUser) {
        console.log('No user logged in');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/cards`, {
            credentials: 'include'
        });
        
        console.log('Cards API Response status:', response.status);
        
        if (response.ok) {
            const data = await response.json();
            console.log('Cards API Response data:', data);
        } else {
            const errorData = await response.json();
            console.log('Cards API Error:', errorData);
        }
    } catch (error) {
        console.error('Cards API Network error:', error);
    }
}

// Add to window for debugging
window.testCardAPI = testCardAPI;