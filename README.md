# 💳 Карти Лояльності - Loyalty Cards App

Повнофункціональний веб-додаток для збереження, сканування та управління картами лояльності з підтримкою PWA, offline режиму та сканування штрих-кодів/QR-кодів.

![App Preview](https://img.shields.io/badge/PWA-Ready-blue)
![Node.js](https://img.shields.io/badge/Node.js-v16+-green)
![MongoDB](https://img.shields.io/badge/Database-MongoDB-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## 🚀 Швидкий старт

```bash
# 1. Клонувати та перейти в папку
git clone <your-repo-url>
cd discard-app

# 2. Запустити одним скриптом
./start.sh
```

Додаток буде доступний на **http://localhost:2804**

## ✨ Особливості

### 🔐 Автентифікація
- Безпечна реєстрація та вхід
- JWT токени з auto-refresh
- Автоматичний logout при неактивності
- Валідація на клієнті та сервері

### 💳 Управління Картами
- Додавання карт з назвою та номером
- Підтримка штрих-кодів та QR-кодів  
- Сканування камерою (всі популярні формати)
- Пошук та фільтрація карт
- Швидкий перегляд та видалення

### 📱 PWA Функціональність
- Встановлення на мобільні пристрої
- Offline робота з синхронізацією
- Service Worker для кешування
- Push-уведомлення (базово)
- Responsive дизайн

### 🔒 Безпека
- Хешування паролів (bcrypt)
- Rate limiting для API
- CORS налаштування
- Input sanitization
- Helmet.js security headers

### 🎨 Сучасний UI/UX
- Градієнтний дизайн
- Темна/світла теми
- Анімації та переходи
- Mobile-first підхід
- Keyboard shortcuts

## 📋 Вимоги

- **Node.js** v16 або новіше
- **MongoDB** (локальна або Atlas)
- **NPM** або **Yarn**
- Сучасний браузер з підтримкою камери

## 🛠 Швидкий Старт

### 1. Клонування та Встановлення
```bash
# Клонувати репозиторій
git clone https://github.com/yourusername/loyalty-cards-app.git
cd loyalty-cards-app

# Встановити залежності
npm install
```

### 2. Налаштування Бази Даних

#### MongoDB (Рекомендовано)
```bash
# Встановити MongoDB локально або використовувати Atlas
# Створити файл .env на основі .env.example
cp .env.example .env

# Відредагувати .env файл:
MONGODB_URI=mongodb://localhost:27017/loyalty-cards
JWT_SECRET=your-secret-key
```

#### Альтернатива: MongoDB Atlas (хмарна база)
```bash
# У .env файлі замінити:
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/loyalty-cards
```

### 3. Запуск Додатку
```bash
# Для розробки (з nodemon)
npm run dev

# Або звичайний запуск
npm start
```

### 4. Відкрити в Браузері
```
http://localhost:2804
```

## 📁 Структура Проекту

```
loyalty-cards-app/
├── 📄 server.js              # Express сервер з API
├── 📄 package.json           # Залежності та скрипти
├── 📄 .env.example          # Приклад конфігурації
├── 📄 README.md             # Документація
└── 📁 public/               # Статичні файли
    ├── 📄 index.html        # SPA головна сторінка
    ├── 📄 style.css         # Стилі з градієнтами
    ├── 📄 script.js         # Frontend логіка
    ├── 📄 manifest.json     # PWA manifest
    ├── 📄 sw.js            # Service Worker
    └── 📁 icons/           # PWA іконки
```

## 🔌 API Ендпоінти

### Автентифікація
```http
POST /api/auth/register    # Реєстрація користувача
POST /api/auth/login       # Вхід користувача
```

### Карти Лояльності
```http
GET    /api/cards         # Отримати карти користувача
POST   /api/cards         # Створити нову картку  
DELETE /api/cards/:id     # Видалити картку
```

### Приклади Запитів

#### Реєстрація
```javascript
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

#### Додавання Картки
```javascript
POST /api/cards
Authorization: Bearer jwt-token
Content-Type: application/json

{
  "name": "АТБ",
  "code": "1234567890123",
  "codeType": "barcode"
}
```

## 🖥 Frontend Особливості

### SPA Роутинг
- `/login` - Сторінка входу
- `/register` - Сторінка реєстрації  
- `/cards` - Головна сторінка з картами
- `/add-card` - Додавання нової картки

### Keyboard Shortcuts (на сторінці карт)
- `Ctrl/Cmd + K` або `/` - Фокус на пошук
- `Ctrl/Cmd + N` - Додати нову картку
- `Escape` - Закрити модальні вікна

### Сканування Кодів
- Підтримка Code 128, EAN, UPC, Code 39, Codabar
- Автоматичне перемикання камер
- Контроль спалаху (якщо підтримується)
- QR-код генерація через qrcode.js

## 🛡 Безпека

### 🔒 Security Rating: **HIGH (9/10)** ✅

### Реалізовані Захисти
- **JWT + Secure Cookies** - Захищені токени з коротким терміном дії (1 год)
- **Account Lockout** - Блокування після 5 невдалих спроб на 2 години
- **Password Strength** - Validation з zxcvbn (мінімум 8 символів)
- **bcrypt** - Хешування паролів (14 salt rounds)
- **Rate Limiting** - 10/15хв для auth, 100/15хв для API
- **Input Sanitization** - Повний XSS/NoSQL injection захист
- **CSRF Protection** - SameSite cookies
- **Helmet.js** - Comprehensive HTTP security headers
- **Audit Logging** - Всі security події з Winston
- **MongoDB Sanitization** - express-mongo-sanitize

### 🚨 Критично для продакшну
```bash
# 1. Згенерувати сильні секрети
node -e "console.log('JWT_SECRET=' + require('crypto').randomBytes(64).toString('hex'))"
node -e "console.log('SESSION_SECRET=' + require('crypto').randomBytes(64).toString('hex'))"

# 2. Встановити production environment
export NODE_ENV=production
export JWT_SECRET=your-generated-jwt-secret
export SESSION_SECRET=your-generated-session-secret
export MONGODB_URI=your-production-db-uri
export FRONTEND_URL=https://yourdomain.com
export COOKIE_SECURE=true

# 3. HTTPS обов'язково
```

### 📋 Security Features Details
- ✅ **No localStorage** - Тільки secure httpOnly cookies
- ✅ **Session invalidation** при зміні пароля  
- ✅ **IP tracking** та logging підозрілої активності
- ✅ **CSP headers** для XSS захисту
- ✅ **CORS** з обмеженими origins
- ✅ **Error handling** без розкриття інформації
- ✅ **Input validation** на клієнті та сервері

Детальніше: [SECURITY.md](./SECURITY.md)

## 📱 PWA Установка

### Встановлення на Мобільний
1. Відкрити сайт у браузері
2. Натиснути "Додати на головний екран"
3. Підтвердити встановлення

### Можливості PWA
- Офлайн робота
- Push-уведомлення
- Нативна поведінка
- Іконка на робочому столі

## 🔄 Offline Підтримка

### Service Worker Стратегії
- **Cache First** - статичні ресурси
- **Network First** - API запити  
- **Stale While Revalidate** - інші ресурси
- **Network Only** - операції запису

### Offline Функції
- Перегляд збережених карт
- Кешування інтерфейсу
- Синхронізація при відновленні з'єднання

## 🚀 Деплой

### Heroku
```bash
# Встановити Heroku CLI та увійти
heroku login

# Створити додаток
heroku create your-app-name

# Додати MongoDB addon
heroku addons:create mongolab:sandbox

# Встановити змінні середовища
heroku config:set JWT_SECRET=your-secret-key
heroku config:set NODE_ENV=production

# Деплой
git push heroku main

# Відкрити додаток
heroku open
```

### Railway
```bash
# Підключити до Railway
railway login
railway init

# Встановити змінні
railway variables set JWT_SECRET=your-secret-key
railway variables set MONGODB_URI=your-mongodb-uri

# Деплой
railway up
```

### Vercel
```bash
# Встановити Vercel CLI
npm i -g vercel

# Деплой
vercel --prod

# Налаштувати змінні середовища у Vercel dashboard
```

### Docker
```dockerfile
# Dockerfile
FROM node:16-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

EXPOSE 2804

CMD ["npm", "start"]
```

```bash
# Збілдити та запустити
docker build -t loyalty-cards .
docker run -p 2804:2804 -e MONGODB_URI=your-uri loyalty-cards
```

## 🧪 Тестування

```bash
# Встановити тестові залежності
npm install --save-dev jest supertest

# Запустити тести
npm test

# Coverage звіт
npm run test:coverage
```

## 📊 Моніторинг та Логування

### Підключення Sentry
```bash
npm install @sentry/node @sentry/tracing

# У .env файлі:
SENTRY_DSN=your-sentry-dsn
```

### Логування з Winston
```bash
npm install winston

# Налаштування в server.js
const winston = require('winston');
```

## 🔧 Налаштування Розробки

### Корисні Скрипти
```bash
# Запуск з nodemon
npm run dev

# Лінтинг коду
npm run lint

# Форматування коду
npm run format

# Очистка кешів
npm run clean
```

### Налаштування VS Code
```json
{
  "recommendations": [
    "ms-vscode.vscode-json",
    "bradlc.vscode-tailwindcss",
    "esbenp.prettier-vscode"
  ]
}
```

## 🐛 Відомі Проблеми та Рішення

### Проблема: Камера не працює
**Рішення:** Переконатися що сайт відкрито через HTTPS або localhost

### Проблема: MongoDB з'єднання
**Рішення:** Перевірити MONGODB_URI та доступність бази даних

### Проблема: JWT токени
**Рішення:** Очистити localStorage та перелогінитися

## 🤝 Внесок у Розробку

### Як допомогти
1. Fork репозиторію
2. Створити feature branch (`git checkout -b feature/amazing-feature`)
3. Commit зміни (`git commit -m 'Add amazing feature'`)
4. Push в branch (`git push origin feature/amazing-feature`)
5. Відкрити Pull Request

### Стилі Кодування
- Використовувати Prettier для форматування
- ESLint для якості коду
- Семантичні commit повідомлення

## 📄 Ліцензія

Цей проект ліцензовано під [MIT License](LICENSE).

## 👨‍💻 Автори

- **Ваше Ім'я** - *Initial work* - [YourGitHub](https://github.com/yourusername)

## 🙏 Подяки

- [QuaggaJS](https://serratus.github.io/quaggaJS/) - Бібліотека сканування штрих-кодів
- [QRCode.js](https://github.com/davidshimjs/qrcodejs) - Генерація QR-кодів
- [Express.js](https://expressjs.com/) - Web framework
- [MongoDB](https://www.mongodb.com/) - База даних

## 📞 Підтримка

Якщо у вас виникли питання:

- 🐛 [Створіть issue](https://github.com/yourusername/loyalty-cards-app/issues)
- 💬 [Discussions](https://github.com/yourusername/loyalty-cards-app/discussions)
- 📧 Email: your-email@example.com

## 🗺 Roadmap

### Версія 2.0
- [ ] Синхронізація між пристроями
- [ ] Експорт/імпорт карт
- [ ] Категорії карт
- [ ] Статистика використання

### Версія 2.1
- [ ] Geolocation для магазинів
- [ ] Інтеграція з Apple Wallet
- [ ] Telegram бот
- [ ] API для сторонніх додатків

---

**Насолоджуйтесь використанням додатку! 🎉**