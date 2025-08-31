# 🚀 Deployment Guide - disCard App

## Варіанти деплою без Docker

### 1. 🌐 Vercel (Рекомендовано)
```bash
# Встановити Vercel CLI
npm i -g vercel

# Deploy
vercel

# Налаштувати environment variables в Vercel dashboard:
# MONGODB_URI, JWT_SECRET, SESSION_SECRET
```

### 2. 🚀 Railway
```bash
# Встановити Railway CLI
npm install -g @railway/cli

# Login та deploy
railway login
railway deploy
```

### 3. 📱 Render
1. Підключити GitHub репозиторій
2. Вибрати "Web Service"
3. Build Command: `npm install`
4. Start Command: `npm start`
5. Додати environment variables

### 4. 🔷 Heroku
```bash
# Встановити Heroku CLI
npm install -g heroku

# Створити додаток
heroku create discard-app

# Додати MongoDB addon
heroku addons:create mongolab

# Deploy
git push heroku main
```

### 5. 💻 VPS (Ubuntu/CentOS)
```bash
# На сервері:
# 1. Встановити Node.js
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# 2. Встановити MongoDB
sudo apt install mongodb

# 3. Встановити PM2
npm install -g pm2

# 4. Клонувати та запустити
git clone <your-repo>
cd discard-app
npm install --production
cp .env.example .env
# Налаштувати .env файл

# 5. Запустити з PM2
pm2 start server.js --name "discard-app"
pm2 startup
pm2 save
```

## 📋 Environment Variables

Створіть `.env` файл з наступними змінними:

```env
# Database
MONGODB_URI=your_mongodb_connection_string

# Security
JWT_SECRET=your_jwt_secret_min_64_chars
SESSION_SECRET=your_session_secret_min_64_chars

# Server
NODE_ENV=production
PORT=2804
FRONTEND_URL=https://yourdomain.com

# Optional
LOG_LEVEL=info
```

## ⚡ Швидкий старт для VPS

```bash
# 1. Підготовка сервера
sudo ufw allow 2804
sudo ufw enable

# 2. Deploy
git clone <your-repo>
cd discard-app
npm install --production

# 3. Налаштування
cp .env.example .env
nano .env  # Заповніть свої данні

# 4. Запуск
npm start
```

## 🔧 Налаштування Nginx (для VPS)

```nginx
server {
    listen 80;
    server_name yourdomain.com;
    
    location / {
        proxy_pass http://localhost:2804;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

## 📊 Моніторинг

Health check endpoint: `GET /api/health`

Відповідь:
```json
{
  "status": "ok",
  "uptime": 123.45,
  "memory": {
    "rss": "90MB",
    "heapTotal": "41MB",  
    "heapUsed": "39MB"
  },
  "timestamp": "2025-08-31T08:50:45.106Z"
}
```

## 🛠 Troubleshooting

### Помилка підключення до MongoDB:
```bash
# Перевірити з'єднання
node -e "console.log('Testing MongoDB:', process.env.MONGODB_URI)"
```

### Порт зайнятий:
```bash
# Знайти процес на порту 2804
lsof -i :2804
kill -9 <PID>
```

### Логи (якщо щось не працює):
```bash
tail -f logs/combined.log
tail -f logs/error.log
```