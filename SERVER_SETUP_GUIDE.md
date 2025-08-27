# 🚀 Повна інструкція: Налаштування HTTPS домена для disCard

## 📋 Що потрібно
- Купленний домен (наприклад: `myapp.com`)
- Сервер з IP: `78.27.236.157`
- Root доступ до сервера

---

## 1️⃣ Налаштування DNS записів

У панелі управління вашого домена створіть:

```
Тип    | Назва | Значення
-------|-------|----------
A      | @     | 78.27.236.157
A      | www   | 78.27.236.157
```

**⏰ Очікування:** DNS зміни поширюються до 24 годин

---

## 2️⃣ Підготовка сервера

### 2.1 Підключення до сервера
```bash
ssh root@78.27.236.157
```

### 2.2 Оновлення системи
```bash
apt update && apt upgrade -y
```

### 2.3 Встановлення необхідних пакетів
```bash
# Встановити Nginx
apt install nginx -y

# Встановити Certbot для SSL
apt install certbot python3-certbot-nginx -y

# Встановити Node.js (якщо ще не встановлено)
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
apt-get install -y nodejs

# Встановити PM2 глобально
npm install -g pm2
```

### 2.4 Налаштування файрволу
```bash
# Дозволити HTTP, HTTPS та SSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 22/tcp
ufw --force enable

# Перевірити статус
ufw status
```

---

## 3️⃣ Розгортання додатку

### 3.1 Створення директорії
```bash
mkdir -p /var/www/discard
cd /var/www/discard
```

### 3.2 Завантаження коду
Завантажте всі файли проекту в `/var/www/discard/`

### 3.3 Встановлення залежностей
```bash
cd /var/www/discard
npm install
```

### 3.4 Налаштування змінних середовища
```bash
nano .env
```

**Замініть `yourdomain.com` на ваш реальний домен:**
```env
PORT=2804
NODE_ENV=production
MONGODB_URI=mongodb+srv://oleksandrzvirich:aoII8cU4Nk1Gz8jV@cluster0.kxjo4hd.mongodb.net/
JWT_SECRET=09d8a738874b4553eb8a95c735b27d436919936727ec4ebd44441a4ca3fd282ef8f0425668680151a450c17f9d1f478a8b79ac5abec6684b0d08255a80321296

# Session security
SESSION_SECRET=secure-session-secret-key-change-in-production
COOKIE_SECURE=true
FRONTEND_URL=https://yourdomain.com
COOKIE_SAME_SITE=strict

# Rate limiting
RATE_LIMIT_WINDOW=900000
RATE_LIMIT_MAX=100

# Account security
MAX_LOGIN_ATTEMPTS=5
ACCOUNT_LOCK_TIME=7200000

# Password requirements
MIN_PASSWORD_LENGTH=8
REQUIRE_PASSWORD_COMPLEXITY=true
```

---

## 4️⃣ Конфігурація Nginx

### 4.1 Створення конфігурації
```bash
nano /etc/nginx/sites-available/discard
```

### 4.2 Додавання конфігурації (замініть `yourdomain.com`):
```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    
    # Дозволити Certbot для валідації
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
    
    # Тимчасове проксування до Node.js
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
        proxy_redirect off;
    }
}
```

### 4.3 Активація конфігурації
```bash
# Створити символічне посилання
ln -s /etc/nginx/sites-available/discard /etc/nginx/sites-enabled/

# Видалити стандартний сайт
rm -f /etc/nginx/sites-enabled/default

# Перевірити конфігурацію
nginx -t

# Перезапустити Nginx
systemctl restart nginx
systemctl enable nginx
```

---

## 5️⃣ Запуск додатку

### 5.1 Запуск через PM2
```bash
cd /var/www/discard
pm2 start server.js --name "discard-app"
pm2 startup
pm2 save
```

### 5.2 Перевірка роботи
```bash
# Перевірити статус PM2
pm2 status

# Перевірити логи
pm2 logs discard-app

# Перевірити що додаток відповідає
curl http://localhost:2804
```

---

## 6️⃣ Отримання SSL сертифікату

### 6.1 Перевірка доступності домена
```bash
# Перевірити що домен вказує на сервер
nslookup yourdomain.com
```

### 6.2 Отримання сертифікату
```bash
# Замініть yourdomain.com на ваш домен
certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

**Під час установки вам буде запропоновано:**
1. **Email:** Введіть ваш email
2. **Умови:** Введіть `A` (Agree)
3. **Новини:** Введіть `N` (No)
4. **Перенаправлення:** Оберіть `2` (Redirect HTTP to HTTPS)

### 6.3 Перевірка автооновлення
```bash
# Тестувати автооновлення
certbot renew --dry-run

# Перевірити таймер
systemctl status certbot.timer
```

---

## 7️⃣ Фінальна перевірка

### 7.1 Перевірити HTTPS
Відкрийте в браузері:
- `https://yourdomain.com` ✅
- `http://yourdomain.com` → має перенаправляти на HTTPS ✅

### 7.2 Перевірити функціональність
- Реєстрація користувача ✅
- Вхід в систему ✅
- Додавання карток ✅

### 7.3 Перевірити SSL рейтинг
Протестуйте на: https://www.ssllabs.com/ssltest/

---

## 8️⃣ Моніторинг та логи

### 8.1 Перевірка статусу сервісів
```bash
# Nginx
systemctl status nginx

# PM2
pm2 status

# SSL сертифікат
certbot certificates
```

### 8.2 Перегляд логів
```bash
# Логи Nginx
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log

# Логи додатку
pm2 logs discard-app

# Логи системи
journalctl -u nginx -f
```

---

## 9️⃣ Автоматизація та backup

### 9.1 Скрипт backup
```bash
nano /usr/local/bin/backup-discard.sh
```

```bash
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/var/backups/discard"
APP_DIR="/var/www/discard"

mkdir -p $BACKUP_DIR
tar -czf $BACKUP_DIR/discard_$DATE.tar.gz $APP_DIR
find $BACKUP_DIR -name "*.tar.gz" -mtime +7 -delete

echo "Backup completed: discard_$DATE.tar.gz"
```

```bash
# Зробити виконуваним
chmod +x /usr/local/bin/backup-discard.sh

# Додати до crontab (щодня о 3:00)
crontab -e
# Додати рядок:
0 3 * * * /usr/local/bin/backup-discard.sh
```

---

## 🔧 Корисні команди

### Перезапуск сервісів
```bash
# Перезапустити додаток
pm2 restart discard-app

# Перезапустити Nginx
systemctl restart nginx

# Перезапустити все
pm2 restart all && systemctl restart nginx
```

### Оновлення коду
```bash
cd /var/www/discard
# Завантажити нові файли
pm2 restart discard-app
```

### Відновлення SSL
```bash
# Якщо проблеми з SSL
certbot renew --force-renewal
systemctl restart nginx
```

---

## 🚨 Troubleshooting

### Проблема: Домен не резолвиться
```bash
# Перевірити DNS
nslookup yourdomain.com
dig yourdomain.com

# Очікати до 24 годин для поширення DNS
```

### Проблема: SSL не працює
```bash
# Перевірити сертифікат
certbot certificates

# Перезапустити Nginx
nginx -t
systemctl restart nginx
```

### Проблема: Додаток не запускається
```bash
# Перевірити логи
pm2 logs discard-app

# Перевірити порт
netstat -tlnp | grep :2804

# Перезапустити
pm2 restart discard-app
```

---

## ✅ Контрольний список

- [ ] DNS записи налаштовані
- [ ] Nginx встановлено та налаштовано  
- [ ] Додаток запущено через PM2
- [ ] SSL сертифікат отримано
- [ ] HTTPS працює
- [ ] HTTP перенаправляється на HTTPS
- [ ] Функціональність додатку працює
- [ ] Автооновлення SSL налаштовано
- [ ] Backup налаштовано

**🎉 Готово! Ваш додаток доступний за адресою https://yourdomain.com**