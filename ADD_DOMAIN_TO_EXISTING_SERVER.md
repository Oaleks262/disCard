# 🎯 Додавання discard.com.ua до існуючого сервера з HTTPS

## 1️⃣ Налаштування DNS для discard.com.ua

У панелі управління доменом `discard.com.ua` створіть:
```
Тип    | Назва | Значення
-------|-------|----------
A      | @     | 78.27.236.157  
A      | www   | 78.27.236.157
```

## 2️⃣ Завантаження додатку на сервер

### 2.1 Створити директорію
```bash
sudo mkdir -p /var/www/discard
cd /var/www/discard
```

### 2.2 Завантажити файли проекту
Скопіюйте всі файли проекту в `/var/www/discard/`

### 2.3 Встановити залежності
```bash
cd /var/www/discard
sudo npm install
```

### 2.4 Перевірити .env файл
```bash
nano /var/www/discard/.env
```
Переконайтеся що `FRONTEND_URL=https://discard.com.ua`

## 3️⃣ Створення Nginx конфігурації

### 3.1 Створити конфіг для discard.com.ua
```bash
sudo nano /etc/nginx/sites-available/discard.com.ua
```

### 3.2 Додати конфігурацію:
```nginx
# HTTP версія (тимчасово для отримання SSL)
server {
    listen 80;
    server_name discard.com.ua www.discard.com.ua;
    
    # Дозволити Certbot
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
    
    # Тимчасове проксування
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

### 3.3 Активувати конфігурацію
```bash
# Створити симлінк
sudo ln -s /etc/nginx/sites-available/discard.com.ua /etc/nginx/sites-enabled/

# Перевірити конфігурацію
sudo nginx -t

# Перезапустити Nginx
sudo systemctl reload nginx
```

## 4️⃣ Запуск додатку

### 4.1 Запустити через PM2
```bash
cd /var/www/discard
pm2 start server.js --name "discard-app"
pm2 save
```

### 4.2 Перевірити що працює
```bash
# Статус PM2
pm2 status

# Тест локально
curl http://localhost:2804

# Тест через домен (після поширення DNS)
curl http://discard.com.ua
```

## 5️⃣ Додати SSL сертифікат

### 5.1 Отримати SSL для нового домена
```bash
sudo certbot --nginx -d discard.com.ua -d www.discard.com.ua
```

### 5.2 Certbot автоматично оновить конфіг до:
```nginx
server {
    server_name discard.com.ua www.discard.com.ua;
    
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
        
        # Додаткові заголовки безпеки
        proxy_set_header X-Forwarded-Host $server_name;
        proxy_set_header X-NginX-Proxy true;
    }

    listen 443 ssl;
    ssl_certificate /etc/letsencrypt/live/discard.com.ua/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/discard.com.ua/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
}

server {
    if ($host = www.discard.com.ua) {
        return 301 https://$host$request_uri;
    }

    if ($host = discard.com.ua) {
        return 301 https://$host$request_uri;
    }

    listen 80;
    server_name discard.com.ua www.discard.com.ua;
    return 404;
}
```

## 6️⃣ Фінальна перевірка

### 6.1 Перевірити роботу
- ✅ https://discard.com.ua
- ✅ https://www.discard.com.ua  
- ✅ http://discard.com.ua → перенаправляє на HTTPS

### 6.2 Перевірити статуси
```bash
# Nginx
sudo systemctl status nginx

# PM2
pm2 status

# SSL сертифікати  
sudo certbot certificates
```

## 7️⃣ Корисні команди

### Керування додатком
```bash
# Перезапустити додаток
pm2 restart discard-app

# Дивитись логи
pm2 logs discard-app

# Зупинити
pm2 stop discard-app
```

### Керування Nginx
```bash
# Перезапустити
sudo systemctl reload nginx

# Перевірити конфігурацію
sudo nginx -t

# Дивитись логи
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log
```

### Оновлення коду
```bash
cd /var/www/discard
# Завантажити нові файли
pm2 restart discard-app
```

## 🚨 Troubleshooting

### Якщо домен не працює:
```bash
# Перевірити DNS
nslookup discard.com.ua

# Перевірити порт
sudo netstat -tlnp | grep :2804
```

### Якщо SSL не працює:
```bash
# Перезапустити Certbot
sudo certbot renew --dry-run
sudo systemctl reload nginx
```

### Якщо конфлікт портів:
```bash
# Змінити порт в .env на інший (наприклад 2805)
nano /var/www/discard/.env
# PORT=2805

# Оновити Nginx конфіг
sudo nano /etc/nginx/sites-available/discard.com.ua
# proxy_pass http://localhost:2805;

pm2 restart discard-app
sudo systemctl reload nginx
```

---

**🎉 Готово! discard.com.ua буде працювати разом з вашими існуючими сайтами на тому ж сервері!**