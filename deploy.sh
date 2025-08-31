#!/bin/bash

# disCard App Deployment Script

echo "🚀 Deploying disCard App..."

# Вибір методу деплою
echo "Оберіть спосіб деплою:"
echo "1) Vercel (рекомендовано)"
echo "2) Railway" 
echo "3) Render"
echo "4) VPS/Server"
read -p "Ваш вибір (1-4): " choice

case $choice in
    1)
        echo "📡 Deploying to Vercel..."
        if ! command -v vercel &> /dev/null; then
            echo "Встановлення Vercel CLI..."
            npm install -g vercel
        fi
        vercel
        ;;
    2)
        echo "🚂 Deploying to Railway..."
        if ! command -v railway &> /dev/null; then
            echo "Встановлення Railway CLI..."
            npm install -g @railway/cli
        fi
        railway login
        railway deploy
        ;;
    3)
        echo "🎨 Deploying to Render..."
        echo "1. Відкрийте https://render.com"
        echo "2. Підключіть GitHub репозиторій"
        echo "3. Вибрати Web Service"
        echo "4. Build: npm install"
        echo "5. Start: npm start"
        echo "6. Додайте environment variables"
        ;;
    4)
        echo "💻 VPS/Server Deployment..."
        echo "Команди для вашого сервера:"
        echo ""
        echo "# Встановлення Node.js"
        echo "curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -"
        echo "sudo apt-get install -y nodejs"
        echo ""
        echo "# Встановлення PM2"
        echo "npm install -g pm2"
        echo ""
        echo "# Deploy додатку"
        echo "git clone <your-repo>"
        echo "cd discard-app"
        echo "npm install --production"
        echo "cp .env.example .env"
        echo "# Налаштуйте .env файл!"
        echo "pm2 start server.js --name discard-app"
        ;;
    *)
        echo "❌ Невірний вибір"
        exit 1
        ;;
esac

echo "✅ Deployment завершено!"
echo "💡 Не забудьте налаштувати environment variables:"
echo "   - MONGODB_URI"
echo "   - JWT_SECRET" 
echo "   - SESSION_SECRET"