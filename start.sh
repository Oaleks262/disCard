#!/bin/bash

# disCard App Startup Script

echo "🚀 Запуск disCard App..."

# Перевірка Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js не встановлено. Встановіть Node.js версії 16 або вище."
    exit 1
fi

echo "✅ Node.js версія: $(node --version)"

# Перевірка залежностей
if [ ! -d "node_modules" ]; then
    echo "📦 Встановлення залежностей..."
    npm install --production
fi

# Перевірка .env файлу
if [ ! -f ".env" ]; then
    echo "⚙️  Створення .env файлу з прикладу..."
    cp .env.example .env
    echo "❗ Налаштуйте .env файл перед запуском!"
    echo "   Особливо: MONGODB_URI, JWT_SECRET, SESSION_SECRET"
    exit 1
fi

# Створення директорії логів
mkdir -p logs

# Запуск додатку
echo "🎯 Запуск додатку в production режимі..."
echo "🌐 Додаток буде доступний на http://localhost:2804"
echo "📊 Health check: http://localhost:2804/api/health"
echo ""
echo "Для зупинки натисніть Ctrl+C"
echo ""

NODE_ENV=production npm start