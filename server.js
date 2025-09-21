const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 2804;

// Trust proxy (for nginx/reverse proxy) - trust only first proxy
app.set('trust proxy', 1);

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 100,
  standardHeaders: true,
  legacyHeaders: false,
  // Skip successful requests
  skipSuccessfulRequests: true
});

const authLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 100,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false
});

app.use(limiter);
app.use('/api/auth', authLimiter);

// CORS
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));

// Body parser
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// App route - serve app.html for /app paths
app.get('/app', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'app.html'));
});

app.get('/app/*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'app.html'));
});

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/loyalty-cards', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Email configuration
const transporter = nodemailer.createTransport({
  service: 'gmail', // або інший сервіс
  auth: {
    user: process.env.EMAIL_USER || 'your-email@gmail.com',
    pass: process.env.EMAIL_PASS || 'your-app-password'
  }
});

// Helper function to generate 5-digit verification code
function generateVerificationCode() {
  return Math.floor(10000 + Math.random() * 90000).toString();
}

// Generate random password
function generateRandomPassword() {
  const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lowercase = 'abcdefghijklmnopqrstuvwxyz';
  const numbers = '0123456789';
  const symbols = '!@#$%^&*';
  
  // Ensure at least one character from each category
  let password = '';
  password += uppercase[Math.floor(Math.random() * uppercase.length)];
  password += lowercase[Math.floor(Math.random() * lowercase.length)];
  password += numbers[Math.floor(Math.random() * numbers.length)];
  password += symbols[Math.floor(Math.random() * symbols.length)];
  
  // Add remaining random characters
  const allChars = uppercase + lowercase + numbers + symbols;
  for (let i = password.length; i < 12; i++) {
    password += allChars[Math.floor(Math.random() * allChars.length)];
  }
  
  // Shuffle the password
  return password.split('').sort(() => Math.random() - 0.5).join('');
}

// Helper function to send verification email
async function sendVerificationEmail(email, code, userAgent = '', ipAddress = '') {
  const resetToken = jwt.sign({ email, action: 'reset' }, process.env.JWT_SECRET, { expiresIn: process.env.RESET_TOKEN_EXPIRES || '1h' });
  const resetUrl = `${process.env.BASE_URL}/reset-password?token=${resetToken}`;
  
  const mailOptions = {
    from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
    to: email,
    subject: `${process.env.COMPANY_NAME} - Код підтвердження входу`,
    html: `
      <div style="font-family: Inter, Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="text-align: center; margin-bottom: 30px;">
          <img src="${process.env.BASE_URL || 'https://discard.com.ua'}/logo.png" alt="${process.env.COMPANY_NAME}" style="height: 48px; margin-bottom: 10px; display: block; margin-left: auto; margin-right: auto;">
          <h1 style="color: #0066FF; margin: 0;">${process.env.COMPANY_NAME}</h1>
          <p style="color: #6C757D; margin: 5px 0;">${process.env.COMPANY_TAGLINE}</p>
        </div>
        
        <div style="background: #F8F9FA; border-radius: 12px; padding: 30px; text-align: center;">
          <h2 style="color: #1A1A1A; margin-bottom: 20px;">Код підтвердження входу</h2>
          <p style="color: #4A4A4A; margin-bottom: 30px;">Використайте цей код для входу в додаток:</p>
          
          <div style="background: white; border: 2px solid #0066FF; border-radius: 8px; padding: 20px; margin: 20px 0; display: inline-block;">
            <span style="font-size: 32px; font-weight: bold; color: #0066FF; letter-spacing: 5px;">${code}</span>
          </div>
          
          <p style="color: #6C757D; font-size: 14px; margin-top: 20px;">
            Код дійсний протягом 10 хвилин
          </p>
          
          ${userAgent ? `<div style="background: #FFF3CD; border: 1px solid #FFEAA7; border-radius: 8px; padding: 15px; margin: 20px 0; font-size: 13px; color: #856404;">
            <p style="margin: 0; font-weight: bold;">Інформація про вхід:</p>
            <p style="margin: 5px 0;">Пристрій: ${userAgent}</p>
            ${ipAddress ? `<p style="margin: 5px 0;">IP: ${ipAddress}</p>` : ''}
          </div>` : ''}
        </div>
        
        <div style="background: #FFF5F5; border: 1px solid #FEB2B2; border-radius: 8px; padding: 20px; margin: 20px 0;">
          <h3 style="color: #C53030; margin: 0 0 10px 0; font-size: 16px;">🔒 Це були не ви?</h3>
          <p style="color: #744210; margin-bottom: 15px; font-size: 14px;">
            Якщо ви не намагалися увійти в свій акаунт, негайно змініть пароль для безпеки.
          </p>
          <div style="text-align: center;">
            <a href="${resetUrl}" style="display: inline-block; background: #E53E3E; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; font-size: 14px;">
              Змінити пароль
            </a>
          </div>
        </div>
        
        <div style="text-align: center; margin-top: 30px; color: #6C757D; font-size: 12px;">
          <p>© 2024 ${process.env.COMPANY_NAME}. Всі права захищені.</p>
          <p style="margin-top: 10px;">
            <a href="mailto:${process.env.SUPPORT_EMAIL || process.env.EMAIL_FROM}" style="color: #0066FF;">Підтримка</a> | 
            <a href="${process.env.BASE_URL}" style="color: #0066FF;">${process.env.COMPANY_NAME}</a>
          </p>
        </div>
      </div>
    `
  };

  try {
    await transporter.sendMail(mailOptions);
    return true;
  } catch (error) {
    console.error('Email sending error:', error);
    return false;
  }
}

// Helper function to send new password email
async function sendNewPasswordEmail(email, newPassword, userAgent = '', ipAddress = '') {
  const mailOptions = {
    from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
    to: email,
    subject: `${process.env.COMPANY_NAME} - Новий пароль`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f8f9fa;">
        <div style="background-color: white; padding: 30px; border-radius: 8px; border: 1px solid #e9ecef;">
          <div style="text-align: center; margin-bottom: 30px;">
            <img src="${process.env.BASE_URL || 'https://discard.com.ua'}/logo.png" alt="${process.env.COMPANY_NAME}" style="height: 48px; margin-bottom: 10px; display: block; margin-left: auto; margin-right: auto;">
            <h1 style="color: #0066FF; margin: 0; font-size: 28px;">${process.env.COMPANY_NAME}</h1>
            <p style="color: #6c757d; margin: 5px 0 0 0; font-size: 14px;">${process.env.COMPANY_TAGLINE}</p>
          </div>
          
          <h2 style="color: #1a1a1a; margin-bottom: 20px;">Новий пароль згенеровано</h2>
          
          <p style="color: #4a4a4a; line-height: 1.6; margin-bottom: 20px;">
            Ми згенерували новий пароль для вашого акаунту ${process.env.COMPANY_NAME}.
          </p>
          
          <div style="background-color: #f8f9fa; border: 2px solid #0066FF; border-radius: 8px; padding: 20px; text-align: center; margin: 25px 0;">
            <p style="margin: 0 0 10px 0; color: #6c757d; font-size: 14px;">Ваш новий пароль:</p>
            <p style="font-size: 24px; font-weight: bold; color: #0066FF; margin: 0; font-family: 'Courier New', monospace; letter-spacing: 2px;">
              ${newPassword}
            </p>
          </div>
          
          <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 6px; padding: 15px; margin: 20px 0;">
            <p style="margin: 0; color: #856404; font-size: 14px;">
              <strong>Важливо:</strong> Після входу рекомендуємо змінити пароль на більш зручний для вас.
            </p>
          </div>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="${process.env.BASE_URL}/app" 
               style="background-color: #0066FF; color: white; text-decoration: none; padding: 12px 30px; border-radius: 6px; font-weight: bold; display: inline-block;">
              Увійти в додаток
            </a>
          </div>
          
          <div style="border-top: 1px solid #e9ecef; margin-top: 30px; padding-top: 20px;">
            <p style="color: #6c757d; font-size: 12px; margin: 0;">
              Цей пароль було згенеровано ${new Date().toLocaleString('uk-UA')}
              ${userAgent ? `<br>Пристрій: ${userAgent}` : ''}
              ${ipAddress ? `<br>IP адреса: ${ipAddress}` : ''}
            </p>
            
            <p style="color: #6c757d; font-size: 12px; margin: 15px 0 0 0;">
              Якщо ви не запитували новий пароль, зверніться до служби підтримки: 
              <a href="mailto:${process.env.ADMIN_EMAIL}" style="color: #0066FF;">${process.env.ADMIN_EMAIL}</a>
            </p>
          </div>
        </div>
      </div>
    `
  };

  try {
    await transporter.sendMail(mailOptions);
    return true;
  } catch (error) {
    console.error('Email sending error:', error);
    return false;
  }
}

// User Schema
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  language: {
    type: String,
    default: 'uk',
    enum: ['uk', 'en']
  },
  // Server-side encryption key for this user's cards
  encryptionKey: {
    type: String,
    required: false // Will be generated on first card creation
  },
  // Two-factor authentication fields
  verificationCode: {
    type: String,
    required: false
  },
  verificationCodeExpires: {
    type: Date,
    required: false
  },
  cards: [{
    name: {
      type: String,
      required: true,
      trim: true
    },
    code: {
      type: String,
      // Make code optional for encrypted cards
      required: function() {
        return !this.isEncrypted;
      },
      trim: true
    },
    codeType: {
      type: String,
      required: true,
      enum: ['barcode', 'qrcode']
    },
    color: {
      type: String,
      default: '#3b82f6',
      validate: {
        validator: function(v) {
          return /^#[0-9A-F]{6}$/i.test(v);
        },
        message: 'Color must be a valid hex color'
      }
    },
    // New fields for encryption support
    encryptedCode: {
      type: String,
      required: function() {
        return this.isEncrypted;
      }
    },
    isEncrypted: {
      type: Boolean,
      default: false
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }]
}, {
  timestamps: true
});

// Server-side encryption utilities
const crypto = require('crypto');

// Generate encryption key for user
function generateUserEncryptionKey() {
  return crypto.randomBytes(32).toString('base64');
}

// Encrypt card code
function encryptCardCode(code, encryptionKey) {
  try {
    const key = Buffer.from(encryptionKey, 'base64');
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    
    let encrypted = cipher.update(code, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    
    // Combine IV and encrypted data
    const result = Buffer.concat([iv, Buffer.from(encrypted, 'base64')]);
    return result.toString('base64');
  } catch (error) {
    console.error('Encryption error:', error);
    throw new Error('Failed to encrypt card code');
  }
}

// Decrypt card code
function decryptCardCode(encryptedCode, encryptionKey) {
  try {
    const key = Buffer.from(encryptionKey, 'base64');
    const data = Buffer.from(encryptedCode, 'base64');
    
    const iv = data.slice(0, 16);
    const encrypted = data.slice(16);
    
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encrypted, null, 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    console.error('Decryption error:', error);
    throw new Error('Failed to decrypt card code');
  }
}

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

// JWT middleware with automatic token refresh
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret-key');
    const user = await User.findById(decoded.userId).select('-password');
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    
    req.user = user;
    
    // Generate new token with extended expiry (30 days from now)
    const newToken = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET || 'fallback-secret-key',
      { expiresIn: '30d' }
    );
    
    // Add new token to response headers for client to update
    res.set('X-New-Token', newToken);
    
    next();
  } catch (error) {
    res.status(403).json({ error: 'Invalid token' });
  }
};

// Validation middleware
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

// Routes

// Register
app.post('/api/auth/register', [
  body('name').trim().isLength({ min: 2, max: 100 }).escape(),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6, max: 128 }),
  body('language').optional().isIn(['uk', 'en'])
], handleValidationErrors, async (req, res) => {
  try {
    const { name, email, password, language = 'uk' } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Create user
    const user = new User({
      name,
      email,
      password,
      language,
      cards: []
    });

    await user.save();

    // Generate token
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET || 'fallback-secret-key',
      { expiresIn: '30d' }
    );

    res.status(201).json({
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        language: user.language,
        createdAt: user.createdAt
      },
      token,
      cards: []
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login
app.post('/api/auth/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').exists()
], handleValidationErrors, async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isValidPassword = await user.comparePassword(password);
    if (!isValidPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Check if email is configured for 2FA
    const emailConfigured = process.env.EMAIL_USER && process.env.EMAIL_PASS;
    
    if (emailConfigured) {
      // Generate and save verification code
      const verificationCode = generateVerificationCode();
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

      user.verificationCode = verificationCode;
      user.verificationCodeExpires = expiresAt;
      await user.save();

      // Send verification email with device info
      const userAgent = req.get('User-Agent') || '';
      const ipAddress = req.ip || req.connection.remoteAddress || '';
      const emailSent = await sendVerificationEmail(email, verificationCode, userAgent, ipAddress);
      
      if (!emailSent) {
        console.error('Failed to send 2FA email, falling back to direct login');
        // Fall through to direct login instead of failing
      } else {
        return res.json({
          requiresVerification: true,
          message: 'Verification code sent to your email',
          email: email
        });
      }
    }

    // Direct login without 2FA (if email not configured or sending failed)
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET || 'fallback-secret-key',
      { expiresIn: '30d' }
    );

    // Return cards as they are - decryption will be handled on client side
    const cardsToReturn = user.cards;

    res.json({
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        language: user.language,
        createdAt: user.createdAt
      },
      token,
      cards: cardsToReturn
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Verify 2FA code
app.post('/api/auth/verify-code', [
  body('email').isEmail().normalizeEmail(),
  body('code').isLength({ min: 5, max: 5 }).isNumeric()
], handleValidationErrors, async (req, res) => {
  try {
    const { email, code } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid email' });
    }

    // Check if code exists and is not expired
    if (!user.verificationCode || !user.verificationCodeExpires) {
      return res.status(400).json({ error: 'No verification code found' });
    }

    if (new Date() > user.verificationCodeExpires) {
      return res.status(400).json({ error: 'Verification code expired' });
    }

    // Check if code matches
    if (user.verificationCode !== code) {
      return res.status(400).json({ error: 'Invalid verification code' });
    }

    // Clear verification code
    user.verificationCode = undefined;
    user.verificationCodeExpires = undefined;
    await user.save();

    // Generate token
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET || 'fallback-secret-key',
      { expiresIn: '30d' }
    );

    // Return cards as they are - decryption will be handled on client side
    const cardsToReturn = user.cards;

    res.json({
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        language: user.language,
        createdAt: user.createdAt
      },
      token,
      cards: cardsToReturn
    });
  } catch (error) {
    console.error('Verify code error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Resend verification code
app.post('/api/auth/resend-code', [
  body('email').isEmail().normalizeEmail()
], handleValidationErrors, async (req, res) => {
  try {
    const { email } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid email' });
    }

    // Generate new verification code
    const verificationCode = generateVerificationCode();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    user.verificationCode = verificationCode;
    user.verificationCodeExpires = expiresAt;
    await user.save();

    // Send verification email with device info
    const userAgent = req.get('User-Agent') || '';
    const ipAddress = req.ip || req.connection.remoteAddress || '';
    const emailSent = await sendVerificationEmail(email, verificationCode, userAgent, ipAddress);
    
    if (!emailSent) {
      return res.status(500).json({ error: 'Failed to send verification email' });
    }

    res.json({
      message: 'Verification code sent to your email'
    });
  } catch (error) {
    console.error('Resend code error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Forgot password endpoint - generate and send new password
app.post('/api/auth/forgot-password', [
  body('email').isEmail().withMessage('Please provide a valid email')
], handleValidationErrors, async (req, res) => {
  try {
    const { email } = req.body;
    
    // Find user by email
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(400).json({ error: 'Користувача з такою електронною поштою не знайдено' });
    }

    // Generate new password
    const newPassword = generateRandomPassword();
    
    // Hash new password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
    
    // Update user password
    await User.findByIdAndUpdate(user._id, { 
      password: hashedPassword 
    });

    // Send email with new password
    const userAgent = req.get('User-Agent') || '';
    const ipAddress = req.ip || req.connection.remoteAddress || '';
    
    const emailSent = await sendNewPasswordEmail(user.email, newPassword, userAgent, ipAddress);
    
    if (!emailSent) {
      return res.status(500).json({ error: 'Помилка надсилання електронної пошти' });
    }

    console.log(`New password generated and sent to: ${user.email}`);
    res.json({ 
      message: `Новий пароль згенеровано та надіслано на ${user.email}`,
      email: user.email 
    });

  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Reset password endpoint
app.post('/api/auth/reset-password', [
  body('token').notEmpty().withMessage('Token is required'),
  body('newPassword').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
], handleValidationErrors, async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    // Verify token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    if (decoded.action !== 'reset') {
      return res.status(400).json({ error: 'Invalid token type' });
    }

    // Find user
    const user = await User.findOne({ email: decoded.email });
    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }

    // Hash new password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update password
    user.password = hashedPassword;
    await user.save();

    console.log(`Password reset successful for user: ${user.email}`);
    res.json({ message: 'Password reset successful' });

  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Serve reset password page
app.get('/reset-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'reset-password.html'));
});

// Get current user with decrypted cards
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    
    // Decrypt cards for client display if user has encryption key
    let cardsToReturn = user.cards;
    if (user.encryptionKey && user.cards.length > 0) {
      cardsToReturn = user.cards.map(card => {
        if (card.isEncrypted && card.encryptedCode) {
          try {
            const decryptedCode = decryptCardCode(card.encryptedCode, user.encryptionKey);
            return {
              ...card.toObject(),
              code: decryptedCode,
              encryptedCode: undefined // Don't send encrypted data to client
            };
          } catch (error) {
            console.error(`Failed to decrypt card ${card.name} - migration issue:`, error.message);
            // For migration compatibility - if decryption fails, check if it needs re-encryption
            return {
              ...card.toObject(),
              code: '[Потрібна переміграція]',
              encryptedCode: undefined,
              needsRemigration: true
            };
          }
        }
        return card.toObject();
      });
    } else if (user.cards.length > 0) {
      // No encryption key but has cards - they need to be re-migrated
      cardsToReturn = user.cards.map(card => {
        if (card.isEncrypted && card.encryptedCode) {
          return {
            ...card.toObject(),
            code: '[Потрібна переміграція]',
            encryptedCode: undefined,
            needsRemigration: true
          };
        }
        return card.toObject();
      });
    }
    
    res.json({
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        language: user.language,
        createdAt: user.createdAt
      },
      cards: cardsToReturn
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update profile
app.put('/api/auth/profile', [
  body('name').optional().trim().isLength({ min: 2, max: 100 }).escape(),
  body('language').optional().isIn(['uk', 'en'])
], handleValidationErrors, authenticateToken, async (req, res) => {
  try {
    const { name, language } = req.body;
    const updateData = {};
    
    if (name) updateData.name = name;
    if (language) updateData.language = language;

    const user = await User.findByIdAndUpdate(
      req.user._id,
      updateData,
      { new: true }
    );

    res.json({
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        language: user.language
      }
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Change password
app.put('/api/auth/password', [
  body('currentPassword').exists(),
  body('newPassword').isLength({ min: 6, max: 128 })
], handleValidationErrors, authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    const user = await User.findById(req.user._id);
    const isValidPassword = await user.comparePassword(currentPassword);
    
    if (!isValidPassword) {
      return res.status(400).json({ error: 'Invalid current password' });
    }

    // Hash new password explicitly
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
    
    // Update password directly
    await User.findByIdAndUpdate(req.user._id, { 
      password: hashedPassword 
    });

    console.log(`Password changed successfully for user: ${user.email}`);
    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Add card with server-side encryption
app.post('/api/cards', [
  body('name').trim().isLength({ min: 1, max: 100 }).escape(),
  body('code').trim().isLength({ min: 1, max: 500 }),
  body('codeType').isIn(['barcode', 'qrcode']),
  body('color').optional().matches(/^#[0-9A-F]{6}$/i).withMessage('Color must be a valid hex color')
], handleValidationErrors, authenticateToken, async (req, res) => {
  try {
    const { name, code, codeType, color } = req.body;

    const user = await User.findById(req.user._id);
    
    // Generate encryption key for user if they don't have one
    if (!user.encryptionKey) {
      user.encryptionKey = generateUserEncryptionKey();
      console.log(`Generated new encryption key for user: ${user.email}`);
    }
    
    // Encrypt the card code on the server
    const encryptedCode = encryptCardCode(code, user.encryptionKey);
    
    const newCard = {
      name,
      codeType,
      color: color || '#3b82f6',
      encryptedCode,
      isEncrypted: true,
      createdAt: new Date()
    };

    user.cards.push(newCard);
    await user.save();

    // Return cards with decrypted codes for client display
    const cardsWithDecryptedCodes = user.cards.map(card => ({
      ...card.toObject(),
      code: card.isEncrypted ? decryptCardCode(card.encryptedCode, user.encryptionKey) : card.code,
      encryptedCode: undefined // Don't send encrypted data to client
    }));

    res.status(201).json({ cards: cardsWithDecryptedCodes });
  } catch (error) {
    console.error('Add card error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update card with server-side encryption
app.put('/api/cards/:id', [
  body('name').optional().trim().isLength({ min: 1, max: 100 }).escape(),
  body('code').optional().trim().isLength({ min: 1, max: 500 }),
  body('codeType').optional().isIn(['barcode', 'qrcode']),
  body('color').optional().matches(/^#[0-9A-F]{6}$/i).withMessage('Color must be a valid hex color')
], handleValidationErrors, authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, code, codeType, color } = req.body;

    const user = await User.findById(req.user._id);
    const card = user.cards.id(id);
    
    if (!card) {
      return res.status(404).json({ error: 'Card not found' });
    }

    if (name) card.name = name;
    if (codeType) card.codeType = codeType;
    if (color) card.color = color;
    
    // Handle code update with server-side encryption
    if (code !== undefined) {
      // Generate encryption key for user if they don't have one
      if (!user.encryptionKey) {
        user.encryptionKey = generateUserEncryptionKey();
      }
      
      // Encrypt the new code on the server
      card.encryptedCode = encryptCardCode(code, user.encryptionKey);
      card.isEncrypted = true;
      card.code = undefined; // Clear plain code
    }

    await user.save();
    
    // Return cards with decrypted codes for client display
    const cardsWithDecryptedCodes = user.cards.map(card => ({
      ...card.toObject(),
      code: card.isEncrypted ? decryptCardCode(card.encryptedCode, user.encryptionKey) : card.code,
      encryptedCode: undefined // Don't send encrypted data to client
    }));

    res.json({ cards: cardsWithDecryptedCodes });
  } catch (error) {
    console.error('Update card error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete card
app.delete('/api/cards/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const user = await User.findById(req.user._id);
    user.cards.pull({ _id: id });
    await user.save();

    // Return cards with decrypted codes for client display
    let cardsToReturn = user.cards;
    if (user.encryptionKey && user.cards.length > 0) {
      cardsToReturn = user.cards.map(card => ({
        ...card.toObject(),
        code: card.isEncrypted ? decryptCardCode(card.encryptedCode, user.encryptionKey) : card.code,
        encryptedCode: undefined // Don't send encrypted data to client
      }));
    }

    res.json({ cards: cardsToReturn });
  } catch (error) {
    console.error('Delete card error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`MongoDB connected to: ${process.env.MONGODB_URI || 'mongodb://localhost:27017/loyalty-cards'}`);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});