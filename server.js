const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const mongoSanitize = require('express-mongo-sanitize');
const zxcvbn = require('zxcvbn');
const winston = require('winston');
const expressWinston = require('express-winston');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 2804;

// Logging configuration
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'loyalty-cards' },
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

// Express logging middleware
app.use(expressWinston.logger({
  winstonInstance: logger,
  meta: true,
  msg: "HTTP {{req.method}} {{req.url}}",
  expressFormat: true,
  colorize: false,
  ignoreRoute: function (req, res) { return false; }
}));

// Trust proxy (важливо для HTTPS/rate limiting)
app.set('trust proxy', 1);

// Security middleware for production
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"],
      mediaSrc: ["'self'", "blob:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false,
  hsts: process.env.NODE_ENV === 'production' ? {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  } : false
}));

// MongoDB sanitization
app.use(mongoSanitize({
  replaceWith: '_'
}));

// Cookie parser
app.use(cookieParser());

// Session configuration  
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-session-secret',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost:27017/loyalty-cards'
  }),
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'strict'
  },
  name: 'sessionId' // Не розкривати що це Express
}));

// CORS configuration
app.use(cors({
  origin: process.env.NODE_ENV === 'production' ? 
    [process.env.FRONTEND_URL] : 
    ['http://localhost:2804', 'http://localhost:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']
}));

// Enhanced Rate limiting
const createRateLimit = (windowMs, max, message) => rateLimit({
  windowMs,
  max,
  message: { error: message },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn(`Rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({ error: message });
  }
});

// Different limits for different endpoints
app.use('/api/auth', createRateLimit(15 * 60 * 1000, 10, 'Занадто багато спроб входу')); // 10 per 15min for auth
app.use('/api/', createRateLimit(15 * 60 * 1000, 100, 'Занадто багато запитів')); // 100 per 15min for API
app.use(createRateLimit(15 * 60 * 1000, 200, 'Занадто багато запитів')); // 200 per 15min general

// Body parser middleware
app.use(express.json({ 
  limit: '1mb',
  verify: (req, res, buf) => {
    try {
      JSON.parse(buf);
    } catch (e) {
      logger.warn(`Invalid JSON from IP: ${req.ip}`);
      throw new Error('Invalid JSON');
    }
  }
}));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Serve static files with cache control
app.use(express.static(path.join(__dirname, 'public'), {
  etag: false,
  lastModified: false,
  setHeaders: (res, path) => {
    // Повністю відключаємо кешування для всіх файлів
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
}));

// MongoDB connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/loyalty-cards';
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

mongoose.connection.on('connected', () => {
  console.log('✅ MongoDB підключено');
});

mongoose.connection.on('error', (err) => {
  console.error('❌ Помилка MongoDB:', err);
});

// Optimized User Schema with embedded data
const userSchema = new mongoose.Schema({
  // Basic user info
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Невірний email']
  },
  name: {
    type: String,
    trim: true,
    maxlength: 50,
    default: function() {
      return this.email ? this.email.split('@')[0] : '';
    }
  },
  password: {
    type: String,
    required: true,
    minlength: 8
  },
  
  // Embedded loyalty cards (moved from separate collection)
  cards: [{
    name: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100
    },
    code: {
      type: String,
      required: true,
      trim: true
    },
    codeType: {
      type: String,
      enum: ['barcode', 'qr'],
      default: 'barcode'
    },
    category: {
      type: String,
      trim: true,
      maxlength: 50,
      default: 'Інше',
      enum: [
        'Супермаркети',
        'Аптеки', 
        'Заправки',
        'Ресторани',
        'Одяг',
        'Електроніка',
        'Краса',
        'Спорт',
        'Банки',
        'Транспорт',
        'Інше'
      ]
    },
    description: {
      type: String,
      trim: true,
      maxlength: 500
    },
    color: {
      type: String,
      match: /^#[0-9A-Fa-f]{6}$/,
      default: '#4F46E5'
    },
    createdAt: {
      type: Date,
      default: Date.now
    },
    updatedAt: {
      type: Date,
      default: Date.now
    }
  }],
  
  // Embedded friends list (simplified from separate collection)
  friends: [{
    friendId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true
    },
    friendName: String, // Denormalized for faster access
    friendEmail: String, // Denormalized for faster access
    status: {
      type: String,
      enum: ['pending_sent', 'pending_received', 'accepted', 'blocked'],
      default: 'pending_sent'
    },
    addedAt: {
      type: Date,
      default: Date.now
    },
    acceptedAt: Date
  }],
  
  // Security settings (consolidated)
  security: {
    loginAttempts: {
      type: Number,
      default: 0
    },
    lockUntil: Date,
    twoFactorSecret: {
      type: String,
      select: false
    },
    twoFactorEnabled: {
      type: Boolean,
      default: false
    },
    lastLogin: Date,
    lastIP: String,
    passwordChangedAt: {
      type: Date,
      default: Date.now
    },
    rememberTokens: [{
      token: {
        type: String,
        required: true
      },
      createdAt: {
        type: Date,
        default: Date.now
      },
      expiresAt: {
        type: Date,
        default: function() {
          return new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
        }
      },
      userAgent: String,
      ip: String
    }]
  },
  
  // User statistics (for better performance)
  stats: {
    totalCards: {
      type: Number,
      default: 0
    },
    totalShoppingLists: {
      type: Number,
      default: 0
    },
    totalFriends: {
      type: Number,
      default: 0
    }
  },
  
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Virtual for checking if account is locked
userSchema.virtual('isLocked').get(function() {
  return !!(this.security.lockUntil && this.security.lockUntil > Date.now());
});

// Instance methods for login attempts
userSchema.methods.incLoginAttempts = function() {
  const maxAttempts = 5;
  const lockTime = 2 * 60 * 60 * 1000; // 2 hours
  
  if (this.security.lockUntil && this.security.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: { 'security.lockUntil': 1 },
      $set: { 'security.loginAttempts': 1 }
    });
  }
  
  const updates = { $inc: { 'security.loginAttempts': 1 } };
  
  if (this.security.loginAttempts + 1 >= maxAttempts && !this.isLocked) {
    updates.$set = { 'security.lockUntil': Date.now() + lockTime };
  }
  
  return this.updateOne(updates);
};

userSchema.methods.resetLoginAttempts = function() {
  return this.updateOne({
    $unset: { 
      'security.loginAttempts': 1,
      'security.lockUntil': 1 
    }
  });
};

// Instance methods for cards management
userSchema.methods.addCard = function(cardData) {
  this.cards.push({
    ...cardData,
    createdAt: new Date(),
    updatedAt: new Date()
  });
  this.stats.totalCards = this.cards.length;
  this.updatedAt = new Date();
  return this.save();
};

userSchema.methods.removeCard = function(cardId) {
  this.cards.id(cardId).remove();
  this.stats.totalCards = this.cards.length;
  this.updatedAt = new Date();
  return this.save();
};

userSchema.methods.updateCard = function(cardId, updateData) {
  const card = this.cards.id(cardId);
  if (card) {
    Object.assign(card, updateData);
    card.updatedAt = new Date();
    this.updatedAt = new Date();
    return this.save();
  }
  throw new Error('Card not found');
};

// Instance methods for friends management
userSchema.methods.addFriend = function(friendId, friendName, friendEmail) {
  this.friends.push({
    friendId,
    friendName,
    friendEmail,
    status: 'pending_sent',
    addedAt: new Date()
  });
  return this.save();
};

userSchema.methods.acceptFriend = function(friendId) {
  const friendship = this.friends.find(f => f.friendId.toString() === friendId.toString());
  if (friendship) {
    friendship.status = 'accepted';
    friendship.acceptedAt = new Date();
    this.stats.totalFriends = this.friends.filter(f => f.status === 'accepted').length;
    this.updatedAt = new Date();
    return this.save();
  }
  throw new Error('Friend request not found');
};

// Pre-save middleware for automatic updates
userSchema.pre('save', function(next) {
  this.updatedAt = new Date();
  
  // Update statistics automatically
  this.stats.totalCards = this.cards.length;
  this.stats.totalFriends = this.friends.filter(f => f.status === 'accepted').length;
  
  // Handle card updates
  this.cards.forEach(card => {
    if (card.isModified() && !card.updatedAt) {
      card.updatedAt = new Date();
    }
  });
  
  next();
});

// Database indexes for performance
userSchema.index({ email: 1 });
userSchema.index({ 'cards.category': 1 });
userSchema.index({ 'cards.code': 1 });
userSchema.index({ 'friends.friendId': 1 });
userSchema.index({ 'friends.status': 1 });

// Optimized Shopping List Schema (kept separate for large data)
const shoppingListSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  description: {
    type: String,
    trim: true,
    maxlength: 500
  },
  items: [{
    name: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100
    },
    quantity: {
      type: String,
      default: '1',
      trim: true,
      maxlength: 20
    },
    category: {
      type: String,
      trim: true,
      maxlength: 50,
      enum: [
        'М\'ясо і риба',
        'Молочні продукти',
        'Фрукти і овочі',
        'Хліб і випічка',
        'Крупи і макарони',
        'Напої',
        'Побутова хімія',
        'Особиста гігієна',
        'Інше'
      ],
      default: 'Інше'
    },
    completed: {
      type: Boolean,
      default: false
    },
    price: {
      type: Number,
      min: 0
    },
    notes: {
      type: String,
      trim: true,
      maxlength: 200
    },
    addedAt: {
      type: Date,
      default: Date.now
    }
  }],
  totalBudget: {
    type: Number,
    min: 0
  },
  color: {
    type: String,
    match: /^#[0-9A-Fa-f]{6}$/,
    default: '#10B981'
  },
  shared: {
    type: Boolean,
    default: false
  },
  sharedWith: [{
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    userName: String, // Denormalized for performance
    permission: {
      type: String,
      enum: ['view', 'edit'],
      default: 'view'
    }
  }],
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Shopping list middleware and methods
shoppingListSchema.pre('save', function(next) {
  this.updatedAt = new Date();
  next();
});

shoppingListSchema.methods.addItem = function(itemData) {
  this.items.push({
    ...itemData,
    addedAt: new Date()
  });
  return this.save();
};

shoppingListSchema.methods.updateItem = function(itemId, updateData) {
  const item = this.items.id(itemId);
  if (item) {
    Object.assign(item, updateData);
    return this.save();
  }
  throw new Error('Item not found');
};

// Model definitions
const User = mongoose.model('User', userSchema);
const ShoppingList = mongoose.model('ShoppingList', shoppingListSchema);

// Enhanced Auth middleware
const authenticateToken = async (req, res, next) => {
  try {
    let token;
    let user = null;
    
    // Check for token in cookies first (more secure), then Authorization header
    if (req.cookies.token) {
      token = req.cookies.token;
    } else {
      const authHeader = req.headers['authorization'];
      token = authHeader && authHeader.split(' ')[1];
    }

    // Try to verify JWT token first
    if (token) {
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback-secret');
        user = await User.findById(decoded.userId).select('-password -twoFactorSecret');
        
        if (user) {
          // Check if account is locked
          if (user.isLocked) {
            logger.warn(`Locked account attempted access: ${user.email}`);
            return res.status(423).json({ error: 'Акаунт заблокований через підозрілу активність' });
          }

          // Check if password was changed after token was issued
          const tokenIssuedAt = new Date(decoded.iat * 1000);
          if (user.passwordChangedAt && user.passwordChangedAt > tokenIssuedAt) {
            logger.warn(`Token invalid due to password change: ${user.email}`);
            user = null; // Force remember token check
          }
        } else {
          logger.warn(`Invalid user ID in token: ${decoded.userId}`);
        }
      } catch (jwtError) {
        logger.info(`JWT verification failed: ${jwtError.message}`);
        // JWT invalid, try remember token
      }
    }

    // If no valid JWT token, try remember token
    if (!user && req.cookies.remember_token) {
      const rememberToken = req.cookies.remember_token;
      
      // Find user with matching remember token
      user = await User.findOne({
        'security.rememberTokens.token': rememberToken,
        'security.rememberTokens.expiresAt': { $gt: new Date() }
      }).select('-password -security.twoFactorSecret');

      if (user) {
        // Check if account is locked
        if (user.isLocked) {
          logger.warn(`Locked account attempted access via remember token: ${user.email}`);
          return res.status(423).json({ error: 'Акаунт заблокований через підозрілу активність' });
        }

        // Generate new JWT token
        const newToken = jwt.sign(
          { 
            userId: user._id,
            iat: Math.floor(Date.now() / 1000),
            type: 'access',
            remember: true
          },
          process.env.JWT_SECRET || 'fallback-secret',
          { expiresIn: '1h' }
        );

        // Set new JWT cookie
        res.cookie('token', newToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 60 * 60 * 1000 // 1 hour
        });

        logger.info(`User authenticated via remember token: ${user.email}`);
      }
    }

    if (!user) {
      return res.status(401).json({ error: 'Токен доступу відсутній або недійсний' });
    }

    req.user = user;
    next();
  } catch (error) {
    logger.error(`Auth middleware error: ${error.message}`);
    return res.status(500).json({ error: 'Помилка автентифікації' });
  }
};

// Password strength validation
const validatePasswordStrength = (password) => {
  const minLength = parseInt(process.env.MIN_PASSWORD_LENGTH) || 8;
  const requireComplexity = process.env.REQUIRE_PASSWORD_COMPLEXITY === 'true';
  
  if (password.length < minLength) {
    return { valid: false, message: `Пароль повинен містити мінімум ${minLength} символів` };
  }
  
  if (requireComplexity) {
    const result = zxcvbn(password);
    if (result.score < 2) { // Score 0-4, we require at least 2
      return { 
        valid: false, 
        message: 'Пароль занадто слабкий. Використовуйте комбінацію букв, цифр та спеціальних символів',
        suggestions: result.feedback.suggestions
      };
    }
  }
  
  return { valid: true };
};

// Enhanced input sanitization
const sanitizeInput = (input) => {
  if (typeof input === 'string') {
    return validator.escape(input.trim());
  }
  return input;
};

// Security headers middleware
const securityHeaders = (req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
};

app.use(securityHeaders);

// Threat Detection Middleware
const threatDetection = {
  // Track suspicious IPs
  suspiciousIPs: new Map(),
  
  // Detect rapid requests from same IP
  detectRapidRequests: (ip) => {
    const now = Date.now();
    const requests = threatDetection.suspiciousIPs.get(ip) || [];
    
    // Clean old requests (older than 1 minute)
    const recentRequests = requests.filter(time => now - time < 60000);
    
    // Add current request
    recentRequests.push(now);
    threatDetection.suspiciousIPs.set(ip, recentRequests);
    
    // If more than 20 requests in 1 minute, mark as suspicious
    if (recentRequests.length > 20) {
      logger.warn(`Rapid requests detected from IP: ${ip}, count: ${recentRequests.length}`);
      return true;
    }
    
    return false;
  },
  
  // Check geolocation anomaly (temporarily disabled)
  checkLocationAnomaly: (user, currentIP) => {
    // Temporarily disabled due to geoip-lite package issue
    // TODO: Re-enable after package is properly installed
    return false;
  }
};

// Apply threat detection to auth routes
app.use('/api/auth', (req, res, next) => {
  const clientIP = req.ip;
  
  // Check for rapid requests
  if (threatDetection.detectRapidRequests(clientIP)) {
    return res.status(429).json({ 
      error: 'Підозріла активність виявлена. Спробуйте пізніше.' 
    });
  }
  
  next();
});

// Prometheus metrics disabled - install prom-client to enable

// Auth Routes

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    const clientIP = req.ip;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ error: 'Email та пароль обов\'язкові' });
    }

    const cleanEmail = sanitizeInput(email);
    if (!validator.isEmail(cleanEmail)) {
      return res.status(400).json({ error: 'Невірний формат email' });
    }

    // Validate password strength
    const passwordValidation = validatePasswordStrength(password);
    if (!passwordValidation.valid) {
      return res.status(400).json({ 
        error: passwordValidation.message,
        suggestions: passwordValidation.suggestions 
      });
    }

    // Check if user exists
    const existingUser = await User.findOne({ email: cleanEmail });
    if (existingUser) {
      logger.warn(`Registration attempt with existing email: ${cleanEmail} from IP: ${clientIP}`);
      // Metrics disabled
      return res.status(400).json({ error: 'Користувач з таким email вже існує' });
    }

    // Hash password with higher salt rounds
    const saltRounds = 14;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user
    const user = new User({
      email: cleanEmail,
      password: hashedPassword,
      lastIP: clientIP
    });

    await user.save();
    logger.info(`New user registered: ${cleanEmail} from IP: ${clientIP}`);
    
    // Prometheus metrics
    // Metrics disabled

    // Generate JWT with shorter expiration
    const token = jwt.sign(
      { 
        userId: user._id,
        iat: Math.floor(Date.now() / 1000),
        type: 'access'
      },
      process.env.JWT_SECRET || 'fallback-secret',
      { expiresIn: '1h' } // Shorter expiration for better security
    );

    // Set secure cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 60 * 60 * 1000 // 1 hour
    });

    res.status(201).json({
      message: 'Користувач успішно зареєстрований',
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        createdAt: user.createdAt,
        twoFactorEnabled: user.twoFactorEnabled
      }
    });

  } catch (error) {
    logger.error('Registration error:', { error: error.message, stack: error.stack });
    
    // Don't expose internal errors
    if (error.code === 11000) {
      return res.status(400).json({ error: 'Користувач з таким email вже існує' });
    }
    
    res.status(500).json({ error: 'Помилка сервера' });
  }
});

// Login with account lockout
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password, rememberMe = false } = req.body;
    const clientIP = req.ip;
    const userAgent = req.get('User-Agent');

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ error: 'Email та пароль обов\'язкові' });
    }

    const cleanEmail = sanitizeInput(email);
    if (!validator.isEmail(cleanEmail)) {
      return res.status(400).json({ error: 'Невірний формат email' });
    }

    // Find user (include login attempt fields)
    const user = await User.findOne({ email: cleanEmail });
    if (!user) {
      logger.warn(`Login attempt with non-existent email: ${cleanEmail} from IP: ${clientIP}`);
      // Metrics disabled
      return res.status(401).json({ error: 'Невірний email або пароль' });
    }

    // Check if account is locked
    if (user.isLocked) {
      logger.warn(`Login attempt on locked account: ${cleanEmail} from IP: ${clientIP}`);
      // Metrics disabled
      return res.status(423).json({ 
        error: 'Акаунт тимчасово заблокований через підозрілу активність. Спробуйте пізніше.' 
      });
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      // Increment login attempts
      await user.incLoginAttempts();
      logger.warn(`Failed login attempt for: ${cleanEmail} from IP: ${clientIP}`);
      
      return res.status(401).json({ error: 'Невірний email або пароль' });
    }

    // Successful login - reset attempts and update user
    if (user.security.loginAttempts > 0) {
      await user.resetLoginAttempts();
    }
    
    await user.updateOne({
      $set: {
        lastLogin: new Date(),
        lastIP: clientIP
      }
    });

    logger.info(`Successful login: ${cleanEmail} from IP: ${clientIP}, Remember: ${rememberMe}`);

    // Determine token expiration based on remember me
    const tokenExpiry = rememberMe ? '30d' : '1h';
    const cookieMaxAge = rememberMe ? 30 * 24 * 60 * 60 * 1000 : 60 * 60 * 1000; // 30 days or 1 hour

    // Generate JWT
    const token = jwt.sign(
      { 
        userId: user._id,
        iat: Math.floor(Date.now() / 1000),
        type: 'access',
        remember: rememberMe
      },
      process.env.JWT_SECRET || 'fallback-secret',
      { expiresIn: tokenExpiry }
    );

    // Generate remember token if needed
    let rememberToken = null;
    if (rememberMe) {
      rememberToken = require('crypto').randomBytes(64).toString('hex');
      
      // Ensure security.rememberTokens array exists
      if (!user.security.rememberTokens) {
        user.security.rememberTokens = [];
      }

      // Clean up old remember tokens (keep only last 5)
      if (user.security.rememberTokens.length >= 5) {
        user.security.rememberTokens = user.security.rememberTokens
          .sort((a, b) => b.createdAt - a.createdAt)
          .slice(0, 4);
      }

      // Add new remember token
      user.security.rememberTokens.push({
        token: rememberToken,
        userAgent: userAgent || 'Unknown',
        ip: clientIP,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days
      });

      await user.save();
    }

    // Set secure cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: cookieMaxAge
    });

    // Set remember token cookie if needed
    if (rememberToken) {
      res.cookie('remember_token', rememberToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
      });
    }

    res.json({
      message: 'Успішний вхід',
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        lastLogin: user.lastLogin,
        createdAt: user.createdAt,
        twoFactorEnabled: user.twoFactorEnabled
      }
    });

  } catch (error) {
    logger.error('Login error:', { error: error.message, stack: error.stack });
    res.status(500).json({ error: 'Помилка сервера' });
  }
});

// Logout route
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    const { logoutAll = false } = req.body;
    const rememberTokenFromCookie = req.cookies.remember_token;

    // If logout from all devices, clear all remember tokens
    if (logoutAll) {
      await User.findByIdAndUpdate(req.user._id, {
        $set: { 'security.rememberTokens': [] }
      });
    } else if (rememberTokenFromCookie) {
      // Remove only current remember token
      await User.findByIdAndUpdate(req.user._id, {
        $pull: { 'security.rememberTokens': { token: rememberTokenFromCookie } }
      });
    }

    // Clear cookies
    res.clearCookie('token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    res.clearCookie('remember_token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });

    logger.info(`User logged out: ${req.user.email}, All devices: ${logoutAll}`);
    res.json({ 
      success: true,
      message: logoutAll ? 'Вихід з усіх пристроїв успішний' : 'Успішний вихід'
    });
  } catch (error) {
    logger.error('Logout error:', error.message);
    res.status(500).json({ error: 'Помилка сервера' });
  }
});

// 2FA Routes

// Setup 2FA - generate secret and QR code
app.post('/api/auth/2fa/setup', authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    
    if (user.twoFactorEnabled) {
      return res.status(400).json({ error: '2FA вже увімкнена для цього акаунту' });
    }
    
    // Generate secret
    const secret = speakeasy.generateSecret({
      name: `Loyalty Cards (${user.email})`,
      issuer: 'Loyalty Cards App',
      length: 32
    });
    
    // Store temporary secret in session (not saved to DB until verified)
    req.session.tempTwoFactorSecret = secret.base32;
    
    // Generate QR code
    const qrCodeDataUrl = await QRCode.toDataURL(secret.otpauth_url);
    
    logger.info(`2FA setup initiated for user: ${user.email}`);
    
    res.json({
      message: '2FA налаштування розпочато',
      qrCode: qrCodeDataUrl,
      secret: secret.base32,
      manualEntryKey: secret.base32
    });
    
  } catch (error) {
    logger.error('2FA setup error:', { error: error.message, userId: req.user.id });
    res.status(500).json({ error: 'Помилка налаштування 2FA' });
  }
});

// Verify and enable 2FA
app.post('/api/auth/2fa/verify', authenticateToken, async (req, res) => {
  try {
    const { token } = req.body;
    const user = req.user;
    
    if (!token) {
      return res.status(400).json({ error: 'Код підтвердження обов\'язковий' });
    }
    
    if (!req.session.tempTwoFactorSecret) {
      return res.status(400).json({ error: 'Спочатку розпочніть налаштування 2FA' });
    }
    
    // Verify the token
    const verified = speakeasy.totp.verify({
      secret: req.session.tempTwoFactorSecret,
      encoding: 'base32',
      token: token,
      window: 2
    });
    
    if (!verified) {
      logger.warn(`Invalid 2FA verification attempt: ${user.email}`);
      return res.status(400).json({ error: 'Невірний код підтвердження' });
    }
    
    // Save secret to user account and enable 2FA
    await User.findByIdAndUpdate(user.id, {
      twoFactorSecret: req.session.tempTwoFactorSecret,
      twoFactorEnabled: true
    });
    
    // Clear temporary secret from session
    delete req.session.tempTwoFactorSecret;
    
    logger.info(`2FA enabled for user: ${user.email}`);
    
    res.json({ 
      message: '2FA успішно увімкнена!',
      twoFactorEnabled: true 
    });
    
  } catch (error) {
    logger.error('2FA verification error:', { error: error.message, userId: req.user.id });
    res.status(500).json({ error: 'Помилка підтвердження 2FA' });
  }
});

// Disable 2FA
app.post('/api/auth/2fa/disable', authenticateToken, async (req, res) => {
  try {
    const { password, token } = req.body;
    const user = await User.findById(req.user.id).select('+twoFactorSecret');
    
    if (!password || !token) {
      return res.status(400).json({ error: 'Пароль та код 2FA обов\'язкові' });
    }
    
    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      logger.warn(`Invalid password for 2FA disable: ${user.email}`);
      return res.status(401).json({ error: 'Невірний пароль' });
    }
    
    // Verify 2FA token
    if (user.twoFactorEnabled && user.twoFactorSecret) {
      const verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: token,
        window: 2
      });
      
      if (!verified) {
        logger.warn(`Invalid 2FA token for disable: ${user.email}`);
        return res.status(400).json({ error: 'Невірний код 2FA' });
      }
    }
    
    // Disable 2FA
    await User.findByIdAndUpdate(user.id, {
      $unset: { twoFactorSecret: 1 },
      twoFactorEnabled: false
    });
    
    logger.info(`2FA disabled for user: ${user.email}`);
    
    res.json({ 
      message: '2FA вимкнена',
      twoFactorEnabled: false 
    });
    
  } catch (error) {
    logger.error('2FA disable error:', { error: error.message, userId: req.user.id });
    res.status(500).json({ error: 'Помилка вимкнення 2FA' });
  }
});

// Enhanced login with 2FA support
app.post('/api/auth/login-2fa', async (req, res) => {
  try {
    const { email, password, twoFactorToken } = req.body;
    const clientIP = req.ip;
    const userAgent = req.get('User-Agent');
    
    // Basic validation
    if (!email || !password) {
      return res.status(400).json({ error: 'Email та пароль обов\'язкові' });
    }
    
    const cleanEmail = sanitizeInput(email);
    if (!validator.isEmail(cleanEmail)) {
      return res.status(400).json({ error: 'Невірний формат email' });
    }
    
    // Find user with 2FA fields
    const user = await User.findOne({ email: cleanEmail }).select('+twoFactorSecret');
    if (!user) {
      logger.warn(`Login attempt with non-existent email: ${cleanEmail} from IP: ${clientIP}`);
      return res.status(401).json({ error: 'Невірний email або пароль' });
    }
    
    // Check if account is locked
    if (user.isLocked) {
      logger.warn(`Login attempt on locked account: ${cleanEmail} from IP: ${clientIP}`);
      return res.status(423).json({ 
        error: 'Акаунт тимчасово заблокований через підозрілу активність. Спробуйте пізніше.' 
      });
    }
    
    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      await user.incLoginAttempts();
      logger.warn(`Failed login attempt for: ${cleanEmail} from IP: ${clientIP}`);
      return res.status(401).json({ error: 'Невірний email або пароль' });
    }
    
    // Check if 2FA is enabled
    if (user.twoFactorEnabled && user.twoFactorSecret) {
      if (!twoFactorToken) {
        return res.status(200).json({ 
          requires2FA: true,
          message: 'Введіть код з додатку аутентифікатора' 
        });
      }
      
      // Verify 2FA token
      const verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: twoFactorToken,
        window: 2
      });
      
      if (!verified) {
        await user.incLoginAttempts();
        logger.warn(`Invalid 2FA token for login: ${cleanEmail} from IP: ${clientIP}`);
        return res.status(401).json({ error: 'Невірний код 2FA' });
      }
    }
    
    // Successful login
    if (user.security.loginAttempts > 0) {
      await user.resetLoginAttempts();
    }
    
    await user.updateOne({
      $set: {
        lastLogin: new Date(),
        lastIP: clientIP
      }
    });
    
    logger.info(`Successful ${user.twoFactorEnabled ? '2FA ' : ''}login: ${cleanEmail} from IP: ${clientIP}`);
    
    // Generate JWT
    const token = jwt.sign(
      { 
        userId: user._id,
        iat: Math.floor(Date.now() / 1000),
        type: 'access'
      },
      process.env.JWT_SECRET || 'fallback-secret',
      { expiresIn: '1h' }
    );
    
    // Set secure cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 60 * 60 * 1000
    });
    
    res.json({
      message: 'Успішний вхід',
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        lastLogin: user.lastLogin,
        createdAt: user.createdAt,
        twoFactorEnabled: user.twoFactorEnabled
      }
    });
    
  } catch (error) {
    logger.error('2FA Login error:', { error: error.message });
    res.status(500).json({ error: 'Помилка сервера' });
  }
});

// User Profile Routes

// Update user name
app.put('/api/user/update-name', authenticateToken, async (req, res) => {
  try {
    const { name } = req.body;
    
    if (!name || name.trim().length === 0) {
      return res.status(400).json({ error: 'Ім\'я не може бути порожнім' });
    }
    
    if (name.length > 50) {
      return res.status(400).json({ error: 'Ім\'я занадто довге (максимум 50 символів)' });
    }
    
    const sanitizedName = sanitizeInput(name);
    
    // Update user name
    const updatedUser = await User.findByIdAndUpdate(
      req.user._id,
      { name: sanitizedName },
      { new: true, runValidators: true }
    ).select('-password -twoFactorSecret');
    
    if (!updatedUser) {
      return res.status(404).json({ error: 'Користувач не знайдений' });
    }
    
    logger.info(`User name updated: ${req.user.email} -> ${sanitizedName}`);
    
    res.json({
      success: true,
      message: 'Ім\'я успішно оновлено',
      user: {
        id: updatedUser._id,
        email: updatedUser.email,
        name: updatedUser.name,
        createdAt: updatedUser.createdAt,
        twoFactorEnabled: updatedUser.twoFactorEnabled
      }
    });
    
  } catch (error) {
    logger.error('Update name error:', { error: error.message, userId: req.user._id });
    res.status(500).json({ error: 'Помилка оновлення імені' });
  }
});

// Update user password
app.put('/api/user/update-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Поточний та новий пароль обов\'язкові' });
    }
    
    // Get user with password field
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ error: 'Користувач не знайдений' });
    }
    
    // Verify current password
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isCurrentPasswordValid) {
      logger.warn(`Invalid current password for password change: ${user.email}`);
      return res.status(401).json({ error: 'Поточний пароль невірний' });
    }
    
    // Validate new password strength
    const passwordValidation = validatePasswordStrength(newPassword);
    if (!passwordValidation.valid) {
      return res.status(400).json({ 
        error: passwordValidation.message,
        suggestions: passwordValidation.suggestions 
      });
    }
    
    // Check if new password is different from current
    const isSamePassword = await bcrypt.compare(newPassword, user.password);
    if (isSamePassword) {
      return res.status(400).json({ error: 'Новий пароль повинен відрізнятися від поточного' });
    }
    
    // Hash new password
    const saltRounds = 14;
    const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);
    
    // Update password and passwordChangedAt
    await User.findByIdAndUpdate(user._id, {
      password: hashedNewPassword,
      'security.passwordChangedAt': new Date(),
      // Clear all remember tokens for security
      'security.rememberTokens': []
    });
    
    logger.info(`Password updated for user: ${user.email}`);
    
    // Clear all cookies to force re-login
    res.clearCookie('token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });
    
    res.clearCookie('remember_token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict'
    });
    
    res.json({
      success: true,
      message: 'Пароль успішно оновлено. Будь ласка, увійдіть знову.',
      requiresReLogin: true
    });
    
  } catch (error) {
    logger.error('Update password error:', { error: error.message, userId: req.user._id });
    res.status(500).json({ error: 'Помилка оновлення пароля' });
  }
});

// Check authentication status
app.get('/api/auth/check', authenticateToken, async (req, res) => {
  try {
    res.json({
      success: true,
      authenticated: true,
      user: {
        id: req.user._id,
        email: req.user.email,
        name: req.user.name,
        twoFactorEnabled: req.user.twoFactorEnabled
      }
    });
  } catch (error) {
    logger.error('Auth check error:', { error: error.message });
    res.status(500).json({ error: 'Помилка перевірки автентифікації' });
  }
});

// Get user profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .select('-password -security.twoFactorSecret -security.rememberTokens');
    
    if (!user) {
      return res.status(404).json({ error: 'Користувач не знайдений' });
    }
    
    // Get user statistics from embedded data and separate collection
    const cardCount = user.cards.length;
    const shoppingListCount = await ShoppingList.countDocuments({ userId: user._id });
    
    // Calculate account age in days
    const accountAge = Math.floor((Date.now() - user.createdAt) / (1000 * 60 * 60 * 24));
    
    res.json({
      success: true,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin,
        twoFactorEnabled: user.twoFactorEnabled,
        statistics: {
          cardCount,
          shoppingListCount,
          accountAge
        }
      }
    });
    
  } catch (error) {
    logger.error('Get profile error:', { error: error.message, userId: req.user._id });
    res.status(500).json({ error: 'Помилка завантаження профілю' });
  }
});

// Cards Routes

// Create card
app.post('/api/cards', authenticateToken, async (req, res) => {
  try {
    const { name, code, codeType, category, description, color } = req.body;

    // Validate input
    if (!name || !code) {
      return res.status(400).json({ error: 'Назва та код картки обов\'язкові' });
    }

    if (name.length > 100) {
      return res.status(400).json({ error: 'Назва картки занадто довга' });
    }

    if (!['barcode', 'qr'].includes(codeType)) {
      return res.status(400).json({ error: 'Невірний тип коду' });
    }

    // Validate optional fields
    const validCategories = [
      'Супермаркети', 'Аптеки', 'Заправки', 'Ресторани', 'Одяг',
      'Електроніка', 'Краса', 'Спорт', 'Банки', 'Транспорт', 'Інше'
    ];

    if (category && !validCategories.includes(category)) {
      return res.status(400).json({ error: 'Невірна категорія картки' });
    }

    if (description && description.length > 500) {
      return res.status(400).json({ error: 'Опис картки занадто довгий' });
    }

    if (color && !/^#[0-9A-Fa-f]{6}$/.test(color)) {
      return res.status(400).json({ error: 'Невірний формат кольору' });
    }

    // Add card to user's embedded cards array
    const newCard = {
      name: sanitizeInput(name),
      code: sanitizeInput(code),
      codeType: codeType || 'barcode',
      category: category || 'Інше',
      description: description ? sanitizeInput(description) : undefined,
      color: color || '#4F46E5'
    };

    await req.user.addCard(newCard);

    res.status(201).json({
      success: true,
      message: 'Картка успішно створена',
      card
    });

  } catch (error) {
    console.error('Create card error:', error);
    res.status(500).json({ success: false, error: 'Помилка при створенні картки' });
  }
});

// Delete card
app.delete('/api/cards/:id', authenticateToken, async (req, res) => {
  try {
    const cardId = req.params.id;

    if (!mongoose.Types.ObjectId.isValid(cardId)) {
      return res.status(400).json({ error: 'Невірний ID картки' });
    }

    const user = await User.findById(req.user._id);
    const card = user.cards.id(cardId);
    
    if (!card) {
      return res.status(404).json({ error: 'Картка не знайдена' });
    }
    
    await user.removeCard(cardId);

    res.json({ message: 'Картка успішно видалена' });

  } catch (error) {
    console.error('Delete card error:', error);
    res.status(500).json({ error: 'Помилка при видаленні картки' });
  }
});

// Update card
app.put('/api/cards/:id', authenticateToken, async (req, res) => {
  try {
    const cardId = req.params.id;
    const { name, code, codeType, category, description, color } = req.body;

    if (!mongoose.Types.ObjectId.isValid(cardId)) {
      return res.status(400).json({ error: 'Невірний ID картки' });
    }

    // Validate input
    if (!name || !code) {
      return res.status(400).json({ error: 'Назва та код картки обов\'язкові' });
    }

    if (name.length > 100) {
      return res.status(400).json({ error: 'Назва картки занадто довга' });
    }

    if (!['barcode', 'qr'].includes(codeType)) {
      return res.status(400).json({ error: 'Невірний тип коду' });
    }

    // Validate optional fields
    const validCategories = [
      'Супермаркети', 'Аптеки', 'Заправки', 'Ресторани', 'Одяг',
      'Електроніка', 'Краса', 'Спорт', 'Банки', 'Транспорт', 'Інше'
    ];

    if (category && !validCategories.includes(category)) {
      return res.status(400).json({ error: 'Невірна категорія картки' });
    }

    if (description && description.length > 500) {
      return res.status(400).json({ error: 'Опис картки занадто довгий' });
    }

    if (color && !/^#[0-9A-Fa-f]{6}$/.test(color)) {
      return res.status(400).json({ error: 'Невірний формат кольору' });
    }

    // Update card in user document
    const user = await User.findById(req.user._id);
    const card = user.cards.id(cardId);
    
    if (!card) {
      return res.status(404).json({ error: 'Картка не знайдена' });
    }
    
    await user.updateCard(cardId, {
      name: sanitizeInput(name),
      code: sanitizeInput(code),
      codeType: codeType || 'barcode',
      category: category || 'Інше',
      description: description ? sanitizeInput(description) : undefined,
      color: color || '#4F46E5'
    });
    
    const updatedCard = user.cards.id(cardId);

    res.json({
      success: true,
      message: 'Картка успішно оновлена',
      card: updatedCard
    });

  } catch (error) {
    console.error('Update card error:', error);
    res.status(500).json({ success: false, error: 'Помилка при оновленні картки' });
  }
});

// Get available categories
app.get('/api/cards/categories', authenticateToken, async (req, res) => {
  try {
    const categories = [
      'Супермаркети', 'Аптеки', 'Заправки', 'Ресторани', 'Одяг',
      'Електроніка', 'Краса', 'Спорт', 'Банки', 'Транспорт', 'Інше'
    ];

    // Get user's card statistics by category from embedded data
    const user = await User.findById(req.user._id);
    const cardsByCategory = {};
    
    // Count cards by category
    user.cards.forEach(card => {
      cardsByCategory[card.category] = (cardsByCategory[card.category] || 0) + 1;
    });

    const categoryStats = categories.map(cat => ({
      name: cat,
      count: cardsByCategory[cat] || 0
    }));

    res.json({
      success: true,
      categories: categoryStats
    });

  } catch (error) {
    console.error('Get categories error:', error);
    res.status(500).json({ success: false, error: 'Помилка при отриманні категорій' });
  }
});

// Get cards with filtering
app.get('/api/cards', authenticateToken, async (req, res) => {
  try {
    const { category, search, sortBy = 'createdAt', sortOrder = 'desc' } = req.query;
    
    // Build filter
    const filter = { userId: req.user._id };
    if (category && category !== 'all') {
      filter.category = category;
    }

    // Build search query
    if (search) {
      filter.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }

    // Build sort
    const sort = {};
    sort[sortBy] = sortOrder === 'desc' ? -1 : 1;

    const user = await User.findById(req.user._id);
    let cards = user.cards;
    
    // Apply filters
    if (category) {
      cards = cards.filter(card => card.category === category);
    }
    if (search) {
      const searchLower = search.toLowerCase();
      cards = cards.filter(card => 
        card.name.toLowerCase().includes(searchLower) ||
        card.code.toLowerCase().includes(searchLower) ||
        (card.description && card.description.toLowerCase().includes(searchLower))
      );
    }
    
    // Apply sorting
    cards.sort((a, b) => {
      const aVal = a[sortBy];
      const bVal = b[sortBy];
      if (sortOrder === 'desc') {
        return aVal < bVal ? 1 : -1;
      }
      return aVal > bVal ? 1 : -1;
    });

    res.json({ 
      success: true, 
      cards,
      total: cards.length 
    });

  } catch (error) {
    console.error('Get cards error:', error);
    res.status(500).json({ success: false, error: 'Помилка при отриманні карт' });
  }
});

// Export cards
app.get('/api/cards/export', authenticateToken, async (req, res) => {
  try {
    const { format = 'json' } = req.query;
    const user = await User.findById(req.user._id);
    const cards = user.cards.sort((a, b) => b.createdAt - a.createdAt);

    // Remove sensitive data and prepare export data
    const exportData = cards.map(card => ({
      name: card.name,
      code: card.code,
      codeType: card.codeType,
      category: card.category,
      description: card.description,
      color: card.color,
      createdAt: card.createdAt,
      updatedAt: card.updatedAt
    }));

    const exportObject = {
      exportedAt: new Date().toISOString(),
      version: '1.0',
      totalCards: exportData.length,
      cards: exportData
    };

    if (format === 'csv') {
      // Convert to CSV
      const csv = [
        'Name,Code,Code Type,Category,Description,Color,Created At,Updated At',
        ...exportData.map(card => [
          `"${card.name}"`,
          `"${card.code}"`,
          card.codeType,
          `"${card.category}"`,
          `"${card.description || ''}"`,
          card.color,
          card.createdAt.toISOString(),
          card.updatedAt.toISOString()
        ].join(','))
      ].join('\n');

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename="loyalty-cards.csv"');
      res.send(csv);
    } else {
      // JSON format (default)
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', 'attachment; filename="loyalty-cards.json"');
      res.json(exportObject);
    }

    logger.info(`Cards exported by user ${req.user._id}`, {
      userId: req.user._id,
      format,
      cardCount: exportData.length
    });

  } catch (error) {
    console.error('Export cards error:', error);
    res.status(500).json({ success: false, error: 'Помилка при експорті карт' });
  }
});

// Import cards
app.post('/api/cards/import', authenticateToken, async (req, res) => {
  try {
    const { cards, options = {} } = req.body;
    const { skipDuplicates = true, overwriteExisting = false } = options;

    if (!Array.isArray(cards)) {
      return res.status(400).json({ error: 'Невірний формат даних для імпорту' });
    }

    const results = {
      imported: 0,
      skipped: 0,
      errors: [],
      total: cards.length
    };

    for (let i = 0; i < cards.length; i++) {
      const cardData = cards[i];
      
      try {
        // Validate required fields
        if (!cardData.name || !cardData.code) {
          results.errors.push(`Картка ${i + 1}: відсутня назва або код`);
          continue;
        }

        // Check for existing card with same code
        const user = await User.findById(req.user._id);
        const existingCard = user.cards.find(card => card.code === cardData.code);

        if (existingCard) {
          if (skipDuplicates && !overwriteExisting) {
            results.skipped++;
            continue;
          }
          
          if (overwriteExisting) {
            // Update existing card
            await user.updateCard(existingCard._id, {
              name: sanitizeInput(cardData.name),
              codeType: cardData.codeType || 'barcode',
              category: cardData.category || 'Інше',
              description: cardData.description ? sanitizeInput(cardData.description) : undefined,
              color: cardData.color || '#4F46E5'
            });
            results.imported++;
            continue;
          }
        }

        // Create new card
        await user.addCard({
          name: sanitizeInput(cardData.name),
          code: sanitizeInput(cardData.code),
          codeType: cardData.codeType || 'barcode',
          category: cardData.category || 'Інше',
          description: cardData.description ? sanitizeInput(cardData.description) : undefined,
          color: cardData.color || '#4F46E5'
        });
        results.imported++;

      } catch (cardError) {
        results.errors.push(`Картка ${i + 1}: ${cardError.message}`);
      }
    }

    res.json({
      success: true,
      message: `Імпорт завершено. Імпортовано: ${results.imported}, пропущено: ${results.skipped}`,
      results
    });

    logger.info(`Cards imported by user ${req.user._id}`, {
      userId: req.user._id,
      imported: results.imported,
      skipped: results.skipped,
      errors: results.errors.length
    });

  } catch (error) {
    console.error('Import cards error:', error);
    res.status(500).json({ success: false, error: 'Помилка при імпорті карт' });
  }
});

// Friends Routes

// Search users by ID for friend requests
app.get('/api/friends/search/:userId', authenticateToken, async (req, res) => {
  try {
    const searchUserId = req.params.userId;
    
    if (!mongoose.Types.ObjectId.isValid(searchUserId)) {
      return res.status(400).json({ error: 'Невірний ID користувача' });
    }
    
    if (searchUserId === req.user._id.toString()) {
      return res.status(400).json({ error: 'Не можна додати себе в друзі' });
    }
    
    const user = await User.findById(searchUserId).select('name email createdAt');
    
    if (!user) {
      return res.status(404).json({ error: 'Користувач не знайдений' });
    }
    
    // Check if friendship already exists in embedded friends array
    const existingFriend = req.user.friends.find(f => f.friendId.toString() === searchUserId.toString());
    
    let friendshipStatus = 'none';
    if (existingFriend) {
      friendshipStatus = existingFriend.status;
    }
    
    res.json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        createdAt: user.createdAt,
        friendshipStatus
      }
    });
    
  } catch (error) {
    logger.error('Search user error:', error);
    res.status(500).json({ error: 'Помилка пошуку користувача' });
  }
});

// Send friend request
app.post('/api/friends/request', authenticateToken, async (req, res) => {
  try {
    const { recipientId } = req.body;
    
    if (!mongoose.Types.ObjectId.isValid(recipientId)) {
      return res.status(400).json({ error: 'Невірний ID користувача' });
    }
    
    if (recipientId === req.user._id.toString()) {
      return res.status(400).json({ error: 'Не можна надіслати запит самому собі' });
    }
    
    // Check if recipient exists
    const recipient = await User.findById(recipientId);
    if (!recipient) {
      return res.status(404).json({ error: 'Користувач не знайдений' });
    }
    
    // Check if friendship already exists in user's friends array
    const existingFriend = req.user.friends.find(f => f.friendId.toString() === recipientId);
    if (existingFriend) {
      if (existingFriend.status === 'accepted') {
        return res.status(400).json({ error: 'Ви вже друзі' });
      } else if (existingFriend.status === 'pending_sent') {
        return res.status(400).json({ error: 'Запит вже надіслано' });
      } else if (existingFriend.status === 'blocked') {
        return res.status(400).json({ error: 'Неможливо надіслати запит' });
      }
    }
    
    // Add friend request to both users
    await req.user.addFriend(recipientId, recipient.name, recipient.email);
    await recipient.addFriend(req.user._id, req.user.name, req.user.email, 'pending_received');
    
    logger.info(`Friend request sent from ${req.user.email} to ${recipient.email}`);
    
    res.status(201).json({
      success: true,
      message: 'Запит на дружбу надіслано',
      friendship: {
        id: friendship._id,
        requester: req.user._id,
        recipient: recipientId,
        status: 'pending',
        createdAt: friendship.createdAt
      }
    });
    
  } catch (error) {
    logger.error('Send friend request error:', error);
    res.status(500).json({ error: 'Помилка надсилання запиту на дружбу' });
  }
});

// Accept/reject friend request
app.put('/api/friends/request/:requestId', authenticateToken, async (req, res) => {
  try {
    const { requestId } = req.params;
    const { action } = req.body; // 'accept' or 'reject'
    
    if (!mongoose.Types.ObjectId.isValid(requestId)) {
      return res.status(400).json({ error: 'Невірний ID запиту' });
    }
    
    if (!['accept', 'reject'].includes(action)) {
      return res.status(400).json({ error: 'Невірна дія. Використовуйте accept або reject' });
    }
    
    // Find pending request in user's friends list
    const friendRequest = req.user.friends.find(f => f._id.toString() === requestId && f.status === 'pending_received');
    
    if (!friendRequest) {
      return res.status(404).json({ error: 'Запит на дружбу не знайдений' });
    }
    
    if (action === 'accept') {
      await req.user.acceptFriend(friendRequest.friendId);
      
      // Also update the friend's status to accepted
      const requester = await User.findById(friendRequest.friendId);
      if (requester) {
        await requester.acceptFriend(req.user._id);
      }
      
      logger.info(`Friend request accepted: ${friendRequest.friendEmail} -> ${req.user.email}`);
      
      res.json({
        success: true,
        message: 'Запит на дружбу прийнято',
        friend: {
          id: friendRequest.friendId,
          name: friendRequest.friendName,
          email: friendRequest.friendEmail,
          status: 'accepted'
        }
      });
    } else {
      await req.user.removeFriend(friendRequest.friendId);
      
      // Also remove from requester's list
      const requester = await User.findById(friendRequest.friendId);
      if (requester) {
        await requester.removeFriend(req.user._id);
      }
      
      logger.info(`Friend request rejected: ${friendRequest.friendEmail} -> ${req.user.email}`);
      
      res.json({
        success: true,
        message: 'Запит на дружбу відхилено'
      });
    }
    
  } catch (error) {
    logger.error('Process friend request error:', error);
    res.status(500).json({ error: 'Помилка обробки запиту на дружбу' });
  }
});

// Get friends list
app.get('/api/friends', authenticateToken, async (req, res) => {
  try {
    // Get friends from embedded friends array
    const friends = req.user.friends
      .filter(f => f.status === 'accepted')
      .map(friend => ({
        id: friend.friendId,
        name: friend.friendName,
        email: friend.friendEmail,
        friendshipId: friend._id,
        friendsSince: friend.acceptedAt
      }));
    
    res.json({
      success: true,
      friends,
      total: friends.length
    });
    
  } catch (error) {
    logger.error('Get friends error:', error);
    res.status(500).json({ error: 'Помилка завантаження друзів' });
  }
});

// Get pending friend requests
app.get('/api/friends/requests', authenticateToken, async (req, res) => {
  try {
    // Get pending requests from embedded friends array
    const sentRequests = req.user.friends.filter(f => f.status === 'pending_sent');
    const receivedRequests = req.user.friends.filter(f => f.status === 'pending_received');
    
    res.json({
      success: true,
      sent: sentRequests.map(friend => ({
        id: friend._id,
        user: {
          _id: friend.friendId,
          name: friend.friendName,
          email: friend.friendEmail
        },
        sentAt: friend.addedAt
      })),
      received: receivedRequests.map(friend => ({
        id: friend._id,
        user: {
          _id: friend.friendId,
          name: friend.friendName,
          email: friend.friendEmail
        },
        receivedAt: friend.addedAt
      }))
    });
    
  } catch (error) {
    logger.error('Get friend requests error:', error);
    res.status(500).json({ error: 'Помилка завантаження запитів на дружбу' });
  }
});

// Remove friend
app.delete('/api/friends/:friendshipId', authenticateToken, async (req, res) => {
  try {
    const { friendshipId } = req.params;
    
    if (!mongoose.Types.ObjectId.isValid(friendshipId)) {
      return res.status(400).json({ error: 'Невірний ID дружби' });
    }
    
    // Find friend in user's friends array
    const friendToRemove = req.user.friends.find(f => f._id.toString() === friendshipId);
    
    if (!friendToRemove) {
      return res.status(404).json({ error: 'Друг не знайдений' });
    }
    
    // Remove friend from both users
    await req.user.removeFriend(friendToRemove.friendId);
    
    const friendUser = await User.findById(friendToRemove.friendId);
    if (friendUser) {
      await friendUser.removeFriend(req.user._id);
    }
    
    logger.info(`Friendship removed: ${req.user._id} <-> ${friendToRemove.friendId}`);
    
    res.json({
      success: true,
      message: 'Друга видалено зі списку'
    });
    
  } catch (error) {
    logger.error('Remove friend error:', error);
    res.status(500).json({ error: 'Помилка видалення друга' });
  }
});

// Share shopping list with friend
app.post('/api/shopping-lists/:id/share', authenticateToken, async (req, res) => {
  try {
    const listId = req.params.id;
    const { friendId, permission = 'view' } = req.body;
    
    if (!mongoose.Types.ObjectId.isValid(listId) || !mongoose.Types.ObjectId.isValid(friendId)) {
      return res.status(400).json({ error: 'Невірні ID' });
    }
    
    if (!['view', 'edit'].includes(permission)) {
      return res.status(400).json({ error: 'Невірний тип дозволу' });
    }
    
    // Check if list exists and belongs to user
    const list = await ShoppingList.findOne({
      _id: listId,
      userId: req.user._id
    });
    
    if (!list) {
      return res.status(404).json({ error: 'Список не знайдено' });
    }
    
    // Check if friendship exists in embedded friends array
    const friendData = req.user.friends.find(f => f.friendId.toString() === friendId && f.status === 'accepted');
    if (!friendData) {
      return res.status(400).json({ error: 'Користувач не є вашим другом' });
    }
    
    // Check if already shared with this user
    const alreadyShared = list.sharedWith.some(share => share.userId.toString() === friendId);
    if (alreadyShared) {
      return res.status(400).json({ error: 'Список вже поділено з цим користувачем' });
    }
    
    // Add to shared list
    list.sharedWith.push({
      userId: friendId,
      permission
    });
    list.shared = true;
    
    await list.save();
    
    // Get friend info
    const friend = await User.findById(friendId).select('name email');
    
    logger.info(`Shopping list shared: ${req.user.email} -> ${friend.email}, permission: ${permission}`);
    
    res.json({
      success: true,
      message: `Список поділено з ${friend.name}`,
      sharedWith: {
        userId: friendId,
        name: friend.name,
        email: friend.email,
        permission
      }
    });
    
  } catch (error) {
    logger.error('Share shopping list error:', error);
    res.status(500).json({ error: 'Помилка поділу списку' });
  }
});

// Get shared shopping lists (lists shared with me)
app.get('/api/shopping-lists/shared', authenticateToken, async (req, res) => {
  try {
    const sharedLists = await ShoppingList.find({
      'sharedWith.userId': req.user._id
    }).populate('userId', 'name email');
    
    const lists = sharedLists.map(list => {
      const myPermission = list.sharedWith.find(share => 
        share.userId.toString() === req.user._id.toString()
      );
      
      return {
        ...list.toObject(),
        owner: list.userId,
        myPermission: myPermission.permission
      };
    });
    
    res.json({
      success: true,
      lists,
      total: lists.length
    });
    
  } catch (error) {
    logger.error('Get shared shopping lists error:', error);
    res.status(500).json({ error: 'Помилка завантаження поділених списків' });
  }
});

// Remove sharing from shopping list
app.delete('/api/shopping-lists/:id/share/:friendId', authenticateToken, async (req, res) => {
  try {
    const { id: listId, friendId } = req.params;
    
    if (!mongoose.Types.ObjectId.isValid(listId) || !mongoose.Types.ObjectId.isValid(friendId)) {
      return res.status(400).json({ error: 'Невірні ID' });
    }
    
    const list = await ShoppingList.findOne({
      _id: listId,
      userId: req.user._id
    });
    
    if (!list) {
      return res.status(404).json({ error: 'Список не знайдено' });
    }
    
    // Remove from shared list
    list.sharedWith = list.sharedWith.filter(share => 
      share.userId.toString() !== friendId
    );
    
    // If no more shares, mark as not shared
    if (list.sharedWith.length === 0) {
      list.shared = false;
    }
    
    await list.save();
    
    const friend = await User.findById(friendId).select('name');
    
    logger.info(`Shopping list unshared: ${req.user.email} removed ${friend.name}`);
    
    res.json({
      success: true,
      message: `Доступ для ${friend.name} видалено`
    });
    
  } catch (error) {
    logger.error('Remove sharing error:', error);
    res.status(500).json({ error: 'Помилка видалення доступу' });
  }
});

// Shopping Lists Routes

// Get user shopping lists
app.get('/api/shopping-lists', authenticateToken, async (req, res) => {
  try {
    const { search, sortBy = 'createdAt', sortOrder = 'desc' } = req.query;
    
    const filter = { userId: req.user._id };
    
    if (search) {
      filter.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }

    const sort = {};
    sort[sortBy] = sortOrder === 'desc' ? -1 : 1;

    const lists = await ShoppingList.find(filter).sort(sort);

    res.json({ 
      success: true, 
      lists,
      total: lists.length 
    });

  } catch (error) {
    console.error('Get shopping lists error:', error);
    res.status(500).json({ success: false, error: 'Помилка при отриманні списків покупок' });
  }
});

// Create shopping list
app.post('/api/shopping-lists', authenticateToken, async (req, res) => {
  try {
    const { name, description, items = [], totalBudget, color } = req.body;

    if (!name || name.trim().length === 0) {
      return res.status(400).json({ error: 'Назва списку обов\'язкова' });
    }

    if (name.length > 100) {
      return res.status(400).json({ error: 'Назва списку занадто довга' });
    }

    if (description && description.length > 500) {
      return res.status(400).json({ error: 'Опис списку занадто довгий' });
    }

    if (color && !/^#[0-9A-Fa-f]{6}$/.test(color)) {
      return res.status(400).json({ error: 'Невірний формат кольору' });
    }

    const shoppingList = new ShoppingList({
      userId: req.user._id,
      name: sanitizeInput(name),
      description: description ? sanitizeInput(description) : undefined,
      items: items.map(item => ({
        name: sanitizeInput(item.name),
        quantity: item.quantity || '1',
        category: item.category || 'Інше',
        price: item.price || undefined,
        notes: item.notes ? sanitizeInput(item.notes) : undefined
      })),
      totalBudget,
      color: color || '#10B981'
    });

    await shoppingList.save();

    res.status(201).json({
      success: true,
      message: 'Список покупок створено',
      list: shoppingList
    });

  } catch (error) {
    console.error('Create shopping list error:', error);
    res.status(500).json({ success: false, error: 'Помилка при створенні списку покупок' });
  }
});

// Update shopping list
app.put('/api/shopping-lists/:id', authenticateToken, async (req, res) => {
  try {
    const listId = req.params.id;
    const { name, description, items, totalBudget, color } = req.body;

    if (!mongoose.Types.ObjectId.isValid(listId)) {
      return res.status(400).json({ error: 'Невірний ID списку' });
    }

    if (!name || name.trim().length === 0) {
      return res.status(400).json({ error: 'Назва списку обов\'язкова' });
    }

    const updateData = {
      name: sanitizeInput(name),
      description: description ? sanitizeInput(description) : undefined,
      totalBudget,
      color: color || '#10B981',
      updatedAt: new Date()
    };

    if (items && Array.isArray(items)) {
      updateData.items = items.map(item => ({
        ...item,
        name: sanitizeInput(item.name),
        notes: item.notes ? sanitizeInput(item.notes) : undefined
      }));
    }

    const list = await ShoppingList.findOneAndUpdate(
      { _id: listId, userId: req.user._id },
      updateData,
      { new: true, runValidators: true }
    );

    if (!list) {
      return res.status(404).json({ error: 'Список не знайдено' });
    }

    res.json({
      success: true,
      message: 'Список оновлено',
      list
    });

  } catch (error) {
    console.error('Update shopping list error:', error);
    res.status(500).json({ success: false, error: 'Помилка при оновленні списку' });
  }
});

// Delete shopping list
app.delete('/api/shopping-lists/:id', authenticateToken, async (req, res) => {
  try {
    const listId = req.params.id;

    if (!mongoose.Types.ObjectId.isValid(listId)) {
      return res.status(400).json({ error: 'Невірний ID списку' });
    }

    const list = await ShoppingList.findOneAndDelete({
      _id: listId,
      userId: req.user._id
    });

    if (!list) {
      return res.status(404).json({ error: 'Список не знайдено' });
    }

    res.json({ 
      success: true,
      message: 'Список видалено' 
    });

  } catch (error) {
    console.error('Delete shopping list error:', error);
    res.status(500).json({ success: false, error: 'Помилка при видаленні списку' });
  }
});

// Add item to shopping list
app.post('/api/shopping-lists/:id/items', authenticateToken, async (req, res) => {
  try {
    const listId = req.params.id;
    const { name, quantity = '1', category = 'Інше', price, notes } = req.body;

    if (!mongoose.Types.ObjectId.isValid(listId)) {
      return res.status(400).json({ error: 'Невірний ID списку' });
    }

    if (!name || name.trim().length === 0) {
      return res.status(400).json({ error: 'Назва товару обов\'язкова' });
    }

    const list = await ShoppingList.findOne({
      _id: listId,
      userId: req.user._id
    });

    if (!list) {
      return res.status(404).json({ error: 'Список не знайдено' });
    }

    const newItem = {
      name: sanitizeInput(name),
      quantity,
      category,
      price,
      notes: notes ? sanitizeInput(notes) : undefined,
      completed: false,
      addedAt: new Date()
    };

    list.items.push(newItem);
    await list.save();

    res.status(201).json({
      success: true,
      message: 'Товар додано до списку',
      item: newItem,
      list
    });

  } catch (error) {
    console.error('Add item error:', error);
    res.status(500).json({ success: false, error: 'Помилка при додаванні товару' });
  }
});

// Update item in shopping list
app.put('/api/shopping-lists/:id/items/:itemId', authenticateToken, async (req, res) => {
  try {
    const { id: listId, itemId } = req.params;
    const updates = req.body;

    if (!mongoose.Types.ObjectId.isValid(listId)) {
      return res.status(400).json({ error: 'Невірний ID списку' });
    }

    const list = await ShoppingList.findOne({
      _id: listId,
      userId: req.user._id
    });

    if (!list) {
      return res.status(404).json({ error: 'Список не знайдено' });
    }

    const item = list.items.id(itemId);
    if (!item) {
      return res.status(404).json({ error: 'Товар не знайдено' });
    }

    // Update item fields
    if (updates.name) item.name = sanitizeInput(updates.name);
    if (updates.quantity !== undefined) item.quantity = updates.quantity;
    if (updates.category) item.category = updates.category;
    if (updates.price !== undefined) item.price = updates.price;
    if (updates.notes !== undefined) item.notes = updates.notes ? sanitizeInput(updates.notes) : undefined;
    if (updates.completed !== undefined) item.completed = updates.completed;

    await list.save();

    res.json({
      success: true,
      message: 'Товар оновлено',
      item,
      list
    });

  } catch (error) {
    console.error('Update item error:', error);
    res.status(500).json({ success: false, error: 'Помилка при оновленні товару' });
  }
});

// Delete item from shopping list
app.delete('/api/shopping-lists/:id/items/:itemId', authenticateToken, async (req, res) => {
  try {
    const { id: listId, itemId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(listId)) {
      return res.status(400).json({ error: 'Невірний ID списку' });
    }

    const list = await ShoppingList.findOne({
      _id: listId,
      userId: req.user._id
    });

    if (!list) {
      return res.status(404).json({ error: 'Список не знайдено' });
    }

    const item = list.items.id(itemId);
    if (!item) {
      return res.status(404).json({ error: 'Товар не знайдено' });
    }

    list.items.pull(itemId);
    await list.save();

    res.json({
      success: true,
      message: 'Товар видалено',
      list
    });

  } catch (error) {
    console.error('Delete item error:', error);
    res.status(500).json({ success: false, error: 'Помилка при видаленні товару' });
  }
});

// Version endpoint for client updates
app.get('/api/version', (req, res) => {
  const { execSync } = require('child_process');
  try {
    const gitHash = execSync('git rev-parse --short HEAD', { encoding: 'utf8' }).trim();
    const version = `${require('./package.json').version}-${gitHash}`;
    res.json({ version });
  } catch (error) {
    // Fallback to package.json version if git not available
    res.json({ version: require('./package.json').version });
  }
});

// Health check endpoint for monitoring
app.get('/api/health', (req, res) => {
  const uptime = process.uptime();
  const memoryUsage = process.memoryUsage();
  
  res.json({
    status: 'ok',
    uptime: uptime,
    memory: {
      rss: Math.round(memoryUsage.rss / 1024 / 1024) + 'MB',
      heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024) + 'MB',
      heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024) + 'MB'
    },
    timestamp: new Date().toISOString()
  });
});

// Catch all handler for SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Внутрішня помилка сервера' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Сервер запущено на порту ${PORT}`);
  console.log(`📱 Відкрийте http://localhost:${PORT} в браузері`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM отримано, закриваю сервер...');
  mongoose.connection.close();
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT отримано, закриваю сервер...');
  mongoose.connection.close();
  process.exit(0);
});