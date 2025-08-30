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
  etag: true,
  lastModified: true,
  setHeaders: (res, path) => {
    if (process.env.NODE_ENV !== 'production') {
      // В режимі розробки відключаємо кешування для JS/CSS файлів
      if (path.endsWith('.js') || path.endsWith('.css')) {
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
      }
    } else {
      // У продакшені встановлюємо нормальний кеш для статичних файлів
      if (path.endsWith('.js') || path.endsWith('.css')) {
        res.setHeader('Cache-Control', 'public, max-age=86400'); // 1 день
      } else if (path.match(/\.(jpg|jpeg|png|gif|ico|svg)$/)) {
        res.setHeader('Cache-Control', 'public, max-age=604800'); // 7 днів
      }
    }
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

// User Schema with enhanced security
const userSchema = new mongoose.Schema({
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
  // Account lockout fields
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: {
    type: Date
  },
  // 2FA fields
  twoFactorSecret: {
    type: String,
    select: false // Don't include by default
  },
  twoFactorEnabled: {
    type: Boolean,
    default: false
  },
  // Security tracking
  lastLogin: {
    type: Date
  },
  lastIP: {
    type: String
  },
  // Remember me tokens
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
  }],
  passwordChangedAt: {
    type: Date,
    default: Date.now
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Virtual for checking if account is locked
userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Pre-save middleware to handle login attempts
userSchema.pre('save', function(next) {
  // If we're not modifying loginAttempts, continue
  if (!this.isModified('loginAttempts')) return next();
  
  // If we have a lockUntil and it's in the past, remove it
  if (this.lockUntil && this.lockUntil < Date.now()) {
    this.lockUntil = undefined;
  }
  
  next();
});

// Instance method to increment login attempts
userSchema.methods.incLoginAttempts = function() {
  // If we have a lockUntil and it's in the past, start over
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: { lockUntil: 1 },
      $set: { loginAttempts: 1 }
    });
  }
  
  const updates = { $inc: { loginAttempts: 1 } };
  const maxAttempts = parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5;
  const lockTime = parseInt(process.env.ACCOUNT_LOCK_TIME) || 7200000; // 2 hours
  
  // If we hit max attempts and aren't locked yet, lock the account
  if (this.loginAttempts + 1 >= maxAttempts && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + lockTime };
    logger.warn(`Account locked for user: ${this.email}`);
  }
  
  return this.updateOne(updates);
};

// Instance method to reset login attempts
userSchema.methods.resetLoginAttempts = function() {
  return this.updateOne({
    $unset: { loginAttempts: 1, lockUntil: 1 }
  });
};

// Card Schema
const cardSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
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
});

// Update timestamp before save
cardSchema.pre('save', function(next) {
  this.updatedAt = new Date();
  next();
});

// Shopping List Schema
const shoppingListSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
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

// Update timestamp before save
shoppingListSchema.pre('save', function(next) {
  this.updatedAt = new Date();
  next();
});

// Friendship Schema
const friendshipSchema = new mongoose.Schema({
  requester: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  recipient: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  status: {
    type: String,
    enum: ['pending', 'accepted', 'blocked'],
    default: 'pending'
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  acceptedAt: {
    type: Date
  }
});

// Ensure unique friendship relationships
friendshipSchema.index({ requester: 1, recipient: 1 }, { unique: true });

// Pre-save middleware to set acceptedAt when status changes to accepted
friendshipSchema.pre('save', function(next) {
  if (this.isModified('status') && this.status === 'accepted') {
    this.acceptedAt = new Date();
  }
  next();
});

// Instance method to check if friendship exists between two users
friendshipSchema.statics.findFriendship = function(userId1, userId2) {
  return this.findOne({
    $or: [
      { requester: userId1, recipient: userId2 },
      { requester: userId2, recipient: userId1 }
    ]
  });
};

// Instance method to get all friends for a user
friendshipSchema.statics.getFriends = function(userId) {
  return this.find({
    $or: [
      { requester: userId, status: 'accepted' },
      { recipient: userId, status: 'accepted' }
    ]
  }).populate('requester recipient', 'name email');
};

const User = mongoose.model('User', userSchema);
const Card = mongoose.model('Card', cardSchema);
const ShoppingList = mongoose.model('ShoppingList', shoppingListSchema);
const Friendship = mongoose.model('Friendship', friendshipSchema);

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
        'rememberTokens.token': rememberToken,
        'rememberTokens.expiresAt': { $gt: new Date() }
      }).select('-password -twoFactorSecret');

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

app.use(securityHeaders);

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
    if (user.loginAttempts > 0) {
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
      
      // Clean up old remember tokens (keep only last 5)
      if (user.rememberTokens.length >= 5) {
        user.rememberTokens = user.rememberTokens
          .sort((a, b) => b.createdAt - a.createdAt)
          .slice(0, 4);
      }

      // Add new remember token
      user.rememberTokens.push({
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
        $set: { rememberTokens: [] }
      });
    } else if (rememberTokenFromCookie) {
      // Remove only current remember token
      await User.findByIdAndUpdate(req.user._id, {
        $pull: { rememberTokens: { token: rememberTokenFromCookie } }
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
    if (user.loginAttempts > 0) {
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
      passwordChangedAt: new Date(),
      // Clear all remember tokens for security
      rememberTokens: []
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
      .select('-password -twoFactorSecret -rememberTokens -loginAttempts -lockUntil');
    
    if (!user) {
      return res.status(404).json({ error: 'Користувач не знайдений' });
    }
    
    // Get user statistics
    const [cardCount, shoppingListCount] = await Promise.all([
      Card.countDocuments({ userId: user._id }),
      ShoppingList.countDocuments({ userId: user._id })
    ]);
    
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

    // Create card
    const card = new Card({
      userId: req.user._id,
      name: sanitizeInput(name),
      code: sanitizeInput(code),
      codeType: codeType || 'barcode',
      category: category || 'Інше',
      description: description ? sanitizeInput(description) : undefined,
      color: color || '#4F46E5'
    });

    await card.save();

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

    const card = await Card.findOneAndDelete({
      _id: cardId,
      userId: req.user._id
    });

    if (!card) {
      return res.status(404).json({ error: 'Картка не знайдена' });
    }

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

    // Update card
    const card = await Card.findOneAndUpdate(
      { _id: cardId, userId: req.user._id },
      {
        name: sanitizeInput(name),
        code: sanitizeInput(code),
        codeType: codeType || 'barcode',
        category: category || 'Інше',
        description: description ? sanitizeInput(description) : undefined,
        color: color || '#4F46E5',
        updatedAt: new Date()
      },
      { new: true, runValidators: true }
    );

    if (!card) {
      return res.status(404).json({ error: 'Картка не знайдена' });
    }

    res.json({
      success: true,
      message: 'Картка успішно оновлена',
      card
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

    // Get user's card statistics by category
    const stats = await Card.aggregate([
      { $match: { userId: req.user._id } },
      { $group: { _id: '$category', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    const categoryStats = categories.map(cat => {
      const stat = stats.find(s => s._id === cat);
      return {
        name: cat,
        count: stat ? stat.count : 0
      };
    });

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

    const cards = await Card.find(filter).sort(sort);

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
    const cards = await Card.find({ userId: req.user._id }).sort({ createdAt: -1 });

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
        const existingCard = await Card.findOne({
          userId: req.user._id,
          code: cardData.code
        });

        if (existingCard) {
          if (skipDuplicates && !overwriteExisting) {
            results.skipped++;
            continue;
          }
          
          if (overwriteExisting) {
            // Update existing card
            await Card.findByIdAndUpdate(existingCard._id, {
              name: sanitizeInput(cardData.name),
              codeType: cardData.codeType || 'barcode',
              category: cardData.category || 'Інше',
              description: cardData.description ? sanitizeInput(cardData.description) : undefined,
              color: cardData.color || '#4F46E5',
              updatedAt: new Date()
            });
            results.imported++;
            continue;
          }
        }

        // Create new card
        const newCard = new Card({
          userId: req.user._id,
          name: sanitizeInput(cardData.name),
          code: sanitizeInput(cardData.code),
          codeType: cardData.codeType || 'barcode',
          category: cardData.category || 'Інше',
          description: cardData.description ? sanitizeInput(cardData.description) : undefined,
          color: cardData.color || '#4F46E5'
        });

        await newCard.save();
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
    
    // Check if friendship already exists
    const existingFriendship = await Friendship.findFriendship(req.user._id, searchUserId);
    
    let friendshipStatus = 'none';
    if (existingFriendship) {
      if (existingFriendship.status === 'pending') {
        friendshipStatus = existingFriendship.requester.toString() === req.user._id.toString() ? 'sent' : 'received';
      } else {
        friendshipStatus = existingFriendship.status;
      }
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
    
    // Check if friendship already exists
    const existingFriendship = await Friendship.findFriendship(req.user._id, recipientId);
    if (existingFriendship) {
      if (existingFriendship.status === 'accepted') {
        return res.status(400).json({ error: 'Ви вже друзі' });
      } else if (existingFriendship.status === 'pending') {
        return res.status(400).json({ error: 'Запит вже надіслано' });
      } else if (existingFriendship.status === 'blocked') {
        return res.status(400).json({ error: 'Неможливо надіслати запит' });
      }
    }
    
    // Create friendship request
    const friendship = new Friendship({
      requester: req.user._id,
      recipient: recipientId,
      status: 'pending'
    });
    
    await friendship.save();
    
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
    
    const friendship = await Friendship.findById(requestId).populate('requester', 'name email');
    
    if (!friendship) {
      return res.status(404).json({ error: 'Запит на дружбу не знайдений' });
    }
    
    if (friendship.recipient.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Ви не можете відповісти на цей запит' });
    }
    
    if (friendship.status !== 'pending') {
      return res.status(400).json({ error: 'Запит вже оброблений' });
    }
    
    if (action === 'accept') {
      friendship.status = 'accepted';
      friendship.acceptedAt = new Date();
      await friendship.save();
      
      logger.info(`Friend request accepted: ${friendship.requester.email} -> ${req.user.email}`);
      
      res.json({
        success: true,
        message: 'Запит на дружбу прийнято',
        friendship: {
          id: friendship._id,
          requester: friendship.requester,
          status: 'accepted',
          acceptedAt: friendship.acceptedAt
        }
      });
    } else {
      await Friendship.findByIdAndDelete(requestId);
      
      logger.info(`Friend request rejected: ${friendship.requester.email} -> ${req.user.email}`);
      
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
    const friendships = await Friendship.getFriends(req.user._id);
    
    const friends = friendships.map(friendship => {
      const friend = friendship.requester._id.toString() === req.user._id.toString() 
        ? friendship.recipient 
        : friendship.requester;
      
      return {
        id: friend._id,
        name: friend.name,
        email: friend.email,
        friendshipId: friendship._id,
        friendsSince: friendship.acceptedAt
      };
    });
    
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
    const [sentRequests, receivedRequests] = await Promise.all([
      Friendship.find({
        requester: req.user._id,
        status: 'pending'
      }).populate('recipient', 'name email'),
      
      Friendship.find({
        recipient: req.user._id,
        status: 'pending'
      }).populate('requester', 'name email')
    ]);
    
    res.json({
      success: true,
      sent: sentRequests.map(req => ({
        id: req._id,
        user: req.recipient,
        sentAt: req.createdAt
      })),
      received: receivedRequests.map(req => ({
        id: req._id,
        user: req.requester,
        receivedAt: req.createdAt
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
    
    const friendship = await Friendship.findById(friendshipId);
    
    if (!friendship) {
      return res.status(404).json({ error: 'Дружба не знайдена' });
    }
    
    // Check if user is part of this friendship
    if (friendship.requester.toString() !== req.user._id.toString() && 
        friendship.recipient.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Ви не можете видалити цю дружбу' });
    }
    
    await Friendship.findByIdAndDelete(friendshipId);
    
    logger.info(`Friendship removed: ${friendship.requester} <-> ${friendship.recipient}`);
    
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
    
    // Check if friendship exists
    const friendship = await Friendship.findFriendship(req.user._id, friendId);
    if (!friendship || friendship.status !== 'accepted') {
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