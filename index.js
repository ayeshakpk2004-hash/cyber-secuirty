require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const cors = require('cors');
const morgan = require('morgan');
const winston = require('winston');

const app = express();

// Security headers
app.use(helmet());

// Basic parsers
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false }));

// CORS (adjust origin as needed)
app.use(cors({ origin: true }));

// Logging
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'security.log' })
  ]
});
app.use(morgan('combined'));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret';
const SALT_ROUNDS = 10;

// In-memory user store for demo purposes
// NEVER use in production; replace with a database.
const users = new Map(); // key: email, value: { email, name, passwordHash }

// Helper: create JWT
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
}

// Helper: auth middleware
function auth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'User Management System (secure demo)' });
});

// Signup
app.post('/signup', async (req, res) => {
  try {
    let { email, password, name } = req.body || {};
    // Basic normalization
    email = typeof email === 'string' ? email.trim().toLowerCase() : '';
    name = typeof name === 'string' ? validator.stripLow(validator.escape(name.trim())) : '';

    // Validate inputs
    if (!validator.isEmail(email)) {
      return res.status(400).json({ error: 'Invalid email' });
    }
    if (!validator.isLength(password || '', { min: 8 })) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    if (!validator.isLength(name || '', { min: 2, max: 50 })) {
      return res.status(400).json({ error: 'Name must be 2–50 chars' });
    }
    if (users.has(email)) {
      return res.status(409).json({ error: 'User already exists' });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

    const user = { email, name, passwordHash };
    users.set(email, user);

    logger.info('User created', { email });

    return res.status(201).json({ message: 'User created' });
  } catch (err) {
    logger.error('Signup error', { error: err.message });
    return res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/login', async (req, res) => {
  try {
    let { email, password } = req.body || {};
    email = typeof email === 'string' ? email.trim().toLowerCase() : '';

    if (!validator.isEmail(email)) {
      return res.status(400).json({ error: 'Invalid email' });
    }

    const user = users.get(email);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password || '', user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = signToken({ email });
    logger.info('User login', { email });
    res.json({ token });
  } catch (err) {
    logger.error('Login error', { error: err.message });
    return res.status(500).json({ error: 'Server error' });
  }
});

// Protected profile
app.get('/profile', auth, (req, res) => {
  const email = req.user.email;
  const user = users.get(email);
  if (!user) return res.status(404).json({ error: 'User not found' });
  // Return safe profile data
  res.json({ email: user.email, name: user.name });
});

// Start server
app.listen(PORT, () => {
  logger.info(`Server running`, { port: PORT });
  console.log(`Server running on http://localhost:${PORT}`);
});
