import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { MongoClient, ObjectId } from 'mongodb';
import jwt from 'jsonwebtoken';

const app = express();
const port = process.env.PORT || 5000;
const clientUrl = process.env.CLIENT_URL || 'http://localhost:3000';

// ==========================================
// 1. EXPRESS & CORS CONFIGURATION
// ==========================================
app.use(express.json());
app.use(
  cors({
    origin: [clientUrl, 'http://localhost:3000'],
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Cookie']
  })
);

// ==========================================
// 2. DATABASE CONNECTION & COLLECTIONS
// ==========================================
const uri = process.env.MONGODB_URI;
if (!uri) {
  console.warn("WARNING: MONGODB_URI is not set in environment variables!");
}

const client = new MongoClient(uri);
let db = null;

// Collections references
let usersCollection = null;
let sessionsCollection = null;
let servicesCollection = null;
let bookingsCollection = null;
let paymentsCollection = null;

async function connectDB() {
  if (!db) {
    await client.connect();
    db = client.db('fixmate'); // Explicitly target 'fixmate' database
    usersCollection = db.collection('user'); // BetterAuth user collection
    sessionsCollection = db.collection('session'); // BetterAuth session collection
    servicesCollection = db.collection('services');
    bookingsCollection = db.collection('bookings');
    paymentsCollection = db.collection('payments');
    console.log("Connected successfully to MongoDB database: fixmate");
  }
  return db;
}

// Connect immediately on startup
connectDB().catch((err) => {
  console.error("Failed to connect to MongoDB on startup:", err);
});

// Cookie parser helper
function parseCookies(cookieHeader) {
  const list = {};
  if (!cookieHeader) return list;
  cookieHeader.split(';').forEach((cookie) => {
    const parts = cookie.split('=');
    list[parts.shift().trim()] = decodeURI(parts.join('='));
  });
  return list;
}

// ==========================================
// 3. AUTHENTICATION & ROLE MIDDLEWARES
// ==========================================

/**
 * verifyToken
 * Validates BetterAuth session token or Bearer JWT token and attaches req.user
 */
async function verifyToken(req, res, next) {
  try {
    let token = null;

    // 1. Check Authorization header (Bearer token)
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.split(' ')[1];
    }

    // 2. Fallback to BetterAuth session cookies
    if (!token && req.headers.cookie) {
      const cookies = parseCookies(req.headers.cookie);
      token = cookies['better-auth.session_token'] || cookies['__Secure-better-auth.session_token'];
    }

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Unauthorized: Missing authentication token'
      });
    }

    let foundUser = null;

    // 3. Lookup active session in MongoDB 'session' collection
    try {
      if (sessionsCollection && usersCollection) {
        const session = await sessionsCollection.findOne({ token: token });
        if (session) {
          const isExpired = new Date(session.expiresAt) < new Date();
          if (!isExpired) {
            let userQuery;
            if (ObjectId.isValid(session.userId)) {
              userQuery = { $or: [{ _id: new ObjectId(session.userId) }, { id: session.userId }] };
            } else {
              userQuery = { id: session.userId };
            }
            foundUser = await usersCollection.findOne(userQuery);
          }
        }
      }
    } catch (err) {
      console.error('Session lookup error:', err);
    }

    // 4. JWT fallback verification with shared BETTER_AUTH_SECRET
    if (!foundUser && process.env.BETTER_AUTH_SECRET) {
      try {
        const decoded = jwt.verify(token, process.env.BETTER_AUTH_SECRET);
        const email = decoded.email || decoded.sub;
        if (email && usersCollection) {
          foundUser = await usersCollection.findOne({ email });
        }
      } catch (jwtErr) {
        // Not a valid JWT or expired
      }
    }

    if (!foundUser) {
      return res.status(401).json({
        success: false,
        message: 'Unauthorized: Invalid or expired session'
      });
    }

    // Attach sanitized user to req.user
    req.user = {
      _id: foundUser._id,
      id: foundUser.id || foundUser._id.toString(),
      name: foundUser.name,
      email: foundUser.email,
      role: foundUser.role || 'customer',
      image: foundUser.image || '',
      phone: foundUser.phone || '',
      area: foundUser.area || '',
      bio: foundUser.bio || ''
    };

    next();
  } catch (error) {
    console.error('Authentication middleware error:', error);
    return res.status(401).json({
      success: false,
      message: 'Unauthorized: Authentication failed'
    });
  }
}

/**
 * verifyCustomer
 * Requires req.user.role === 'customer'
 */
function verifyCustomer(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }
  if (req.user.role !== 'customer') {
    return res.status(403).json({
      success: false,
      message: 'Forbidden: Access restricted to customers only'
    });
  }
  next();
}

/**
 * verifyTechnician
 * Requires req.user.role === 'technician'
 */
function verifyTechnician(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }
  if (req.user.role !== 'technician') {
    return res.status(403).json({
      success: false,
      message: 'Forbidden: Access restricted to technicians only'
    });
  }
  next();
}

/**
 * verifyAdmin
 * Requires req.user.role === 'admin'
 */
function verifyAdmin(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }
  if (req.user.role !== 'admin') {
    return res.status(403).json({
      success: false,
      message: 'Forbidden: Access restricted to administrators only'
    });
  }
  next();
}

// ==========================================
// 4. API ROUTES
// ==========================================

// Health Check
app.get('/', (req, res) => {
  res.status(200).json({
    success: true,
    message: 'FixMate API Server is running fine',
    database: 'connected (fixmate)',
    timestamp: new Date().toISOString()
  });
});

// --- USER ROUTES ---
/**
 * PATCH /api/users/profile
 * Allows logged-in user to update name, phone, area, bio, and image.
 * Email and role cannot be changed here.
 */
app.patch('/api/users/profile', verifyToken, async (req, res) => {
  try {
    const { name, phone, area, bio, image } = req.body;
    const userEmail = req.user.email;

    const updateFields = {
      updatedAt: new Date()
    };

    if (typeof name === 'string' && name.trim()) updateFields.name = name.trim();
    if (typeof phone === 'string') updateFields.phone = phone.trim();
    if (typeof area === 'string') updateFields.area = area.trim();
    if (typeof bio === 'string') updateFields.bio = bio.trim();
    if (typeof image === 'string' && image.trim()) updateFields.image = image.trim();

    const result = await usersCollection.findOneAndUpdate(
      { email: userEmail },
      { $set: updateFields },
      { returnDocument: 'after' }
    );

    const updatedUser = result.value || result;

    return res.status(200).json({
      success: true,
      message: 'Profile updated successfully',
      user: {
        id: updatedUser._id || updatedUser.id,
        name: updatedUser.name,
        email: updatedUser.email,
        role: updatedUser.role,
        image: updatedUser.image,
        phone: updatedUser.phone,
        area: updatedUser.area,
        bio: updatedUser.bio
      }
    });
  } catch (error) {
    console.error('Error updating profile:', error);
    return res.status(500).json({
      success: false,
      message: 'Internal server error updating profile'
    });
  }
});

// ==========================================
// 5. ERROR HANDLING & SERVER START
// ==========================================

// 404 Route Handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: `Route ${req.method} ${req.originalUrl} not found`
  });
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error('Unhandled server error:', err);
  res.status(500).json({
    success: false,
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

app.listen(port, () => {
  console.log(`FixMate Server is running on port ${port}`);
});
