import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { MongoClient, ObjectId } from 'mongodb';
import jwt from 'jsonwebtoken';
import Stripe from 'stripe';

const app = express();
const port = process.env.PORT || 5000;
const clientUrl = process.env.CLIENT_URL || 'http://localhost:3000';
const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;

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
            if (!sessionsCollection || !usersCollection) {
                await connectDB();
            }

            if (sessionsCollection && usersCollection) {
                // BetterAuth cookie tokens may be signed as "token.signature" or URL-encoded
                const cleanToken = decodeURIComponent(token).split('.')[0].replace(/^s:/, '');

                const session = await sessionsCollection.findOne({
                    $or: [
                        { token: token },
                        { token: cleanToken },
                        { id: token },
                        { id: cleanToken }
                    ]
                });

                if (session) {
                    const isExpired = new Date(session.expiresAt) < new Date();
                    if (!isExpired) {
                        let userQuery;
                        if (session.userId instanceof ObjectId) {
                            userQuery = { _id: session.userId };
                        } else if (typeof session.userId === 'string' && ObjectId.isValid(session.userId)) {
                            userQuery = { $or: [{ _id: new ObjectId(session.userId) }, { id: session.userId }] };
                        } else {
                            userQuery = { $or: [{ id: session.userId }, { _id: session.userId }] };
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

// ==========================================
// --- SEED ROUTE (IDEMPOTENT SAMPLE DATA) ---
// ==========================================
const SEED_TECHNICIANS = [
    {
        name: 'Tanvir Hasan',
        email: 'tanvir.tech@wefix.com',
        role: 'technician',
        phone: '+880 1711-223344',
        area: 'Dhanmondi, Dhaka',
        bio: 'Certified Apple & Dell hardware diagnostic specialist with 8+ years experience in micro-soldering, board repairs, and display replacements.',
        image: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&w=500&q=80',
        emailVerified: true,
        createdAt: new Date('2026-01-10T10:00:00Z')
    },
    {
        name: 'Karim Uddin',
        email: 'karim.repair@wefix.com',
        role: 'technician',
        phone: '+880 1822-334455',
        area: 'Mirpur & Uttara, Dhaka',
        bio: 'Master technician specializing in HVAC, AC gas refill, inverter refrigerators, and heavy appliance motor troubleshooting.',
        image: 'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?auto=format&fit=crop&w=500&q=80',
        emailVerified: true,
        createdAt: new Date('2026-01-12T10:00:00Z')
    }
];

const SEED_SERVICES = [
    {
        title: 'iPhone 13 & 14 OLED Screen Replacement',
        category: 'Smartphone',
        basePrice: 65,
        estimatedDuration: '1-2 hours',
        serviceMode: 'Shop Drop-off',
        serviceArea: 'Dhanmondi, Dhaka',
        technicianName: 'Tanvir Hasan',
        technicianEmail: 'tanvir.tech@wefix.com',
        approvalStatus: 'approved',
        isAvailable: true,
        image: 'https://images.unsplash.com/photo-1598327105666-5b89351aff97?auto=format&fit=crop&w=800&q=80',
        description: 'Genuine OLED display panel replacement with TrueTone restoration and waterproof seal installation. Fast turnaround with 90-day warranty included.',
        createdAt: new Date('2026-02-01T10:00:00Z')
    },
    {
        title: 'Samsung Galaxy Battery & Type-C Port Replacement',
        category: 'Smartphone',
        basePrice: 35,
        estimatedDuration: '1 hour',
        serviceMode: 'Home Visit',
        serviceArea: 'Mirpur, Dhaka',
        technicianName: 'Karim Uddin',
        technicianEmail: 'karim.repair@wefix.com',
        approvalStatus: 'approved',
        isAvailable: true,
        image: 'https://images.unsplash.com/photo-1580910051074-3eb694886505?auto=format&fit=crop&w=800&q=80',
        description: 'High-capacity OEM battery replacement and Type-C fast-charging port repair. Tested for thermal safety and peak battery endurance.',
        createdAt: new Date('2026-02-02T10:00:00Z')
    },
    {
        title: 'MacBook Pro Thermal Repaste & Fan Servicing',
        category: 'Laptop & PC',
        basePrice: 45,
        estimatedDuration: '2-3 hours',
        serviceMode: 'Shop Drop-off',
        serviceArea: 'Dhanmondi, Dhaka',
        technicianName: 'Tanvir Hasan',
        technicianEmail: 'tanvir.tech@wefix.com',
        approvalStatus: 'approved',
        isAvailable: true,
        image: 'https://images.unsplash.com/photo-1517336714731-489689fd1ca8?auto=format&fit=crop&w=800&q=80',
        description: 'Deep ultrasonic cleaning of dual cooling fans, Arctic MX-4 thermal paste re-application, and kernel thermal sensor calibration to eliminate thermal throttling.',
        createdAt: new Date('2026-02-03T10:00:00Z')
    },
    {
        title: 'Gaming PC Diagnostic & Motherboard Short Fix',
        category: 'Laptop & PC',
        basePrice: 70,
        estimatedDuration: '1 day',
        serviceMode: 'Home Visit',
        serviceArea: 'Gulshan & Banani, Dhaka',
        technicianName: 'Tanvir Hasan',
        technicianEmail: 'tanvir.tech@wefix.com',
        approvalStatus: 'approved',
        isAvailable: true,
        image: 'https://images.unsplash.com/photo-1587202372775-e229f172b9d7?auto=format&fit=crop&w=800&q=80',
        description: 'Comprehensive short-circuit testing, VRM mosfet replacement, BIOS reprogramming, and GPU stress stability testing using professional oscilloscope gear.',
        createdAt: new Date('2026-02-04T10:00:00Z')
    },
    {
        title: 'Split AC Deep Jet Foam Master Servicing',
        category: 'AC',
        basePrice: 30,
        estimatedDuration: '2 hours',
        serviceMode: 'Home Visit',
        serviceArea: 'Mirpur & Uttara, Dhaka',
        technicianName: 'Karim Uddin',
        technicianEmail: 'karim.repair@wefix.com',
        approvalStatus: 'approved',
        isAvailable: true,
        image: 'https://images.unsplash.com/photo-1621905251189-08b45d6a269e?auto=format&fit=crop&w=800&q=80',
        description: 'High-pressure jet wash for indoor cooling coil and outdoor condenser unit. Antibacterial foam treatment, blower wheel cleaning, and drain line flush.',
        createdAt: new Date('2026-02-05T10:00:00Z')
    },
    {
        title: 'Inverter AC R32/R410 Gas Refill & Leak Repair',
        category: 'AC',
        basePrice: 55,
        estimatedDuration: '2-3 hours',
        serviceMode: 'Home Visit',
        serviceArea: 'Dhanmondi & Mohammadpur, Dhaka',
        technicianName: 'Karim Uddin',
        technicianEmail: 'karim.repair@wefix.com',
        approvalStatus: 'approved',
        isAvailable: true,
        image: 'https://images.unsplash.com/photo-1581092160607-ee22621dd758?auto=format&fit=crop&w=800&q=80',
        description: 'Nitrogen pressure leak detection, copper pipe silver brazing, deep vacuumization, and full factory-spec gas charging with cooling pressure verification.',
        createdAt: new Date('2026-02-06T10:00:00Z')
    },
    {
        title: 'Frost-Free Refrigerator Cooling Defrost Repair',
        category: 'Refrigerator',
        basePrice: 40,
        estimatedDuration: '2-3 hours',
        serviceMode: 'Home Visit',
        serviceArea: 'Mirpur, Dhaka',
        technicianName: 'Karim Uddin',
        technicianEmail: 'karim.repair@wefix.com',
        approvalStatus: 'approved',
        isAvailable: true,
        image: 'https://images.unsplash.com/photo-1584992236310-6edddc08acff?auto=format&fit=crop&w=800&q=80',
        description: 'Troubleshooting bi-metal sensor, defrost timer, evaporator heater, and thermostat calibration for continuous, balanced freezing and fresh cooling.',
        createdAt: new Date('2026-02-07T10:00:00Z')
    },
    {
        title: 'Inverter Compressor Relay & Eco Gas Re-Charge',
        category: 'Refrigerator',
        basePrice: 60,
        estimatedDuration: '3-4 hours',
        serviceMode: 'Home Visit',
        serviceArea: 'Gulshan, Dhaka',
        technicianName: 'Karim Uddin',
        technicianEmail: 'karim.repair@wefix.com',
        approvalStatus: 'approved',
        isAvailable: true,
        image: 'https://images.unsplash.com/photo-1571175443880-49e1d25b2bc5?auto=format&fit=crop&w=800&q=80',
        description: 'Inverter drive board diagnosis, compressor starter relay replacement, and R600a eco gas recharging with capillary pipe cleaning.',
        createdAt: new Date('2026-02-08T10:00:00Z')
    },
    {
        title: 'Smart LED TV Backlight Strip Replacement',
        category: 'TV',
        basePrice: 50,
        estimatedDuration: '3-4 hours',
        serviceMode: 'Shop Drop-off',
        serviceArea: 'Dhanmondi, Dhaka',
        technicianName: 'Tanvir Hasan',
        technicianEmail: 'tanvir.tech@wefix.com',
        approvalStatus: 'approved',
        isAvailable: true,
        image: 'https://images.unsplash.com/photo-1593359677879-a4bb92f829d1?auto=format&fit=crop&w=800&q=80',
        description: 'Fix black screen with sound issues. Complete array replacement with brand-new high-brightness LED strips and uniform diffuser alignment.',
        createdAt: new Date('2026-02-09T10:00:00Z')
    },
    {
        title: '4K Smart TV Motherboard & Power Supply Fix',
        category: 'TV',
        basePrice: 65,
        estimatedDuration: '1 day',
        serviceMode: 'Home Visit',
        serviceArea: 'Uttara, Dhaka',
        technicianName: 'Tanvir Hasan',
        technicianEmail: 'tanvir.tech@wefix.com',
        approvalStatus: 'approved',
        isAvailable: true,
        image: 'https://images.unsplash.com/photo-1522869635100-9f4c5e86aa37?auto=format&fit=crop&w=800&q=80',
        description: 'Component-level board repair for TVs stuck on boot loop, no power, or dead HDMI ports. Includes firmware recovery and voltage rail stabilization.',
        createdAt: new Date('2026-02-10T10:00:00Z')
    },
    {
        title: 'Front Load Washing Machine Drum Bearing & Seal',
        category: 'Washing Machine',
        basePrice: 55,
        estimatedDuration: '3-4 hours',
        serviceMode: 'Home Visit',
        serviceArea: 'Mirpur & Dhanmondi, Dhaka',
        technicianName: 'Karim Uddin',
        technicianEmail: 'karim.repair@wefix.com',
        approvalStatus: 'approved',
        isAvailable: true,
        image: 'https://images.unsplash.com/photo-1626806787461-102c1bfaaea1?auto=format&fit=crop&w=800&q=80',
        description: 'Elimination of loud rattling noise during high-speed spin cycle. Heavy-duty SKF bearing installation with water-tight rubber gasket seal.',
        createdAt: new Date('2026-02-11T10:00:00Z')
    },
    {
        title: 'Top Load Drain Pump & PCB Control Repair',
        category: 'Washing Machine',
        basePrice: 35,
        estimatedDuration: '1-2 hours',
        serviceMode: 'Home Visit',
        serviceArea: 'Uttara, Dhaka',
        technicianName: 'Karim Uddin',
        technicianEmail: 'karim.repair@wefix.com',
        approvalStatus: 'approved',
        isAvailable: true,
        image: 'https://images.unsplash.com/photo-1582735689369-4fe89db7114c?auto=format&fit=crop&w=800&q=80',
        description: 'Fix drainage error codes (OE/E2), drain motor replacement, water inlet valve solenoid cleaning, and drum suspension vibration calibration.',
        createdAt: new Date('2026-02-12T10:00:00Z')
    },
    {
        title: 'Home Distribution Box & Circuit Breaker Overhaul',
        category: 'Electrical',
        basePrice: 40,
        estimatedDuration: '2-3 hours',
        serviceMode: 'Home Visit',
        serviceArea: 'Dhanmondi & Lalmatia, Dhaka',
        technicianName: 'Karim Uddin',
        technicianEmail: 'karim.repair@wefix.com',
        approvalStatus: 'approved',
        isAvailable: true,
        image: 'https://images.unsplash.com/photo-1621905252507-b35492cc74b4?auto=format&fit=crop&w=800&q=80',
        description: 'Replacement of faulty MCB/RCCB breakers, load balancing across phases, neutral wire short protection, and total earth grounding test.',
        createdAt: new Date('2026-02-13T10:00:00Z')
    },
    {
        title: 'Short Circuit Emergency Diagnostic & Concealed Rewiring',
        category: 'Electrical',
        basePrice: 45,
        estimatedDuration: '2-4 hours',
        serviceMode: 'Home Visit',
        serviceArea: 'Gulshan & Banani, Dhaka',
        technicianName: 'Karim Uddin',
        technicianEmail: 'karim.repair@wefix.com',
        approvalStatus: 'approved',
        isAvailable: true,
        image: 'https://images.unsplash.com/photo-1544716278-ca5e3f4abd8c?auto=format&fit=crop&w=800&q=80',
        description: 'Megger insulation resistance testing, concealed wall wire fault tracing, thermal imaging for overheated junctions, and safe conduit re-routing.',
        createdAt: new Date('2026-02-14T10:00:00Z')
    }
];

export async function runSeedData() {
    let techCount = 0;
    let serviceCount = 0;

    // 1. Upsert Technicians into 'user' collection
    for (const tech of SEED_TECHNICIANS) {
        await usersCollection.updateOne(
            { email: tech.email },
            { $set: tech },
            { upsert: true }
        );
        techCount++;
    }

    // 2. Upsert Services into 'services' collection
    for (const s of SEED_SERVICES) {
        await servicesCollection.updateOne(
            { title: s.title },
            { $set: s },
            { upsert: true }
        );
        serviceCount++;
    }

    return { techCount, serviceCount };
}

// Endpoint to trigger idempotent seed (Safe & sanitized: no unauthenticated role escalation)
app.all('/api/seed', async (req, res) => {
    try {
        const { techCount, serviceCount } = await runSeedData();
        return res.status(200).json({
            success: true,
            message: 'Idempotent seed completed successfully',
            techniciansUpserted: techCount,
            servicesUpserted: serviceCount
        });
    } catch (error) {
        console.error('Seed error:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to seed sample data',
            error: error.message
        });
    }
});

// --- SERVICES ROUTES (PUBLIC) ---
/**
 * GET /api/services
 * Returns approved and available repair services with optional search, category, mode, sort, and limit.
 */
app.get('/api/services', async (req, res) => {
    try {
        const { search, category, serviceMode, sort, limit, page } = req.query;

        const query = {
            approvalStatus: 'approved',
            isAvailable: true
        };

        if (category && category !== 'All') {
            query.category = category;
        }

        if (serviceMode && serviceMode !== 'All') {
            query.serviceMode = serviceMode;
        }

        if (search && typeof search === 'string' && search.trim()) {
            const regex = new RegExp(search.trim(), 'i');
            query.$or = [
                { title: regex },
                { category: regex },
                { description: regex },
                { serviceArea: regex }
            ];
        }

        let sortOption = { createdAt: -1 };
        if (sort === 'price_asc') {
            sortOption = { basePrice: 1 };
        } else if (sort === 'price_desc') {
            sortOption = { basePrice: -1 };
        } else if (sort === 'newest') {
            sortOption = { createdAt: -1 };
        }

        const total = await servicesCollection.countDocuments(query);

        let cursor = servicesCollection.find(query).sort(sortOption);

        const parsedLimit = limit ? parseInt(limit, 10) : 0;
        const parsedPage = page ? parseInt(page, 10) : 1;

        if (parsedLimit > 0) {
            const skip = (parsedPage - 1) * parsedLimit;
            cursor = cursor.skip(skip).limit(parsedLimit);
        }

        const services = await cursor.toArray();

        return res.status(200).json({
            success: true,
            count: services.length,
            total,
            page: parsedPage,
            services
        });
    } catch (error) {
        console.error('Error fetching services:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to retrieve services'
        });
    }
});

/**
 * GET /api/services/:id
 * Returns a single approved service with technician details
 */
app.get('/api/services/:id', async (req, res) => {
    try {
        const { id } = req.params;
        let query;
        if (ObjectId.isValid(id)) {
            query = { _id: new ObjectId(id) };
        } else {
            query = { id: id };
        }

        const service = await servicesCollection.findOne(query);

        if (!service || service.approvalStatus !== 'approved' || service.isAvailable === false) {
            return res.status(404).json({
                success: false,
                message: 'Service not found or not currently available'
            });
        }

        // Attach technician profile details
        let technician = null;
        if (service.technicianEmail) {
            technician = await usersCollection.findOne(
                { email: service.technicianEmail },
                { projection: { name: 1, email: 1, image: 1, phone: 1, area: 1, bio: 1 } }
            );
        }

        return res.status(200).json({
            success: true,
            service,
            technician: technician || {
                name: service.technicianName,
                email: service.technicianEmail,
                area: service.serviceArea || '',
                bio: ''
            }
        });
    } catch (error) {
        console.error('Error fetching service details:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to retrieve service details'
        });
    }
});

// ==========================================
// --- BOOKINGS ROUTES ---
// ==========================================

/**
 * POST /api/bookings
 * Submits a new repair request (Customer only)
 * Enforces duplicate active request prevention and snapshot copying
 */
app.post('/api/bookings', verifyToken, verifyCustomer, async (req, res) => {
    try {
        const { serviceId, customerPhone, address, preferredDate, problemDescription } = req.body;

        // Validation
        if (!serviceId) {
            return res.status(400).json({ success: false, message: 'Service ID is required' });
        }
        if (!customerPhone || typeof customerPhone !== 'string' || !customerPhone.trim()) {
            return res.status(400).json({ success: false, message: 'Valid contact phone number is required' });
        }
        if (!address || typeof address !== 'string' || !address.trim()) {
            return res.status(400).json({ success: false, message: 'Service/pickup address is required' });
        }
        if (!preferredDate) {
            return res.status(400).json({ success: false, message: 'Preferred service date is required' });
        }

        const dateObj = new Date(preferredDate);
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        if (isNaN(dateObj.getTime()) || dateObj < today) {
            return res.status(400).json({ success: false, message: 'Preferred date must be today or a future date' });
        }

        if (!problemDescription || typeof problemDescription !== 'string' || problemDescription.trim().length < 20) {
            return res.status(400).json({
                success: false,
                message: 'Problem description must be at least 20 characters long'
            });
        }

        // Verify service exists and is approved & available
        let serviceQuery;
        if (ObjectId.isValid(serviceId)) {
            serviceQuery = { _id: new ObjectId(serviceId) };
        } else {
            serviceQuery = { id: serviceId };
        }

        const service = await servicesCollection.findOne(serviceQuery);
        if (!service || service.approvalStatus !== 'approved' || service.isAvailable === false) {
            return res.status(404).json({
                success: false,
                message: 'This service is currently unavailable for booking'
            });
        }

        // Business Rule: Technician cannot request their own service
        if (service.technicianEmail === req.user.email) {
            return res.status(400).json({
                success: false,
                message: 'You cannot request your own service'
            });
        }

        // Business Rule: Duplicate active request prevention
        // A customer cannot have two active requests (requested, accepted or in-progress) for the same service
        const existingActiveBooking = await bookingsCollection.findOne({
            $or: [
                { serviceId: service._id.toString() },
                { serviceId: serviceId }
            ],
            customerEmail: req.user.email,
            status: { $in: ['requested', 'accepted', 'in-progress'] }
        });

        if (existingActiveBooking) {
            return res.status(409).json({
                success: false,
                message: 'You already have an active request for this service'
            });
        }

        // Snapshot fields from service & user
        const newBooking = {
            serviceId: service._id.toString(),
            serviceTitle: service.title,
            serviceImage: service.image || '',
            category: service.category,
            basePrice: Number(service.basePrice),
            technicianName: service.technicianName,
            technicianEmail: service.technicianEmail,
            customerName: req.user.name,
            customerEmail: req.user.email,
            customerPhone: customerPhone.trim(),
            address: address.trim(),
            preferredDate: dateObj,
            problemDescription: problemDescription.trim(),
            status: 'requested',
            finalAmount: Number(service.basePrice), // Initial final amount equals base price
            paymentStatus: 'unpaid',
            createdAt: new Date(),
            statusHistory: [
                { status: 'requested', changedAt: new Date() }
            ]
        };

        const result = await bookingsCollection.insertOne(newBooking);

        return res.status(201).json({
            success: true,
            message: 'Repair request submitted successfully',
            bookingId: result.insertedId
        });
    } catch (error) {
        console.error('Error creating booking request:', error);
        return res.status(500).json({
            success: false,
            message: 'Internal server error processing repair request'
        });
    }
});


// ==========================================
// --- CUSTOMER BOOKING ROUTES (PROTECTED) ---
// ==========================================

/**
 * GET /api/bookings/my
 * Returns all bookings belonging to the logged-in customer (sorted newest first)
 */
app.get('/api/bookings/my', verifyToken, verifyCustomer, async (req, res) => {
    try {
        const bookings = await bookingsCollection
            .find({ customerEmail: req.user.email })
            .sort({ createdAt: -1 })
            .toArray();

        return res.status(200).json({
            success: true,
            count: bookings.length,
            bookings
        });
    } catch (error) {
        console.error('Error fetching customer bookings:', error);
        return res.status(500).json({ success: false, message: 'Failed to retrieve your bookings' });
    }
});

/**
 * PATCH /api/bookings/:id/cancel
 * Allows a customer to cancel their own repair request ONLY if status is 'requested'
 */
app.patch('/api/bookings/:id/cancel', verifyToken, verifyCustomer, async (req, res) => {
    try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) {
            return res.status(400).json({ success: false, message: 'Invalid booking ID format' });
        }

        const booking = await bookingsCollection.findOne({ _id: new ObjectId(id) });
        if (!booking) {
            return res.status(404).json({ success: false, message: 'Repair request not found' });
        }

        // Ownership enforcement
        if (booking.customerEmail !== req.user.email) {
            return res.status(403).json({ success: false, message: 'Unauthorized: You do not own this repair request' });
        }

        // Only allow cancellation if status is 'requested'
        if (booking.status !== 'requested') {
            return res.status(400).json({
                success: false,
                message: `Cannot cancel a request that has already been ${booking.status}. Only requests in 'requested' status can be cancelled.`
            });
        }

        const statusEntry = {
            status: 'cancelled',
            changedAt: new Date(),
            changedBy: req.user.email,
            note: 'Cancelled by customer'
        };

        const result = await bookingsCollection.findOneAndUpdate(
            { _id: new ObjectId(id) },
            {
                $set: {
                    status: 'cancelled',
                    updatedAt: new Date()
                },
                $push: { statusHistory: statusEntry }
            },
            { returnDocument: 'after' }
        );

        return res.status(200).json({
            success: true,
            message: 'Repair request cancelled successfully',
            booking: result.value || result
        });
    } catch (error) {
        console.error('Error cancelling booking:', error);
        return res.status(500).json({ success: false, message: 'Failed to cancel repair request' });
    }
});

// ==========================================
// --- TECHNICIAN ROUTES (PROTECTED) ---
// ==========================================

/**
 * GET /api/services/technician
 * Returns all services belonging to the logged-in technician
 */
app.get('/api/services/technician', verifyToken, verifyTechnician, async (req, res) => {
    try {
        const services = await servicesCollection
            .find({ technicianEmail: req.user.email })
            .sort({ createdAt: -1 })
            .toArray();

        return res.status(200).json({
            success: true,
            count: services.length,
            services
        });
    } catch (error) {
        console.error('Error fetching technician services:', error);
        return res.status(500).json({ success: false, message: 'Failed to retrieve your services' });
    }
});

/**
 * POST /api/services
 * Creates a new service under the logged-in technician (Status defaults to 'pending')
 */
app.post('/api/services', verifyToken, verifyTechnician, async (req, res) => {
    try {
        const {
            title,
            category,
            description,
            basePrice,
            estimatedDuration,
            serviceMode,
            serviceArea,
            image
        } = req.body;

        if (!title || !category || !description || !basePrice || !estimatedDuration || !serviceMode || !serviceArea || !image) {
            return res.status(400).json({ success: false, message: 'All fields including image are required' });
        }

        const priceNum = Number(basePrice);
        if (isNaN(priceNum) || priceNum <= 0) {
            return res.status(400).json({ success: false, message: 'Base price must be a positive number' });
        }

        const newService = {
            title: title.trim(),
            category: category.trim(),
            description: description.trim(),
            basePrice: priceNum,
            estimatedDuration: estimatedDuration.trim(),
            serviceMode: serviceMode.trim(),
            serviceArea: serviceArea.trim(),
            image: image.trim(),
            technicianName: req.user.name,
            technicianEmail: req.user.email,
            approvalStatus: 'pending', // Awaiting admin approval
            isAvailable: true,
            createdAt: new Date()
        };

        const result = await servicesCollection.insertOne(newService);

        return res.status(201).json({
            success: true,
            message: 'Service created successfully and is waiting for admin approval',
            serviceId: result.insertedId
        });
    } catch (error) {
        console.error('Error creating service:', error);
        return res.status(500).json({ success: false, message: 'Failed to create service' });
    }
});

/**
 * PATCH /api/services/:id
 * Updates an existing service owned by the logged-in technician
 * Resets approvalStatus back to 'pending' upon editing
 */
app.patch('/api/services/:id', verifyToken, verifyTechnician, async (req, res) => {
    try {
        const { id } = req.params;
        let query;
        if (ObjectId.isValid(id)) query = { _id: new ObjectId(id) };
        else query = { id: id };

        const service = await servicesCollection.findOne(query);
        if (!service) {
            return res.status(404).json({ success: false, message: 'Service not found' });
        }

        if (service.technicianEmail !== req.user.email) {
            return res.status(403).json({ success: false, message: 'Forbidden: You do not own this service' });
        }

        const {
            title,
            category,
            description,
            basePrice,
            estimatedDuration,
            serviceMode,
            serviceArea,
            image
        } = req.body;

        const updateFields = {
            updatedAt: new Date(),
            approvalStatus: 'pending' // Rule: Editing resets status to pending
        };

        if (title) updateFields.title = title.trim();
        if (category) updateFields.category = category.trim();
        if (description) updateFields.description = description.trim();
        if (basePrice) {
            const p = Number(basePrice);
            if (p > 0) updateFields.basePrice = p;
        }
        if (estimatedDuration) updateFields.estimatedDuration = estimatedDuration.trim();
        if (serviceMode) updateFields.serviceMode = serviceMode.trim();
        if (serviceArea) updateFields.serviceArea = serviceArea.trim();
        if (image) updateFields.image = image.trim();

        const result = await servicesCollection.findOneAndUpdate(
            query,
            { $set: updateFields },
            { returnDocument: 'after' }
        );

        return res.status(200).json({
            success: true,
            message: 'Service updated successfully and reset to pending approval',
            service: result.value || result
        });
    } catch (error) {
        console.error('Error updating service:', error);
        return res.status(500).json({ success: false, message: 'Failed to update service' });
    }
});

/**
 * DELETE /api/services/:id
 * Deletes a service owned by the logged-in technician
 */
app.delete('/api/services/:id', verifyToken, verifyTechnician, async (req, res) => {
    try {
        const { id } = req.params;
        let query;
        if (ObjectId.isValid(id)) query = { _id: new ObjectId(id) };
        else query = { id: id };

        const service = await servicesCollection.findOne(query);
        if (!service) {
            return res.status(404).json({ success: false, message: 'Service not found' });
        }

        if (service.technicianEmail !== req.user.email) {
            return res.status(403).json({ success: false, message: 'Forbidden: You do not own this service' });
        }

        await servicesCollection.deleteOne(query);

        return res.status(200).json({
            success: true,
            message: 'Service deleted successfully'
        });
    } catch (error) {
        console.error('Error deleting service:', error);
        return res.status(500).json({ success: false, message: 'Failed to delete service' });
    }
});

/**
 * PATCH /api/services/:id/availability
 * Toggles isAvailable for a technician's service
 */
app.patch('/api/services/:id/availability', verifyToken, verifyTechnician, async (req, res) => {
    try {
        const { id } = req.params;
        let query;
        if (ObjectId.isValid(id)) query = { _id: new ObjectId(id) };
        else query = { id: id };

        const service = await servicesCollection.findOne(query);
        if (!service) {
            return res.status(404).json({ success: false, message: 'Service not found' });
        }

        if (service.technicianEmail !== req.user.email) {
            return res.status(403).json({ success: false, message: 'Forbidden: You do not own this service' });
        }

        const isAvailable = Boolean(req.body.isAvailable);

        await servicesCollection.updateOne(
            query,
            { $set: { isAvailable, updatedAt: new Date() } }
        );

        return res.status(200).json({
            success: true,
            message: `Service availability turned ${isAvailable ? 'ON' : 'OFF'}`,
            isAvailable
        });
    } catch (error) {
        console.error('Error toggling availability:', error);
        return res.status(500).json({ success: false, message: 'Failed to update availability' });
    }
});

/**
 * GET /api/bookings/technician
 * Returns all bookings assigned to the logged-in technician
 */
app.get('/api/bookings/technician', verifyToken, verifyTechnician, async (req, res) => {
    try {
        const query = { technicianEmail: req.user.email };
        const { status } = req.query;

        if (status && status !== 'All') {
            query.status = status;
        }

        const bookings = await bookingsCollection.find(query).sort({ createdAt: -1 }).toArray();

        return res.status(200).json({
            success: true,
            count: bookings.length,
            bookings
        });
    } catch (error) {
        console.error('Error fetching technician bookings:', error);
        return res.status(500).json({ success: false, message: 'Failed to retrieve bookings' });
    }
});

/**
 * PATCH /api/bookings/:id/status
 * Server-Enforced Job Status Pipeline (Challenge 3)
 * Only the assigned technician can move the job forward
 */
app.patch('/api/bookings/:id/status', verifyToken, verifyTechnician, async (req, res) => {
    try {
        const { id } = req.params;
        const { status: targetStatus, finalAmount } = req.body;

        let query;
        if (ObjectId.isValid(id)) query = { _id: new ObjectId(id) };
        else query = { id: id };

        const booking = await bookingsCollection.findOne(query);
        if (!booking) {
            return res.status(404).json({ success: false, message: 'Booking not found' });
        }

        // Ownership enforcement
        if (booking.technicianEmail !== req.user.email) {
            return res.status(403).json({
                success: false,
                message: 'Forbidden: You are not assigned to this job'
            });
        }

        const currentStatus = booking.status;

        // Strict state transitions:
        // requested -> accepted OR rejected
        // accepted -> in-progress
        // in-progress -> completed (requires finalAmount > 0)
        let isValidTransition = false;

        if (currentStatus === 'requested' && (targetStatus === 'accepted' || targetStatus === 'rejected')) {
            isValidTransition = true;
        } else if (currentStatus === 'accepted' && targetStatus === 'in-progress') {
            isValidTransition = true;
        } else if (currentStatus === 'in-progress' && targetStatus === 'completed') {
            isValidTransition = true;
        }

        if (!isValidTransition) {
            return res.status(400).json({
                success: false,
                message: `Invalid status transition from '${currentStatus}' to '${targetStatus}'. Illegal step rejected by server.`
            });
        }

        const updateSet = {
            status: targetStatus,
            updatedAt: new Date()
        };

        // When moving to 'completed', validate finalAmount
        if (targetStatus === 'completed') {
            const amountNum = Number(finalAmount);
            if (!finalAmount || isNaN(amountNum) || amountNum <= 0) {
                return res.status(400).json({
                    success: false,
                    message: 'Final amount must be a number greater than 0 when completing a job'
                });
            }
            updateSet.finalAmount = amountNum;
        }

        const result = await bookingsCollection.findOneAndUpdate(
            query,
            {
                $set: updateSet,
                $push: {
                    statusHistory: { status: targetStatus, changedAt: new Date() }
                }
            },
            { returnDocument: 'after' }
        );

        return res.status(200).json({
            success: true,
            message: `Job status successfully updated to '${targetStatus}'`,
            booking: result.value || result
        });
    } catch (error) {
        console.error('Error updating booking status:', error);
        return res.status(500).json({ success: false, message: 'Failed to update job status' });
    }
});

// ==========================================
// --- ADMIN ROUTES (PROTECTED) ---
// ==========================================

/**
 * GET /api/admin/overview
 * Returns aggregate metrics for admin overview
 */
app.get('/api/admin/overview', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const totalUsers = await usersCollection.countDocuments({});
        const totalTechnicians = await usersCollection.countDocuments({ role: 'technician' });
        const pendingServices = await servicesCollection.countDocuments({ approvalStatus: 'pending' });
        const totalBookings = await bookingsCollection.countDocuments({});
        
        const payments = await paymentsCollection.find({}).toArray();
        const totalRevenue = payments.reduce((acc, p) => acc + (Number(p.amount) || 0), 0);

        return res.status(200).json({
            success: true,
            totalUsers,
            totalTechnicians,
            pendingServices,
            totalBookings,
            totalRevenue
        });
    } catch (error) {
        console.error('Error fetching admin overview:', error);
        return res.status(500).json({ success: false, message: 'Failed to fetch admin overview' });
    }
});

/**
 * GET /api/admin/users
 * Returns all registered users
 */
app.get('/api/admin/users', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const users = await usersCollection
            .find({}, { projection: { password: 0 } })
            .sort({ createdAt: -1 })
            .toArray();

        return res.status(200).json({
            success: true,
            count: users.length,
            users
        });
    } catch (error) {
        console.error('Error fetching admin users:', error);
        return res.status(500).json({ success: false, message: 'Failed to retrieve users' });
    }
});

/**
 * PATCH /api/admin/users/:id/role
 * Allows an admin to change a user's role (customer / technician / admin)
 * Strictly prevents an admin from changing their own role
 */
app.patch('/api/admin/users/:id/role', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { role: newRole } = req.body;

        if (!newRole || !['customer', 'technician', 'admin'].includes(newRole)) {
            return res.status(400).json({
                success: false,
                message: "Role must be 'customer', 'technician', or 'admin'"
            });
        }

        let query;
        if (ObjectId.isValid(id)) query = { _id: new ObjectId(id) };
        else query = { id: id };

        const targetUser = await usersCollection.findOne(query);
        if (!targetUser) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        // Strict Rule: Admin cannot modify their own role
        const targetIdStr = targetUser._id ? targetUser._id.toString() : targetUser.id;
        const reqUserIdStr = req.user._id ? req.user._id.toString() : req.user.id;

        if (targetUser.email === req.user.email || targetIdStr === reqUserIdStr) {
            return res.status(400).json({
                success: false,
                message: 'Forbidden: Administrators cannot modify their own role'
            });
        }

        const result = await usersCollection.findOneAndUpdate(
            query,
            { $set: { role: newRole, updatedAt: new Date() } },
            { returnDocument: 'after' }
        );

        return res.status(200).json({
            success: true,
            message: `User role successfully updated to '${newRole}'`,
            user: result.value || result
        });
    } catch (error) {
        console.error('Error updating user role:', error);
        return res.status(500).json({ success: false, message: 'Failed to update user role' });
    }
});

/**
 * GET /api/admin/services
 * Returns all services across all technicians with optional approvalStatus filter
 */
app.get('/api/admin/services', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { approvalStatus } = req.query;
        const query = {};

        if (approvalStatus && approvalStatus !== 'all') {
            query.approvalStatus = approvalStatus;
        }

        const services = await servicesCollection
            .find(query)
            .sort({ createdAt: -1 })
            .toArray();

        return res.status(200).json({
            success: true,
            count: services.length,
            services
        });
    } catch (error) {
        console.error('Error fetching admin services:', error);
        return res.status(500).json({ success: false, message: 'Failed to retrieve services' });
    }
});

/**
 * PATCH /api/admin/services/:id/approval
 * Approves or Rejects a technician service
 */
app.patch('/api/admin/services/:id/approval', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { approvalStatus } = req.body;

        if (!approvalStatus || !['approved', 'rejected'].includes(approvalStatus)) {
            return res.status(400).json({
                success: false,
                message: "Approval status must be either 'approved' or 'rejected'"
            });
        }

        let query;
        if (ObjectId.isValid(id)) query = { _id: new ObjectId(id) };
        else query = { id: id };

        const result = await servicesCollection.findOneAndUpdate(
            query,
            { $set: { approvalStatus, updatedAt: new Date() } },
            { returnDocument: 'after' }
        );

        if (!result) {
            return res.status(404).json({ success: false, message: 'Service not found' });
        }

        return res.status(200).json({
            success: true,
            message: `Service successfully ${approvalStatus}`,
            service: result.value || result
        });
    } catch (error) {
        console.error('Error updating service approval status:', error);
        return res.status(500).json({ success: false, message: 'Failed to update approval status' });
    }
});

/**
 * GET /api/admin/bookings
 * Returns all bookings across the platform
 */
app.get('/api/admin/bookings', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { status } = req.query;
        const query = {};

        if (status && status !== 'All') {
            query.status = status;
        }

        const bookings = await bookingsCollection
            .find(query)
            .sort({ createdAt: -1 })
            .toArray();

        return res.status(200).json({
            success: true,
            count: bookings.length,
            bookings
        });
    } catch (error) {
        console.error('Error fetching admin bookings:', error);
        return res.status(500).json({ success: false, message: 'Failed to retrieve bookings' });
    }
});

/**
 * GET /api/admin/payments
 * Returns all payments and total revenue across the platform
 */
app.get('/api/admin/payments', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const payments = await paymentsCollection
            .find({})
            .sort({ paidAt: -1 })
            .toArray();

        const totalRevenue = payments.reduce((acc, p) => acc + (Number(p.amount) || 0), 0);

        return res.status(200).json({
            success: true,
            count: payments.length,
            totalRevenue,
            payments
        });
    } catch (error) {
        console.error('Error fetching admin payments:', error);
        return res.status(500).json({ success: false, message: 'Failed to retrieve payments' });
    }
});

// ==========================================
// --- PAYMENT ROUTES (STRIPE & CUSTOMER) ---
// ==========================================

/**
 * GET /api/payments/my
 * Returns all payments made by the logged-in customer (newest first)
 */
app.get('/api/payments/my', verifyToken, verifyCustomer, async (req, res) => {
    try {
        const payments = await paymentsCollection
            .find({ customerEmail: req.user.email })
            .sort({ paidAt: -1, createdAt: -1 })
            .toArray();

        return res.status(200).json({
            success: true,
            count: payments.length,
            payments
        });
    } catch (error) {
        console.error('Error fetching customer payments:', error);
        return res.status(500).json({ success: false, message: 'Failed to retrieve payment history' });
    }
});

/**
 * POST /api/payments/create-checkout-session
 * Creates a Stripe Checkout Session for a completed repair job
 * Enforces ownership, status === 'completed', and paymentStatus === 'unpaid'
 */
app.post('/api/payments/create-checkout-session', verifyToken, verifyCustomer, async (req, res) => {
    try {
        if (!stripe) {
            return res.status(500).json({
                success: false,
                message: 'Stripe is not configured. Missing STRIPE_SECRET_KEY in server environment.'
            });
        }

        const { bookingId } = req.body;
        if (!bookingId || !ObjectId.isValid(bookingId)) {
            return res.status(400).json({ success: false, message: 'Valid booking ID is required' });
        }

        const booking = await bookingsCollection.findOne({ _id: new ObjectId(bookingId) });
        if (!booking) {
            return res.status(404).json({ success: false, message: 'Repair request not found' });
        }

        // Ownership enforcement
        if (booking.customerEmail !== req.user.email) {
            return res.status(403).json({ success: false, message: 'Unauthorized: You do not own this repair request' });
        }

        // Enforce completed and unpaid status
        if (booking.status !== 'completed') {
            return res.status(400).json({
                success: false,
                message: `Payment can only be made for completed repair requests. Current status is '${booking.status}'.`
            });
        }

        if (booking.paymentStatus === 'paid') {
            return res.status(400).json({
                success: false,
                message: 'This repair request has already been paid.'
            });
        }

        const amountToPay = Number(booking.finalAmount ?? booking.basePrice);
        if (isNaN(amountToPay) || amountToPay <= 0) {
            return res.status(400).json({
                success: false,
                message: 'Invalid final repair amount on this booking.'
            });
        }

        const unitAmountInCents = Math.round(amountToPay * 100);

        const images = [];
        if (booking.serviceImage && typeof booking.serviceImage === 'string' && booking.serviceImage.startsWith('http')) {
            images.push(booking.serviceImage);
        }

        const session = await stripe.checkout.sessions.create({
            line_items: [
                {
                    price_data: {
                        currency: 'usd',
                        product_data: {
                            name: `WeFix: ${booking.serviceTitle || 'Repair Service'}`,
                            description: `Technician: ${booking.technicianName} | Booking Ref: ${booking._id.toString()}`,
                            images
                        },
                        unit_amount: unitAmountInCents
                    },
                    quantity: 1
                }
            ],
            mode: 'payment',
            customer_email: req.user.email,
            client_reference_id: booking._id.toString(),
            metadata: {
                bookingId: booking._id.toString(),
                customerEmail: req.user.email,
                customerName: req.user.name || '',
                technicianEmail: booking.technicianEmail || '',
                technicianName: booking.technicianName || '',
                serviceTitle: booking.serviceTitle || 'Repair Service',
                finalAmount: String(amountToPay)
            },
            success_url: `${clientUrl}/payment/success?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${clientUrl}/payment/cancel?booking_id=${booking._id}`
        });

        return res.status(200).json({
            success: true,
            url: session.url,
            sessionId: session.id
        });
    } catch (error) {
        console.error('Error creating Stripe checkout session:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to create checkout session',
            error: error.message
        });
    }
});

/**
 * GET /api/payments/verify
 * Verifies a paid Stripe session and records the transaction idempotently
 */
app.get('/api/payments/verify', verifyToken, async (req, res) => {
    try {
        if (!stripe) {
            return res.status(500).json({ success: false, message: 'Stripe is not configured' });
        }

        const { session_id } = req.query;
        if (!session_id || typeof session_id !== 'string') {
            return res.status(400).json({ success: false, message: 'Missing session_id query parameter' });
        }

        // Retrieve Stripe checkout session
        const checkoutSession = await stripe.checkout.sessions.retrieve(session_id);
        if (!checkoutSession) {
            return res.status(404).json({ success: false, message: 'Stripe session not found' });
        }

        if (checkoutSession.payment_status !== 'paid') {
            return res.status(400).json({
                success: false,
                message: `Payment status is '${checkoutSession.payment_status}'. Payment was not completed.`
            });
        }

        const bookingIdStr = checkoutSession.metadata?.bookingId || checkoutSession.client_reference_id;
        if (!bookingIdStr || !ObjectId.isValid(bookingIdStr)) {
            return res.status(400).json({ success: false, message: 'Missing valid booking reference in payment session' });
        }

        const bookingId = new ObjectId(bookingIdStr);

        // Idempotency: check if payment record already exists
        const existingPayment = await paymentsCollection.findOne({
            $or: [
                { stripeSessionId: session_id },
                { bookingId }
            ]
        });

        if (existingPayment) {
            return res.status(200).json({
                success: true,
                message: 'Payment already processed and recorded',
                payment: existingPayment
            });
        }

        // Fetch original booking
        const booking = await bookingsCollection.findOne({ _id: bookingId });

        const amountPaid = (checkoutSession.amount_total || 0) / 100;

        const newPayment = {
            bookingId,
            stripeSessionId: session_id,
            stripePaymentIntentId: checkoutSession.payment_intent || '',
            customerEmail: checkoutSession.metadata?.customerEmail || (booking ? booking.customerEmail : req.user.email),
            customerName: checkoutSession.metadata?.customerName || (booking ? booking.customerName : req.user.name),
            technicianEmail: checkoutSession.metadata?.technicianEmail || (booking ? booking.technicianEmail : ''),
            technicianName: checkoutSession.metadata?.technicianName || (booking ? booking.technicianName : ''),
            serviceTitle: checkoutSession.metadata?.serviceTitle || (booking ? booking.serviceTitle : 'Repair Service'),
            serviceCategory: booking ? booking.serviceCategory : '',
            amount: amountPaid,
            currency: checkoutSession.currency || 'usd',
            paymentStatus: 'paid',
            paymentMethod: 'card',
            paidAt: new Date(),
            createdAt: new Date()
        };

        const insertResult = await paymentsCollection.insertOne(newPayment);
        newPayment._id = insertResult.insertedId;

        // Update the booking status and paymentStatus
        const statusEntry = {
            status: 'completed',
            changedAt: new Date(),
            changedBy: req.user ? req.user.email : 'stripe',
            note: `Payment of $${amountPaid.toFixed(2)} completed successfully via Stripe (Session: ${session_id.slice(-8)})`
        };

        await bookingsCollection.updateOne(
            { _id: bookingId },
            {
                $set: {
                    paymentStatus: 'paid',
                    stripeSessionId: session_id,
                    stripePaymentIntentId: checkoutSession.payment_intent || '',
                    paidAt: new Date(),
                    updatedAt: new Date()
                },
                $push: { statusHistory: statusEntry }
            }
        );

        return res.status(200).json({
            success: true,
            message: 'Payment verified and recorded successfully',
            payment: newPayment
        });
    } catch (error) {
        console.error('Error verifying payment:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to verify payment session',
            error: error.message
        });
    }
});

// ==========================================
// --- USER PROFILE ROUTE ---
// ==========================================
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
