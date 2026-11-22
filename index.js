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
                // BetterAuth cookie tokens may be signed as "token.signature" or URL-encoded
                const cleanToken = decodeURIComponent(token).split('.')[0].replace(/^s:/, '');

                const session = await sessionsCollection.findOne({
                    $or: [
                        { token: token },
                        { token: cleanToken }
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

// Endpoint to trigger idempotent seed
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
