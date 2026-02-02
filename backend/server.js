require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

const app = express();

// CORS configuration
app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        if (process.env.NODE_ENV !== 'production') return callback(null, true);
        const allowedOrigins = [
            'https://playful-rugelach-33592e.netlify.app',
            'https://lively-kataifi-011ede.netlify.app',
            'http://localhost:3000',
            'http://localhost:5000'
        ];
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = 'The CORS policy does not allow access from this Origin.';
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Create directories if they don't exist (for development)
const directories = ['frontend', 'admin-panel'];
directories.forEach(dir => {
    const dirPath = path.join(__dirname, '..', dir);
    if (!fs.existsSync(dirPath)) {
        fs.mkdirSync(dirPath, { recursive: true });
    }
});

// Serve static files from correct paths
app.use(express.static(path.join(__dirname, '..', 'frontend')));
app.use('/admin', express.static(path.join(__dirname, '..', 'admin-panel')));

// Routes for serving HTML
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'frontend', 'index.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'admin-panel', 'admin.html'));
});

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/alnoor-perfume';
let isMongoConnected = false;

mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
})
.then(() => {
    console.log('✅ MongoDB Connected Successfully');
    isMongoConnected = true;
    initializeData();
})
.catch(err => {
    console.error('❌ MongoDB Connection Error:', err.message);
    console.log('⚠️ Running in demo mode...');
    isMongoConnected = false;
});

// Database Schemas
const orderSchema = new mongoose.Schema({
    orderId: { type: String, unique: true, required: true },
    customerName: { type: String, required: true },
    phone: { type: String, required: true },
    email: { type: String },
    address: { type: String, required: true },
    product: { type: String, required: true },
    productId: { type: String },
    quantity: { type: Number, required: true, min: 1 },
    totalPrice: { type: Number, required: true, min: 0 },
    paymentMethod: { type: String, required: true },
    status: { 
        type: String, 
        default: 'Pending',
        enum: ['Pending', 'Processing', 'Shipped', 'Delivered', 'Cancelled']
    },
    orderDate: { type: Date, default: Date.now },
    deliveryDate: Date,
    notes: String,
    isDemo: { type: Boolean, default: false }
}, { timestamps: true });

const reviewSchema = new mongoose.Schema({
    customerName: { type: String, required: true },
    product: { type: String, required: true },
    rating: { 
        type: Number, 
        required: true, 
        min: 1, 
        max: 5 
    },
    reviewText: { type: String, required: true },
    date: { type: Date, default: Date.now },
    approved: { type: Boolean, default: false },
    isDemo: { type: Boolean, default: false }
}, { timestamps: true });

const productSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: { type: String, required: true },
    price: { type: Number, required: true, min: 0 },
    originalPrice: { type: Number, min: 0 },
    category: { 
        type: String, 
        default: 'আতর',
        enum: ['আতর', 'পারফিউম', 'অয়েল'] 
    },
    tags: [String],
    stock: { type: Number, required: true, min: 0 },
    sold: { type: Number, default: 0 },
    imageUrl: { type: String },
    featured: { type: Boolean, default: false },
    isDemo: { type: Boolean, default: false }
}, { timestamps: true });

const adminSchema = new mongoose.Schema({
    email: { 
        type: String, 
        unique: true, 
        required: true 
    },
    password: { type: String, required: true },
    name: { type: String, default: 'এডমিন' },
    lastLogin: Date,
    isDemo: { type: Boolean, default: false }
}, { timestamps: true });

// Models
const Order = mongoose.models.Order || mongoose.model('Order', orderSchema);
const Review = mongoose.models.Review || mongoose.model('Review', reviewSchema);
const Product = mongoose.models.Product || mongoose.model('Product', productSchema);
const Admin = mongoose.models.Admin || mongoose.model('Admin', adminSchema);

// Initialize Data Function
const initializeData = async () => {
    try {
        if (!isMongoConnected) return;

        // Initialize Admin
        const adminEmail = process.env.ADMIN_EMAIL || 'admin@alnoor.com';
        const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
        
        let admin = await Admin.findOne({ email: adminEmail });
        if (!admin) {
            const hashedPassword = await bcrypt.hash(adminPassword, 10);
            admin = new Admin({
                email: adminEmail,
                password: hashedPassword,
                name: 'এডমিন',
                lastLogin: new Date()
            });
            await admin.save();
            console.log('✅ Admin account created');
        }

        // Initialize Products
        const productCount = await Product.countDocuments();
        if (productCount === 0) {
            const sampleProducts = [
                {
                    name: 'গোলাপ আতর',
                    description: '১০০% খাঁটি গোলাপ পাপড়ি থেকে তৈরি, মিষ্টি ও টেকসই সুগন্ধি',
                    price: 1299,
                    originalPrice: 1599,
                    category: 'আতর',
                    stock: 50,
                    sold: 234,
                    imageUrl: 'https://images.unsplash.com/photo-1541643600914-78b084683601?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=80',
                    featured: true,
                    tags: ['বেস্টসেলার', 'প্রিমিয়াম']
                },
                {
                    name: 'কস্তুরী আতর',
                    description: 'উচ্চমানের কস্তুরী থেকে তৈরি, গভীর ও আকর্ষণীয় সুগন্ধি',
                    price: 2499,
                    originalPrice: 2999,
                    category: 'আতর',
                    stock: 25,
                    sold: 189,
                    imageUrl: 'https://images.unsplash.com/photo-1601042879364-f3947d1f9fc9?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=80',
                    featured: true,
                    tags: ['লাক্সারি', 'দীর্ঘস্থায়ী']
                },
                {
                    name: 'জসমিন আতর',
                    description: 'তাজা জসমিন ফুল থেকে নিষ্কাশিত, হালকা ও তাজা সুগন্ধি',
                    price: 999,
                    originalPrice: 1299,
                    category: 'আতর',
                    stock: 100,
                    sold: 97,
                    imageUrl: 'https://images.unsplash.com/photo-1590736969955-0126f7e1e88d?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=80',
                    featured: false,
                    tags: ['ফ্রেশ', 'হালকা']
                }
            ];
            
            await Product.insertMany(sampleProducts);
            console.log('✅ Sample products created');
        }

        // Initialize Reviews
        const reviewCount = await Review.countDocuments();
        if (reviewCount === 0) {
            const sampleReviews = [
                {
                    customerName: 'রাফিদ আহমেদ',
                    product: 'গোলাপ আতর',
                    rating: 5,
                    reviewText: 'গোলাপ আতরটি অত্যন্ত উৎকৃষ্ট মানের। সুগন্ধটি টেকসই এবং প্রকৃত গোলাপের ঘ্রাণ নিয়ে আসে। ডেলিভারিও খুব দ্রুত পেয়েছি।',
                    date: new Date('2023-10-10'),
                    approved: true
                },
                {
                    customerName: 'সাবরিনা ইসলাম',
                    product: 'কস্তুরী আতর',
                    rating: 4,
                    reviewText: 'কস্তুরী আতরটি অসাধারণ! গভীর ও মিষ্টি ঘ্রাণ সারাদিন স্থায়ী হয়। দামের তুলনায় মান অনেক ভালো। নিশ্চিতভাবে আবার কিনব।',
                    date: new Date('2023-10-05'),
                    approved: true
                },
                {
                    customerName: 'ইমরান হোসেন',
                    product: 'জসমিন আতর',
                    rating: 5,
                    reviewText: 'জসমিন আতরটি হালকা ও সতেজ ঘ্রাণের জন্য পারফেক্ট। অফিসে ব্যবহারের জন্য আদর্শ। বোতলের ডিজাইনও খুব সুন্দর।',
                    date: new Date('2023-09-28'),
                    approved: true
                }
            ];
            
            await Review.insertMany(sampleReviews);
            console.log('✅ Sample reviews created');
        }

        // Initialize Orders
        const orderCount = await Order.countDocuments();
        if (orderCount === 0) {
            const sampleOrders = [
                {
                    orderId: 'ALP' + Date.now().toString().slice(-8),
                    customerName: 'রাফিদ আহমেদ',
                    phone: '01712345678',
                    email: 'rafid@example.com',
                    address: 'মিরপুর, ঢাকা',
                    product: 'গোলাপ আতর',
                    quantity: 2,
                    totalPrice: 2598,
                    paymentMethod: 'cod',
                    status: 'Delivered',
                    orderDate: new Date(Date.now() - 86400000 * 7),
                    deliveryDate: new Date(Date.now() - 86400000 * 6)
                },
                {
                    orderId: 'ALP' + (Date.now() + 1000).toString().slice(-8),
                    customerName: 'সাবরিনা ইসলাম',
                    phone: '01787654321',
                    email: 'sabrina@example.com',
                    address: 'ধানমন্ডি, ঢাকা',
                    product: 'কস্তুরী আতর',
                    quantity: 1,
                    totalPrice: 2499,
                    paymentMethod: 'bkash',
                    status: 'Processing',
                    orderDate: new Date(Date.now() - 86400000 * 2)
                }
            ];
            
            await Order.insertMany(sampleOrders);
            console.log('✅ Sample orders created');
        }

    } catch (error) {
        console.error('❌ Error initializing data:', error.message);
    }
};

// Auth Middleware
const authenticateToken = (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ 
                success: false, 
                error: 'Access token required' 
            });
        }

        jwt.verify(token, process.env.JWT_SECRET || 'AlNoor@Attar#JWT$9fK2Lx8Pq', (err, user) => {
            if (err) {
                return res.status(403).json({ 
                    success: false, 
                    error: 'Invalid or expired token' 
                });
            }
            req.user = user;
            next();
        });
    } catch (error) {
        console.error('Auth middleware error:', error);
        return res.status(500).json({ 
            success: false, 
            error: 'Authentication error' 
        });
    }
};

// Generate Demo Data
const getDemoData = () => {
    return {
        totalOrders: 156,
        totalRevenue: 254890,
        pendingOrders: 23,
        totalReviews: 89,
        pendingReviews: 12,
        totalProducts: 15,
        recentOrders: [
            {
                customerName: 'রাফিদ আহমেদ',
                product: 'গোলাপ আতর',
                quantity: 2,
                totalPrice: 2598,
                status: 'Pending'
            },
            {
                customerName: 'সাবরিনা ইসলাম',
                product: 'কস্তুরী আতর',
                quantity: 1,
                totalPrice: 2499,
                status: 'Delivered'
            },
            {
                customerName: 'ইমরান হোসেন',
                product: 'জসমিন আতর',
                quantity: 3,
                totalPrice: 2997,
                status: 'Processing'
            }
        ],
        monthlyRevenue: [
            { _id: 1, revenue: 45000 },
            { _id: 2, revenue: 52000 },
            { _id: 3, revenue: 48000 },
            { _id: 4, revenue: 61000 },
            { _id: 5, revenue: 58000 },
            { _id: 6, revenue: 72000 },
            { _id: 7, revenue: 68000 },
            { _id: 8, revenue: 75000 },
            { _id: 9, revenue: 82000 },
            { _id: 10, revenue: 78000 },
            { _id: 11, revenue: 90000 },
            { _id: 12, revenue: 95000 }
        ]
    };
};

// ==================== ROUTES ====================

// Test route
app.get('/api/test', (req, res) => {
    res.json({ 
        success: true, 
        message: 'Al-NoorPerfume API is working! 🚀',
        mongoConnected: isMongoConnected,
        timestamp: new Date().toISOString(),
        version: '2.0.0'
    });
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'healthy',
        timestamp: new Date().toISOString(),
        database: isMongoConnected ? 'connected' : 'disconnected',
        uptime: process.uptime()
    });
});

// ==================== AUTHENTICATION ====================

// Admin Login
app.post('/api/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ 
                success: false, 
                error: 'Email and password are required' 
            });
        }
        
        // Demo mode if MongoDB not connected
        if (!isMongoConnected) {
            const demoAdminEmail = 'admin@alnoor.com';
            const demoAdminPassword = 'admin123';
            
            if (email === demoAdminEmail && password === demoAdminPassword) {
                const token = jwt.sign(
                    { 
                        id: 'demo-admin-id', 
                        email: email,
                        demo: true 
                    },
                    process.env.JWT_SECRET || 'AlNoor@Attar#JWT$9fK2Lx8Pq',
                    { expiresIn: '24h' }
                );
                
                return res.json({ 
                    success: true, 
                    token, 
                    admin: { 
                        email: email,
                        demo: true
                    },
                    message: 'Logged in with demo account (MongoDB not connected)'
                });
            } else {
                return res.status(401).json({ 
                    success: false, 
                    error: 'Invalid credentials' 
                });
            }
        }
        
        // MongoDB is connected
        const admin = await Admin.findOne({ email });
        if (!admin) {
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid credentials' 
            });
        }

        const validPassword = await bcrypt.compare(password, admin.password);
        if (!validPassword) {
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid credentials' 
            });
        }

        // Update last login
        admin.lastLogin = new Date();
        await admin.save();

        // Create token
        const token = jwt.sign(
            { 
                id: admin._id, 
                email: admin.email 
            },
            process.env.JWT_SECRET || 'AlNoor@Attar#JWT$9fK2Lx8Pq',
            { expiresIn: '24h' }
        );

        res.json({ 
            success: true, 
            token, 
            admin: { 
                email: admin.email,
                lastLogin: admin.lastLogin,
                demo: false
            } 
        });
    } catch (error) {
        console.error('❌ Login error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Server error during login' 
        });
    }
});

// ==================== DASHBOARD ====================

// Dashboard Stats
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
    try {
        if (!isMongoConnected) {
            const demoData = getDemoData();
            return res.json({
                success: true,
                ...demoData,
                demo: true,
                message: 'Showing demo data (MongoDB not connected)'
            });
        }
        
        const totalOrders = await Order.countDocuments();
        
        const totalRevenueAgg = await Order.aggregate([
            { $group: { _id: null, total: { $sum: '$totalPrice' } } }
        ]);
        
        const pendingOrders = await Order.countDocuments({ status: 'Pending' });
        const totalReviews = await Review.countDocuments();
        const pendingReviews = await Review.countDocuments({ approved: false });
        const totalProducts = await Product.countDocuments();

        const recentOrders = await Order.find()
            .sort({ orderDate: -1 })
            .limit(5)
            .select('customerName product quantity totalPrice status orderDate');

        const monthlyRevenue = await Order.aggregate([
            {
                $group: {
                    _id: { $month: '$orderDate' },
                    revenue: { $sum: '$totalPrice' }
                }
            },
            { $sort: { '_id': 1 } }
        ]);

        res.json({
            success: true,
            totalOrders,
            totalRevenue: totalRevenueAgg[0]?.total || 0,
            pendingOrders,
            totalReviews,
            pendingReviews,
            totalProducts,
            recentOrders,
            monthlyRevenue,
            demo: false
        });
    } catch (error) {
        console.error('❌ Dashboard stats error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Error fetching dashboard stats' 
        });
    }
});

// ==================== PRODUCTS API ====================

// Get all products (Admin)
app.get('/api/products', authenticateToken, async (req, res) => {
    try {
        if (!isMongoConnected) {
            const demoProducts = [
                {
                    _id: '1',
                    name: 'গোলাপ আতর',
                    description: '১০০% খাঁটি গোলাপ পাপড়ি থেকে তৈরি, মিষ্টি ও টেকসই সুগন্ধি',
                    price: 1299,
                    originalPrice: 1599,
                    category: 'আতর',
                    stock: 50,
                    sold: 234,
                    imageUrl: 'https://images.unsplash.com/photo-1541643600914-78b084683601?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=80',
                    featured: true,
                    tags: ['বেস্টসেলার', 'প্রিমিয়াম'],
                    demo: true
                },
                {
                    _id: '2',
                    name: 'কস্তুরী আতর',
                    description: 'উচ্চমানের কস্তুরী থেকে তৈরি, গভীর ও আকর্ষণীয় সুগন্ধি',
                    price: 2499,
                    originalPrice: 2999,
                    category: 'আতর',
                    stock: 25,
                    sold: 189,
                    imageUrl: 'https://images.unsplash.com/photo-1601042879364-f3947d1f9fc9?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=80',
                    featured: true,
                    tags: ['লাক্সারি', 'দীর্ঘস্থায়ী'],
                    demo: true
                }
            ];
            return res.json(demoProducts);
        }
        
        const products = await Product.find().sort({ createdAt: -1 });
        res.json(products);
    } catch (error) {
        console.error('❌ Get products error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Error fetching products' 
        });
    }
});

// Create product
app.post('/api/products', authenticateToken, async (req, res) => {
    try {
        const productData = req.body;
        
        if (!productData.name || !productData.description || !productData.price || !productData.stock) {
            return res.status(400).json({ 
                success: false, 
                error: 'Missing required fields' 
            });
        }
        
        if (!isMongoConnected) {
            return res.json({ 
                success: true, 
                message: 'Product saved locally (MongoDB not connected)',
                product: {
                    ...productData,
                    _id: 'demo-' + Date.now(),
                    sold: 0,
                    demo: true
                }
            });
        }
        
        const product = new Product(productData);
        await product.save();
        
        res.json({ 
            success: true, 
            message: 'Product created successfully',
            product 
        });
    } catch (error) {
        console.error('❌ Create product error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Error creating product' 
        });
    }
});

// Get single product
app.get('/api/products/:id', authenticateToken, async (req, res) => {
    try {
        if (!isMongoConnected) {
            return res.json({
                _id: req.params.id,
                name: 'গোলাপ আতর',
                description: '১০০% খাঁটি গোলাপ পাপড়ি থেকে তৈরি',
                price: 1299,
                originalPrice: 1599,
                category: 'আতর',
                stock: 50,
                sold: 234,
                imageUrl: 'https://images.unsplash.com/photo-1541643600914-78b084683601?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=80',
                featured: true,
                tags: ['বেস্টসেলার', 'প্রিমিয়াম'],
                demo: true
            });
        }
        
        const product = await Product.findById(req.params.id);
        if (!product) {
            return res.status(404).json({ 
                success: false, 
                error: 'Product not found' 
            });
        }
        res.json(product);
    } catch (error) {
        console.error('❌ Get product error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Error fetching product' 
        });
    }
});

// Update product
app.put('/api/products/:id', authenticateToken, async (req, res) => {
    try {
        const productData = req.body;
        
        if (!isMongoConnected) {
            return res.json({ 
                success: true, 
                message: 'Product update simulated (MongoDB not connected)',
                product: productData
            });
        }
        
        const product = await Product.findByIdAndUpdate(
            req.params.id, 
            productData, 
            { new: true, runValidators: true }
        );
        
        if (!product) {
            return res.status(404).json({ 
                success: false, 
                error: 'Product not found' 
            });
        }
        
        res.json({ 
            success: true, 
            message: 'Product updated successfully',
            product 
        });
    } catch (error) {
        console.error('❌ Update product error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Error updating product' 
        });
    }
});

// Delete product
app.delete('/api/products/:id', authenticateToken, async (req, res) => {
    try {
        if (!isMongoConnected) {
            return res.json({ 
                success: true, 
                message: 'Product deletion simulated (MongoDB not connected)'
            });
        }
        
        const product = await Product.findByIdAndDelete(req.params.id);
        
        if (!product) {
            return res.status(404).json({ 
                success: false, 
                error: 'Product not found' 
            });
        }
        
        res.json({ 
            success: true, 
            message: 'Product deleted successfully' 
        });
    } catch (error) {
        console.error('❌ Delete product error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Error deleting product' 
        });
    }
});

// Public products endpoint
app.get('/api/products/public', async (req, res) => {
    try {
        if (!isMongoConnected) {
            const defaultProducts = [
                {
                    _id: '1',
                    name: 'গোলাপ আতর',
                    description: '১০০% খাঁটি গোলাপ পাপড়ি থেকে তৈরি, মিষ্টি ও টেকসই সুগন্ধি',
                    price: 1299,
                    originalPrice: 1599,
                    stock: 50,
                    sold: 234,
                    imageUrl: 'https://images.unsplash.com/photo-1541643600914-78b084683601?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=80',
                    featured: true,
                    tags: ['বেস্টসেলার', 'প্রিমিয়াম'],
                    demo: true
                },
                {
                    _id: '2',
                    name: 'কস্তুরী আতর',
                    description: 'উচ্চমানের কস্তুরী থেকে তৈরি, গভীর ও আকর্ষণীয় সুগন্ধি',
                    price: 2499,
                    originalPrice: 2999,
                    stock: 25,
                    sold: 189,
                    imageUrl: 'https://images.unsplash.com/photo-1601042879364-f3947d1f9fc9?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=80',
                    featured: true,
                    tags: ['লাক্সারি', 'দীর্ঘস্থায়ী'],
                    demo: true
                },
                {
                    _id: '3',
                    name: 'জসমিন আতর',
                    description: 'তাজা জসমিন ফুল থেকে নিষ্কাশিত, হালকা ও তাজা সুগন্ধি',
                    price: 999,
                    originalPrice: 1299,
                    stock: 100,
                    sold: 97,
                    imageUrl: 'https://images.unsplash.com/photo-1590736969955-0126f7e1e88d?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=80',
                    featured: false,
                    tags: ['ফ্রেশ', 'হালকা'],
                    demo: true
                }
            ];
            return res.json(defaultProducts);
        }
        
        const products = await Product.find({ stock: { $gt: 0 } }).sort({ featured: -1, createdAt: -1 });
        res.json(products);
    } catch (error) {
        console.error('❌ Public products error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Error fetching public products' 
        });
    }
});

// ==================== ORDERS API ====================

// Get all orders (Admin)
app.get('/api/orders', authenticateToken, async (req, res) => {
    try {
        const { status, page = 1, limit = 10, search } = req.query;
        
        if (!isMongoConnected) {
            const demoOrders = [
                {
                    _id: '1',
                    orderId: 'ALP123456',
                    customerName: 'রাফিদ আহমেদ',
                    phone: '01712345678',
                    email: 'rafid@example.com',
                    address: 'মিরপুর, ঢাকা',
                    product: 'গোলাপ আতর',
                    productId: '1',
                    quantity: 2,
                    totalPrice: 2598,
                    paymentMethod: 'cod',
                    status: 'Pending',
                    orderDate: new Date(),
                    notes: '',
                    demo: true
                },
                {
                    _id: '2',
                    orderId: 'ALP123457',
                    customerName: 'সাবরিনা ইসলাম',
                    phone: '01787654321',
                    email: 'sabrina@example.com',
                    address: 'ধানমন্ডি, ঢাকা',
                    product: 'কস্তুরী আতর',
                    productId: '2',
                    quantity: 1,
                    totalPrice: 2499,
                    paymentMethod: 'bkash',
                    status: 'Delivered',
                    orderDate: new Date(Date.now() - 86400000),
                    deliveryDate: new Date(Date.now() - 86400000 + 3600000),
                    notes: 'গ্রাহক খুশি',
                    demo: true
                }
            ];
            
            let filteredOrders = demoOrders;
            
            if (status) {
                filteredOrders = demoOrders.filter(order => order.status === status);
            }
            
            if (search) {
                const searchLower = search.toLowerCase();
                filteredOrders = filteredOrders.filter(order => 
                    order.customerName.toLowerCase().includes(searchLower) ||
                    order.orderId.toLowerCase().includes(searchLower) ||
                    order.phone.includes(search)
                );
            }
            
            return res.json({
                success: true,
                orders: filteredOrders,
                totalPages: 1,
                currentPage: 1,
                total: filteredOrders.length
            });
        }
        
        let query = {};
        
        if (status && status !== '') {
            query.status = status;
        }
        
        if (search && search !== '') {
            query.$or = [
                { customerName: { $regex: search, $options: 'i' } },
                { orderId: { $regex: search, $options: 'i' } },
                { phone: { $regex: search, $options: 'i' } }
            ];
        }
        
        const skip = (page - 1) * limit;
        
        const orders = await Order.find(query)
            .sort({ orderDate: -1 })
            .skip(skip)
            .limit(parseInt(limit));

        const total = await Order.countDocuments(query);

        res.json({
            success: true,
            orders,
            totalPages: Math.ceil(total / limit),
            currentPage: parseInt(page),
            total
        });
    } catch (error) {
        console.error('❌ Get orders error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Error fetching orders' 
        });
    }
});

// Get single order
app.get('/api/orders/:id', authenticateToken, async (req, res) => {
    try {
        if (!isMongoConnected) {
            return res.json({
                success: true,
                _id: req.params.id,
                orderId: 'ALP123456',
                customerName: 'রাফিদ আহমেদ',
                phone: '01712345678',
                email: 'rafid@example.com',
                address: 'মিরপুর, ঢাকা',
                product: 'গোলাপ আতর',
                productId: '1',
                quantity: 2,
                totalPrice: 2598,
                paymentMethod: 'cod',
                status: 'Pending',
                orderDate: new Date(),
                notes: '',
                demo: true
            });
        }
        
        const order = await Order.findById(req.params.id);
        if (!order) {
            return res.status(404).json({ 
                success: false, 
                error: 'Order not found' 
            });
        }
        
        res.json({
            success: true,
            ...order.toObject()
        });
    } catch (error) {
        console.error('❌ Get order error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Error fetching order' 
        });
    }
});

// Update order status
app.put('/api/orders/:id/status', authenticateToken, async (req, res) => {
    try {
        const { status, notes } = req.body;
        
        const validStatuses = ['Pending', 'Processing', 'Shipped', 'Delivered', 'Cancelled'];
        if (!validStatuses.includes(status)) {
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid status' 
            });
        }
        
        if (!isMongoConnected) {
            return res.json({ 
                success: true, 
                message: 'Order status updated locally (MongoDB not connected)',
                status,
                notes: notes || ''
            });
        }
        
        const updateData = { status };
        if (status === 'Delivered') {
            updateData.deliveryDate = new Date();
        }
        if (notes !== undefined) {
            updateData.notes = notes;
        }
        
        const order = await Order.findByIdAndUpdate(
            req.params.id, 
            updateData, 
            { new: true }
        );
        
        if (!order) {
            return res.status(404).json({ 
                success: false, 
                error: 'Order not found' 
            });
        }
        
        res.json({ 
            success: true, 
            message: 'Order status updated successfully',
            order 
        });
    } catch (error) {
        console.error('❌ Update order status error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Error updating order status' 
        });
    }
});

// Delete order
app.delete('/api/orders/:id', authenticateToken, async (req, res) => {
    try {
        if (!isMongoConnected) {
            return res.json({ 
                success: true, 
                message: 'Order deletion simulated (MongoDB not connected)'
            });
        }
        
        const order = await Order.findByIdAndDelete(req.params.id);
        
        if (!order) {
            return res.status(404).json({ 
                success: false, 
                error: 'Order not found' 
            });
        }
        
        res.json({ 
            success: true, 
            message: 'Order deleted successfully' 
        });
    } catch (error) {
        console.error('❌ Delete order error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Error deleting order' 
        });
    }
});

// Create new order from frontend
app.post('/api/orders/new', async (req, res) => {
    try {
        const orderData = req.body;
        
        const requiredFields = ['customerName', 'phone', 'address', 'product', 'quantity', 'totalPrice', 'paymentMethod'];
        for (const field of requiredFields) {
            if (!orderData[field]) {
                return res.status(400).json({ 
                    success: false, 
                    error: `Missing required field: ${field}` 
                });
            }
        }
        
        // Generate order ID
        const orderId = 'ALP' + Date.now().toString().slice(-8);
        
        let savedOrder = null;
        
        if (isMongoConnected) {
            const order = new Order({
                ...orderData,
                orderId,
                status: 'Pending',
                orderDate: new Date()
            });

            savedOrder = await order.save();

            // Update product stock
            if (orderData.productId) {
                const product = await Product.findById(orderData.productId);
                if (product) {
                    product.sold = (product.sold || 0) + orderData.quantity;
                    product.stock = Math.max(0, product.stock - orderData.quantity);
                    await product.save();
                }
            }
        } else {
            savedOrder = {
                ...orderData,
                _id: 'demo-' + Date.now(),
                orderId,
                status: 'Pending',
                orderDate: new Date(),
                demo: true
            };
        }
        
        res.json({ 
            success: true, 
            message: 'Order placed successfully! 🎉', 
            orderId,
            order: savedOrder
        });
        
    } catch (error) {
        console.error('❌ Order creation error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Error creating order' 
        });
    }
});

// ==================== REVIEWS API ====================

// Get all reviews (Admin)
app.get('/api/reviews', authenticateToken, async (req, res) => {
    try {
        const { approved, page = 1, limit = 10 } = req.query;
        
        if (!isMongoConnected) {
            const demoReviews = [
                {
                    _id: '1',
                    customerName: 'রাফিদ আহমেদ',
                    product: 'গোলাপ আতর',
                    rating: 5,
                    reviewText: 'গোলাপ আতরটি অত্যন্ত উৎকৃষ্ট মানের। সুগন্ধটি টেকসই এবং প্রকৃত গোলাপের ঘ্রাণ নিয়ে আসে।',
                    date: new Date('2023-10-10'),
                    approved: true,
                    demo: true
                },
                {
                    _id: '2',
                    customerName: 'সাবরিনা ইসলাম',
                    product: 'কস্তুরী আতর',
                    rating: 4,
                    reviewText: 'কস্তুরী আতরটি অসাধারণ! গভীর ও মিষ্টি ঘ্রাণ সারাদিন স্থায়ী হয়।',
                    date: new Date('2023-10-05'),
                    approved: true,
                    demo: true
                },
                {
                    _id: '3',
                    customerName: 'ইমরান হোসেন',
                    product: 'জসমিন আতর',
                    rating: 5,
                    reviewText: 'জসমিন আতরটি হালকা ও সতেজ ঘ্রাণের জন্য পারফেক্ট। অফিসে ব্যবহারের জন্য আদর্শ।',
                    date: new Date('2023-09-28'),
                    approved: true,
                    demo: true
                }
            ];
            
            let filteredReviews = demoReviews;
            
            if (approved !== undefined) {
                const isApproved = approved === 'true';
                filteredReviews = demoReviews.filter(review => review.approved === isApproved);
            }
            
            return res.json({
                success: true,
                reviews: filteredReviews,
                totalPages: 1,
                currentPage: 1,
                total: filteredReviews.length
            });
        }
        
        const query = approved !== undefined ? { approved: approved === 'true' } : {};
        const skip = (page - 1) * limit;
        
        const reviews = await Review.find(query)
            .sort({ date: -1 })
            .skip(skip)
            .limit(parseInt(limit));

        const total = await Review.countDocuments(query);

        res.json({
            success: true,
            reviews,
            totalPages: Math.ceil(total / limit),
            currentPage: parseInt(page),
            total
        });
    } catch (error) {
        console.error('❌ Get reviews error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Error fetching reviews' 
        });
    }
});

// Update review approval
app.put('/api/reviews/:id/approve', authenticateToken, async (req, res) => {
    try {
        const { approved } = req.body;
        
        if (typeof approved !== 'boolean') {
            return res.status(400).json({ 
                success: false, 
                error: 'Approved must be a boolean value' 
            });
        }
        
        if (!isMongoConnected) {
            return res.json({ 
                success: true, 
                message: 'Review approval updated locally (MongoDB not connected)',
                approved
            });
        }
        
        const review = await Review.findByIdAndUpdate(
            req.params.id, 
            { approved }, 
            { new: true }
        );
        
        if (!review) {
            return res.status(404).json({ 
                success: false, 
                error: 'Review not found' 
            });
        }
        
        res.json({ 
            success: true, 
            message: `Review ${approved ? 'approved' : 'unapproved'} successfully`,
            review 
        });
    } catch (error) {
        console.error('❌ Approve review error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Error updating review approval' 
        });
    }
});

// Delete review
app.delete('/api/reviews/:id', authenticateToken, async (req, res) => {
    try {
        if (!isMongoConnected) {
            return res.json({ 
                success: true, 
                message: 'Review deletion simulated (MongoDB not connected)'
            });
        }
        
        const review = await Review.findByIdAndDelete(req.params.id);
        
        if (!review) {
            return res.status(404).json({ 
                success: false, 
                error: 'Review not found' 
            });
        }
        
        res.json({ 
            success: true, 
            message: 'Review deleted successfully' 
        });
    } catch (error) {
        console.error('❌ Delete review error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Error deleting review' 
        });
    }
});

// Public reviews endpoint (approved only)
app.get('/api/reviews/public', async (req, res) => {
    try {
        if (!isMongoConnected) {
            const defaultReviews = [
                {
                    _id: '1',
                    customerName: 'রাফিদ আহমেদ',
                    product: 'গোলাপ আতর',
                    rating: 5,
                    reviewText: 'গোলাপ আতরটি অত্যন্ত উৎকৃষ্ট মানের। সুগন্ধটি টেকসই এবং প্রকৃত গোলাপের ঘ্রাণ নিয়ে আসে। ডেলিভারিও খুব দ্রুত পেয়েছি।',
                    date: new Date('2023-10-10'),
                    approved: true,
                    demo: true
                },
                {
                    _id: '2',
                    customerName: 'সাবরিনা ইসলাম',
                    product: 'কস্তুরী আতর',
                    rating: 4,
                    reviewText: 'কস্তুরী আতরটি অসাধারণ! গভীর ও মিষ্টি ঘ্রাণ সারাদিন স্থায়ী হয়। দামের তুলনায় মান অনেক ভালো। নিশ্চিতভাবে আবার কিনব।',
                    date: new Date('2023-10-05'),
                    approved: true,
                    demo: true
                },
                {
                    _id: '3',
                    customerName: 'ইমরান হোসেন',
                    product: 'জসমিন আতর',
                    rating: 5,
                    reviewText: 'জসমিন আতরটি হালকা ও সতেজ ঘ্রাণের জন্য পারফেক্ট। অফিসে ব্যবহারের জন্য আদর্শ। বোতলের ডিজাইনও খুব সুন্দর।',
                    date: new Date('2023-09-28'),
                    approved: true,
                    demo: true
                }
            ];
            return res.json({ 
                success: true,
                reviews: defaultReviews, 
                total: defaultReviews.length 
            });
        }
        
        const reviews = await Review.find({ approved: true })
            .sort({ date: -1 })
            .limit(20);

        res.json({ 
            success: true,
            reviews, 
            total: reviews.length 
        });
    } catch (error) {
        console.error('❌ Public reviews error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Error fetching public reviews' 
        });
    }
});

// Create new review from frontend
app.post('/api/reviews/new', async (req, res) => {
    try {
        const reviewData = req.body;
        
        if (!reviewData.customerName || !reviewData.product || !reviewData.reviewText) {
            return res.status(400).json({ 
                success: false, 
                error: 'Missing required fields' 
            });
        }
        
        if (!reviewData.rating || reviewData.rating < 1 || reviewData.rating > 5) {
            return res.status(400).json({ 
                success: false, 
                error: 'Rating must be between 1 and 5' 
            });
        }
        
        let savedReview = null;
        
        if (isMongoConnected) {
            const review = new Review({
                ...reviewData,
                date: new Date(),
                approved: false
            });

            savedReview = await review.save();
        } else {
            savedReview = {
                ...reviewData,
                _id: 'demo-' + Date.now(),
                date: new Date(),
                approved: false,
                demo: true
            };
        }
        
        res.json({ 
            success: true, 
            message: 'Review submitted successfully! It will be visible after approval.',
            review: savedReview
        });
        
    } catch (error) {
        console.error('❌ Review creation error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Error submitting review' 
        });
    }
});

// ==================== ERROR HANDLING ====================

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ 
        success: false, 
        error: 'Route not found' 
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('❌ Server error:', err.stack);
    res.status(500).json({ 
        success: false, 
        error: 'Internal server error' 
    });
});

// Start server
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`
    ╔══════════════════════════════════════╗
    ║      Al-NoorPerfume সার্ভার          ║
    ╚══════════════════════════════════════╝
    
    🚀 Server running on port: ${PORT}
    
    📍 Access URLs:
       Frontend:     http://localhost:${PORT}
       Admin Panel:  http://localhost:${PORT}/admin
       API Test:     http://localhost:${PORT}/api/test
    
    📊 Database Status: ${isMongoConnected ? '✅ Connected' : '⚠️ Disconnected (Demo Mode)'}
    
    ⏰ Started at: ${new Date().toLocaleString()}
    `);
});