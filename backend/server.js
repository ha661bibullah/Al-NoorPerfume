require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();

// CORS কনফিগারেশন - Netlify এবং লোকালহোস্ট উভয়ের জন্য
const allowedOrigins = [
    'https://playful-rugelach-33592e.netlify.app',
    'https://lively-kataifi-011ede.netlify.app',
    'http://localhost:3000',
    'http://localhost:5000'
];

app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = 'CORS policy does not allow access from this origin.';
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// মিডলওয়্যার
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// স্ট্যাটিক ফাইল সার্ভ করা
app.use(express.static(path.join(__dirname, '../frontend')));
app.use('/admin', express.static(path.join(__dirname, '../admin-panel')));

// HTML ফাইল সার্ভ করা
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, '../admin-panel/admin.html'));
});

// মঙ্গোডিবি কানেকশন
const MONGODB_URI = process.env.MONGODB_URI;
let isMongoConnected = false;

mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 30000,
    socketTimeoutMS: 45000,
})
.then(() => {
    console.log('✅ MongoDB সংযুক্ত হয়েছে');
    isMongoConnected = true;
    initializeData();
})
.catch(err => {
    console.error('❌ MongoDB কানেকশন এরর:', err.message);
    console.log('MongoDB URI:', MONGODB_URI ? 'URI আছে কিন্তু সংযোগ ব্যর্থ' : 'URI পাওয়া যায়নি');
    isMongoConnected = false;
});

// ডাটাবেজ স্কিমা
const orderSchema = new mongoose.Schema({
    orderId: { type: String, required: true, unique: true },
    customerName: { type: String, required: true },
    phone: { type: String, required: true },
    email: { type: String },
    address: { type: String, required: true },
    product: { type: String, required: true },
    productId: { type: String, required: true },
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
    notes: String
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
    approved: { type: Boolean, default: false }
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
    featured: { type: Boolean, default: false }
}, { timestamps: true });

const adminSchema = new mongoose.Schema({
    email: { 
        type: String, 
        unique: true, 
        required: true 
    },
    password: { type: String, required: true },
    name: { type: String, default: 'এডমিন' },
    lastLogin: Date
}, { timestamps: true });

// মডেল
const Order = mongoose.models.Order || mongoose.model('Order', orderSchema);
const Review = mongoose.models.Review || mongoose.model('Review', reviewSchema);
const Product = mongoose.models.Product || mongoose.model('Product', productSchema);
const Admin = mongoose.models.Admin || mongoose.model('Admin', adminSchema);

// ডাটা ইনিশিয়ালাইজেশন
const initializeData = async () => {
    try {
        // এডমিন একাউন্ট তৈরি
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
            console.log('✅ এডমিন একাউন্ট তৈরি করা হয়েছে');
        }

        // প্রোডাক্ট তৈরি
        const productCount = await Product.countDocuments();
        if (productCount === 0) {
            const sampleProducts = [
                {
                    name: 'গোলাপ আতর',
                    description: '১০০% খাঁটি গোলাপ পাপড়ি থেকে তৈরি, মিষ্টি ও টেকসই সুগন্ধি। প্রকৃতির বিশুদ্ধতা নিয়ে আসুন আপনার দৈনন্দিন জীবনে।',
                    price: 1299,
                    originalPrice: 1599,
                    category: 'আতর',
                    stock: 50,
                    sold: 234,
                    imageUrl: 'https://images.unsplash.com/photo-1541643600914-78b084683601?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=80',
                    featured: true,
                    tags: ['বেস্টসেলার', 'প্রিমিয়াম', 'দীর্ঘস্থায়ী']
                },
                {
                    name: 'কস্তুরী আতর',
                    description: 'উচ্চমানের কস্তুরী থেকে তৈরি, গভীর ও আকর্ষণীয় সুগন্ধি। আধ্যাত্মিকতা ও প্রশান্তির অনুভূতি দেয়।',
                    price: 2499,
                    originalPrice: 2999,
                    category: 'আতর',
                    stock: 25,
                    sold: 189,
                    imageUrl: 'https://images.unsplash.com/photo-1601042879364-f3947d1f9fc9?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=80',
                    featured: true,
                    tags: ['লাক্সারি', 'আধ্যাত্মিক', 'দীর্ঘস্থায়ী']
                },
                {
                    name: 'জসমিন আতর',
                    description: 'তাজা জসমিন ফুল থেকে নিষ্কাশিত, হালকা ও সতেজ সুগন্ধি। দৈনন্দিন ব্যবহারের জন্য পারফেক্ট।',
                    price: 999,
                    originalPrice: 1299,
                    category: 'আতর',
                    stock: 100,
                    sold: 97,
                    imageUrl: 'https://images.unsplash.com/photo-1590736969955-0126f7e1e88d?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=80',
                    featured: false,
                    tags: ['ফ্রেশ', 'হালকা', 'দৈনন্দিন']
                }
            ];
            
            await Product.insertMany(sampleProducts);
            console.log('✅ স্যাম্পল প্রোডাক্ট তৈরি করা হয়েছে');
        }

        // রিভিউ তৈরি
        const reviewCount = await Review.countDocuments();
        if (reviewCount === 0) {
            const sampleReviews = [
                {
                    customerName: 'রাফিদ আহমেদ',
                    product: 'গোলাপ আতর',
                    rating: 5,
                    reviewText: 'গোলাপ আতরটি অত্যন্ত উৎকৃষ্ট মানের। সুগন্ধটি টেকসই এবং প্রকৃত গোলাপের ঘ্রাণ নিয়ে আসে। ডেলিভারিও খুব দ্রুত পেয়েছি। সত্যিই অসাধারণ পণ্য।',
                    date: new Date('2023-10-10'),
                    approved: true
                },
                {
                    customerName: 'সাবরিনা ইসলাম',
                    product: 'কস্তুরী আতর',
                    rating: 4,
                    reviewText: 'কস্তুরী আতরটি অসাধারণ! গভীর ও মিষ্টি ঘ্রাণ সারাদিন স্থায়ী হয়। দামের তুলনায় মান অনেক ভালো। নিশ্চিতভাবে আবার কিনব। সবাইকে সুপারিশ করছি।',
                    date: new Date('2023-10-05'),
                    approved: true
                },
                {
                    customerName: 'ইমরান হোসেন',
                    product: 'জসমিন আতর',
                    rating: 5,
                    reviewText: 'জসমিন আতরটি হালকা ও সতেজ ঘ্রাণের জন্য পারফেক্ট। অফিসে ব্যবহারের জন্য আদর্শ। বোতলের ডিজাইনও খুব সুন্দর। প্যাকেজিং অত্যন্ত আকর্ষণীয়।',
                    date: new Date('2023-09-28'),
                    approved: true
                }
            ];
            
            await Review.insertMany(sampleReviews);
            console.log('✅ স্যাম্পল রিভিউ তৈরি করা হয়েছে');
        }

    } catch (error) {
        console.error('❌ ডাটা ইনিশিয়ালাইজেশন এরর:', error.message);
    }
};

// অথেন্টিকেশন মিডলওয়্যার
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ 
            success: false, 
            error: 'অ্যাক্সেস টোকেন প্রয়োজন' 
        });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'JwtSecret9fK2Lx8Pq', (err, user) => {
        if (err) {
            return res.status(403).json({ 
                success: false, 
                error: 'ভুল বা মেয়াদোত্তীর্ণ টোকেন' 
            });
        }
        req.user = user;
        next();
    });
};

// ==================== এপিআই রাউটস ====================

// টেস্ট রাউট
app.get('/api/test', (req, res) => {
    res.json({ 
        success: true, 
        message: 'আল-নূর আতর এপিআই কাজ করছে!',
        mongoConnected: isMongoConnected,
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development'
    });
});

// হেলথ চেক
app.get('/api/health', (req, res) => {
    res.json({ 
        status: isMongoConnected ? 'healthy' : 'unhealthy',
        database: isMongoConnected ? 'connected' : 'disconnected',
        timestamp: new Date().toISOString(),
        message: 'Al-Noor Attar API is running'
    });
});

// ==================== অথেন্টিকেশন ====================

// এডমিন লগইন
app.post('/api/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ 
                success: false, 
                error: 'ইমেইল ও পাসওয়ার্ড প্রয়োজন' 
            });
        }
        
        // এডমিন খুঁজুন
        const admin = await Admin.findOne({ email });
        if (!admin) {
            return res.status(401).json({ 
                success: false, 
                error: 'ভুল লগইন তথ্য' 
            });
        }

        // পাসওয়ার্ড চেক করুন
        const validPassword = await bcrypt.compare(password, admin.password);
        if (!validPassword) {
            return res.status(401).json({ 
                success: false, 
                error: 'ভুল লগইন তথ্য' 
            });
        }

        // শেষ লগইন আপডেট করুন
        admin.lastLogin = new Date();
        await admin.save();

        // জেডব্লিউটি টোকেন তৈরি করুন
        const token = jwt.sign(
            { 
                id: admin._id, 
                email: admin.email 
            },
            process.env.JWT_SECRET || 'JwtSecret9fK2Lx8Pq',
            { expiresIn: '24h' }
        );

        res.json({ 
            success: true, 
            token, 
            admin: { 
                email: admin.email,
                name: admin.name,
                lastLogin: admin.lastLogin
            } 
        });
    } catch (error) {
        console.error('❌ লগইন এরর:', error);
        res.status(500).json({ 
            success: false, 
            error: 'লগইনে সমস্যা হয়েছে' 
        });
    }
});

// ==================== ড্যাশবোর্ড ====================

// ড্যাশবোর্ড স্ট্যাটস
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
    try {
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

        res.json({
            success: true,
            totalOrders,
            totalRevenue: totalRevenueAgg[0]?.total || 0,
            pendingOrders,
            totalReviews,
            pendingReviews,
            totalProducts,
            recentOrders
        });
    } catch (error) {
        console.error('❌ ড্যাশবোর্ড স্ট্যাটস এরর:', error);
        res.status(500).json({ 
            success: false, 
            error: 'ড্যাশবোর্ড স্ট্যাটস লোড করতে সমস্যা হয়েছে' 
        });
    }
});

// ==================== প্রোডাক্টস এপিআই ====================

// সকল প্রোডাক্ট পান (এডমিন)
app.get('/api/products', authenticateToken, async (req, res) => {
    try {
        const products = await Product.find().sort({ createdAt: -1 });
        res.json(products);
    } catch (error) {
        console.error('❌ প্রোডাক্টস লোড এরর:', error);
        res.status(500).json({ 
            success: false, 
            error: 'প্রোডাক্টস লোড করতে সমস্যা হয়েছে' 
        });
    }
});

// নতুন প্রোডাক্ট তৈরি করুন
app.post('/api/products', authenticateToken, async (req, res) => {
    try {
        const productData = req.body;
        
        if (!productData.name || !productData.description || !productData.price || !productData.stock) {
            return res.status(400).json({ 
                success: false, 
                error: 'সকল প্রয়োজনীয় ফিল্ড পূরণ করুন' 
            });
        }
        
        const product = new Product(productData);
        await product.save();
        
        res.json({ 
            success: true, 
            message: 'প্রোডাক্ট তৈরি করা হয়েছে',
            product 
        });
    } catch (error) {
        console.error('❌ প্রোডাক্ট তৈরি এরর:', error);
        res.status(500).json({ 
            success: false, 
            error: 'প্রোডাক্ট তৈরি করতে সমস্যা হয়েছে' 
        });
    }
});

// একক প্রোডাক্ট পান
app.get('/api/products/:id', authenticateToken, async (req, res) => {
    try {
        const product = await Product.findById(req.params.id);
        if (!product) {
            return res.status(404).json({ 
                success: false, 
                error: 'প্রোডাক্ট পাওয়া যায়নি' 
            });
        }
        res.json(product);
    } catch (error) {
        console.error('❌ প্রোডাক্ট লোড এরর:', error);
        res.status(500).json({ 
            success: false, 
            error: 'প্রোডাক্ট লোড করতে সমস্যা হয়েছে' 
        });
    }
});

// প্রোডাক্ট আপডেট করুন
app.put('/api/products/:id', authenticateToken, async (req, res) => {
    try {
        const productData = req.body;
        
        const product = await Product.findByIdAndUpdate(
            req.params.id, 
            productData, 
            { new: true, runValidators: true }
        );
        
        if (!product) {
            return res.status(404).json({ 
                success: false, 
                error: 'প্রোডাক্ট পাওয়া যায়নি' 
            });
        }
        
        res.json({ 
            success: true, 
            message: 'প্রোডাক্ট আপডেট করা হয়েছে',
            product 
        });
    } catch (error) {
        console.error('❌ প্রোডাক্ট আপডেট এরর:', error);
        res.status(500).json({ 
            success: false, 
            error: 'প্রোডাক্ট আপডেট করতে সমস্যা হয়েছে' 
        });
    }
});

// প্রোডাক্ট ডিলিট করুন
app.delete('/api/products/:id', authenticateToken, async (req, res) => {
    try {
        const product = await Product.findByIdAndDelete(req.params.id);
        
        if (!product) {
            return res.status(404).json({ 
                success: false, 
                error: 'প্রোডাক্ট পাওয়া যায়নি' 
            });
        }
        
        res.json({ 
            success: true, 
            message: 'প্রোডাক্ট ডিলিট করা হয়েছে' 
        });
    } catch (error) {
        console.error('❌ প্রোডাক্ট ডিলিট এরর:', error);
        res.status(500).json({ 
            success: false, 
            error: 'প্রোডাক্ট ডিলিট করতে সমস্যা হয়েছে' 
        });
    }
});

// পাবলিক প্রোডাক্টস এন্ডপয়েন্ট
app.get('/api/products/public', async (req, res) => {
    try {
        const products = await Product.find({ stock: { $gt: 0 } }).sort({ featured: -1, createdAt: -1 });
        res.json(products);
    } catch (error) {
        console.error('❌ পাবলিক প্রোডাক্টস এরর:', error);
        res.status(500).json({ 
            success: false, 
            error: 'প্রোডাক্টস লোড করতে সমস্যা হয়েছে' 
        });
    }
});

// ==================== অর্ডারস এপিআই ====================

// সকল অর্ডার পান (এডমিন)
app.get('/api/orders', authenticateToken, async (req, res) => {
    try {
        const { status, page = 1, limit = 10, search } = req.query;
        
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
        console.error('❌ অর্ডারস লোড এরর:', error);
        res.status(500).json({ 
            success: false, 
            error: 'অর্ডারস লোড করতে সমস্যা হয়েছে' 
        });
    }
});

// একক অর্ডার পান
app.get('/api/orders/:id', authenticateToken, async (req, res) => {
    try {
        const order = await Order.findById(req.params.id);
        if (!order) {
            return res.status(404).json({ 
                success: false, 
                error: 'অর্ডার পাওয়া যায়নি' 
            });
        }
        
        res.json({
            success: true,
            ...order.toObject()
        });
    } catch (error) {
        console.error('❌ অর্ডার লোড এরর:', error);
        res.status(500).json({ 
            success: false, 
            error: 'অর্ডার লোড করতে সমস্যা হয়েছে' 
        });
    }
});

// অর্ডার স্ট্যাটাস আপডেট করুন
app.put('/api/orders/:id/status', authenticateToken, async (req, res) => {
    try {
        const { status, notes } = req.body;
        
        const validStatuses = ['Pending', 'Processing', 'Shipped', 'Delivered', 'Cancelled'];
        if (!validStatuses.includes(status)) {
            return res.status(400).json({ 
                success: false, 
                error: 'ভুল স্ট্যাটাস' 
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
                error: 'অর্ডার পাওয়া যায়নি' 
            });
        }
        
        res.json({ 
            success: true, 
            message: 'অর্ডার স্ট্যাটাস আপডেট করা হয়েছে',
            order 
        });
    } catch (error) {
        console.error('❌ অর্ডার স্ট্যাটাস আপডেট এরর:', error);
        res.status(500).json({ 
            success: false, 
            error: 'অর্ডার স্ট্যাটাস আপডেট করতে সমস্যা হয়েছে' 
        });
    }
});

// অর্ডার ডিলিট করুন
app.delete('/api/orders/:id', authenticateToken, async (req, res) => {
    try {
        const order = await Order.findByIdAndDelete(req.params.id);
        
        if (!order) {
            return res.status(404).json({ 
                success: false, 
                error: 'অর্ডার পাওয়া যায়নি' 
            });
        }
        
        res.json({ 
            success: true, 
            message: 'অর্ডার ডিলিট করা হয়েছে' 
        });
    } catch (error) {
        console.error('❌ অর্ডার ডিলিট এরর:', error);
        res.status(500).json({ 
            success: false, 
            error: 'অর্ডার ডিলিট করতে সমস্যা হয়েছে' 
        });
    }
});

// ফ্রন্টএন্ড থেকে নতুন অর্ডার তৈরি করুন
app.post('/api/orders/new', async (req, res) => {
    try {
        const orderData = req.body;
        
        const requiredFields = ['customerName', 'phone', 'address', 'product', 'quantity', 'totalPrice', 'paymentMethod'];
        for (const field of requiredFields) {
            if (!orderData[field]) {
                return res.status(400).json({ 
                    success: false, 
                    error: `প্রয়োজনীয় ফিল্ড ${field} পূরণ করুন` 
                });
            }
        }
        
        // অর্ডার আইডি জেনারেট করুন
        const orderId = 'ALN' + Date.now().toString().slice(-8);
        
        const order = new Order({
            ...orderData,
            orderId,
            status: 'Pending',
            orderDate: new Date()
        });

        const savedOrder = await order.save();

        // প্রোডাক্ট স্টক আপডেট করুন
        if (orderData.productId) {
            const product = await Product.findById(orderData.productId);
            if (product) {
                product.sold = (product.sold || 0) + orderData.quantity;
                product.stock = Math.max(0, product.stock - orderData.quantity);
                await product.save();
            }
        }
        
        res.json({ 
            success: true, 
            message: 'অর্ডার সফলভাবে তৈরি হয়েছে!', 
            orderId,
            order: savedOrder
        });
        
    } catch (error) {
        console.error('❌ অর্ডার তৈরি এরর:', error);
        res.status(500).json({ 
            success: false, 
            error: 'অর্ডার তৈরি করতে সমস্যা হয়েছে' 
        });
    }
});

// ==================== রিভিউস এপিআই ====================

// সকল রিভিউ পান (এডমিন)
app.get('/api/reviews', authenticateToken, async (req, res) => {
    try {
        const { approved, page = 1, limit = 10 } = req.query;
        
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
        console.error('❌ রিভিউস লোড এরর:', error);
        res.status(500).json({ 
            success: false, 
            error: 'রিভিউস লোড করতে সমস্যা হয়েছে' 
        });
    }
});

// রিভিউ অনুমোদন আপডেট করুন
app.put('/api/reviews/:id/approve', authenticateToken, async (req, res) => {
    try {
        const { approved } = req.body;
        
        if (typeof approved !== 'boolean') {
            return res.status(400).json({ 
                success: false, 
                error: 'অনুমোদিত অবশ্যই বুলিয়ান মান হতে হবে' 
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
                error: 'রিভিউ পাওয়া যায়নি' 
            });
        }
        
        res.json({ 
            success: true, 
            message: `রিভিউ ${approved ? 'অনুমোদিত' : 'অননুমোদিত'} করা হয়েছে`,
            review 
        });
    } catch (error) {
        console.error('❌ রিভিউ অনুমোদন এরর:', error);
        res.status(500).json({ 
            success: false, 
            error: 'রিভিউ অনুমোদন আপডেট করতে সমস্যা হয়েছে' 
        });
    }
});

// রিভিউ ডিলিট করুন
app.delete('/api/reviews/:id', authenticateToken, async (req, res) => {
    try {
        const review = await Review.findByIdAndDelete(req.params.id);
        
        if (!review) {
            return res.status(404).json({ 
                success: false, 
                error: 'রিভিউ পাওয়া যায়নি' 
            });
        }
        
        res.json({ 
            success: true, 
            message: 'রিভিউ ডিলিট করা হয়েছে' 
        });
    } catch (error) {
        console.error('❌ রিভিউ ডিলিট এরর:', error);
        res.status(500).json({ 
            success: false, 
            error: 'রিভিউ ডিলিট করতে সমস্যা হয়েছে' 
        });
    }
});

// পাবলিক রিভিউস এন্ডপয়েন্ট (শুধু অনুমোদিত)
app.get('/api/reviews/public', async (req, res) => {
    try {
        const reviews = await Review.find({ approved: true })
            .sort({ date: -1 })
            .limit(20);

        res.json({ 
            success: true,
            reviews, 
            total: reviews.length 
        });
    } catch (error) {
        console.error('❌ পাবলিক রিভিউস এরর:', error);
        res.status(500).json({ 
            success: false,
            error: 'রিভিউস লোড করতে সমস্যা হয়েছে' 
        });
    }
});

// ফ্রন্টএন্ড থেকে নতুন রিভিউ তৈরি করুন
app.post('/api/reviews/new', async (req, res) => {
    try {
        const reviewData = req.body;
        
        if (!reviewData.customerName || !reviewData.product || !reviewData.reviewText) {
            return res.status(400).json({ 
                success: false, 
                error: 'সকল প্রয়োজনীয় ফিল্ড পূরণ করুন' 
            });
        }
        
        if (!reviewData.rating || reviewData.rating < 1 || reviewData.rating > 5) {
            return res.status(400).json({ 
                success: false, 
                error: 'রেটিং অবশ্যই ১ থেকে ৫ এর মধ্যে হতে হবে' 
            });
        }
        
        const review = new Review({
            ...reviewData,
            date: new Date(),
            approved: false
        });

        const savedReview = await review.save();
        
        res.json({ 
            success: true, 
            message: 'রিভিউ জমা দেওয়া হয়েছে! অনুমোদনের পর এটি দেখা যাবে।',
            review: savedReview
        });
        
    } catch (error) {
        console.error('❌ রিভিউ তৈরি এরর:', error);
        res.status(500).json({ 
            success: false, 
            error: 'রিভিউ তৈরি করতে সমস্যা হয়েছে' 
        });
    }
});

// ==================== এরর হ্যান্ডলিং ====================

// 404 হ্যান্ডলার
app.use('*', (req, res) => {
    res.status(404).json({ 
        success: false, 
        error: 'রাউট পাওয়া যায়নি' 
    });
});

// এরর হ্যান্ডলিং মিডলওয়্যার
app.use((err, req, res, next) => {
    console.error('❌ সার্ভার এরর:', err.stack);
    res.status(500).json({ 
        success: false, 
        error: 'অভ্যন্তরীণ সার্ভার এরর' 
    });
});

// সার্ভার শুরু করুন
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`
    ╔══════════════════════════════════════╗
    ║      আল-নূর আতর সার্ভার             ║
    ╚══════════════════════════════════════╝
    
    🚀 সার্ভার চলছে পোর্ট: ${PORT}
    
    📍 অ্যাক্সেস URLs:
       ফ্রন্টএন্ড:     http://localhost:${PORT}
       এডমিন প্যানেল:  http://localhost:${PORT}/admin
       এপিআই টেস্ট:     http://localhost:${PORT}/api/test
    
    📊 ডাটাবেজ স্ট্যাটাস: ${isMongoConnected ? '✅ সংযুক্ত' : '❌ সংযোগ নেই'}
    
    ⏰ শুরু হয়েছে: ${new Date().toLocaleString('bn-BD')}
    `);
});