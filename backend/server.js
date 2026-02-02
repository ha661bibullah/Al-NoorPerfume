require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();

// CORS configuration
app.use(cors({
    origin: '*', // Allow all origins for now
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI;
let isMongoConnected = false;

console.log('Attempting MongoDB connection...');
console.log('MongoDB URI available:', !!MONGODB_URI);

mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 30000,
    socketTimeoutMS: 45000,
})
.then(() => {
    console.log('✅ MongoDB Connected Successfully!');
    isMongoConnected = true;
    initializeData();
})
.catch(err => {
    console.error('❌ MongoDB Connection Error:', err.message);
    console.log('MongoDB URI length:', MONGODB_URI ? MONGODB_URI.length : 'No URI');
    isMongoConnected = false;
});

// Database Schemas
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

// Models
const Order = mongoose.models.Order || mongoose.model('Order', orderSchema);
const Review = mongoose.models.Review || mongoose.model('Review', reviewSchema);
const Product = mongoose.models.Product || mongoose.model('Product', productSchema);
const Admin = mongoose.models.Admin || mongoose.model('Admin', adminSchema);

// Initialize Data
const initializeData = async () => {
    try {
        // Admin Account
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

        // Products
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
            console.log('✅ Sample products created');
        }

        // Reviews
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
            console.log('✅ Sample reviews created');
        }

    } catch (error) {
        console.error('❌ Data initialization error:', error.message);
    }
};

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ 
            success: false, 
            error: 'Access token required' 
        });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'JwtSecret9fK2Lx8Pq', (err, user) => {
        if (err) {
            return res.status(403).json({ 
                success: false, 
                error: 'Invalid or expired token' 
            });
        }
        req.user = user;
        next();
    });
};

// ==================== API ROUTES ====================

// Test Route
app.get('/api/test', (req, res) => {
    res.json({ 
        success: true, 
        message: 'Al-Noor Attar API is working!',
        mongoConnected: isMongoConnected,
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development'
    });
});

// Health Check
app.get('/api/health', (req, res) => {
    res.json({ 
        status: isMongoConnected ? 'healthy' : 'unhealthy',
        database: isMongoConnected ? 'connected' : 'disconnected',
        timestamp: new Date().toISOString(),
        message: 'Al-Noor Attar API'
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
                error: 'Email and password required' 
            });
        }
        
        const admin = await Admin.findOne({ email });
        if (!admin) {
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid login credentials' 
            });
        }

        const validPassword = await bcrypt.compare(password, admin.password);
        if (!validPassword) {
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid login credentials' 
            });
        }

        admin.lastLogin = new Date();
        await admin.save();

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
        console.error('❌ Login error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Login failed' 
        });
    }
});

// ==================== DASHBOARD ====================

// Dashboard Stats
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
        console.error('❌ Dashboard stats error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to load dashboard stats' 
        });
    }
});

// ==================== PRODUCTS API ====================

// All Products (Admin)
app.get('/api/products', authenticateToken, async (req, res) => {
    try {
        const products = await Product.find().sort({ createdAt: -1 });
        res.json(products);
    } catch (error) {
        console.error('❌ Products load error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to load products' 
        });
    }
});

// Create Product
app.post('/api/products', authenticateToken, async (req, res) => {
    try {
        const productData = req.body;
        
        if (!productData.name || !productData.description || !productData.price || !productData.stock) {
            return res.status(400).json({ 
                success: false, 
                error: 'All required fields must be filled' 
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
        console.error('❌ Product creation error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to create product' 
        });
    }
});

// Single Product
app.get('/api/products/:id', authenticateToken, async (req, res) => {
    try {
        const product = await Product.findById(req.params.id);
        if (!product) {
            return res.status(404).json({ 
                success: false, 
                error: 'Product not found' 
            });
        }
        res.json(product);
    } catch (error) {
        console.error('❌ Product load error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to load product' 
        });
    }
});

// Update Product
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
                error: 'Product not found' 
            });
        }
        
        res.json({ 
            success: true, 
            message: 'Product updated successfully',
            product 
        });
    } catch (error) {
        console.error('❌ Product update error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to update product' 
        });
    }
});

// Delete Product
app.delete('/api/products/:id', authenticateToken, async (req, res) => {
    try {
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
        console.error('❌ Product delete error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to delete product' 
        });
    }
});

// Public Products Endpoint
app.get('/api/products/public', async (req, res) => {
    try {
        const products = await Product.find({ stock: { $gt: 0 } }).sort({ featured: -1, createdAt: -1 });
        res.json(products);
    } catch (error) {
        console.error('❌ Public products error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to load products' 
        });
    }
});

// ==================== ORDERS API ====================

// All Orders (Admin)
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
        console.error('❌ Orders load error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to load orders' 
        });
    }
});

// Single Order
app.get('/api/orders/:id', authenticateToken, async (req, res) => {
    try {
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
        console.error('❌ Order load error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to load order' 
        });
    }
});

// Update Order Status
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
        console.error('❌ Order status update error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to update order status' 
        });
    }
});

// Delete Order
app.delete('/api/orders/:id', authenticateToken, async (req, res) => {
    try {
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
        console.error('❌ Order delete error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to delete order' 
        });
    }
});

// New Order from Frontend
app.post('/api/orders/new', async (req, res) => {
    try {
        const orderData = req.body;
        
        const requiredFields = ['customerName', 'phone', 'address', 'product', 'quantity', 'totalPrice', 'paymentMethod'];
        for (const field of requiredFields) {
            if (!orderData[field]) {
                return res.status(400).json({ 
                    success: false, 
                    error: `Required field ${field} is missing` 
                });
            }
        }
        
        const orderId = 'ALN' + Date.now().toString().slice(-8);
        
        const order = new Order({
            ...orderData,
            orderId,
            status: 'Pending',
            orderDate: new Date()
        });

        const savedOrder = await order.save();

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
            message: 'Order created successfully!', 
            orderId,
            order: savedOrder
        });
        
    } catch (error) {
        console.error('❌ Order creation error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to create order' 
        });
    }
});

// ==================== REVIEWS API ====================

// All Reviews (Admin)
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
        console.error('❌ Reviews load error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to load reviews' 
        });
    }
});

// Update Review Approval
app.put('/api/reviews/:id/approve', authenticateToken, async (req, res) => {
    try {
        const { approved } = req.body;
        
        if (typeof approved !== 'boolean') {
            return res.status(400).json({ 
                success: false, 
                error: 'Approved must be boolean' 
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
            message: `Review ${approved ? 'approved' : 'disapproved'} successfully`,
            review 
        });
    } catch (error) {
        console.error('❌ Review approval error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to update review approval' 
        });
    }
});

// Delete Review
app.delete('/api/reviews/:id', authenticateToken, async (req, res) => {
    try {
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
        console.error('❌ Review delete error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to delete review' 
        });
    }
});

// Public Reviews Endpoint (only approved)
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
        console.error('❌ Public reviews error:', error);
        res.status(500).json({ 
            success: false,
            error: 'Failed to load reviews' 
        });
    }
});

// New Review from Frontend
app.post('/api/reviews/new', async (req, res) => {
    try {
        const reviewData = req.body;
        
        if (!reviewData.customerName || !reviewData.product || !reviewData.reviewText) {
            return res.status(400).json({ 
                success: false, 
                error: 'All required fields must be filled' 
            });
        }
        
        if (!reviewData.rating || reviewData.rating < 1 || reviewData.rating > 5) {
            return res.status(400).json({ 
                success: false, 
                error: 'Rating must be between 1 and 5' 
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
            message: 'Review submitted successfully! It will appear after approval.',
            review: savedReview
        });
        
    } catch (error) {
        console.error('❌ Review creation error:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to create review' 
        });
    }
});

// ==================== ERROR HANDLING ====================

// 404 Handler
app.use('*', (req, res) => {
    res.status(404).json({ 
        success: false, 
        error: 'Route not found' 
    });
});

// Error Handling Middleware
app.use((err, req, res, next) => {
    console.error('❌ Server error:', err.stack);
    res.status(500).json({ 
        success: false, 
        error: 'Internal server error' 
    });
});

// Start Server
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`
    ╔══════════════════════════════════════╗
    ║      Al-Noor Attar Server           ║
    ╚══════════════════════════════════════╝
    
    🚀 Server running on port: ${PORT}
    
    📍 Access URLs:
       API Test:     http://localhost:${PORT}/api/test
       Health Check: http://localhost:${PORT}/api/health
    
    📊 Database Status: ${isMongoConnected ? '✅ Connected' : '❌ Disconnected'}
    
    ⏰ Started: ${new Date().toLocaleString('bn-BD')}
    `);
});