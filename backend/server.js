const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB Connected Successfully'))
  .catch(err => {
    console.error('❌ MongoDB Connection Error:', err);
    process.exit(1);
  });

// Models
const ProductSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String },
  price: { type: Number, required: true },
  originalPrice: { type: Number },
  stock: { type: Number, default: 0 },
  category: { type: String, default: 'আতর' },
  imageUrl: { type: String },
  tags: [{ type: String }],
  sold: { type: Number, default: 0 },
  featured: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const OrderSchema = new mongoose.Schema({
  orderId: { type: String, required: true, unique: true },
  customerName: { type: String, required: true },
  phone: { type: String, required: true },
  email: { type: String },
  address: { type: String, required: true },
  productId: { type: String, required: true },
  productName: { type: String, required: true },
  quantity: { type: Number, required: true },
  totalPrice: { type: Number, required: true },
  paymentMethod: { type: String, required: true },
  status: { 
    type: String, 
    enum: ['pending', 'processing', 'shipped', 'delivered', 'cancelled'],
    default: 'pending'
  },
  createdAt: { type: Date, default: Date.now }
});

const ReviewSchema = new mongoose.Schema({
  customerName: { type: String, required: true },
  product: { type: String, required: true },
  rating: { type: Number, required: true, min: 1, max: 5 },
  reviewText: { type: String, required: true },
  approved: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const AdminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, default: 'Admin' },
  createdAt: { type: Date, default: Date.now }
});

// Create models
const Product = mongoose.model('Product', ProductSchema);
const Order = mongoose.model('Order', OrderSchema);
const Review = mongoose.model('Review', ReviewSchema);
const Admin = mongoose.model('Admin', AdminSchema);

// Generate Order ID
function generateOrderId() {
  const timestamp = Date.now().toString().slice(-6);
  const random = Math.floor(Math.random() * 1000).toString().padStart(3, '0');
  return `ATT${timestamp}${random}`;
}

// Middleware to verify admin token
const verifyAdminToken = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ success: false, message: 'Authentication required' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const admin = await Admin.findById(decoded.id);
    
    if (!admin) {
      return res.status(401).json({ success: false, message: 'Admin not found' });
    }
    
    req.admin = admin;
    next();
  } catch (error) {
    console.error('Token verification error:', error);
    res.status(401).json({ success: false, message: 'Invalid token' });
  }
};

// Routes

// Test Route
app.get('/api/test', (req, res) => {
  res.json({ 
    success: true, 
    message: 'API is working!',
    timestamp: new Date().toISOString()
  });
});

// Admin Auth Routes
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find admin by email
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid credentials' 
      });
    }
    
    // In production, use bcrypt.compare
    // For demo, we're comparing directly
    const isValidPassword = password === admin.password;
    
    if (!isValidPassword) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid credentials' 
      });
    }
    
    // Generate JWT token
    const token = jwt.sign(
      { id: admin._id, email: admin.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({
      success: true,
      token,
      admin: {
        id: admin._id,
        email: admin.email,
        name: admin.name
      }
    });
    
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error' 
    });
  }
});

// Initialize admin (run once)
app.post('/api/admin/init', async (req, res) => {
  try {
    // Check if admin already exists
    const existingAdmin = await Admin.findOne({ email: process.env.ADMIN_EMAIL });
    
    if (existingAdmin) {
      return res.json({ 
        success: true, 
        message: 'Admin already exists' 
      });
    }
    
    // Create new admin
    const admin = new Admin({
      email: process.env.ADMIN_EMAIL,
      password: process.env.ADMIN_PASSWORD,
      name: 'Super Admin'
    });
    
    await admin.save();
    
    res.json({ 
      success: true, 
      message: 'Admin created successfully' 
    });
    
  } catch (error) {
    console.error('Admin init error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error' 
    });
  }
});

// Public Product Routes
app.get('/api/products/public', async (req, res) => {
  try {
    const products = await Product.find({}).sort({ createdAt: -1 });
    res.json(products);
  } catch (error) {
    console.error('Products fetch error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch products' 
    });
  }
});

// Admin Product Routes
app.get('/api/products', verifyAdminToken, async (req, res) => {
  try {
    const products = await Product.find({}).sort({ createdAt: -1 });
    res.json({ success: true, products });
  } catch (error) {
    console.error('Products fetch error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch products' 
    });
  }
});

app.post('/api/products', verifyAdminToken, async (req, res) => {
  try {
    const product = new Product(req.body);
    await product.save();
    res.json({ success: true, product });
  } catch (error) {
    console.error('Product create error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to create product' 
    });
  }
});

app.put('/api/products/:id', verifyAdminToken, async (req, res) => {
  try {
    const product = await Product.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );
    
    if (!product) {
      return res.status(404).json({ 
        success: false, 
        message: 'Product not found' 
      });
    }
    
    res.json({ success: true, product });
  } catch (error) {
    console.error('Product update error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to update product' 
    });
  }
});

app.delete('/api/products/:id', verifyAdminToken, async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);
    
    if (!product) {
      return res.status(404).json({ 
        success: false, 
        message: 'Product not found' 
      });
    }
    
    res.json({ success: true, message: 'Product deleted successfully' });
  } catch (error) {
    console.error('Product delete error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to delete product' 
    });
  }
});

// Public Review Routes
app.get('/api/reviews/public', async (req, res) => {
  try {
    const reviews = await Review.find({ approved: true }).sort({ createdAt: -1 });
    res.json({ success: true, reviews });
  } catch (error) {
    console.error('Reviews fetch error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch reviews' 
    });
  }
});

app.post('/api/reviews/new', async (req, res) => {
  try {
    const review = new Review({
      ...req.body,
      approved: false // Reviews need admin approval
    });
    
    await review.save();
    
    res.json({ 
      success: true, 
      message: 'Review submitted successfully. It will appear after admin approval.',
      review 
    });
  } catch (error) {
    console.error('Review submission error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to submit review' 
    });
  }
});

// Admin Review Routes
app.get('/api/reviews', verifyAdminToken, async (req, res) => {
  try {
    const reviews = await Review.find({}).sort({ createdAt: -1 });
    res.json({ success: true, reviews });
  } catch (error) {
    console.error('Reviews fetch error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch reviews' 
    });
  }
});

app.put('/api/reviews/:id/approve', verifyAdminToken, async (req, res) => {
  try {
    const review = await Review.findByIdAndUpdate(
      req.params.id,
      { approved: true },
      { new: true }
    );
    
    if (!review) {
      return res.status(404).json({ 
        success: false, 
        message: 'Review not found' 
      });
    }
    
    res.json({ 
      success: true, 
      message: 'Review approved successfully',
      review 
    });
  } catch (error) {
    console.error('Review approval error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to approve review' 
    });
  }
});

app.delete('/api/reviews/:id', verifyAdminToken, async (req, res) => {
  try {
    const review = await Review.findByIdAndDelete(req.params.id);
    
    if (!review) {
      return res.status(404).json({ 
        success: false, 
        message: 'Review not found' 
      });
    }
    
    res.json({ 
      success: true, 
      message: 'Review deleted successfully' 
    });
  } catch (error) {
    console.error('Review delete error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to delete review' 
    });
  }
});

// Order Routes
app.post('/api/orders/new', async (req, res) => {
  try {
    const orderId = generateOrderId();
    
    // Create new order
    const order = new Order({
      ...req.body,
      orderId,
      status: 'pending'
    });
    
    await order.save();
    
    // Update product stock
    if (req.body.productId && req.body.quantity) {
      await Product.findByIdAndUpdate(
        req.body.productId,
        { $inc: { stock: -req.body.quantity, sold: req.body.quantity } }
      );
    }
    
    res.json({ 
      success: true, 
      message: 'Order placed successfully',
      orderId,
      order 
    });
  } catch (error) {
    console.error('Order creation error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to place order' 
    });
  }
});

// Admin Order Routes
app.get('/api/orders', verifyAdminToken, async (req, res) => {
  try {
    const orders = await Order.find({}).sort({ createdAt: -1 });
    res.json({ success: true, orders });
  } catch (error) {
    console.error('Orders fetch error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch orders' 
    });
  }
});

app.get('/api/orders/stats', verifyAdminToken, async (req, res) => {
  try {
    const totalOrders = await Order.countDocuments();
    const totalRevenue = await Order.aggregate([
      { $group: { _id: null, total: { $sum: '$totalPrice' } } }
    ]);
    const pendingOrders = await Order.countDocuments({ status: 'pending' });
    const deliveredOrders = await Order.countDocuments({ status: 'delivered' });
    
    res.json({
      success: true,
      stats: {
        totalOrders,
        totalRevenue: totalRevenue[0]?.total || 0,
        pendingOrders,
        deliveredOrders
      }
    });
  } catch (error) {
    console.error('Order stats error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch order stats' 
    });
  }
});

app.put('/api/orders/:id/status', verifyAdminToken, async (req, res) => {
  try {
    const { status } = req.body;
    
    const order = await Order.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );
    
    if (!order) {
      return res.status(404).json({ 
        success: false, 
        message: 'Order not found' 
      });
    }
    
    res.json({ 
      success: true, 
      message: 'Order status updated successfully',
      order 
    });
  } catch (error) {
    console.error('Order status update error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to update order status' 
    });
  }
});

// Initialize with sample data
app.post('/api/init-sample-data', verifyAdminToken, async (req, res) => {
  try {
    // Clear existing data
    await Product.deleteMany({});
    await Review.deleteMany({});
    
    // Sample products
    const sampleProducts = [
      {
        name: 'গোলাপ আতর',
        description: '১০০% খাঁটি গোলাপ পাপড়ি থেকে তৈরি, মিষ্টি ও টেকসই সুগন্ধি। প্রকৃতির বিশুদ্ধতা নিয়ে আসুন আপনার দৈনন্দিন জীবনে।',
        price: 1299,
        originalPrice: 1599,
        stock: 50,
        category: 'আতর',
        imageUrl: 'https://images.unsplash.com/photo-1541643600914-78b084683601?ixlib=rb-4.0.3&auto=format&fit=crop&w=1460&q=80',
        tags: ['বেস্টসেলার', 'প্রিমিয়াম', 'দীর্ঘস্থায়ী'],
        sold: 234,
        featured: true
      },
      {
        name: 'কস্তুরী আতর',
        description: 'উচ্চমানের কস্তুরী থেকে তৈরি, গভীর ও আকর্ষণীয় সুগন্ধি। আধ্যাত্মিকতা ও প্রশান্তির অনুভূতি দেয়।',
        price: 2499,
        originalPrice: 2999,
        stock: 25,
        category: 'আতর',
        imageUrl: 'https://images.unsplash.com/photo-1601042879364-f3947d1f9fc9?ixlib=rb-4.0.3&auto=format&fit=crop&w=1468&q=80',
        tags: ['লাক্সারি', 'আধ্যাত্মিক', 'দীর্ঘস্থায়ী'],
        sold: 189,
        featured: true
      },
      {
        name: 'জসমিন আতর',
        description: 'তাজা জসমিন ফুল থেকে নিষ্কাশিত, হালকা ও সতেজ সুগন্ধি। দৈনন্দিন ব্যবহারের জন্য পারফেক্ট।',
        price: 999,
        originalPrice: 1299,
        stock: 100,
        category: 'আতর',
        imageUrl: 'https://images.unsplash.com/photo-1590736969955-0126f7e1e88d?ixlib=rb-4.0.3&auto=format&fit=crop&w=1468&q=80',
        tags: ['ফ্রেশ', 'হালকা', 'দৈনন্দিন'],
        sold: 97
      }
    ];
    
    // Sample reviews
    const sampleReviews = [
      {
        customerName: 'রাফিদ আহমেদ',
        product: 'গোলাপ আতর',
        rating: 5,
        reviewText: 'গোলাপ আতরটি অত্যন্ত উৎকৃষ্ট মানের। সুগন্ধটি টেকসই এবং প্রকৃত গোলাপের ঘ্রাণ নিয়ে আসে। ডেলিভারিও খুব দ্রুত পেয়েছি। সত্যিই অসাধারণ পণ্য।',
        approved: true
      },
      {
        customerName: 'সাবরিনা ইসলাম',
        product: 'কস্তুরী আতর',
        rating: 4,
        reviewText: 'কস্তুরী আতরটি অসাধারণ! গভীর ও মিষ্টি ঘ্রাণ সারাদিন স্থায়ী হয়। দামের তুলনায় মান অনেক ভালো। নিশ্চিতভাবে আবার কিনব। সবাইকে সুপারিশ করছি।',
        approved: true
      },
      {
        customerName: 'ইমরান হোসেন',
        product: 'জসমিন আতর',
        rating: 5,
        reviewText: 'জসমিন আতরটি হালকা ও সতেজ ঘ্রাণের জন্য পারফেক্ট। অফিসে ব্যবহারের জন্য আদর্শ। বোতলের ডিজাইনও খুব সুন্দর। প্যাকেজিং অত্যন্ত আকর্ষণীয়।',
        approved: true
      }
    ];
    
    await Product.insertMany(sampleProducts);
    await Review.insertMany(sampleReviews);
    
    res.json({ 
      success: true, 
      message: 'Sample data initialized successfully',
      products: sampleProducts.length,
      reviews: sampleReviews.length
    });
  } catch (error) {
    console.error('Sample data init error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to initialize sample data' 
    });
  }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`✅ Server is running on port ${PORT}`);
});