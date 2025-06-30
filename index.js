const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI);

const User = require('./models/User');
const Complaint = require('./models/Complaint');

// Middleware to check JWT token
const authenticate = async (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).send('Access Denied');
  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).send('Invalid Token');
  }
};

// Register
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ name, email, password: hashedPassword, role: 'user' });
  await user.save();
  res.send('User registered');
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.password))) return res.status(400).send('Invalid credentials');
  const token = jwt.sign({ _id: user._id, role: user.role }, process.env.JWT_SECRET);
  res.json({ token });
});

// Submit Complaint
app.post('/api/complaints', authenticate, async (req, res) => {
  const complaint = new Complaint({ ...req.body, userId: req.user._id, status: 'Pending' });
  await complaint.save();
  res.send('Complaint submitted');
});

// Get Complaints
app.get('/api/complaints', authenticate, async (req, res) => {
  const query = req.user.role === 'admin' ? {} : { userId: req.user._id };
  const complaints = await Complaint.find(query);
  res.json(complaints);
});

// Update Complaint Status (Admin)
app.put('/api/complaints/:id', authenticate, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).send('Forbidden');
  await Complaint.findByIdAndUpdate(req.params.id, { status: req.body.status });
  res.send('Complaint status updated');
});

app.listen(5000, () => console.log('Server running on port 5000'));
