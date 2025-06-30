const mongoose = require('mongoose');
const ComplaintSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  title: String,
  description: String,
  status: String,
  createdAt: { type: Date, default: Date.now }
});
module.exports = mongoose.model('Complaint', ComplaintSchema);
