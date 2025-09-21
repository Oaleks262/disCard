const mongoose = require('mongoose');
const crypto = require('crypto');
require('dotenv').config();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/loyalty-cards');

// User Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  encryptionKey: String,
  cards: [{
    name: String,
    code: String,
    codeType: String,
    encryptedCode: String,
    isEncrypted: Boolean,
    createdAt: Date
  }]
});

const User = mongoose.model('User', userSchema);

// Generate encryption key for user
function generateUserEncryptionKey() {
  return crypto.randomBytes(32).toString('base64');
}

async function fixUserEncryptionKey() {
  try {
    const user = await User.findOne({ email: 'oaleks262@gmail.com' });
    if (!user) {
      console.log('User not found');
      return;
    }
    
    console.log('User found:', user.email);
    console.log('Current encryptionKey:', !!user.encryptionKey);
    
    if (!user.encryptionKey) {
      // Generate new encryption key
      user.encryptionKey = generateUserEncryptionKey();
      await user.save();
      console.log('✅ Generated new encryption key for user');
    } else {
      console.log('User already has encryption key');
    }
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    mongoose.connection.close();
  }
}

fixUserEncryptionKey();