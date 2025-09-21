// Update user password
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
require('dotenv').config();

// User Schema (same as in server.js)
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    maxlength: 255
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  cards: [{
    name: String,
    code: String,
    codeType: String,
    encryptedCode: String,
    isEncrypted: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
  }],
  encryptionKey: String,
  verificationCode: String,
  verificationCodeExpires: Date,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

async function updatePassword() {
  try {
    console.log('Connecting to MongoDB...');
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('Connected to MongoDB');

    const userEmail = 'oaleks262@gmail.com';
    const newPassword = 'Zvir_yatko28';
    
    // Find user
    const user = await User.findOne({ email: userEmail });
    
    if (!user) {
      console.log(`❌ User with email ${userEmail} not found`);
      return;
    }

    console.log(`✅ User found: ${user.email} (${user.name})`);
    
    // Hash new password
    console.log('🔐 Hashing new password...');
    const hashedPassword = await bcrypt.hash(newPassword, 12);
    
    // Update password
    await User.findByIdAndUpdate(user._id, { 
      password: hashedPassword 
    });
    
    console.log(`✅ Password updated successfully for ${userEmail}`);
    console.log(`New password: ${newPassword}`);
    
    // Test the new password
    console.log('\n🧪 Testing new password...');
    const updatedUser = await User.findById(user._id);
    const isValid = await bcrypt.compare(newPassword, updatedUser.password);
    console.log(`Password test: ${isValid ? '✅ VALID' : '❌ Invalid'}`);

  } catch (error) {
    console.error('❌ Error:', error.message);
  } finally {
    await mongoose.disconnect();
    process.exit(0);
  }
}

updatePassword();