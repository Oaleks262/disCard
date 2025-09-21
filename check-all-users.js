// Check all users' passwords
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

async function checkAllUsers() {
  try {
    console.log('Connecting to MongoDB...');
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('Connected to MongoDB\n');

    // Get all users
    const users = await User.find({}, { email: 1, name: 1, password: 1, createdAt: 1 });
    
    console.log(`Found ${users.length} users in database:\n`);
    
    // Test common passwords for each user
    const testPasswords = ['123456', '32Gesohe', 'Zvir_yatko28', 'password', '111111', '123123'];
    
    for (const user of users) {
      console.log(`👤 ${user.name} (${user.email})`);
      console.log(`   Created: ${user.createdAt}`);
      
      let passwordFound = false;
      
      for (const password of testPasswords) {
        try {
          const isValid = await bcrypt.compare(password, user.password);
          if (isValid) {
            console.log(`   🔐 Password: "${password}" ✅`);
            passwordFound = true;
            break;
          }
        } catch (error) {
          // Skip errors
        }
      }
      
      if (!passwordFound) {
        console.log(`   🔐 Password: Unknown ❓`);
      }
      
      console.log(''); // Empty line for readability
    }

  } catch (error) {
    console.error('❌ Error:', error.message);
  } finally {
    await mongoose.disconnect();
    process.exit(0);
  }
}

checkAllUsers();