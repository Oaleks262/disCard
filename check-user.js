// Check user password in database
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

async function checkUser() {
  try {
    console.log('Connecting to MongoDB...');
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('Connected to MongoDB');

    // Find your user (replace with your actual email)
    const userEmail = 'oaleks262@gmail.com'; // This seems to be your actual email based on the database
    const user = await User.findOne({ email: userEmail });
    
    if (!user) {
      console.log(`❌ User with email ${userEmail} not found`);
      console.log('\nAll users in database:');
      const allUsers = await User.find({}, { email: 1, name: 1, createdAt: 1 });
      allUsers.forEach(u => {
        console.log(`- ${u.email} (${u.name}) - Created: ${u.createdAt}`);
      });
      return;
    }

    console.log(`✅ User found: ${user.email}`);
    console.log(`Name: ${user.name}`);
    console.log(`Created: ${user.createdAt}`);
    
    // Test password validation
    const testPasswords = ['32Gesohe', 'Zvir_yatko28', '123456'];
    
    console.log('\n🔐 Testing passwords:');
    for (const password of testPasswords) {
      try {
        const isValid = await bcrypt.compare(password, user.password);
        console.log(`- "${password}": ${isValid ? '✅ VALID' : '❌ Invalid'}`);
      } catch (error) {
        console.log(`- "${password}": ❌ Error testing - ${error.message}`);
      }
    }

  } catch (error) {
    console.error('❌ Error:', error.message);
  } finally {
    await mongoose.disconnect();
    process.exit(0);
  }
}

checkUser();