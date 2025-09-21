const mongoose = require('mongoose');
require('dotenv').config();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/loyalty-cards');

// User Schema
const userSchema = new mongoose.Schema({
  email: String,
  encryptionKey: String,
  cards: [{
    name: String,
    code: String,
    codeType: String,
    encryptedCode: String,
    isEncrypted: Boolean,
    needsClientEncryption: Boolean,
    createdAt: Date
  }]
});

const User = mongoose.model('User', userSchema);

async function checkIfPlainCodes() {
  try {
    const user = await User.findOne({ email: 'oaleks262@gmail.com' });
    if (!user) {
      console.log('User not found');
      return;
    }
    
    console.log('Checking if encryptedCode contains plain text codes...\n');
    
    user.cards.forEach((card, index) => {
      if (card.encryptedCode) {
        console.log(`Card ${index + 1}: ${card.name}`);
        console.log(`  encryptedCode: "${card.encryptedCode}"`);
        console.log(`  Length: ${card.encryptedCode.length}`);
        
        // Check if this looks like a plain card code (not base64 encryption)
        const isLikelyPlain = /^[0-9]+$/.test(card.encryptedCode) || 
                             (card.encryptedCode.length < 30 && !/[+/=]/.test(card.encryptedCode));
        
        if (isLikelyPlain) {
          console.log('  🚨 This looks like a PLAIN TEXT code, not encrypted!');
        } else {
          console.log('  🔒 This looks like encrypted data');
        }
        console.log();
      }
    });
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    mongoose.connection.close();
  }
}

checkIfPlainCodes();