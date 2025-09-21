const mongoose = require('mongoose');
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
    needsClientEncryption: Boolean,
    createdAt: Date
  }]
});

const User = mongoose.model('User', userSchema);

async function debugCardContent() {
  try {
    const user = await User.findOne({ email: 'oaleks262@gmail.com' });
    if (!user) {
      console.log('User not found');
      return;
    }
    
    console.log('User:', user.email);
    console.log('Cards count:', user.cards.length);
    
    // Look at first card in detail
    if (user.cards.length > 0) {
      const card = user.cards[0];
      console.log('\nFirst card details:');
      console.log('Name:', card.name);
      console.log('CodeType:', card.codeType);
      console.log('isEncrypted:', card.isEncrypted);
      console.log('needsClientEncryption:', card.needsClientEncryption);
      console.log('Has code:', !!card.code);
      console.log('Has encryptedCode:', !!card.encryptedCode);
      
      if (card.encryptedCode) {
        console.log('\nencryptedCode (first 100 chars):');
        console.log(card.encryptedCode.substring(0, 100));
        console.log('Length:', card.encryptedCode.length);
        
        // Check if it's base64 encoded data or plain text
        try {
          const decoded = Buffer.from(card.encryptedCode, 'base64');
          console.log('Seems to be base64 encoded (length after decode):', decoded.length);
          
          // Try to see if it looks like a plain card code
          if (card.encryptedCode.length < 50 && !card.encryptedCode.includes('=')) {
            console.log('⚠️ This might be plain text, not encrypted data!');
          }
        } catch (error) {
          console.log('Not valid base64');
        }
      }
    }
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    mongoose.connection.close();
  }
}

debugCardContent();