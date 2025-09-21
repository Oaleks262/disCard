const mongoose = require('mongoose');
require('dotenv').config();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/loyalty-cards');

// User Schema (simplified for debug)
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

async function debugUser() {
  try {
    const user = await User.findOne({ email: 'oaleks262@gmail.com' });
    if (!user) {
      console.log('User not found');
      return;
    }
    
    console.log('User found:', user.email);
    console.log('Has encryption key:', !!user.encryptionKey);
    console.log('Number of cards:', user.cards.length);
    
    user.cards.forEach((card, index) => {
      console.log(`\nCard ${index + 1}:`);
      console.log('  Name:', card.name);
      console.log('  Code type:', card.codeType);
      console.log('  Has code:', !!card.code);
      console.log('  Has encryptedCode:', !!card.encryptedCode);
      console.log('  Is encrypted:', card.isEncrypted);
      console.log('  Created:', card.createdAt);
    });
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    mongoose.connection.close();
  }
}

debugUser();