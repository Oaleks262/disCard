const mongoose = require('mongoose');
require('dotenv').config();

mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/loyalty-cards');

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

async function clearCardsForFreshStart() {
  try {
    const user = await User.findOne({ email: 'oaleks262@gmail.com' });
    if (!user) {
      console.log('User not found');
      return;
    }
    
    console.log('Clearing all cards for fresh start...');
    
    // Clear all cards
    user.cards = [];
    
    // Clear encryption key so server generates a fresh one
    user.encryptionKey = undefined;
    
    await user.save();
    
    console.log('✅ All cards cleared!');
    console.log('✅ Encryption key reset!');
    console.log('🎯 Ready for fresh start - add your cards in the app now!');
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    mongoose.connection.close();
  }
}

clearCardsForFreshStart();