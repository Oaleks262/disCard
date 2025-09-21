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

// Sample card data for testing
const sampleCards = [
  { name: 'BeerMarket', code: '1234567890123', codeType: 'barcode' },
  { name: 'ЄКнигарня', code: '9876543210987', codeType: 'barcode' },
  { name: 'Ашан', code: '5555555555555', codeType: 'barcode' },
  { name: 'Камбуз', code: '1111111111111', codeType: 'barcode' },
  { name: 'АромаКава', code: '2222222222222', codeType: 'barcode' },
  { name: 'Simi', code: 'QR123ABC', codeType: 'qrcode' },
  { name: 'НоваПошта Фарлеп', code: '3333333333333', codeType: 'barcode' },
  { name: 'НоваПошта Моя', code: '4444444444444', codeType: 'barcode' },
  { name: 'Метро', code: '7777777777777', codeType: 'barcode' }
];

async function resetCardsToPlain() {
  try {
    const user = await User.findOne({ email: 'oaleks262@gmail.com' });
    if (!user) {
      console.log('User not found');
      return;
    }
    
    console.log('Found user:', user.email);
    console.log('Current cards:', user.cards.length);
    
    // Clear existing cards and add sample ones
    user.cards = [];
    
    // Add sample cards as plain text for testing
    for (const cardData of sampleCards) {
      user.cards.push({
        name: cardData.name,
        code: cardData.code,
        codeType: cardData.codeType,
        isEncrypted: false,
        createdAt: new Date()
      });
    }
    
    // Clear encryption key so server generates a new one
    user.encryptionKey = undefined;
    
    await user.save();
    
    console.log('✅ Reset complete!');
    console.log('Added', sampleCards.length, 'sample cards as plain text');
    console.log('Server will encrypt them when you next create a card');
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    mongoose.connection.close();
  }
}

resetCardsToPlain();