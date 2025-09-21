const mongoose = require('mongoose');
require('dotenv').config();

// Restore original encrypted cards from what we saw earlier
const originalEncryptedCards = [
  {
    name: 'BeerMarket',
    encryptedCode: 'i7j1EYu7pa9lA+AnMJ4KgiAd1UeYg9YUsTZ2boXeLLFfqUQyeX5b8sMYcaVWO+32dHDlDw==',
    codeType: 'barcode',
    isEncrypted: true
  },
  {
    name: 'ЄКнигарня', 
    encryptedCode: 'OP467BaINHax5LlnSbAqolUEZlsA/QQamIEmT78Ltc9HSkTmAOWTVa0uXoyRW7yENZZf/w==',
    codeType: 'barcode',
    isEncrypted: true
  },
  {
    name: 'Ашан',
    encryptedCode: 'JVZLcfXUu4d35Wkee6EaJtPdw6kJq8otl4h/9DJlu8RMoNlJxr4b5pdyMb8KlCBjfdwH4Q==',
    codeType: 'barcode', 
    isEncrypted: true
  },
  {
    name: 'Камбуз',
    encryptedCode: 'RrF1Hcrsek6+2dLGZbglxu5A8TL01jy8M+GgvYAbgjQbcGJlanTj6pTRgzRqvV1dBwX+pA==',
    codeType: 'barcode',
    isEncrypted: true
  },
  {
    name: 'АромаКава',
    encryptedCode: 'i2qCFOoIA6KxwUWtZvTgfEawbIkNIL80CbXQbKjbkXq/v3BJF3lV25yqZOQ6JA==',
    codeType: 'barcode',
    isEncrypted: true
  },
  {
    name: 'Simi',
    encryptedCode: 'lHcZf2dyj7AXSk3jYwGmmmc4rkuYPMtAURMJEBxkByzSoJglFZRIrE3PUhZRy3WH1qBP4d0=',
    codeType: 'qrcode',
    isEncrypted: true
  },
  {
    name: 'НоваПошта Фарлеп',
    encryptedCode: 'bThrnraQ/AEcOCsFMvWjF1qkF7JFaaawbrqWxDFsqiC2vOo2qx7mmWxinApSPQNH7Df/oTljGw==',
    codeType: 'barcode',
    isEncrypted: true
  },
  {
    name: 'НоваПошта Моя', 
    encryptedCode: '21qCUOoo39jE2uiDMCTrToIpXoKpZb0wNFx+YxAuMX6Boo8jIyrpLd/biIteawbf6CbvZcpuxQ==',
    codeType: 'barcode',
    isEncrypted: true
  },
  {
    name: 'Метро',
    encryptedCode: 'gVecM21WBbqLJUEcaWV/VjAiP+UydW2QlLHYd31PEkptxRac9hz8SLSqfH2wVwS9CSJJmm8kQdEyYOgKCg==',
    codeType: 'barcode',
    isEncrypted: true
  }
];

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
    needsClientEncryption: Boolean,
    createdAt: Date
  }]
});

const User = mongoose.model('User', userSchema);

async function restoreOriginalCards() {
  try {
    const user = await User.findOne({ email: 'oaleks262@gmail.com' });
    if (!user) {
      console.log('User not found');
      return;
    }
    
    console.log('Restoring original encrypted cards...');
    
    // Clear current cards
    user.cards = [];
    
    // Add original encrypted cards
    for (const cardData of originalEncryptedCards) {
      user.cards.push({
        name: cardData.name,
        encryptedCode: cardData.encryptedCode,
        codeType: cardData.codeType,
        isEncrypted: true,
        needsRemigration: true, // Flag for special handling
        createdAt: new Date()
      });
    }
    
    await user.save();
    
    console.log('✅ Restored', originalEncryptedCards.length, 'original encrypted cards');
    console.log('⚠️  These cards need special decryption handling');
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    mongoose.connection.close();
  }
}

restoreOriginalCards();