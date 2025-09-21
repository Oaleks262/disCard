const mongoose = require('mongoose');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
require('dotenv').config();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/loyalty-cards');

// User Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
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

// Old GCM decryption (from migration script)
class OldCrypto {
  constructor() {
    this.algorithm = 'aes-256-gcm';
    this.keyLength = 32;
    this.ivLength = 12;
    this.saltLength = 16;
    this.iterations = 100000;
  }

  generateSalt(userEmail) {
    const data = userEmail + 'discard-salt-2024';
    const hash = crypto.createHash('sha256').update(data, 'utf8').digest();
    return hash.slice(0, this.saltLength);
  }

  generateKey(userEmail, userPassword) {
    const keyMaterial = userEmail + userPassword;
    const salt = this.generateSalt(userEmail);
    return crypto.pbkdf2Sync(keyMaterial, salt, this.iterations, this.keyLength, 'sha256');
  }

  decryptCard(encryptedData, key) {
    try {
      const data = Buffer.from(encryptedData, 'base64');
      
      const iv = data.slice(0, this.ivLength);
      const authTag = data.slice(this.ivLength, this.ivLength + 16);
      const encryptedContent = data.slice(this.ivLength + 16);

      const decipher = crypto.createDecipheriv(this.algorithm, key, iv);
      decipher.setAuthTag(authTag);
      decipher.setAAD(Buffer.from('discard-card', 'utf8'));
      
      let decrypted = decipher.update(encryptedContent, null, 'utf8');
      decrypted += decipher.final('utf8');
      
      return JSON.parse(decrypted);
    } catch (error) {
      throw new Error('Failed to decrypt with old format');
    }
  }
}

// New CBC encryption (from server.js)
function generateUserEncryptionKey() {
  return crypto.randomBytes(32).toString('base64');
}

function encryptCardCode(code, encryptionKey) {
  try {
    const key = Buffer.from(encryptionKey, 'base64');
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    
    let encrypted = cipher.update(code, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    
    const result = Buffer.concat([iv, Buffer.from(encrypted, 'base64')]);
    return result.toString('base64');
  } catch (error) {
    throw new Error('Failed to encrypt card code');
  }
}

async function fixUserMigration() {
  try {
    const user = await User.findOne({ email: 'oaleks262@gmail.com' });
    if (!user) {
      console.log('User not found');
      return;
    }
    
    console.log('Found user:', user.email);
    console.log('Cards:', user.cards.length);
    
    // Ask for user password to decrypt old cards
    console.log('\nFor migration we need your password:');
    const readline = require('readline');
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });
    
    const password = await new Promise(resolve => {
      rl.question('Password: ', resolve);
    });
    rl.close();
    
    // Verify password
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      console.log('❌ Invalid password');
      return;
    }
    
    console.log('✅ Password verified');
    
    // Initialize old and new crypto
    const oldCrypto = new OldCrypto();
    const oldKey = oldCrypto.generateKey(user.email, password);
    
    // Ensure user has new encryption key
    if (!user.encryptionKey) {
      user.encryptionKey = generateUserEncryptionKey();
      console.log('Generated new encryption key');
    }
    
    let migratedCount = 0;
    let errorCount = 0;
    
    // Migrate each card
    for (const card of user.cards) {
      if (card.isEncrypted && card.encryptedCode) {
        try {
          console.log(`Migrating card: ${card.name}`);
          
          // Try to decrypt with old format
          const decryptedData = oldCrypto.decryptCard(card.encryptedCode, oldKey);
          const plainCode = decryptedData.code;
          
          // Re-encrypt with new format
          const newEncryptedCode = encryptCardCode(plainCode, user.encryptionKey);
          
          // Update card
          card.encryptedCode = newEncryptedCode;
          card.isEncrypted = true;
          card.needsClientEncryption = false;
          
          console.log(`  ✅ Migrated: ${plainCode.substring(0, 10)}...`);
          migratedCount++;
          
        } catch (error) {
          console.log(`  ❌ Failed to migrate ${card.name}:`, error.message);
          errorCount++;
        }
      }
    }
    
    if (migratedCount > 0) {
      await user.save();
      console.log(`\n🎉 Migration completed!`);
      console.log(`✅ Successfully migrated: ${migratedCount} cards`);
      console.log(`❌ Errors: ${errorCount} cards`);
    } else {
      console.log('\n❌ No cards were migrated');
    }
    
  } catch (error) {
    console.error('Migration error:', error);
  } finally {
    mongoose.connection.close();
  }
}

fixUserMigration();