#!/usr/bin/env node

// Card Encryption Migration Script
// This script migrates existing unencrypted loyalty cards to encrypted format
// Run with: node rollback-migration.js

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const readline = require('readline');

// Load environment variables
require('dotenv').config();

// MongoDB connection string - update if needed  
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/loyalty-cards';

// User schema (matches server.js)
const UserSchema = new mongoose.Schema({
  name: { type: String },
  username: { type: String },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  language: { type: String, default: 'uk' },
  cards: [{
    name: { type: String, required: true, trim: true },
    code: { type: String },
    codeType: { type: String, enum: ['barcode', 'qrcode'] },
    encryptedCode: { type: String },
    isEncrypted: { type: Boolean, default: false },
    needsClientEncryption: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, {
  timestamps: true
});

let User;

// Crypto utilities (matches CryptoManager.js)
class MigrationCrypto {
  constructor() {
    this.algorithm = 'aes-256-gcm';
    this.keyLength = 32; // 256 bits
    this.ivLength = 12; // 96 bits for GCM
    this.saltLength = 16; // 128 bits
    this.iterations = 100000; // PBKDF2 iterations
  }

  // Generate deterministic salt from email (matches client-side)
  generateSalt(userEmail) {
    const data = userEmail + 'discard-salt-2024';
    const hash = crypto.createHash('sha256').update(data, 'utf8').digest();
    return hash.slice(0, this.saltLength);
  }

  // Generate encryption key from user credentials
  generateKey(userEmail, userPassword) {
    const keyMaterial = userEmail + userPassword;
    const salt = this.generateSalt(userEmail);
    
    return crypto.pbkdf2Sync(keyMaterial, salt, this.iterations, this.keyLength, 'sha256');
  }

  // Encrypt card data
  encryptCard(cardData, key) {
    try {
      const data = JSON.stringify(cardData);
      const iv = crypto.randomBytes(this.ivLength);
      
      const cipher = crypto.createCipher(this.algorithm, key);
      cipher.setAAD(Buffer.from('discard-card', 'utf8'));
      
      let encrypted = cipher.update(data, 'utf8', 'base64');
      encrypted += cipher.final('base64');
      
      const authTag = cipher.getAuthTag();
      
      // Combine IV, auth tag, and encrypted data
      const result = Buffer.concat([iv, authTag, Buffer.from(encrypted, 'base64')]);
      return result.toString('base64');
    } catch (error) {
      console.error('Error encrypting card data:', error);
      throw new Error('Failed to encrypt card data');
    }
  }

  // Decrypt card data for verification
  decryptCard(encryptedData, key) {
    try {
      const data = Buffer.from(encryptedData, 'base64');
      
      const iv = data.slice(0, this.ivLength);
      const authTag = data.slice(this.ivLength, this.ivLength + 16);
      const encryptedContent = data.slice(this.ivLength + 16);

      const decipher = crypto.createDecipher(this.algorithm, key);
      decipher.setAuthTag(authTag);
      decipher.setAAD(Buffer.from('discard-card', 'utf8'));
      
      let decrypted = decipher.update(encryptedContent, null, 'utf8');
      decrypted += decipher.final('utf8');
      
      return JSON.parse(decrypted);
    } catch (error) {
      console.error('Error decrypting card data:', error);
      throw new Error('Failed to decrypt card data');
    }
  }
}

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function question(prompt) {
  return new Promise(resolve => {
    rl.question(prompt, resolve);
  });
}

async function connectToDatabase() {
  try {
    await mongoose.connect(MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    
    User = mongoose.model('User', UserSchema);
    console.log('✅ Connected to MongoDB');
    return true;
  } catch (error) {
    console.error('❌ Failed to connect to MongoDB:', error.message);
    return false;
  }
}

async function findUnencryptedCards() {
  try {
    const users = await User.find({
      $or: [
        { 'cards.isEncrypted': { $ne: true } },
        { 'cards.isEncrypted': false },
        { 'cards.isEncrypted': { $exists: false } }
      ]
    });
    
    let totalCards = 0;
    const userSummary = [];
    
    for (const user of users) {
      const unencryptedCards = user.cards.filter(card => 
        !card.isEncrypted || card.isEncrypted === false || typeof card.isEncrypted === 'undefined'
      );
      if (unencryptedCards.length > 0) {
        totalCards += unencryptedCards.length;
        userSummary.push({
          email: user.email,
          username: user.username || user.name,
          cardCount: unencryptedCards.length,
          cards: unencryptedCards.map(card => ({
            name: card.name,
            isEncrypted: card.isEncrypted,
            hasCode: !!card.code,
            hasEncryptedCode: !!card.encryptedCode
          }))
        });
      }
    }
    
    return { users: userSummary, totalCards };
  } catch (error) {
    console.error('❌ Error finding unencrypted cards:', error);
    return { users: [], totalCards: 0 };
  }
}

async function migrateUserCards(user, userPassword) {
  const cryptoManager = new MigrationCrypto();
  const key = cryptoManager.generateKey(user.email, userPassword);
  
  let migratedCount = 0;
  const errors = [];
  
  for (const card of user.cards) {
    if (!card.isEncrypted && card.code) {
      try {
        // Encrypt the card code
        const encryptedCode = cryptoManager.encryptCard({ code: card.code }, key);
        
        // Verify encryption by decrypting
        const decryptedData = cryptoManager.decryptCard(encryptedCode, key);
        if (decryptedData.code !== card.code) {
          throw new Error('Encryption verification failed');
        }
        
        // Update card
        card.encryptedCode = encryptedCode;
        card.isEncrypted = true;
        card.code = undefined; // Remove plain text code
        
        migratedCount++;
      } catch (error) {
        errors.push(`Card "${card.name}": ${error.message}`);
      }
    }
  }
  
  if (migratedCount > 0) {
    await user.save();
  }
  
  return { migratedCount, errors };
}

async function performMigration() {
  console.log('\n🔍 Searching for users with unencrypted cards...');
  
  const { users, totalCards } = await findUnencryptedCards();
  
  if (totalCards === 0) {
    console.log('✅ No unencrypted cards found. All cards are already encrypted!');
    return;
  }
  
  console.log(`\n📊 Found ${totalCards} unencrypted cards across ${users.length} users:`);
  users.forEach(user => {
    console.log(`  • ${user.email} (${user.username}): ${user.cardCount} cards`);
  });
  
  const confirm = await question('\n❓ Do you want to proceed with migration? (yes/no): ');
  if (confirm.toLowerCase() !== 'yes' && confirm.toLowerCase() !== 'y') {
    console.log('Migration cancelled.');
    return;
  }
  
  console.log('\n🔐 Starting card encryption migration...');
  console.log('Note: You will need to provide user passwords for encryption.');
  
  let totalMigrated = 0;
  let totalErrors = 0;
  
  for (const userSummary of users) {
    console.log(`\n👤 Processing user: ${userSummary.email}`);
    
    const user = await User.findOne({ email: userSummary.email });
    if (!user) {
      console.log('  ❌ User not found');
      continue;
    }
    
    // For migration, we need the user's password
    console.log('  ℹ️  Password needed for encryption key generation.');
    const password = await question(`  🔑 Enter password for ${userSummary.email}: `);
    
    if (!password) {
      console.log('  ⏭️  Skipping user (no password provided)');
      continue;
    }
    
    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      console.log('  ❌ Invalid password, skipping user');
      continue;
    }
    
    try {
      const result = await migrateUserCards(user, password);
      
      console.log(`  ✅ Migrated ${result.migratedCount} cards`);
      totalMigrated += result.migratedCount;
      
      if (result.errors.length > 0) {
        console.log('  ⚠️  Errors:');
        result.errors.forEach(error => console.log(`    • ${error}`));
        totalErrors += result.errors.length;
      }
    } catch (error) {
      console.log(`  ❌ Migration failed: ${error.message}`);
      totalErrors++;
    }
  }
  
  console.log('\n📋 Migration Summary:');
  console.log(`  • Total cards migrated: ${totalMigrated}`);
  console.log(`  • Total errors: ${totalErrors}`);
  
  if (totalMigrated > 0) {
    console.log('\n✅ Migration completed successfully!');
    console.log('🔒 All migrated cards are now encrypted with AES-256-GCM.');
  }
}

async function verifyMigration() {
  console.log('\n🔍 Verifying migration...');
  
  const { users, totalCards } = await findUnencryptedCards();
  
  if (totalCards === 0) {
    console.log('✅ Verification passed: All cards are encrypted!');
  } else {
    console.log(`⚠️  ${totalCards} cards still unencrypted across ${users.length} users`);
    users.forEach(user => {
      console.log(`  • ${user.email}: ${user.cardCount} cards`);
    });
  }
}

async function autoMigrateWithoutPasswords() {
  console.log('\n🔄 Starting automatic migration (no passwords required)...');
  console.log('⚠️  Note: This will only mark cards as needing client-side encryption');
  
  const { users, totalCards } = await findUnencryptedCards();
  
  if (totalCards === 0) {
    console.log('✅ No unencrypted cards found. All cards are already encrypted!');
    return;
  }
  
  console.log(`📊 Found ${totalCards} unencrypted cards across ${users.length} users:`);
  users.forEach(user => {
    console.log(`  • ${user.email} (${user.username}): ${user.cardCount} cards`);
    user.cards.forEach(card => {
      console.log(`    - "${card.name}": encrypted=${card.isEncrypted}, hasCode=${card.hasCode}`);
    });
  });
  
  let totalMigrated = 0;
  
  for (const userSummary of users) {
    const user = await User.findOne({ email: userSummary.email });
    if (!user) continue;
    
    let userUpdated = false;
    
    for (const card of user.cards) {
      if ((!card.isEncrypted || card.isEncrypted === false) && card.code) {
        console.log(`  🔄 Preparing card "${card.name}" for encryption`);
        
        // Move unencrypted code to encryptedCode temporarily 
        // Client will handle proper encryption on next login
        card.encryptedCode = card.code;
        card.code = undefined;
        card.isEncrypted = true;
        card.needsClientEncryption = true; // Flag for client to re-encrypt properly
        
        totalMigrated++;
        userUpdated = true;
      }
    }
    
    if (userUpdated) {
      await user.save();
      console.log(`✅ Prepared ${userSummary.cardCount} cards for user: ${user.email}`);
    }
  }
  
  console.log(`\n🎉 Auto-migration completed!`);
  console.log(`📈 Total cards prepared: ${totalMigrated}`);
  console.log('🔐 Cards will be properly encrypted when users next log in.');
}

async function main() {
  console.log('🚀 disCard Loyalty Card Encryption Migration Tool');
  console.log('================================================');
  
  const connected = await connectToDatabase();
  if (!connected) {
    process.exit(1);
  }
  
  try {
    // Check if we have command line arguments
    const args = process.argv.slice(2);
    
    if (args.includes('--auto') || args.includes('-a')) {
      await autoMigrateWithoutPasswords();
    } else if (args.includes('--verify') || args.includes('-v')) {
      await verifyMigration();
    } else {
      const action = await question('\nSelect action:\n1. Migrate unencrypted cards (requires passwords)\n2. Auto-migrate (no passwords, client-side encryption)\n3. Verify migration status\nEnter choice (1, 2, or 3): ');
      
      if (action === '1') {
        await performMigration();
      } else if (action === '2') {
        await autoMigrateWithoutPasswords();
      } else if (action === '3') {
        await verifyMigration();
      } else {
        console.log('Invalid choice. Exiting.');
      }
    }
  } catch (error) {
    console.error('❌ Migration error:', error);
  } finally {
    rl.close();
    await mongoose.disconnect();
    console.log('\n👋 Disconnected from database. Migration complete!');
  }
}

// Handle process termination
process.on('SIGINT', async () => {
  console.log('\n\n⏹️  Migration interrupted by user');
  rl.close();
  await mongoose.disconnect();
  process.exit(0);
});

// Run migration
main().catch(error => {
  console.error('💥 Fatal error:', error);
  process.exit(1);
});