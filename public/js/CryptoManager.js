// Card Data Encryption Manager
// Uses AES-256-GCM encryption for card data security

class CryptoManager {
  constructor() {
    this.algorithm = 'AES-GCM';
    this.keyLength = 256;
    this.ivLength = 12; // 96 bits for GCM
    this.saltLength = 16; // 128 bits
    this.iterations = 100000; // PBKDF2 iterations
  }

  // Generate a secure encryption key from user credentials
  async generateKey(userEmail, userPassword) {
    try {
      // Create a deterministic key from user email and password
      const keyMaterial = await this.deriveKeyMaterial(userEmail + userPassword);
      const salt = await this.generateSalt(userEmail);
      
      // Derive the actual encryption key
      const key = await crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: salt,
          iterations: this.iterations,
          hash: 'SHA-256'
        },
        keyMaterial,
        { name: this.algorithm, length: this.keyLength },
        false, // not extractable
        ['encrypt', 'decrypt']
      );

      return key;
    } catch (error) {
      console.error('Error generating encryption key:', error);
      throw new Error('Failed to generate encryption key');
    }
  }

  // Create key material from string
  async deriveKeyMaterial(keyString) {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(keyString);
    
    return await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );
  }

  // Generate deterministic salt from email
  async generateSalt(userEmail) {
    const encoder = new TextEncoder();
    const data = encoder.encode(userEmail + 'discard-salt-2024');
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(hashBuffer.slice(0, this.saltLength));
  }

  // Encrypt card data
  async encryptCard(cardData, key) {
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(JSON.stringify(cardData));
      
      // Generate random IV
      const iv = crypto.getRandomValues(new Uint8Array(this.ivLength));
      
      // Encrypt the data
      const encryptedData = await crypto.subtle.encrypt(
        {
          name: this.algorithm,
          iv: iv
        },
        key,
        data
      );

      // Combine IV and encrypted data
      const result = new Uint8Array(iv.length + encryptedData.byteLength);
      result.set(iv);
      result.set(new Uint8Array(encryptedData), iv.length);

      // Convert to base64 for storage
      return this.arrayBufferToBase64(result);
    } catch (error) {
      console.error('Error encrypting card data:', error);
      throw new Error('Failed to encrypt card data');
    }
  }

  // Decrypt card data with proper Web Crypto API GCM
  async decryptCard(encryptedData, key) {
    try {
      // Convert from base64
      const data = this.base64ToArrayBuffer(encryptedData);
      
      // Extract IV (12 bytes), AuthTag (16 bytes), and encrypted content
      const iv = data.slice(0, this.ivLength);
      const authTag = data.slice(this.ivLength, this.ivLength + 16);
      const encryptedContent = data.slice(this.ivLength + 16);

      // Decrypt with GCM - need to add auth tag to the encrypted content
      const encryptedWithTag = new Uint8Array(encryptedContent.length + authTag.length);
      encryptedWithTag.set(encryptedContent);
      encryptedWithTag.set(authTag, encryptedContent.length);

      const decryptedData = await crypto.subtle.decrypt(
        {
          name: this.algorithm,
          iv: iv,
          additionalData: new TextEncoder().encode('discard-card')
        },
        key,
        encryptedWithTag
      );

      // Convert back to string and parse JSON
      const decoder = new TextDecoder();
      const jsonString = decoder.decode(decryptedData);
      return JSON.parse(jsonString);
    } catch (error) {
      console.error('Error decrypting card data:', error);
      // For debugging - try to show what we have
      console.log('Encrypted data length:', encryptedData.length);
      console.log('First 50 chars:', encryptedData.substring(0, 50));
      throw new Error('Failed to decrypt card data');
    }
  }

  // Encrypt array of cards
  async encryptCards(cards, key) {
    try {
      const encryptedCards = [];
      for (const card of cards) {
        // Create a copy to avoid modifying original
        const cardCopy = { ...card };
        
        // Encrypt sensitive fields
        if (cardCopy.code) {
          cardCopy.code = await this.encryptCard({ code: cardCopy.code }, key);
        }
        
        // Keep non-sensitive metadata unencrypted for search/display
        const encryptedCard = {
          id: cardCopy.id,
          name: cardCopy.name, // Keep name unencrypted for search
          codeType: cardCopy.codeType,
          createdAt: cardCopy.createdAt,
          encryptedCode: cardCopy.code, // Store encrypted code separately
          isEncrypted: true
        };
        
        delete encryptedCard.code; // Remove the encrypted code from main object
        encryptedCards.push(encryptedCard);
      }
      return encryptedCards;
    } catch (error) {
      console.error('Error encrypting cards array:', error);
      throw new Error('Failed to encrypt cards');
    }
  }

  // Decrypt array of cards
  async decryptCards(encryptedCards, key) {
    try {
      const decryptedCards = [];
      for (const encryptedCard of encryptedCards) {
        if (!encryptedCard.isEncrypted) {
          // Handle legacy unencrypted cards
          decryptedCards.push(encryptedCard);
          continue;
        }

        // Handle auto-migrated cards that need proper encryption
        if (encryptedCard.needsClientEncryption && encryptedCard.encryptedCode) {
          // This card was auto-migrated and contains plain text in encryptedCode
          const plainCode = encryptedCard.encryptedCode;
          
          // Reconstruct card with plain code for display
          const decryptedCard = {
            id: encryptedCard.id || encryptedCard._id,
            name: encryptedCard.name,
            code: plainCode,
            codeType: encryptedCard.codeType,
            createdAt: encryptedCard.createdAt,
            needsClientEncryption: true // Preserve flag for re-encryption
          };
          
          decryptedCards.push(decryptedCard);
          continue;
        }

        // Decrypt properly encrypted cards
        let code = '';
        if (encryptedCard.encryptedCode) {
          try {
            const decryptedData = await this.decryptCard(encryptedCard.encryptedCode, key);
            code = decryptedData.code || '';
          } catch (error) {
            console.warn('Failed to decrypt card, may be auto-migrated:', encryptedCard.name);
            // Treat as auto-migrated card
            code = encryptedCard.encryptedCode;
          }
        }

        // Reconstruct original card object
        const decryptedCard = {
          id: encryptedCard.id || encryptedCard._id,
          name: encryptedCard.name,
          code: code,
          codeType: encryptedCard.codeType,
          createdAt: encryptedCard.createdAt
        };
        
        decryptedCards.push(decryptedCard);
      }
      return decryptedCards;
    } catch (error) {
      console.error('Error decrypting cards array:', error);
      throw new Error('Failed to decrypt cards');
    }
  }

  // Utility: Convert ArrayBuffer to Base64
  arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  // Utility: Convert Base64 to ArrayBuffer
  base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  // Check if Web Crypto API is available
  static isSupported() {
    return typeof crypto !== 'undefined' && 
           typeof crypto.subtle !== 'undefined' &&
           typeof crypto.getRandomValues !== 'undefined';
  }

  // Migrate unencrypted cards to encrypted format
  async migrateCards(unencryptedCards, key) {
    try {
      const migratedCards = [];
      for (const card of unencryptedCards) {
        if (card.isEncrypted) {
          // Already encrypted, skip
          migratedCards.push(card);
          continue;
        }

        // Encrypt the card
        const encryptedCode = await this.encryptCard({ code: card.code || '' }, key);
        
        const encryptedCard = {
          id: card.id,
          name: card.name,
          codeType: card.codeType,
          createdAt: card.createdAt,
          encryptedCode: encryptedCode,
          isEncrypted: true
        };
        
        migratedCards.push(encryptedCard);
      }

      return migratedCards;
    } catch (error) {
      console.error('Error migrating cards:', error);
      throw new Error('Failed to migrate cards to encrypted format');
    }
  }

  // Generate a test encryption key for development/testing
  async generateTestKey() {
    const testEmail = 'test@discard.com';
    const testPassword = 'testpassword123';
    return await this.generateKey(testEmail, testPassword);
  }
}

// Export for use in other modules
window.CryptoManager = CryptoManager;

// Auto-initialize if needed
if (typeof module !== 'undefined' && module.exports) {
  module.exports = CryptoManager;
}