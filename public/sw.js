// Service Worker for disCard PWA

const CACHE_NAME = 'discard-v1.1.0';
const RUNTIME = 'runtime';
const API_CACHE = 'api-cache';

// Files to cache immediately for the app
const PRECACHE_URLS = [
  '/app',
  '/app/',
  '/app.html',
  '/css/app.css',
  '/js/app.js',
  '/js/api.js',
  '/js/i18n.js',
  '/manifest.json',
  // Icons
  '/icons/favicon-32x32.png',
  '/icons/favicon-16x16.png',
  '/icons/apple-touch-icon.png',
  // External libraries (only cache the most reliable ones)
  'https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap',
  'https://cdnjs.cloudflare.com/ajax/libs/qrcode-generator/1.4.4/qrcode.min.js',
  'https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js',
  'https://cdn.jsdelivr.net/npm/jsbarcode@3.11.5/dist/JsBarcode.all.min.js'
];

// Install Service Worker with better error handling
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(async cache => {
        console.log('Precaching app shell');
        
        // Cache each resource individually to handle failures gracefully
        const cachePromises = PRECACHE_URLS.map(async url => {
          try {
            await cache.add(url);
            console.log(`✅ Cached: ${url}`);
          } catch (error) {
            console.warn(`⚠️ Failed to cache: ${url}`, error);
            // Continue with other resources even if one fails
          }
        });
        
        await Promise.allSettled(cachePromises);
        console.log('App shell precaching completed');
      })
      .then(() => {
        console.log('Service Worker installed successfully');
        return self.skipWaiting();
      })
      .catch(error => {
        console.error('Service Worker install failed:', error);
      })
  );
});

// Activate Service Worker
self.addEventListener('activate', event => {
  const currentCaches = [CACHE_NAME, RUNTIME, API_CACHE];
  
  event.waitUntil(
    caches.keys()
      .then(cacheNames => {
        return cacheNames.filter(cacheName => !currentCaches.includes(cacheName));
      })
      .then(cachesToDelete => {
        return Promise.all(cachesToDelete.map(cacheToDelete => {
          console.log('Deleting old cache:', cacheToDelete);
          return caches.delete(cacheToDelete);
        }));
      })
      .then(() => {
        console.log('Service Worker activated successfully');
        
        // Notify all clients about update
        return self.clients.matchAll();
      })
      .then(clients => {
        clients.forEach(client => {
          client.postMessage({
            type: 'SW_UPDATED',
            message: 'Service Worker has been updated'
          });
        });
        
        return self.clients.claim();
      })
  );
});

// Fetch event handler with different caching strategies
self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip non-GET requests
  if (request.method !== 'GET') {
    return;
  }

  // Handle different types of requests with appropriate strategies
  if (url.pathname.startsWith('/api/')) {
    // API requests - Network First with cache fallback
    event.respondWith(networkFirstWithFallback(request));
  } else if (isStaticAsset(url.pathname)) {
    // Static assets - Cache First
    event.respondWith(cacheFirstWithNetworkFallback(request));
  } else if (url.pathname.startsWith('/app')) {
    // App routes - serve app.html for SPA routing
    event.respondWith(serveAppShell(request));
  } else if (url.pathname === '/' || url.pathname.endsWith('.html')) {
    // HTML pages - Stale While Revalidate
    event.respondWith(staleWhileRevalidate(request));
  } else {
    // Default strategy
    event.respondWith(networkFirstWithFallback(request));
  }
});

// Caching Strategies

// Network First - Try network first, fallback to cache
async function networkFirstWithFallback(request) {
  try {
    const networkResponse = await fetch(request);
    
    if (networkResponse.status === 200) {
      const cache = await caches.open(isApiRequest(request) ? API_CACHE : RUNTIME);
      cache.put(request, networkResponse.clone());
    }
    
    return networkResponse;
  } catch (error) {
    console.log('Network failed, trying cache:', request.url);
    const cachedResponse = await caches.match(request);
    
    if (cachedResponse) {
      return cachedResponse;
    }
    
    // Return offline page for HTML requests
    if (request.destination === 'document') {
      const cache = await caches.open(CACHE_NAME);
      return cache.match('/app.html') || new Response('Offline', { status: 503 });
    }
    
    throw error;
  }
}

// Cache First - Try cache first, fallback to network
async function cacheFirstWithNetworkFallback(request) {
  const cachedResponse = await caches.match(request);
  
  if (cachedResponse) {
    // Update cache in background
    updateCacheInBackground(request);
    return cachedResponse;
  }
  
  try {
    const networkResponse = await fetch(request);
    const cache = await caches.open(CACHE_NAME);
    cache.put(request, networkResponse.clone());
    return networkResponse;
  } catch (error) {
    console.error('Cache and network failed:', error);
    throw error;
  }
}

// Stale While Revalidate - Return cache immediately, update in background
async function staleWhileRevalidate(request) {
  const cachedResponse = await caches.match(request);
  
  const networkResponsePromise = fetch(request).then(async networkResponse => {
    if (networkResponse.ok) {
      const cache = await caches.open(CACHE_NAME);
      await cache.put(request, networkResponse.clone());
    }
    return networkResponse;
  }).catch(() => null);
  
  return cachedResponse || networkResponsePromise;
}

// Background cache update
async function updateCacheInBackground(request) {
  try {
    const networkResponse = await fetch(request);
    const cache = await caches.open(CACHE_NAME);
    cache.put(request, networkResponse);
  } catch (error) {
    // Silent fail for background updates
  }
}

// Serve app shell for SPA routes
async function serveAppShell(request) {
  try {
    // Try network first for the app shell
    const networkResponse = await fetch('/app.html');
    
    if (networkResponse.status === 200) {
      const cache = await caches.open(CACHE_NAME);
      cache.put('/app.html', networkResponse.clone());
      return networkResponse;
    }
    
    throw new Error('Network failed');
  } catch (error) {
    // Fallback to cached app shell
    console.log('Network failed for app shell, using cache');
    const cache = await caches.open(CACHE_NAME);
    const cachedResponse = await cache.match('/app.html');
    
    if (cachedResponse) {
      return cachedResponse;
    }
    
    // Final fallback
    return new Response('App not available offline', { 
      status: 503,
      statusText: 'Service Unavailable'
    });
  }
}

// Helper functions
function isStaticAsset(pathname) {
  const staticAssetExtensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.svg', '.ico', '.woff', '.woff2'];
  return staticAssetExtensions.some(ext => pathname.endsWith(ext));
}

function isApiRequest(request) {
  return request.url.includes('/api/');
}

// Background Sync for offline actions
self.addEventListener('sync', event => {
  console.log('Background sync triggered:', event.tag);
  
  if (event.tag === 'card-sync') {
    event.waitUntil(syncCards());
  } else if (event.tag === 'profile-sync') {
    event.waitUntil(syncProfile());
  }
});

async function syncCards() {
  try {
    // Get offline cards from IndexedDB
    const offlineCards = await getOfflineCards();
    
    for (const cardData of offlineCards) {
      try {
        const response = await fetch('/api/cards', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${cardData.token}`
          },
          body: JSON.stringify(cardData.card)
        });
        
        if (response.ok) {
          // Remove from offline storage
          await removeOfflineCard(cardData.id);
          
          // Notify client about successful sync
          await notifyClient('card-synced', { card: cardData.card });
        }
      } catch (error) {
        console.error('Failed to sync card:', error);
      }
    }
  } catch (error) {
    console.error('Background sync failed:', error);
  }
}

async function syncProfile() {
  // Similar implementation for profile sync
}

// Push Notifications
self.addEventListener('push', event => {
  console.log('Push message received');
  
  const options = {
    body: 'У вас є нові оновлення!',
    icon: '/icons/icon-192x192.png',
    badge: '/icons/badge-72x72.png',
    vibrate: [100, 50, 100],
    data: {
      dateOfArrival: Date.now(),
      primaryKey: 1
    },
    actions: [
      {
        action: 'explore',
        title: 'Переглянути',
        icon: '/icons/checkmark.png'
      },
      {
        action: 'close',
        title: 'Закрити',
        icon: '/icons/xmark.png'
      }
    ]
  };
  
  event.waitUntil(
    self.registration.showNotification('disCard', options)
  );
});

// Notification click handler
self.addEventListener('notificationclick', event => {
  console.log('Notification click received.');
  
  event.notification.close();
  
  if (event.action === 'explore') {
    event.waitUntil(
      clients.openWindow('/app.html')
    );
  }
});

// Message handler for communication with main app
self.addEventListener('message', event => {
  console.log('SW received message:', event.data);
  
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
  
  if (event.data && event.data.type === 'GET_VERSION') {
    event.ports[0].postMessage({ version: CACHE_NAME });
  }
  
  if (event.data && event.data.type === 'CACHE_CARD_OFFLINE') {
    event.waitUntil(cacheCardOffline(event.data.card));
  }
});

// Offline storage helpers (using IndexedDB)
async function getOfflineCards() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('discard-offline', 1);
    
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const db = request.result;
      const transaction = db.transaction(['cards'], 'readonly');
      const store = transaction.objectStore('cards');
      const getRequest = store.getAll();
      
      getRequest.onsuccess = () => resolve(getRequest.result);
      getRequest.onerror = () => reject(getRequest.error);
    };
    
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains('cards')) {
        db.createObjectStore('cards', { keyPath: 'id', autoIncrement: true });
      }
    };
  });
}

async function cacheCardOffline(cardData) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('discard-offline', 1);
    
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const db = request.result;
      const transaction = db.transaction(['cards'], 'readwrite');
      const store = transaction.objectStore('cards');
      const addRequest = store.add({
        card: cardData,
        timestamp: Date.now(),
        token: localStorage.getItem('authToken')
      });
      
      addRequest.onsuccess = () => resolve();
      addRequest.onerror = () => reject(addRequest.error);
    };
  });
}

async function removeOfflineCard(id) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('discard-offline', 1);
    
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const db = request.result;
      const transaction = db.transaction(['cards'], 'readwrite');
      const store = transaction.objectStore('cards');
      const deleteRequest = store.delete(id);
      
      deleteRequest.onsuccess = () => resolve();
      deleteRequest.onerror = () => reject(deleteRequest.error);
    };
  });
}

// Notify clients
async function notifyClient(type, data) {
  const clients = await self.clients.matchAll();
  clients.forEach(client => {
    client.postMessage({ type, data });
  });
}

// Periodic Background Sync (if supported)
self.addEventListener('periodicsync', event => {
  if (event.tag === 'cards-sync') {
    event.waitUntil(syncCards());
  }
});

// Share Target API (if the app is installed)
self.addEventListener('share', event => {
  console.log('Share event received:', event);
  // Handle shared content
});

// Error handling
self.addEventListener('error', event => {
  console.error('Service Worker error:', event.error);
});

self.addEventListener('unhandledrejection', event => {
  console.error('Service Worker unhandled rejection:', event.reason);
});

console.log('Service Worker script loaded successfully');

// Performance monitoring
let swStartTime = Date.now();

self.addEventListener('install', () => {
  console.log(`SW install took ${Date.now() - swStartTime}ms`);
});

// Cache management - clean up old caches periodically
async function cleanupOldCaches() {
  const cacheNames = await caches.keys();
  const oldCaches = cacheNames.filter(name => 
    name.startsWith('discard-') && name !== CACHE_NAME
  );
  
  return Promise.all(oldCaches.map(name => caches.delete(name)));
}

// Run cleanup on activate
self.addEventListener('activate', event => {
  event.waitUntil(cleanupOldCaches());
});