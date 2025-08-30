// Service Worker for Loyalty Cards App
const CACHE_NAME = 'loyalty-cards-v1.0.1';
const STATIC_CACHE = 'static-v1.0.1';
const DYNAMIC_CACHE = 'dynamic-v1.0.1';

// Files to cache
const STATIC_ASSETS = [
    '/',
    '/index.html',
    '/style.css',
    '/script.js',
    '/manifest.json',
    '/libs/quagga.min.js',
    '/libs/jsqr.min.js'
];

// API endpoints to cache
const CACHABLE_API_ENDPOINTS = [
    '/api/cards'
];

// Install event - cache static assets
self.addEventListener('install', (event) => {
    console.log('Service Worker: Installing...');
    
    event.waitUntil(
        caches.open(STATIC_CACHE)
            .then((cache) => {
                console.log('Service Worker: Caching static assets');
                return cache.addAll(STATIC_ASSETS);
            })
            .then(() => {
                console.log('Service Worker: Static assets cached');
                return self.skipWaiting();
            })
            .catch((error) => {
                console.error('Service Worker: Error caching static assets:', error);
            })
    );
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
    console.log('Service Worker: Activating...');
    
    event.waitUntil(
        caches.keys()
            .then((cacheNames) => {
                return Promise.all(
                    cacheNames.map((cacheName) => {
                        if (cacheName !== STATIC_CACHE && cacheName !== DYNAMIC_CACHE) {
                            console.log('Service Worker: Deleting old cache:', cacheName);
                            return caches.delete(cacheName);
                        }
                    })
                );
            })
            .then(() => {
                console.log('Service Worker: Activated');
                return self.clients.claim();
            })
    );
});

// Fetch event - serve cached content when offline
self.addEventListener('fetch', (event) => {
    const { request } = event;
    const url = new URL(request.url);
    
    // Handle different types of requests
    if (request.method === 'GET') {
        // Static assets
        if (STATIC_ASSETS.some(asset => request.url.includes(asset))) {
            event.respondWith(cacheFirst(request));
        }
        // API requests
        else if (url.pathname.startsWith('/api/')) {
            event.respondWith(networkFirst(request));
        }
        // Other requests (images, fonts, etc.)
        else {
            event.respondWith(staleWhileRevalidate(request));
        }
    }
    // POST, PUT, DELETE requests
    else if (['POST', 'PUT', 'DELETE'].includes(request.method)) {
        event.respondWith(networkOnly(request));
    }
});

// Caching strategies

// Cache First - for static assets
async function cacheFirst(request) {
    try {
        const cachedResponse = await caches.match(request);
        if (cachedResponse) {
            return cachedResponse;
        }
        
        const networkResponse = await fetch(request);
        
        // Cache successful responses
        if (networkResponse.ok) {
            const cache = await caches.open(STATIC_CACHE);
            cache.put(request, networkResponse.clone());
        }
        
        return networkResponse;
    } catch (error) {
        console.error('Cache First error:', error);
        
        // Return offline page for navigation requests
        if (request.destination === 'document') {
            return caches.match('/index.html');
        }
        
        // Return empty response for other requests
        return new Response('', { status: 408, statusText: 'Request timeout' });
    }
}

// Network First - for API requests
async function networkFirst(request) {
    try {
        const networkResponse = await fetch(request);
        
        // Cache successful GET requests
        if (networkResponse.ok && request.method === 'GET') {
            const cache = await caches.open(DYNAMIC_CACHE);
            cache.put(request, networkResponse.clone());
        }
        
        return networkResponse;
    } catch (error) {
        console.error('Network First error:', error);
        
        // Try to serve from cache
        const cachedResponse = await caches.match(request);
        if (cachedResponse) {
            return cachedResponse;
        }
        
        // Return offline response for API requests
        if (request.url.includes('/api/')) {
            return new Response(
                JSON.stringify({ 
                    error: 'Немає з\'єднання з інтернетом',
                    offline: true
                }), 
                {
                    status: 503,
                    statusText: 'Service Unavailable',
                    headers: { 'Content-Type': 'application/json' }
                }
            );
        }
        
        return new Response('', { status: 503, statusText: 'Service Unavailable' });
    }
}

// Stale While Revalidate - for other resources
async function staleWhileRevalidate(request) {
    const cache = await caches.open(DYNAMIC_CACHE);
    const cachedResponse = await cache.match(request);
    
    const networkResponsePromise = fetch(request)
        .then((networkResponse) => {
            if (networkResponse.ok) {
                cache.put(request, networkResponse.clone());
            }
            return networkResponse;
        })
        .catch(() => null);
    
    return cachedResponse || await networkResponsePromise || new Response('', { 
        status: 404, 
        statusText: 'Not Found' 
    });
}

// Network Only - for write operations
async function networkOnly(request) {
    try {
        return await fetch(request);
    } catch (error) {
        console.error('Network Only error:', error);
        
        return new Response(
            JSON.stringify({ 
                error: 'Немає з\'єднання з інтернетом. Спробуйте пізніше.',
                offline: true
            }), 
            {
                status: 503,
                statusText: 'Service Unavailable',
                headers: { 'Content-Type': 'application/json' }
            }
        );
    }
}

// Background Sync for offline actions
self.addEventListener('sync', (event) => {
    console.log('Service Worker: Background sync triggered:', event.tag);
    
    if (event.tag === 'background-sync-cards') {
        event.waitUntil(syncOfflineActions());
    }
});

async function syncOfflineActions() {
    try {
        // Get offline actions from IndexedDB or localStorage
        const offlineActions = JSON.parse(localStorage.getItem('offlineActions') || '[]');
        
        for (const action of offlineActions) {
            try {
                const response = await fetch(action.url, {
                    method: action.method,
                    headers: action.headers,
                    body: action.body
                });
                
                if (response.ok) {
                    console.log('Offline action synced:', action);
                } else {
                    console.error('Failed to sync offline action:', action);
                }
            } catch (error) {
                console.error('Error syncing offline action:', error);
            }
        }
        
        // Clear synced actions
        localStorage.removeItem('offlineActions');
        
    } catch (error) {
        console.error('Background sync error:', error);
    }
}

// Push notifications
self.addEventListener('push', (event) => {
    if (!event.data) return;
    
    const data = event.data.json();
    
    const options = {
        body: data.body || 'У вас є нове повідомлення',
        icon: '/icons/icon-192x192.png',
        badge: '/icons/icon-72x72.png',
        tag: data.tag || 'general',
        requireInteraction: data.requireInteraction || false,
        actions: data.actions || [],
        data: data.data || {}
    };
    
    event.waitUntil(
        self.registration.showNotification(data.title || 'Карти Лояльності', options)
    );
});

// Notification click handling
self.addEventListener('notificationclick', (event) => {
    event.notification.close();
    
    if (event.action) {
        // Handle action clicks
        console.log('Notification action clicked:', event.action);
    } else {
        // Handle notification click
        event.waitUntil(
            clients.matchAll({ type: 'window' }).then((clientList) => {
                // If a window is already open, focus it
                for (const client of clientList) {
                    if (client.url.includes(self.location.origin) && 'focus' in client) {
                        return client.focus();
                    }
                }
                
                // Otherwise, open a new window
                if (clients.openWindow) {
                    return clients.openWindow('/');
                }
            })
        );
    }
});

// Message handling from main thread
self.addEventListener('message', (event) => {
    const { type, data } = event.data;
    
    switch (type) {
        case 'SKIP_WAITING':
            self.skipWaiting();
            break;
            
        case 'CLEAR_CACHE':
            clearAllCaches();
            break;
            
        case 'CACHE_URLS':
            cacheUrls(data.urls);
            break;
            
        default:
            console.log('Service Worker: Unknown message type:', type);
    }
});

// Utility functions
async function clearAllCaches() {
    const cacheNames = await caches.keys();
    return Promise.all(cacheNames.map(cacheName => caches.delete(cacheName)));
}

async function cacheUrls(urls) {
    const cache = await caches.open(DYNAMIC_CACHE);
    return cache.addAll(urls);
}

// Error handling
self.addEventListener('error', (event) => {
    console.error('Service Worker error:', event.error);
});

self.addEventListener('unhandledrejection', (event) => {
    console.error('Service Worker unhandled promise rejection:', event.reason);
});

console.log('Service Worker: Script loaded');