// API Client for disCard Backend
class APIClient {
    constructor() {
        this.baseURL = window.location.origin + '/api';
        this.token = localStorage.getItem('authToken');
    }

    // Set authentication token
    setToken(token) {
        this.token = token;
        if (token) {
            localStorage.setItem('authToken', token);
        } else {
            localStorage.removeItem('authToken');
        }
    }

    // Get authentication headers
    getAuthHeaders() {
        const headers = {
            'Content-Type': 'application/json',
        };
        
        if (this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }
        
        return headers;
    }

    // Generic request handler
    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        const config = {
            headers: this.getAuthHeaders(),
            ...options
        };

        try {
            console.log(`API Request: ${options.method || 'GET'} ${url}`);
            const response = await fetch(url, config);
            
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ error: 'Network error' }));
                
                // Handle 401 errors (token expired/invalid)
                if (response.status === 401) {
                    console.log('Token expired or invalid, clearing authentication');
                    this.setToken(null);
                    localStorage.removeItem('authToken');
                    
                    // Instead of force reload, trigger auth screen through app
                    if (window.app && typeof window.app.showAuthScreen === 'function') {
                        window.app.showAuthScreen();
                    }
                    
                    throw new Error('Unauthorized - token expired');
                }
                
                throw new Error(errorData.error || `HTTP ${response.status}`);
            }

            const data = await response.json();
            console.log('API Response:', data);
            
            // Check for refreshed token in response headers
            const newToken = response.headers.get('X-New-Token');
            if (newToken) {
                console.log('🔄 Token refreshed automatically');
                this.setToken(newToken);
            }
            
            return data;
        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    }

    // Authentication methods
    async register(userData) {
        return this.request('/auth/register', {
            method: 'POST',
            body: JSON.stringify(userData)
        });
    }

    async login(credentials) {
        const response = await this.request('/auth/login', {
            method: 'POST',
            body: JSON.stringify(credentials)
        });
        
        if (response.token) {
            this.setToken(response.token);
        }
        
        return response;
    }

    async logout() {
        this.setToken(null);
    }

    async getProfile() {
        return this.request('/auth/me');
    }

    async updateProfile(userData) {
        return this.request('/auth/profile', {
            method: 'PUT',
            body: JSON.stringify(userData)
        });
    }

    async changePassword(passwordData) {
        return this.request('/auth/password', {
            method: 'PUT',
            body: JSON.stringify(passwordData)
        });
    }

    // Cards methods
    async getCards() {
        const response = await this.getProfile();
        return response.user.cards || [];
    }

    async createCard(cardData) {
        return this.request('/cards', {
            method: 'POST',
            body: JSON.stringify(cardData)
        });
    }

    async updateCard(cardId, cardData) {
        return this.request(`/cards/${cardId}`, {
            method: 'PUT',
            body: JSON.stringify(cardData)
        });
    }

    async deleteCard(cardId) {
        return this.request(`/cards/${cardId}`, {
            method: 'DELETE'
        });
    }

    // Utility methods
    isAuthenticated() {
        return !!this.token;
    }

    // Check if online
    isOnline() {
        return navigator.onLine;
    }

    // Sync method for offline/online data
    async syncData() {
        if (!this.isOnline() || !this.isAuthenticated()) {
            console.log('Cannot sync: offline or not authenticated');
            return false;
        }

        try {
            console.log('🔄 Starting data synchronization...');
            
            // Get server data
            const serverCards = await this.getCards();
            
            // Simple sync strategy: server data wins for now
            // In a more complex app, you'd compare timestamps and merge changes
            localStorage.setItem('cards', JSON.stringify(serverCards));
            
            console.log('✅ Data synchronized successfully');
            return true;
        } catch (error) {
            console.error('❌ Sync failed:', error);
            return false;
        }
    }
}

// Create global API instance
window.api = new APIClient();

// Export for modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = APIClient;
}