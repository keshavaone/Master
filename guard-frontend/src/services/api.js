import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
console.log("API Base URL:", API_BASE_URL);

// Create axios instance
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add request interceptor to include auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('accessToken');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Add response interceptor to handle token refresh
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    
    // If error is 401 (Unauthorized) and we haven't already tried to refresh
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      
      // Try to refresh the token
      const refreshToken = localStorage.getItem('refreshToken');
      if (refreshToken) {
        try {
          const response = await axios.post(`${API_BASE_URL}/auth/refresh`, {
            refresh_token: refreshToken
          });
          
          // Update tokens in localStorage
          localStorage.setItem('accessToken', response.data.access_token);
          if (response.data.refresh_token) {
            localStorage.setItem('refreshToken', response.data.refresh_token);
          }
          
          // Retry the original request with new token
          originalRequest.headers.Authorization = `Bearer ${response.data.access_token}`;
          return api(originalRequest);
        } catch (refreshError) {
          // Refresh failed, log out
          localStorage.removeItem('accessToken');
          localStorage.removeItem('refreshToken');
          window.location.href = '/login';
          return Promise.reject(refreshError);
        }
      }
    }
    
    return Promise.reject(error);
  }
);

// Auth API
export const authAPI = {
  loginWithSSO: (accessKey, secretKey, sessionToken) => {
    console.log("API client: Sending AWS SSO login request");
    return axios.post(`${API_BASE_URL}/auth/aws-sso`, {}, {
      headers: {
        'X-AWS-Access-Key-ID': accessKey,
        'X-AWS-Secret-Access-Key': secretKey,
        ...(sessionToken && { 'X-AWS-Session-Token': sessionToken })
      }
    });
  },
  
  loginWithPassword: (username, password) => {
    return axios.post(`${API_BASE_URL}/auth/login`, { username, password });
  },
  
  getCurrentUser: () => api.get('/auth/user'),
  
  logout: () => api.post('/auth/logout')
};

// PII Data API
export const dataAPI = {
  getAllItems: (params = {}) => {
    console.log("Fetching all PII items with params:", params);
    // Log request for debugging
    console.log(`API Request: GET ${API_BASE_URL}/pii`, params);
    
    // Add a timestamp to prevent caching
    const cacheBuster = { _t: new Date().getTime() };
    const fullParams = { ...params, ...cacheBuster };
    
    return api.get('/pii', { 
      params: fullParams,
      // Increase timeout for potentially slow response
      timeout: 20000,
      // Log request progress
      onDownloadProgress: (progressEvent) => {
        console.log(`Download progress: ${progressEvent.loaded} bytes received`);
      }
    })
    .then(response => {
      // Enhanced response handling with better debugging
      console.log("PII API Raw Response:", typeof response.data, response.data && typeof response.data.data);
      
      // Handle the expected format: {success: true, data: [...]}
      if (response.data && response.data.success === true && response.data.data) {
        // Check if data is an array (list of items) or object (single item)
        if (Array.isArray(response.data.data)) {
          console.log(`Received ${response.data.data.length} PII items in success.data format`);
          
          // Validate each item has piiData array
          response.data.data.forEach((item, index) => {
            if (!item.piiData || !Array.isArray(item.piiData)) {
              console.warn(`Item ${index} has invalid piiData format:`, item.piiData);
              // Fix it - ensure piiData is always an array
              item.piiData = item.piiData ? (
                Array.isArray(item.piiData) ? item.piiData : [{ name: "Data", value: String(item.piiData) }]
              ) : [];
            }
          });
          
          // Replace response.data with response.data.data to maintain compatibility
          return { ...response, data: response.data.data };
        } else if (typeof response.data.data === 'object') {
          // Single item response - wrap in array for consistency
          console.log(`Received single PII item in success.data format`);
          
          // Ensure piiData is an array
          const item = response.data.data;
          if (!item.piiData || !Array.isArray(item.piiData)) {
            console.warn(`Item has invalid piiData format:`, item.piiData);
            item.piiData = item.piiData ? (
              Array.isArray(item.piiData) ? item.piiData : [{ name: "Data", value: String(item.piiData) }]
            ) : [];
          }
          
          return { ...response, data: response.data.data };
        }
      }
      
      // Handle direct array format (legacy)
      if (Array.isArray(response.data)) {
        console.log(`Received ${response.data.length} PII items in direct array format`);
        
        // Ensure each item has piiData as array
        response.data.forEach((item, index) => {
          if (!item.piiData || !Array.isArray(item.piiData)) {
            console.warn(`Item ${index} has invalid piiData format:`, item.piiData);
            item.piiData = item.piiData ? (
              Array.isArray(item.piiData) ? item.piiData : [{ name: "Data", value: String(item.piiData) }]
            ) : [];
          }
        });
        
        return response;
      } 
      
      // Handle any other unexpected formats
      console.warn("Unexpected API response format:", response.data);
      
      // Try to extract data if possible
      const dataField = response.data && response.data.data;
      if (dataField) {
        // Convert to array if it's not already
        const dataArray = Array.isArray(dataField) ? dataField : [dataField];
        
        // Ensure each item has piiData as array
        dataArray.forEach((item, index) => {
          if (!item.piiData || !Array.isArray(item.piiData)) {
            console.warn(`Item ${index} has invalid piiData format:`, item.piiData);
            item.piiData = item.piiData ? (
              Array.isArray(item.piiData) ? item.piiData : [{ name: "Data", value: String(item.piiData) }]
            ) : [];
          }
        });
        
        return { ...response, data: dataArray };
      }
      
      // Return empty array as fallback to prevent errors
      console.error("Failed to extract any usable data from API response");
      return { ...response, data: [] };
    })
      .catch(error => {
        console.error("Error fetching PII data:", error);
        // Log detailed error information
        if (error.response) {
          // The request was made and the server responded with a status code
          // that falls out of the range of 2xx
          console.error("Error response data:", error.response.data);
          console.error("Error response status:", error.response.status);
          console.error("Error response headers:", error.response.headers);
        } else if (error.request) {
          // The request was made but no response was received
          console.error("Error request:", error.request);
        } else {
          // Something happened in setting up the request that triggered an Error
          console.error("Error message:", error.message);
        }
        console.error("Error config:", error.config);
        
        // For development/testing purposes, return mock data if API fails
        if (process.env.NODE_ENV === 'development') {
          console.log("Returning mock PII data for development");
          return {
            data: [
              {
                id: "mock-id-1",
                category: "Financial",
                type: "Credit Card",
                securityLevel: "high",
                lastUpdated: "1 day ago",
                piiData: [
                  {name: "Card Number", value: "****-****-****-1234"},
                  {name: "Expiry", value: "12/25"}
                ],
                createdAt: "2025-03-01T12:00:00Z",
                updatedAt: "2025-04-04T08:30:00Z"
              },
              {
                id: "mock-id-2",
                category: "Personal",
                type: "Home Address",
                securityLevel: "medium",
                lastUpdated: "3 days ago",
                piiData: [
                  {name: "Street", value: "123 Main St"},
                  {name: "City", value: "New York"}
                ]
              }
            ]
          };
        }
        throw error;
      });
  },
  
  getItemById: (id) => {
    console.log("Fetching PII item with ID:", id);
    return api.get(`/pii/${id}`)
      .then(response => {
        console.log("PII Item API Response:", response.data);
        
        // Handle the expected format: {success: true, data: {...}}
        if (response.data && response.data.success === true && response.data.data) {
          console.log("Received PII item in success.data format");
          
          // Get the item data
          const item = response.data.data;
          
          // Ensure piiData exists and is a list 
          if (!item.piiData) {
            console.warn("Item has no piiData field, creating empty array");
            item.piiData = [];
          } else if (!Array.isArray(item.piiData)) {
            console.warn("Item's piiData is not an array, converting:", item.piiData);
            
            // Convert non-array formats to array of name/value objects
            if (typeof item.piiData === 'string') {
              try {
                // Try to parse as JSON
                const parsed = JSON.parse(item.piiData);
                if (Array.isArray(parsed)) {
                  item.piiData = parsed;
                } else if (typeof parsed === 'object') {
                  item.piiData = Object.entries(parsed).map(([k, v]) => ({ name: k, value: v }));
                } else {
                  item.piiData = [{ name: "Data", value: item.piiData }];
                }
              } catch (error) {
                // Not valid JSON, use as raw string
                item.piiData = [{ name: "Data", value: item.piiData }];
              }
            } else if (typeof item.piiData === 'object') {
              // Convert object to array of entries
              item.piiData = Object.entries(item.piiData).map(([k, v]) => ({ name: k, value: v }));
            } else {
              // Convert any other type to string
              item.piiData = [{ name: "Data", value: String(item.piiData) }];
            }
          }
          
          // Ensure each piiData entry has name and value
          item.piiData.forEach((field, index) => {
            if (typeof field !== 'object' || field === null) {
              item.piiData[index] = { name: `Item ${index+1}`, value: String(field) };
            } else if (!field.name) {
              field.name = `Item ${index+1}`;
            } else if (!field.value && field.value !== 0 && field.value !== false) {
              field.value = "";
            }
          });
          
          // Replace response.data with response.data.data to maintain compatibility
          return { ...response, data: item };
        }
        
        // Handle direct object format
        if (typeof response.data === 'object' && !Array.isArray(response.data)) {
          console.log("Received PII item in direct object format");
          
          const item = response.data;
          
          // Ensure piiData exists and is a list
          if (!item.piiData) {
            item.piiData = [];
          } else if (!Array.isArray(item.piiData)) {
            // Convert to array using same logic as above
            if (typeof item.piiData === 'string') {
              try {
                const parsed = JSON.parse(item.piiData);
                if (Array.isArray(parsed)) {
                  item.piiData = parsed;
                } else if (typeof parsed === 'object') {
                  item.piiData = Object.entries(parsed).map(([k, v]) => ({ name: k, value: v }));
                } else {
                  item.piiData = [{ name: "Data", value: item.piiData }];
                }
              } catch (error) {
                item.piiData = [{ name: "Data", value: item.piiData }];
              }
            } else if (typeof item.piiData === 'object') {
              item.piiData = Object.entries(item.piiData).map(([k, v]) => ({ name: k, value: v }));
            } else {
              item.piiData = [{ name: "Data", value: String(item.piiData) }];
            }
          }
          
          // Ensure each piiData entry has name and value
          item.piiData.forEach((field, index) => {
            if (typeof field !== 'object' || field === null) {
              item.piiData[index] = { name: `Item ${index+1}`, value: String(field) };
            } else if (!field.name) {
              field.name = `Item ${index+1}`;
            } else if (!field.value && field.value !== 0 && field.value !== false) {
              field.value = "";
            }
          });
        }
        
        // Return direct object format as is (but fixed)
        return response;
      })
      .catch(error => {
        console.error(`Error fetching PII item ${id}:`, error);
        // For development/testing purposes, return mock data if API fails
        if (process.env.NODE_ENV === 'development') {
          console.log("Returning mock PII item for development");
          return {
            data: {
              id: id,
              category: "Financial",
              type: "Credit Card",
              securityLevel: "high",
              lastUpdated: "1 day ago",
              piiData: [
                {name: "Card Number", value: "****-****-****-1234"},
                {name: "Expiry", value: "12/25"},
                {name: "CVV", value: "***"}
              ],
              createdAt: "2025-03-01T12:00:00Z",
              updatedAt: "2025-04-04T08:30:00Z",
              createdBy: "user123",
              accessCount: 5
            }
          };
        }
        throw error;
      });
  },
  
  createItem: (itemData) => api.post('/pii', itemData),
  
  updateItem: (id, itemData) => api.put(`/pii/${id}`, itemData),
  
  deleteItem: (id) => api.delete(`/pii/${id}`)
};

// Categories API
export const categoriesAPI = {
  getAllCategories: () => api.get('/categories'),
  
  getItemsByCategory: (categoryName, params = {}) => 
    api.get(`/categories/${categoryName}/items`, { params })
};

// System API
export const systemAPI = {
  getActivityLog: (params = {}) => api.get('/system/activity', { params }),
  
  getSystemStats: () => api.get('/system/stats'),
  
  getHealthCheck: () => api.get('/system/health')
};

// Calendar API
export const calendarAPI = {
  sendCalendarSummary: (daysAhead = 0, method = "whatsapp", recipient = null) => {
    const params = { days_ahead: daysAhead };
    if (method) params.method = method;
    if (recipient) params.recipient = recipient;
    
    return api.post('/api/calendar/send-summary', params);
  },
  
  listSubscriptions: () => api.get('/api/calendar/subscriptions'),
  
  addSubscription: (name, url) => api.post('/api/calendar/subscription', { name, url }),
  
  removeSubscription: (urlOrName) => api.delete('/api/calendar/subscription', { 
    data: { url_or_name: urlOrName } 
  })
};

export default api;