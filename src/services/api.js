// src/services/api.js
import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

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
  getAllItems: (params = {}) => api.get('/pii', { params }),
  
  getItemById: (id) => api.get(`/pii/${id}`),
  
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

export default api;