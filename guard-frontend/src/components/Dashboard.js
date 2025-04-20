import React, { useState, useEffect } from 'react';
import { Shield, Eye, User, Lock, Database, FileText, Settings, LogOut, BarChart2, Bell, Search, Plus, RefreshCw, Calendar, Key } from 'lucide-react';
import CalendarNotifications from './CalendarNotifications';
import { dataAPI } from '../services/api';
import { useAuth } from '../contexts/AuthContext';
import { useNavigate } from 'react-router-dom';

// Main dashboard component
const GuardDashboard = () => {
  const [, setAuthenticated] = useState(true);
  const [activePage, setActivePage] = useState('dashboard');
  const [showLogoutConfirm, setShowLogoutConfirm] = useState(false);
  const { logout } = useAuth();
  const navigate = useNavigate();
  const [darkMode, setDarkMode] = useState(true);
  const [notifications] = useState(3);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState(null);
  const [piiData, setPiiData] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selectedPiiItem, setSelectedPiiItem] = useState(null);
  
  // Sample data
  const categories = [
    { id: 1, name: 'Financial', count: 12, icon: 'credit-card' },
    { id: 2, name: 'Personal', count: 8, icon: 'user' },
    { id: 3, name: 'Medical', count: 5, icon: 'activity' },
    { id: 4, name: 'Accounts', count: 15, icon: 'key' },
    { id: 5, name: 'Documents', count: 7, icon: 'file' },
  ];
  
  const dataItems = [
    { id: 1, category: 'Financial', type: 'Credit Card', updated: '2 hours ago', sensitive: true },
    { id: 2, category: 'Financial', type: 'Bank Account', updated: '1 day ago', sensitive: true },
    { id: 3, category: 'Personal', type: 'Home Address', updated: '5 days ago', sensitive: false },
    { id: 4, category: 'Medical', type: 'Insurance', updated: '1 week ago', sensitive: true },
    { id: 5, category: 'Accounts', type: 'Email Credentials', updated: '3 days ago', sensitive: true },
  ];
  
  // Filter data based on search and category
  const filteredData = dataItems.filter(item => {
    const matchesSearch = searchQuery === '' || 
      item.type.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.category.toLowerCase().includes(searchQuery.toLowerCase());
      
    const matchesCategory = selectedCategory === null || 
      item.category === selectedCategory;
      
    return matchesSearch && matchesCategory;
  });
  
  // Session timer simulation
  const [sessionTime, setSessionTime] = useState(45 * 60); // 45 minutes in seconds
  
  useEffect(() => {
    const timer = setInterval(() => {
      setSessionTime(prev => {
        if (prev <= 0) return 0;
        return prev - 1;
      });
    }, 1000);
    
    return () => clearInterval(timer);
  }, []);
  
  const formatTime = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs < 10 ? '0' : ''}${secs}`;
  };
  
  const sessionPercentage = (sessionTime / (45 * 60)) * 100;
  
  // Logout handler function
  const handleLogout = async () => {
    try {
      // Show confirmation dialog
      setShowLogoutConfirm(true);
    } catch (error) {
      console.error("Error initiating logout:", error);
    }
  };
  
  // Confirm logout and perform actual logout
  const confirmLogout = async () => {
    try {
      console.log("Logging out...");
      // Call the logout function from AuthContext
      await logout();
      
      // Clear any local state
      setShowLogoutConfirm(false);
      setAuthenticated(false);
      setPiiData([]);
      setSelectedPiiItem(null);
      
      // Log the user out on the client side immediately
      console.log("Logout successful, redirecting to login");
      
      // Redirect to login page
      navigate("/login");
    } catch (error) {
      console.error("Error during logout:", error);
      setShowLogoutConfirm(false);
      alert("There was a problem logging out. Please try again.");
    }
  };
  
  // Cancel logout
  const cancelLogout = () => {
    setShowLogoutConfirm(false);
  };
  
  // Function to fetch PII data from AWS through API
  const fetchPiiData = async () => {
    try {
      setLoading(true);
      setSelectedPiiItem(null); // Clear any selected item
      
      console.log("Calling PII API from Dashboard");
      const response = await dataAPI.getAllItems();
      console.log("PII API Response in Dashboard:", response);
      
      if (response && response.data) {
        console.log("Setting PII data:", response.data);
        setPiiData(response.data);
        setActivePage('pii-data');
      } else {
        console.error("Invalid API response format:", response);
        alert("Received invalid data format from API. Please try again.");
      }
    } catch (error) {
      console.error("Error fetching PII data:", error);
      alert("Failed to fetch PII data. Please try again.");
    } finally {
      setLoading(false);
    }
  };
  
  // Function to view details of a PII item
  const viewPiiItemDetails = async (itemId) => {
    try {
      setLoading(true);
      console.log("Fetching details for PII item ID:", itemId);
      
      // Find item in local data first if possible (to avoid extra API calls)
      const localItem = piiData.find(item => (item.id === itemId || item._id === itemId));
      
      if (localItem && process.env.NODE_ENV === 'development') {
        console.log("Using local item data:", localItem);
        setSelectedPiiItem(localItem);
      } else {
        // Fetch from API
        console.log("Fetching item from API");
        const response = await dataAPI.getItemById(itemId);
        console.log("API response:", response);
        
        // Normalize data if needed
        const responseData = response.data;
        
        // The API might return different formats - normalize here
        const normalizedItem = {
          ...responseData,
          // Ensure consistent property names
          id: responseData.id || responseData._id,
          category: responseData.category || responseData.Category,
          type: responseData.type || responseData.Type,
          // Handle PII data formatting in the render function
        };
        
        setSelectedPiiItem(normalizedItem);
      }
    } catch (error) {
      console.error("Error fetching PII item details:", error);
      alert("Failed to fetch item details. Please try again.");
    } finally {
      setLoading(false);
    }
  };
  
  // For simplicity, we'll handle most UI updates through state
  
  // Color scheme based on dark/light mode
  const colors = darkMode ? {
    bg: '#121826',
    sidebar: '#1E293B',
    card: '#1E293B',
    text: '#E2E8F0',
    textDim: '#94A3B8',
    accent: '#3B82F6',
    accentHover: '#2563EB',
    border: '#334155'
  } : {
    bg: '#F8FAFC',
    sidebar: '#F1F5F9',
    card: '#FFFFFF',
    text: '#334155',
    textDim: '#64748B',
    accent: '#3B82F6',
    accentHover: '#2563EB',
    border: '#E2E8F0'
  };

  // Logout confirmation modal JSX
  const logoutConfirmationModal = (
    <div className={`fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 transition-opacity ${showLogoutConfirm ? 'opacity-100' : 'opacity-0 pointer-events-none'}`}>
      <div className="bg-gray-800 rounded-xl p-6 shadow-2xl max-w-md w-full mx-4 border border-gray-700">
        <h3 className="text-xl font-bold text-white mb-2">Confirm Logout</h3>
        <p className="text-gray-300 mb-6">
          Are you sure you want to log out? This will end your current session and you'll need to authenticate again to access the application.
        </p>
        <div className="flex flex-col sm:flex-row sm:justify-end gap-3">
          <button
            onClick={cancelLogout}
            className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg"
          >
            Cancel
          </button>
          <button
            onClick={confirmLogout}
            className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg flex items-center justify-center"
          >
            <LogOut className="h-4 w-4 mr-2" />
            Confirm Logout
          </button>
        </div>
      </div>
    </div>
  );

  return (
    <>
      <div 
        className="flex h-screen w-full overflow-hidden" 
        style={{ backgroundColor: colors.bg, color: colors.text }}
      >
      {/* Sidebar Navigation */}
      <div 
        className="w-64 h-full flex flex-col"
        style={{ backgroundColor: colors.sidebar, borderRight: `1px solid ${colors.border}` }}
      >
        {/* App Logo */}
        <div className="flex items-center justify-center h-16 border-b" style={{ borderColor: colors.border }}>
          <Shield className="h-6 w-6 mr-2" style={{ color: colors.accent }} />
          <span className="text-xl font-bold">GUARD</span>
        </div>
        
        {/* Main Navigation */}
        <nav className="flex-1 pt-5 pb-4 overflow-y-auto">
          <div className="px-4 mb-6">
            <h2 className="text-xs font-semibold opacity-60 uppercase tracking-wider">Main</h2>
            <div className="mt-3 space-y-1">
              <button 
                onClick={() => setActivePage('dashboard')}
                className={`flex items-center px-3 py-2 text-sm font-medium rounded-md w-full ${activePage === 'dashboard' ? 'bg-blue-600 text-white' : 'hover:bg-opacity-10 hover:bg-white'}`}
              >
                <BarChart2 className="mr-3 h-5 w-5 opacity-80" />
                Dashboard
              </button>
              
              <button 
                onClick={() => setActivePage('data')}
                className={`flex items-center px-3 py-2 text-sm font-medium rounded-md w-full ${activePage === 'data' ? 'bg-blue-600 text-white' : 'hover:bg-opacity-10 hover:bg-white'}`}
              >
                <Database className="mr-3 h-5 w-5 opacity-80" />
                Data Management
              </button>
              
              <button 
                onClick={() => setActivePage('documents')}
                className={`flex items-center px-3 py-2 text-sm font-medium rounded-md w-full ${activePage === 'documents' ? 'bg-blue-600 text-white' : 'hover:bg-opacity-10 hover:bg-white'}`}
              >
                <FileText className="mr-3 h-5 w-5 opacity-80" />
                Documents
              </button>
              
              <button 
                onClick={() => setActivePage('calendar')}
                className={`flex items-center px-3 py-2 text-sm font-medium rounded-md w-full ${activePage === 'calendar' ? 'bg-blue-600 text-white' : 'hover:bg-opacity-10 hover:bg-white'}`}
              >
                <Calendar className="mr-3 h-5 w-5 opacity-80" />
                Calendar
              </button>
              
              <button 
                onClick={fetchPiiData}
                className={`flex items-center px-3 py-2 text-sm font-medium rounded-md w-full ${activePage === 'pii-data' ? 'bg-blue-600 text-white' : 'hover:bg-opacity-10 hover:bg-white'}`}
              >
                <Key className="mr-3 h-5 w-5 opacity-80" />
                PII Data
              </button>
            </div>
          </div>
          
          <div className="px-4 mb-6">
            <h2 className="text-xs font-semibold opacity-60 uppercase tracking-wider">Account</h2>
            <div className="mt-3 space-y-1">
              <button 
                onClick={() => setActivePage('profile')}
                className={`flex items-center px-3 py-2 text-sm font-medium rounded-md w-full ${activePage === 'profile' ? 'bg-blue-600 text-white' : 'hover:bg-opacity-10 hover:bg-white'}`}
              >
                <User className="mr-3 h-5 w-5 opacity-80" />
                Profile
              </button>
              
              <button 
                onClick={() => setActivePage('settings')}
                className={`flex items-center px-3 py-2 text-sm font-medium rounded-md w-full ${activePage === 'settings' ? 'bg-blue-600 text-white' : 'hover:bg-opacity-10 hover:bg-white'}`}
              >
                <Settings className="mr-3 h-5 w-5 opacity-80" />
                Settings
              </button>
            </div>
          </div>
          
          <div className="px-4">
            <h2 className="text-xs font-semibold opacity-60 uppercase tracking-wider">Categories</h2>
            <div className="mt-3 space-y-1">
              {categories.map(category => (
                <button 
                  key={category.id}
                  onClick={() => setSelectedCategory(category.name)}
                  className={`flex items-center justify-between px-3 py-2 text-sm font-medium rounded-md w-full ${selectedCategory === category.name ? 'bg-blue-600 text-white' : 'hover:bg-opacity-10 hover:bg-white'}`}
                >
                  <span className="flex items-center">
                    <span className="mr-3 h-5 w-5 opacity-80">{category.icon}</span>
                    {category.name}
                  </span>
                  <span className="bg-blue-500 bg-opacity-20 text-blue-300 text-xs px-2 py-0.5 rounded-full">
                    {category.count}
                  </span>
                </button>
              ))}
            </div>
          </div>
        </nav>
        
        {/* Session Info */}
        <div className="p-4 border-t" style={{ borderColor: colors.border }}>
          <div className="bg-blue-900 bg-opacity-20 rounded-lg p-3">
            <div className="flex justify-between items-center mb-1">
              <span className="text-sm font-medium">Session Time</span>
              <span className="text-sm">{formatTime(sessionTime)}</span>
            </div>
            <div className="w-full bg-gray-700 rounded-full h-2">
              <div 
                className="bg-blue-500 h-2 rounded-full" 
                style={{ width: `${sessionPercentage}%`, transition: 'width 1s ease-in-out' }}
              ></div>
            </div>
            <div className="flex justify-between mt-3">
              <button className="text-xs bg-blue-600 hover:bg-blue-700 px-2 py-1 rounded">
                Refresh
              </button>
              <button 
                className="text-xs flex items-center bg-red-500 hover:bg-red-600 px-2 py-1 rounded"
                onClick={handleLogout}
              >
                <LogOut className="h-3 w-3 mr-1" /> Logout
              </button>
            </div>
          </div>
        </div>
      </div>
      
      {/* Main Content Area */}
      <div className="flex-1 overflow-auto">
        {/* Top Header */}
        <header 
          className="h-16 flex items-center justify-between px-6 border-b"
          style={{ borderColor: colors.border }}
        >
          <div className="flex items-center w-96">
            <Search className="h-5 w-5 mr-2 opacity-60" />
            <input
              type="text"
              placeholder="Search..."
              className="w-full bg-transparent border-none focus:outline-none text-sm"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{ color: colors.text }}
            />
          </div>
          
          <div className="flex items-center space-x-4">
            <button 
              className="relative p-2 rounded-full hover:bg-white hover:bg-opacity-10"
              onClick={() => alert('Notifications')}
            >
              <Bell className="h-5 w-5" />
              {notifications > 0 && (
                <span className="absolute top-0 right-0 h-4 w-4 text-xs flex items-center justify-center bg-red-500 text-white rounded-full">
                  {notifications}
                </span>
              )}
            </button>
            
            <button 
              className="p-1 rounded-full hover:bg-white hover:bg-opacity-10 border"
              style={{ borderColor: colors.border }}
              onClick={() => setDarkMode(!darkMode)}
            >
              {darkMode ? '☀️' : '🌙'}
            </button>
            
            <div className="flex items-center">
              <div className="h-8 w-8 rounded-full bg-blue-500 flex items-center justify-center mr-2">
                <User className="h-4 w-4 text-white" />
              </div>
              <div>
                <div className="text-sm font-medium">John Doe</div>
                <div className="text-xs opacity-60">Administrator</div>
              </div>
            </div>
          </div>
        </header>
        
        {/* Main Content */}
        <main className="p-6">
          {activePage === 'calendar' ? (
            <CalendarNotifications darkMode={darkMode} />
          ) : activePage === 'pii-data' ? (
            <>
              {/* PII Data Header */}
              <div className="flex justify-between items-center mb-6">
                <div>
                  <h1 className="text-2xl font-bold">PII Data from AWS</h1>
                  <p className="text-sm opacity-60">View your personal identifiable information securely.</p>
                </div>
                
                <div className="flex space-x-3">
                  <button 
                    className="flex items-center bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg text-white text-sm"
                    onClick={() => fetchPiiData()}
                    disabled={loading}
                  >
                    <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
                    {loading ? 'Loading...' : 'Refresh Data'}
                  </button>
                </div>
              </div>
              
              {/* PII Data Table */}
              <div className="rounded-xl overflow-hidden mb-6" style={{ backgroundColor: colors.card, border: `1px solid ${colors.border}` }}>
                <div className="p-4 border-b" style={{ borderColor: colors.border }}>
                  <div className="flex justify-between items-center">
                    <h2 className="font-bold">Personal Identifiable Information</h2>
                    <span className="text-sm bg-blue-500 bg-opacity-20 text-blue-300 px-2 py-0.5 rounded-full">
                      {piiData.length} items
                    </span>
                  </div>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="text-left text-xs uppercase tracking-wider" style={{ color: colors.textDim }}>
                        <th className="px-4 py-3 font-medium">ID</th>
                        <th className="px-4 py-3 font-medium">Category</th>
                        <th className="px-4 py-3 font-medium">Type</th>
                        <th className="px-4 py-3 font-medium">Security Level</th>
                        <th className="px-4 py-3 font-medium">Last Updated</th>
                        <th className="px-4 py-3 font-medium">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y" style={{ borderColor: colors.border }}>
                      {loading ? (
                        <tr>
                          <td colSpan="6" className="px-4 py-10 text-center">
                            <div className="flex flex-col items-center">
                              <RefreshCw className="h-8 w-8 animate-spin mb-2" style={{ color: colors.accent }} />
                              <p>Loading PII data...</p>
                            </div>
                          </td>
                        </tr>
                      ) : piiData.length === 0 ? (
                        <tr>
                          <td colSpan="6" className="px-4 py-10 text-center">
                            <p>No PII data available. Try refreshing or adding new data.</p>
                          </td>
                        </tr>
                      ) : (
                        piiData.map((item, index) => (
                          <tr key={item.id || item._id || index} className="text-sm hover:bg-black hover:bg-opacity-10">
                            <td className="px-4 py-3">#{item.id || item._id || `item-${index}`}</td>
                            <td className="px-4 py-3">{item.category || item.Category || 'Unknown'}</td>
                            <td className="px-4 py-3">{item.type || item.Type || 'Unknown'}</td>
                            <td className="px-4 py-3">
                              <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${
                                (item.securityLevel === 'high' || item.category === 'Financial' || item.Category === 'Financial' || 
                                 item.category === 'Medical' || item.Category === 'Medical')
                                  ? 'bg-red-100 text-red-800' 
                                  : (item.securityLevel === 'medium' || item.category === 'Personal' || item.Category === 'Personal')
                                  ? 'bg-yellow-100 text-yellow-800'
                                  : 'bg-green-100 text-green-800'
                              }`}>
                                {item.securityLevel === 'high' ? 'High' : 
                                 item.securityLevel === 'medium' ? 'Medium' : 
                                 item.category === 'Financial' || item.Category === 'Financial' || 
                                 item.category === 'Medical' || item.Category === 'Medical' ? 'High' :
                                 item.category === 'Personal' || item.Category === 'Personal' ? 'Medium' : 'Low'}
                              </span>
                            </td>
                            <td className="px-4 py-3">{item.lastUpdated || 
                              (item.updated_at ? new Date(item.updated_at).toLocaleDateString() : 
                              (item.created_at ? new Date(item.created_at).toLocaleDateString() : 'N/A'))}</td>
                            <td className="px-4 py-3">
                              <div className="flex space-x-2">
                                <button 
                                  className="p-1 rounded hover:bg-white hover:bg-opacity-10" 
                                  title="View"
                                  onClick={() => viewPiiItemDetails(item.id || item._id)}
                                >
                                  <Eye className="h-4 w-4" />
                                </button>
                                <button className="p-1 rounded hover:bg-white hover:bg-opacity-10" title="Settings">
                                  <Settings className="h-4 w-4" />
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
              
              {/* PII Item Detail View */}
              {selectedPiiItem && (
                <div className="rounded-xl overflow-hidden mb-6" style={{ backgroundColor: colors.card, border: `1px solid ${colors.border}` }}>
                  <div className="p-4 border-b" style={{ borderColor: colors.border }}>
                    <div className="flex justify-between items-center">
                      <div className="flex items-center">
                        <button 
                          className="mr-3 p-1.5 rounded-full hover:bg-white hover:bg-opacity-10"
                          onClick={() => setSelectedPiiItem(null)}
                        >
                          &larr;
                        </button>
                        <h2 className="font-bold">PII Item Details</h2>
                      </div>
                      <span className={`text-sm px-2 py-0.5 rounded-full ${
                        selectedPiiItem.securityLevel === 'high' 
                          ? 'bg-red-500 bg-opacity-20 text-red-300' 
                          : selectedPiiItem.securityLevel === 'medium'
                          ? 'bg-yellow-500 bg-opacity-20 text-yellow-300'
                          : 'bg-green-500 bg-opacity-20 text-green-300'
                      }`}>
                        {selectedPiiItem.securityLevel === 'high' ? 'High Security' : 
                         selectedPiiItem.securityLevel === 'medium' ? 'Medium Security' : 'Low Security'}
                      </span>
                    </div>
                  </div>
                  <div className="p-6 space-y-6">
                    <div className="grid grid-cols-2 gap-6">
                      <div>
                        <h3 className="text-sm font-medium mb-2 opacity-70">Category</h3>
                        <p className="text-lg">{selectedPiiItem.category || selectedPiiItem.Category || 'N/A'}</p>
                      </div>
                      <div>
                        <h3 className="text-sm font-medium mb-2 opacity-70">Type</h3>
                        <p className="text-lg">{selectedPiiItem.type || selectedPiiItem.Type || 'N/A'}</p>
                      </div>
                      <div>
                        <h3 className="text-sm font-medium mb-2 opacity-70">Last Updated</h3>
                        <p className="text-lg">{
                          selectedPiiItem.lastUpdated || 
                          (selectedPiiItem.updated_at ? new Date(selectedPiiItem.updated_at).toLocaleString() : 
                           (selectedPiiItem.created_at ? new Date(selectedPiiItem.created_at).toLocaleString() : 'N/A'))
                        }</p>
                      </div>
                      <div>
                        <h3 className="text-sm font-medium mb-2 opacity-70">Created By</h3>
                        <p className="text-lg">{selectedPiiItem.createdBy || selectedPiiItem.created_by || 'N/A'}</p>
                      </div>
                    </div>
                    
                    <div className="border-t pt-6" style={{ borderColor: colors.border }}>
                      <h3 className="text-lg font-medium mb-4">PII Data Fields</h3>
                      <div className="space-y-4">
                        {(() => {
                          // Handle different PII data formats
                          let piiFields = [];
                          
                          if (selectedPiiItem.piiData && selectedPiiItem.piiData.length > 0) {
                            // Standard format
                            piiFields = selectedPiiItem.piiData;
                          } else if (selectedPiiItem.PII) {
                            try {
                              // Try to parse PII data if it's a string
                              const piiData = typeof selectedPiiItem.PII === 'string' 
                                ? JSON.parse(selectedPiiItem.PII) 
                                : selectedPiiItem.PII;
                              
                              if (Array.isArray(piiData)) {
                                // Format from backend might be different
                                piiFields = piiData.map(item => ({
                                  name: item.name || item["Item Name"] || Object.keys(item)[0] || "Field",
                                  value: item.value || item["Data"] || item[Object.keys(item)[0]] || "N/A"
                                }));
                              } else if (typeof piiData === 'object') {
                                // Handle object format
                                piiFields = Object.entries(piiData).map(([key, value]) => ({
                                  name: key,
                                  value: value
                                }));
                              }
                            } catch (e) {
                              console.error("Error parsing PII data:", e);
                              // If parsing fails, try to display as-is
                              piiFields = [{ name: "Raw Data", value: selectedPiiItem.PII }];
                            }
                          } else {
                            // Last resort: display all properties that might contain PII
                            const excludedKeys = ['id', '_id', 'category', 'Category', 'type', 'Type', 
                                                  'lastUpdated', 'updated_at', 'created_at', 'createdBy',
                                                  'created_by', 'securityLevel', 'piiData', 'PII'];
                            
                            piiFields = Object.entries(selectedPiiItem)
                              .filter(([key]) => !excludedKeys.includes(key))
                              .map(([key, value]) => ({
                                name: key,
                                value: typeof value === 'object' ? JSON.stringify(value) : value
                              }));
                          }
                          
                          return piiFields.length > 0 ? (
                            piiFields.map((field, index) => (
                              <div key={index} className="p-4 rounded-lg" style={{ backgroundColor: 'rgba(59, 130, 246, 0.1)' }}>
                                <h4 className="text-sm font-medium mb-1 opacity-70">{field.name}</h4>
                                <p className="font-mono bg-black bg-opacity-20 p-2 rounded">
                                  {typeof field.value === 'object' ? JSON.stringify(field.value) : field.value}
                                </p>
                              </div>
                            ))
                          ) : (
                            <p className="italic opacity-60">No PII data fields available</p>
                          );
                        })()}
                      </div>
                    </div>
                    
                    <div className="border-t pt-6 flex justify-end space-x-3" style={{ borderColor: colors.border }}>
                      <button 
                        className="px-4 py-2 border rounded-lg text-sm"
                        style={{ borderColor: colors.border }}
                        onClick={() => setSelectedPiiItem(null)}
                      >
                        Close
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </>
          ) : (
            <>
              {/* Welcome Header */}
              <div className="flex justify-between items-center mb-6">
                <div>
                  <h1 className="text-2xl font-bold">Welcome back, John!</h1>
                  <p className="text-sm opacity-60">Here's what's happening with your data today.</p>
                </div>
                
                <div className="flex space-x-3">
                  <button className="flex items-center bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg text-white text-sm">
                    <Plus className="h-4 w-4 mr-2" />
                    Add New Entry
                  </button>
                  
                  <button className="flex items-center border px-3 py-2 rounded-lg text-sm"
                    style={{ borderColor: colors.border }}
                  >
                    <RefreshCw className="h-4 w-4 mr-2" />
                    Refresh
                  </button>
                </div>
              </div>
            </>
          )}
          
          {/* Stats Cards */}
          {activePage !== 'calendar' && activePage !== 'pii-data' && (
            <>
              <div className="grid grid-cols-4 gap-6 mb-6">
                <div className="rounded-xl p-4 flex flex-col" style={{ backgroundColor: colors.card, border: `1px solid ${colors.border}` }}>
                  <div className="flex justify-between items-center mb-3">
                    <h3 className="text-sm font-medium">Total Items</h3>
                    <div className="p-2 rounded-lg" style={{ backgroundColor: 'rgba(59, 130, 246, 0.2)' }}>
                      <Database className="h-5 w-5 text-blue-500" />
                    </div>
                  </div>
                  <p className="text-2xl font-bold mb-1">47</p>
                  <p className="text-xs opacity-60">+12% from last month</p>
                </div>
                
                <div className="rounded-xl p-4 flex flex-col" style={{ backgroundColor: colors.card, border: `1px solid ${colors.border}` }}>
                  <div className="flex justify-between items-center mb-3">
                    <h3 className="text-sm font-medium">Categories</h3>
                    <div className="p-2 rounded-lg" style={{ backgroundColor: 'rgba(245, 158, 11, 0.2)' }}>
                      <FileText className="h-5 w-5 text-amber-500" />
                    </div>
                  </div>
                  <p className="text-2xl font-bold mb-1">5</p>
                  <p className="text-xs opacity-60">+2 new categories</p>
                </div>
                
                <div className="rounded-xl p-4 flex flex-col" style={{ backgroundColor: colors.card, border: `1px solid ${colors.border}` }}>
                  <div className="flex justify-between items-center mb-3">
                    <h3 className="text-sm font-medium">Security Level</h3>
                    <div className="p-2 rounded-lg" style={{ backgroundColor: 'rgba(16, 185, 129, 0.2)' }}>
                      <Shield className="h-5 w-5 text-emerald-500" />
                    </div>
                  </div>
                  <p className="text-2xl font-bold mb-1">High</p>
                  <p className="text-xs opacity-60">All systems secure</p>
                </div>
                
                <div className="rounded-xl p-4 flex flex-col" style={{ backgroundColor: colors.card, border: `1px solid ${colors.border}` }}>
                  <div className="flex justify-between items-center mb-3">
                    <h3 className="text-sm font-medium">Last Access</h3>
                    <div className="p-2 rounded-lg" style={{ backgroundColor: 'rgba(239, 68, 68, 0.2)' }}>
                      <Lock className="h-5 w-5 text-red-500" />
                    </div>
                  </div>
                  <p className="text-2xl font-bold mb-1">2h ago</p>
                  <p className="text-xs opacity-60">John (via AWS SSO)</p>
                </div>
              </div>
              
              {/* Data Table */}
            </>
          )}
          {activePage !== 'calendar' && activePage !== 'pii-data' && (
            <>
              <div className="rounded-xl overflow-hidden mb-6" style={{ backgroundColor: colors.card, border: `1px solid ${colors.border}` }}>
                <div className="p-4 border-b" style={{ borderColor: colors.border }}>
                  <div className="flex justify-between items-center">
                    <h2 className="font-bold">Recent Data Items</h2>
                    <button className="text-sm opacity-60 hover:opacity-100">View All</button>
                  </div>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="text-left text-xs uppercase tracking-wider" style={{ color: colors.textDim }}>
                        <th className="px-4 py-3 font-medium">ID</th>
                        <th className="px-4 py-3 font-medium">Category</th>
                        <th className="px-4 py-3 font-medium">Type</th>
                        <th className="px-4 py-3 font-medium">Last Updated</th>
                        <th className="px-4 py-3 font-medium">Status</th>
                        <th className="px-4 py-3 font-medium">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y" style={{ borderColor: colors.border }}>
                      {filteredData.map(item => (
                        <tr key={item.id} className="text-sm hover:bg-black hover:bg-opacity-10">
                          <td className="px-4 py-3"># {item.id.toString().padStart(4, '0')}</td>
                          <td className="px-4 py-3">{item.category}</td>
                          <td className="px-4 py-3">{item.type}</td>
                          <td className="px-4 py-3">{item.updated}</td>
                          <td className="px-4 py-3">
                            <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${item.sensitive ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'}`}>
                              {item.sensitive ? 'Sensitive' : 'Standard'}
                            </span>
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex space-x-2">
                              <button className="p-1 rounded hover:bg-white hover:bg-opacity-10">
                                <Eye className="h-4 w-4" />
                              </button>
                              <button className="p-1 rounded hover:bg-white hover:bg-opacity-10">
                                <Settings className="h-4 w-4" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="p-4 border-t" style={{ borderColor: colors.border }}>
                  <div className="flex justify-between items-center text-sm">
                    <span>Showing {filteredData.length} of {dataItems.length} entries</span>
                    <div className="flex space-x-1">
                      <button className="px-3 py-1 rounded border" style={{ borderColor: colors.border }}>Previous</button>
                      <button className="px-3 py-1 rounded bg-blue-600 text-white">1</button>
                      <button className="px-3 py-1 rounded border" style={{ borderColor: colors.border }}>Next</button>
                    </div>
                  </div>
                </div>
              </div>
              
              {/* Activity Log */}
              <div className="rounded-xl overflow-hidden" style={{ backgroundColor: colors.card, border: `1px solid ${colors.border}` }}>
                <div className="p-4 border-b" style={{ borderColor: colors.border }}>
                  <h2 className="font-bold">Recent Activity</h2>
                </div>
                <div className="p-4">
                  <div className="space-y-4">
                    <div className="flex items-start">
                      <div className="h-8 w-8 rounded-full bg-blue-500 bg-opacity-20 flex items-center justify-center mr-3">
                        <Eye className="h-4 w-4 text-blue-500" />
                      </div>
                      <div>
                        <p className="text-sm">You viewed <strong>Bank Account</strong> data</p>
                        <p className="text-xs opacity-60">2 hours ago</p>
                      </div>
                    </div>
                    
                    <div className="flex items-start">
                      <div className="h-8 w-8 rounded-full bg-green-500 bg-opacity-20 flex items-center justify-center mr-3">
                        <Plus className="h-4 w-4 text-green-500" />
                      </div>
                      <div>
                        <p className="text-sm">Added new <strong>Credit Card</strong> entry</p>
                        <p className="text-xs opacity-60">5 hours ago</p>
                      </div>
                    </div>
                    
                    <div className="flex items-start">
                      <div className="h-8 w-8 rounded-full bg-amber-500 bg-opacity-20 flex items-center justify-center mr-3">
                        <Settings className="h-4 w-4 text-amber-500" />
                      </div>
                      <div>
                        <p className="text-sm">Updated <strong>Home Address</strong> information</p>
                        <p className="text-xs opacity-60">Yesterday</p>
                      </div>
                    </div>
                    
                    <div className="flex items-start">
                      <div className="h-8 w-8 rounded-full bg-red-500 bg-opacity-20 flex items-center justify-center mr-3">
                        <LogOut className="h-4 w-4 text-red-500" />
                      </div>
                      <div>
                        <p className="text-sm">Logged out of session</p>
                        <p className="text-xs opacity-60">2 days ago</p>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="p-4 border-t" style={{ borderColor: colors.border }}>
                  <button className="text-sm text-blue-500 hover:text-blue-600">View All Activity</button>
                </div>
              </div>
            </>
          )}
        </main>
      </div>
    </div>
      {/* Render the logout confirmation modal */}
      {logoutConfirmationModal}
    </>
  );
};

export default GuardDashboard;