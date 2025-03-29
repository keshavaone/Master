import React, { useState, useEffect } from 'react';
import { Shield, Eye, User, Lock, Database, FileText, Settings, LogOut, BarChart2, Bell, Search, Plus, RefreshCw } from 'lucide-react';

// Main dashboard component
const GuardDashboard = () => {
  const [, setAuthenticated] = useState(true);
  const [activePage, setActivePage] = useState('dashboard');
  const [darkMode, setDarkMode] = useState(true);
  const [notifications] = useState(3);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState(null);
  
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

  return (
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
                onClick={() => setAuthenticated(false)}
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
          
          {/* Stats Cards */}
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
        </main>
      </div>
    </div>
  );
};

export default GuardDashboard;