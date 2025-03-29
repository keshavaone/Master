import React, { useState, useEffect } from 'react';
import { Eye, Edit, Trash2, AlertTriangle, Lock, Shield, Search, Plus, Filter, RefreshCw, Download, FileText } from 'lucide-react';

const SecurityLevel = ({ level }) => {
  const colors = {
    high: { bg: 'bg-red-500 bg-opacity-20', text: 'text-red-500', border: 'border-red-500' },
    medium: { bg: 'bg-amber-500 bg-opacity-20', text: 'text-amber-500', border: 'border-amber-500' },
    low: { bg: 'bg-green-500 bg-opacity-20', text: 'text-green-500', border: 'border-green-500' }
  };
  
  const style = colors[level.toLowerCase()] || colors.medium;
  
  return (
    <div className={`inline-flex items-center px-2 py-1 rounded-full text-xs ${style.bg} ${style.text} border ${style.border} border-opacity-50`}>
      <Lock className="h-3 w-3 mr-1" />
      {level.charAt(0).toUpperCase() + level.slice(1)}
    </div>
  );
};

const DataItemDialog = ({ item, onClose }) => {
  const [isDecrypting, setIsDecrypting] = useState(true);
  const [decryptProgress, setDecryptProgress] = useState(0);
  
  useEffect(() => {
    // Simulate decryption process
    const interval = setInterval(() => {
      setDecryptProgress(prev => {
        const next = prev + Math.random() * 15;
        if (next >= 100) {
          clearInterval(interval);
          setTimeout(() => setIsDecrypting(false), 500);
          return 100;
        }
        return next;
      });
    }, 200);
    
    return () => clearInterval(interval);
  }, []);
  
  if (!item) return null;
  
  return (
    <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 rounded-xl max-w-2xl w-full max-h-[80vh] overflow-hidden border border-gray-700 shadow-2xl flex flex-col">
        <div className="p-5 border-b border-gray-700 flex justify-between items-center">
          <div className="flex items-center">
            <div className="bg-blue-500 bg-opacity-20 p-2 rounded-lg mr-3">
              <FileText className="h-6 w-6 text-blue-400" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white">{item.type}</h2>
              <p className="text-gray-400">{item.category}</p>
            </div>
          </div>
          <button 
            onClick={onClose}
            className="text-gray-400 hover:text-white p-1 rounded-full hover:bg-white hover:bg-opacity-10"
          >
            <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        
        <div className="flex-1 overflow-y-auto p-5">
          {isDecrypting ? (
            <div className="flex flex-col items-center justify-center h-60 p-6">
              <div className="flex items-center mb-4">
                <Shield className="h-6 w-6 text-blue-500 mr-2 animate-pulse" />
                <h3 className="text-lg font-medium text-white">Decrypting Secure Data</h3>
              </div>
              <div className="w-full max-w-md h-2 bg-gray-800 rounded-full overflow-hidden mb-3">
                <div 
                  className="h-full bg-blue-500 rounded-full transition-all duration-300 ease-out"
                  style={{ width: `${decryptProgress}%` }}
                ></div>
              </div>
              <p className="text-gray-400 text-sm">
                Decrypting data with AES-256 encryption...
              </p>
            </div>
          ) : (
            <>
              <div className="mb-6 flex items-start">
                <div className="bg-gray-800 p-3 rounded-lg mr-4">
                  <Lock className="h-5 w-5 text-blue-400" />
                </div>
                <div>
                  <h3 className="text-white font-medium mb-1">Security Information</h3>
                  <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <p className="text-gray-400 mb-1">Security Level</p>
                        <SecurityLevel level={item.securityLevel || "High"} />
                      </div>
                      <div>
                        <p className="text-gray-400 mb-1">Last Access</p>
                        <p className="text-white">{item.lastAccess || "2 hours ago"}</p>
                      </div>
                      <div>
                        <p className="text-gray-400 mb-1">Created By</p>
                        <p className="text-white">{item.createdBy || "John Doe"}</p>
                      </div>
                      <div>
                        <p className="text-gray-400 mb-1">Access Count</p>
                        <p className="text-white">{item.accessCount || "12"} times</p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              
              <h3 className="text-white font-medium mb-3 flex items-center">
                <Eye className="h-5 w-5 mr-2 text-blue-400" />
                Decrypted PII Data
              </h3>
              
              <div className="space-y-4">
                {(item.piiData || [
                  { name: "Card Number", value: "**** **** **** 1234" },
                  { name: "Cardholder", value: "John Smith" },
                  { name: "Expiration", value: "05/27" },
                  { name: "Billing Address", value: "123 Security Ave, Encryption City, 94103" }
                ]).map((field, index) => (
                  <div key={index} className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                    <p className="text-gray-400 text-xs uppercase tracking-wider mb-1">{field.name}</p>
                    <p className="text-white font-medium">{field.value}</p>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
        
        <div className="p-5 border-t border-gray-700 flex justify-between">
          <div className="text-xs text-gray-500">
            <p>Item ID: {item.id}</p>
            <p>Encryption: AES-256 (AWS KMS)</p>
          </div>
          
          <div className="flex space-x-3">
            <button 
              onClick={onClose} 
              className="px-4 py-2 border border-gray-700 rounded-lg text-gray-300 hover:bg-gray-800 text-sm"
            >
              Close
            </button>
            <button className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm flex items-center">
              <Edit className="h-4 w-4 mr-2" />
              Edit Data
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

const EnhancedDataView = () => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState(null);
  const [viewMode, setViewMode] = useState('grid'); // 'grid' or 'table'
  const [selectedItem, setSelectedItem] = useState(null);
  const [showDialog, setShowDialog] = useState(false);
  const [dataItems, setDataItems] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  
  // Sample data
  const categories = [
    { id: 1, name: 'Financial', count: 12, color: '#3B82F6', icon: '💳' },
    { id: 2, name: 'Personal', count: 8, color: '#F59E0B', icon: '👤' },
    { id: 3, name: 'Medical', count: 5, color: '#EF4444', icon: '🏥' },
    { id: 4, name: 'Accounts', count: 15, color: '#10B981', icon: '🔑' },
    { id: 5, name: 'Documents', count: 7, color: '#8B5CF6', icon: '📄' },
  ];
  
  useEffect(() => {
    // Simulate loading data
    setIsLoading(true);
    
    setTimeout(() => {
      const sampleItems = [
        { id: 'CC-4389', category: 'Financial', type: 'Credit Card', lastUpdated: '2 hours ago', securityLevel: 'high' },
        { id: 'BA-2271', category: 'Financial', type: 'Bank Account', lastUpdated: '1 day ago', securityLevel: 'high' },
        { id: 'HA-1092', category: 'Personal', type: 'Home Address', lastUpdated: '5 days ago', securityLevel: 'medium' },
        { id: 'MI-5472', category: 'Medical', type: 'Insurance Info', lastUpdated: '1 week ago', securityLevel: 'high' },
        { id: 'EA-9983', category: 'Accounts', type: 'Email Account', lastUpdated: '3 days ago', securityLevel: 'medium' },
        { id: 'PA-1277', category: 'Accounts', type: 'Password Manager', lastUpdated: '6 hours ago', securityLevel: 'high' },
        { id: 'PP-3344', category: 'Documents', type: 'Passport', lastUpdated: '2 months ago', securityLevel: 'high' },
        { id: 'DL-7821', category: 'Documents', type: 'Driver License', lastUpdated: '2 months ago', securityLevel: 'medium' },
        { id: 'SSN-6612', category: 'Personal', type: 'Social Security', lastUpdated: '3 months ago', securityLevel: 'high' },
        { id: 'TX-9912', category: 'Financial', type: 'Tax Records', lastUpdated: '11 months ago', securityLevel: 'high' },
        { id: 'IN-5167', category: 'Medical', type: 'Insurance Card', lastUpdated: '4 months ago', securityLevel: 'medium' },
        { id: 'PC-2981', category: 'Accounts', type: 'PC Login', lastUpdated: '1 month ago', securityLevel: 'low' },
      ];
      
      setDataItems(sampleItems);
      setIsLoading(false);
    }, 1500);
  }, []);
  
  // Handle viewing an item
  const handleViewItem = (item) => {
    setSelectedItem(item);
    setShowDialog(true);
  };
  
  // Filter data based on search and category
  const filteredData = dataItems.filter(item => {
    const matchesSearch = searchQuery === '' || 
      item.type.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.category.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.id.toLowerCase().includes(searchQuery.toLowerCase());
      
    const matchesCategory = selectedCategory === null || 
      item.category === selectedCategory;
      
    return matchesSearch && matchesCategory;
  });
  
  // Get category by name
  const getCategoryByName = (name) => {
    return categories.find(cat => cat.name === name) || { color: '#6B7280', icon: '📄' };
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700 p-6">
        <div className="container mx-auto">
          <div className="flex justify-between items-center">
            <div>
              <h1 className="text-2xl font-bold flex items-center">
                <Shield className="h-6 w-6 mr-2 text-blue-500" />
                PII Data Management
              </h1>
              <p className="text-gray-400 mt-1">Securely manage and view your encrypted personal information</p>
            </div>
            
            <div className="flex items-center space-x-4">
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Search className="h-5 w-5 text-gray-500" />
                </div>
                <input
                  type="text"
                  className="bg-gray-700 text-white pl-10 pr-4 py-2 rounded-lg border border-gray-600 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none w-64"
                  placeholder="Search data items..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
              </div>
              
              <button className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg flex items-center">
                <Plus className="h-5 w-5 mr-2" />
                Add New
              </button>
            </div>
          </div>
          
          {/* Filter bar */}
          <div className="mt-6 flex items-center justify-between">
            <div className="flex space-x-2">
              <button 
                onClick={() => setSelectedCategory(null)}
                className={`px-3 py-1.5 rounded-lg text-sm ${!selectedCategory ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-300 hover:bg-gray-600'}`}
              >
                All Categories
              </button>
              {categories.map(category => (
                <button
                  key={category.id}
                  onClick={() => setSelectedCategory(category.name)}
                  className={`px-3 py-1.5 rounded-lg text-sm flex items-center ${selectedCategory === category.name ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-300 hover:bg-gray-600'}`}
                >
                  <span className="mr-1.5">{category.icon}</span>
                  {category.name}
                </button>
              ))}
            </div>
            
            <div className="flex items-center space-x-3">
              <button className="p-2 rounded-lg bg-gray-700 hover:bg-gray-600 flex items-center text-sm">
                <Filter className="h-4 w-4 mr-1.5" />
                Filters
              </button>
              
              <button className="p-2 rounded-lg bg-gray-700 hover:bg-gray-600 flex items-center text-sm">
                <RefreshCw className="h-4 w-4 mr-1.5" />
                Refresh
              </button>
              
              <div className="flex bg-gray-700 rounded-lg p-1">
                <button 
                  onClick={() => setViewMode('grid')}
                  className={`p-1.5 rounded-md ${viewMode === 'grid' ? 'bg-gray-600' : 'hover:bg-gray-600'}`}
                >
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" />
                  </svg>
                </button>
                <button 
                  onClick={() => setViewMode('table')}
                  className={`p-1.5 rounded-md ${viewMode === 'table' ? 'bg-gray-600' : 'hover:bg-gray-600'}`}
                >
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 10h16M4 14h16M4 18h16" />
                  </svg>
                </button>
              </div>
            </div>
          </div>
        </div>
      </header>
      
      {/* Main Content */}
      <main className="container mx-auto py-8 px-6">
        {/* Status bar */}
        <div className="flex justify-between items-center mb-6">
          <div className="text-sm text-gray-400">
            {isLoading ? (
              <div className="flex items-center">
                <svg className="animate-spin mr-2 h-4 w-4 text-blue-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Loading data items...
              </div>
            ) : (
              <>
                {selectedCategory ? (
                  <span>Showing {filteredData.length} items in <strong>{selectedCategory}</strong> category</span>
                ) : (
                  <span>Showing {filteredData.length} items across all categories</span>
                )}
                {searchQuery && <span> • Filtered by: "{searchQuery}"</span>}
              </>
            )}
          </div>
          
          <button className="text-sm flex items-center text-gray-300 hover:text-white">
            <Download className="h-4 w-4 mr-1.5" />
            Export Data
          </button>
        </div>
        
        {isLoading ? (
          // Loading skeleton
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {[1, 2, 3, 4, 5, 6].map(i => (
              <div key={i} className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden animate-pulse">
                <div className="h-24 bg-gray-700"></div>
                <div className="p-5 space-y-3">
                  <div className="h-5 bg-gray-700 rounded w-1/2"></div>
                  <div className="h-4 bg-gray-700 rounded w-3/4"></div>
                  <div className="h-4 bg-gray-700 rounded w-1/4"></div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <>
            {filteredData.length === 0 ? (
              <div className="bg-gray-800 border border-gray-700 rounded-xl p-10 text-center">
                <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-gray-700 mb-4">
                  <AlertTriangle className="h-8 w-8 text-gray-400" />
                </div>
                <h3 className="text-xl font-medium text-white mb-2">No Data Items Found</h3>
                <p className="text-gray-400 max-w-md mx-auto mb-6">
                  {searchQuery 
                    ? `No items match your search "${searchQuery}". Try a different search term or clear filters.`
                    : `No data items found in this category. Add your first item to get started.`
                  }
                </p>
                <button className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg flex items-center mx-auto">
                  <Plus className="h-5 w-5 mr-2" />
                  Add New Item
                </button>
              </div>
            ) : (
              <>
                {viewMode === 'grid' ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {filteredData.map(item => {
                      const category = getCategoryByName(item.category);
                      return (
                        <div 
                          key={item.id}
                          className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden hover:border-blue-500 transition-all duration-200 shadow-lg hover:shadow-xl cursor-pointer"
                          onClick={() => handleViewItem(item)}
                        >
                          <div className="h-2" style={{ backgroundColor: category.color }}></div>
                          <div className="p-5">
                            <div className="flex justify-between items-start mb-4">
                              <div className="flex items-center">
                                <div className="h-10 w-10 rounded-lg flex items-center justify-center text-lg mr-3" style={{ backgroundColor: `${category.color}25` }}>
                                  {category.icon}
                                </div>
                                <div>
                                  <h3 className="text-lg font-semibold text-white">{item.type}</h3>
                                  <p className="text-gray-400 text-sm">{item.category}</p>
                                </div>
                              </div>
                              <SecurityLevel level={item.securityLevel} />
                            </div>
                            
                            <div className="border-t border-gray-700 pt-4 mt-2">
                              <div className="flex justify-between items-center">
                                <div className="text-sm text-gray-400">
                                  <p>ID: {item.id}</p>
                                  <p>Updated: {item.lastUpdated}</p>
                                </div>
                                
                                <div className="flex space-x-1">
                                  <button 
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      handleViewItem(item);
                                    }}
                                    className="p-1.5 rounded-lg hover:bg-blue-500 hover:bg-opacity-20 text-blue-400"
                                  >
                                    <Eye className="h-5 w-5" />
                                  </button>
                                  <button 
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      // Handle edit
                                    }}
                                    className="p-1.5 rounded-lg hover:bg-amber-500 hover:bg-opacity-20 text-amber-400"
                                  >
                                    <Edit className="h-5 w-5" />
                                  </button>
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden shadow-lg">
                    <div className="overflow-x-auto">
                      <table className="w-full">
                        <thead>
                          <tr className="bg-gray-700 text-left">
                            <th className="px-6 py-3 text-xs font-medium text-gray-300 uppercase tracking-wider">ID</th>
                            <th className="px-6 py-3 text-xs font-medium text-gray-300 uppercase tracking-wider">Category</th>
                            <th className="px-6 py-3 text-xs font-medium text-gray-300 uppercase tracking-wider">Type</th>
                            <th className="px-6 py-3 text-xs font-medium text-gray-300 uppercase tracking-wider">Last Updated</th>
                            <th className="px-6 py-3 text-xs font-medium text-gray-300 uppercase tracking-wider">Security</th>
                            <th className="px-6 py-3 text-xs font-medium text-gray-300 uppercase tracking-wider">Actions</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-700">
                          {filteredData.map(item => {
                            const category = getCategoryByName(item.category);
                            return (
                              <tr 
                                key={item.id}
                                className="hover:bg-gray-700 cursor-pointer"
                                onClick={() => handleViewItem(item)}
                              >
                                <td className="px-6 py-4 whitespace-nowrap">
                                  <span className="text-sm font-medium">{item.id}</span>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap">
                                  <div className="flex items-center">
                                    <div className="h-8 w-8 rounded-md flex items-center justify-center text-sm mr-2" style={{ backgroundColor: `${category.color}25` }}>
                                      {category.icon}
                                    </div>
                                    <span className="text-sm">{item.category}</span>
                                  </div>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm">{item.type}</td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">{item.lastUpdated}</td>
                                <td className="px-6 py-4 whitespace-nowrap">
                                  <SecurityLevel level={item.securityLevel} />
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-right text-sm">
                                  <div className="flex space-x-2 justify-end">
                                    <button 
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        handleViewItem(item);
                                      }}
                                      className="p-1.5 rounded-lg hover:bg-blue-500 hover:bg-opacity-20 text-blue-400"
                                    >
                                      <Eye className="h-5 w-5" />
                                    </button>
                                    <button 
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        // Handle edit
                                      }}
                                      className="p-1.5 rounded-lg hover:bg-amber-500 hover:bg-opacity-20 text-amber-400"
                                    >
                                      <Edit className="h-5 w-5" />
                                    </button>
                                    <button 
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        // Handle delete
                                      }}
                                      className="p-1.5 rounded-lg hover:bg-red-500 hover:bg-opacity-20 text-red-400"
                                    >
                                      <Trash2 className="h-5 w-5" />
                                    </button>
                                  </div>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                    
                    <div className="p-4 border-t border-gray-700 flex justify-between items-center text-sm">
                      <span className="text-gray-400">
                        Showing {Math.min(10, filteredData.length)} of {filteredData.length} items
                      </span>
                      
                      <div className="flex space-x-2">
                        <button className="px-3 py-1 rounded border border-gray-600 text-gray-300 hover:bg-gray-700">
                          Previous
                        </button>
                        <button className="px-3 py-1 rounded bg-blue-600 text-white">
                          1
                        </button>
                        <button className="px-3 py-1 rounded border border-gray-600 text-gray-300 hover:bg-gray-700">
                          Next
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </>
            )}
          </>
        )}
      </main>
      
      {/* Item View Dialog */}
      {showDialog && (
        <DataItemDialog 
          item={selectedItem} 
          onClose={() => setShowDialog(false)} 
        />
      )}
    </div>
  );
};

export default EnhancedDataView;