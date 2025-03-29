// src/components/Login.js
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { Shield, Lock, User, AlertTriangle } from 'lucide-react';

const Login = () => {
  const [loginMethod, setLoginMethod] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  
  // Form inputs
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [accessKey, setAccessKey] = useState('');
  const [secretKey, setSecretKey] = useState('');
  const [sessionToken, setSessionToken] = useState('');
  
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleAWSSSOLogin = async (e) => {
    if (e) e.preventDefault();
    
    if (!accessKey || !secretKey) {
      setErrorMessage('Please provide AWS access key and secret key');
      return;
    }
    
    setIsLoading(true);
    setErrorMessage('');
    
    try {
      await login({
        accessKey,
        secretKey,
        sessionToken
      }, 'aws_sso');
      
      // Redirect to dashboard on success
      navigate('/dashboard');
    } catch (error) {
      console.error('AWS SSO Login error:', error);
      setErrorMessage(error.response?.data?.detail || 'Authentication failed');
    } finally {
      setIsLoading(false);
    }
  };

  const handlePasswordLogin = async (e) => {
    e.preventDefault();
    
    if (!username || !password) {
      setErrorMessage('Please provide username and password');
      return;
    }
    
    setIsLoading(true);
    setErrorMessage('');
    
    try {
      await login({
        username,
        password
      }, 'password');
      
      // Redirect to dashboard on success
      navigate('/dashboard');
    } catch (error) {
      console.error('Password Login error:', error);
      setErrorMessage(error.response?.data?.detail || 'Authentication failed');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex h-screen">
      {/* Left panel - similar to GUARD Modern Login.tsx */}
      
      {/* Right panel with auth forms */}
      <div className="w-full lg:w-1/2 bg-gray-900 flex items-center justify-center p-6">
        <div className="max-w-md w-full">
          <div className="bg-gray-800 rounded-xl p-8 border border-gray-700 shadow-xl">
            <h2 className="text-2xl font-bold text-white mb-1">Welcome Back</h2>
            <p className="text-gray-400 mb-6">Please authenticate to continue</p>
            
            {errorMessage && (
              <div className="mb-6 bg-red-900 bg-opacity-30 border border-red-800 rounded-lg p-3 flex items-start">
                <AlertTriangle className="h-5 w-5 text-red-500 mr-2 flex-shrink-0 mt-0.5" />
                <p className="text-red-300 text-sm">{errorMessage}</p>
              </div>
            )}
            
            {!loginMethod && (
              <div className="space-y-4">
                <button
                  onClick={() => setLoginMethod('aws')}
                  className="w-full bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white py-3 px-4 rounded-lg flex items-center justify-center font-medium transition-all duration-200"
                >
                  <div className="mr-3 bg-white bg-opacity-20 rounded-full p-1">
                    <Shield className="h-5 w-5" />
                  </div>
                  Sign in with AWS SSO
                </button>
                
                <div className="relative flex items-center">
                  <div className="flex-grow border-t border-gray-700"></div>
                  <span className="flex-shrink mx-3 text-gray-500 text-sm">or</span>
                  <div className="flex-grow border-t border-gray-700"></div>
                </div>
                
                <button
                  onClick={() => setLoginMethod('password')}
                  className="w-full bg-gray-700 hover:bg-gray-600 text-white py-3 px-4 rounded-lg flex items-center justify-center font-medium transition-all duration-200"
                >
                  <div className="mr-3 bg-white bg-opacity-10 rounded-full p-1">
                    <Lock className="h-5 w-5" />
                  </div>
                  Sign in with Password
                </button>
              </div>
            )}
            
            {loginMethod === 'aws' && (
              <div>
                <form onSubmit={handleAWSSSOLogin}>
                  <div className="mb-4">
                    <label className="block text-gray-400 text-sm font-medium mb-2">
                      AWS Access Key ID
                    </label>
                    <input
                      type="text"
                      value={accessKey}
                      onChange={(e) => setAccessKey(e.target.value)}
                      className="bg-gray-700 text-white rounded-lg block w-full px-3 py-2.5 border border-gray-600 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none"
                      placeholder="Enter your AWS Access Key ID"
                      required
                    />
                  </div>
                  
                  <div className="mb-4">
                    <label className="block text-gray-400 text-sm font-medium mb-2">
                      AWS Secret Access Key
                    </label>
                    <input
                      type="password"
                      value={secretKey}
                      onChange={(e) => setSecretKey(e.target.value)}
                      className="bg-gray-700 text-white rounded-lg block w-full px-3 py-2.5 border border-gray-600 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none"
                      placeholder="Enter your AWS Secret Access Key"
                      required
                    />
                  </div>
                  
                  <div className="mb-6">
                    <label className="block text-gray-400 text-sm font-medium mb-2">
                      AWS Session Token (Optional)
                    </label>
                    <input
                      type="password"
                      value={sessionToken}
                      onChange={(e) => setSessionToken(e.target.value)}
                      className="bg-gray-700 text-white rounded-lg block w-full px-3 py-2.5 border border-gray-600 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none"
                      placeholder="Enter your AWS Session Token (if available)"
                    />
                  </div>
                  
                  <button
                    type="submit"
                    className="w-full bg-blue-600 hover:bg-blue-700 text-white py-3 px-4 rounded-lg flex items-center justify-center font-medium transition-all duration-200"
                    disabled={isLoading}
                  >
                    {isLoading ? (
                      <>
                        <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                        Signing in...
                      </>
                    ) : (
                      'Sign in with AWS SSO'
                    )}
                  </button>
                </form>
                
                <button 
                  onClick={() => setLoginMethod(null)}
                  className="mt-4 text-center w-full text-gray-400 hover:text-white text-sm"
                >
                  Back to authentication options
                </button>
              </div>
            )}
            
            {loginMethod === 'password' && (
              <div>
                <form onSubmit={handlePasswordLogin}>
                  <div className="mb-4">
                    <label className="block text-gray-400 text-sm font-medium mb-2" htmlFor="username">
                      Username
                    </label>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <User className="h-5 w-5 text-gray-500" />
                      </div>
                      <input
                        id="username"
                        type="text"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        className="bg-gray-700 text-white rounded-lg block w-full pl-10 pr-3 py-2.5 border border-gray-600 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none"
                        placeholder="Enter your username"
                        required
                      />
                    </div>
                  </div>
                  
                  <div className="mb-6">
                    <div className="flex items-center justify-between mb-2">
                      <label className="block text-gray-400 text-sm font-medium" htmlFor="password">
                        Password
                      </label>
                      <a href="#" className="text-blue-400 text-sm hover:text-blue-300">
                        Forgot password?
                      </a>
                    </div>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <Lock className="h-5 w-5 text-gray-500" />
                      </div>
                      <input
                        id="password"
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        className="bg-gray-700 text-white rounded-lg block w-full pl-10 pr-3 py-2.5 border border-gray-600 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none"
                        placeholder="Enter your password"
                        required
                      />
                    </div>
                  </div>
                  
                  <button
                    type="submit"
                    className="w-full bg-blue-600 hover:bg-blue-700 text-white py-3 px-4 rounded-lg flex items-center justify-center font-medium transition-all duration-200"
                    disabled={isLoading}
                  >
                    {isLoading ? (
                      <>
                        <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                        Signing in...
                      </>
                    ) : (
                      'Sign in'
                    )}
                  </button>
                </form>
                
                <button 
                  onClick={() => setLoginMethod(null)}
                  className="mt-4 text-center w-full text-gray-400 hover:text-white text-sm"
                >
                  Back to authentication options
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;