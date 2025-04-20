import React, { useEffect, useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { Shield } from 'lucide-react';

const AuthCallback = () => {
  const [status, setStatus] = useState('processing');
  const [error, setError] = useState('');
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    const processCallback = async () => {
      try {
        // Get the authorization code from URL parameters
        const searchParams = new URLSearchParams(location.search);
        const code = searchParams.get('code');
        
        if (!code) {
          setStatus('error');
          setError('No authorization code found in the callback URL');
          return;
        }
        
        // Process the authentication with the code
        setStatus('authenticating');
        await login({ ssoCode: code }, 'aws_sso_browser');
        
        // Success - redirect to the dashboard
        setStatus('success');
        setTimeout(() => navigate('/dashboard'), 1000);
      } catch (error) {
        console.error('Auth callback error:', error);
        setStatus('error');
        
        // Make sure error is a string
        let errorMsg = 'Authentication failed';
        if (error.response?.data?.detail) {
          errorMsg = typeof error.response.data.detail === 'string' 
            ? error.response.data.detail 
            : JSON.stringify(error.response.data.detail);
        } else if (error.message) {
          errorMsg = typeof error.message === 'string' 
            ? error.message 
            : JSON.stringify(error.message);
        }
        
        setError(errorMsg);
      }
    };
    
    processCallback();
  }, [login, navigate, location]);
  
  return (
    <div className="h-screen bg-gray-900 flex items-center justify-center">
      <div className="max-w-md w-full mx-4">
        <div className="flex justify-center mb-8">
          <Shield className="h-16 w-16 text-blue-500" />
        </div>
        
        <div className="bg-gray-800 rounded-xl p-8 border border-gray-700 shadow-xl">
          <h1 className="text-2xl font-bold text-center text-white mb-6">
            {status === 'processing' ? 'Processing Login' :
             status === 'authenticating' ? 'Completing Authentication' :
             status === 'success' ? 'Login Successful' :
             'Authentication Error'}
          </h1>
          
          {status === 'processing' || status === 'authenticating' ? (
            <div className="flex flex-col items-center">
              <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500 mb-4"></div>
              <p className="text-gray-300 text-center">
                {status === 'processing' ? 
                  'Processing your login request...' : 
                  'Completing your authentication...'}
              </p>
            </div>
          ) : status === 'success' ? (
            <div className="text-center">
              <div className="bg-green-900 bg-opacity-30 text-green-400 p-4 rounded-lg mb-4">
                <p>You have been successfully authenticated!</p>
                <p className="mt-2 text-sm">Redirecting to dashboard...</p>
              </div>
            </div>
          ) : (
            <div className="text-center">
              <div className="bg-red-900 bg-opacity-30 text-red-400 p-4 rounded-lg mb-4">
                <p className="font-medium">Authentication failed</p>
                <p className="mt-2 text-sm">{error || 'An unexpected error occurred'}</p>
              </div>
              <button 
                onClick={() => navigate('/login')}
                className="mt-4 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg"
              >
                Return to Login
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default AuthCallback;