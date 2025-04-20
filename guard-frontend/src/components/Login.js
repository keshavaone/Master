import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { Shield, Lock, User, AlertTriangle, ExternalLink } from 'lucide-react';

const Login = () => {
  const [loginMethod, setLoginMethod] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [securityTip, setSecurityTip] = useState('');
  const [browserLoginStarted, setBrowserLoginStarted] = useState(false);

  // Form inputs
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [accessKey, setAccessKey] = useState('');
  const [secretKey, setSecretKey] = useState('');
  const [sessionToken, setSessionToken] = useState('');

  // Animation states
  const [logoAnimated, setLogoAnimated] = useState(false);
  const [formAnimated, setFormAnimated] = useState(false);

  const { login, startSSOBrowserLogin } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    // Trigger animations sequentially
    setTimeout(() => setLogoAnimated(true), 300);
    setTimeout(() => setFormAnimated(true), 800);

    // Rotate security tips
    const tips = [
      'Use AWS SSO for seamless enterprise authentication.',
      'Your credentials are never stored locally for enhanced security.',
      'All data is encrypted with AES-256 at rest and in transit.',
      'Regular security audits ensure the highest level of protection.',
      'Multi-factor authentication adds an additional layer of security.'
    ];

    setSecurityTip(tips[Math.floor(Math.random() * tips.length)]);

    const tipInterval = setInterval(() => {
      setSecurityTip(tips[Math.floor(Math.random() * tips.length)]);
    }, 8000);

    return () => clearInterval(tipInterval);
  }, []);

  const handleAWSSSOLogin = async (e) => {
    if (e) {
      e.preventDefault();
      console.log("AWS SSO form submitted");
    }

    if (!accessKey || !secretKey) {
      setErrorMessage('Please provide AWS access key and secret key');
      return;
    }

    console.log("Attempting AWS SSO login with:", {
      accessKey,
      secretKeyLength: secretKey.length,
      hasSessionToken: !!sessionToken
    });

    setIsLoading(true);
    setErrorMessage('');

    try {
      console.log("Calling login function");
      await login({
        accessKey,
        secretKey,
        sessionToken
      }, 'aws_sso');

      console.log("Login successful, navigating to dashboard");
      // Redirect to dashboard on success
      navigate('/dashboard');
    } catch (error) {
      console.error('AWS SSO Login error:', error);
      console.error('Response data:', error.response?.data);

      // Ensure error message is a string
      let errorMsg = 'Authentication failed';
      if (error.response?.data?.detail) {
        errorMsg = typeof error.response.data.detail === 'string'
          ? error.response.data.detail
          : JSON.stringify(error.response.data.detail);
      } else if (error.message) {
        errorMsg = error.message;
      }

      setErrorMessage(errorMsg);
    } finally {
      setIsLoading(false);
    }
  };

  const handleBrowserSSOLogin = async () => {
    try {
      setIsLoading(true);
      setBrowserLoginStarted(true);
      setErrorMessage('');

      console.log("Starting AWS SSO browser login flow");

      // Create or get redirect URL from origins 
      const redirectUrl = `${window.location.origin}/auth-callback`;
      console.log("Will redirect back to:", redirectUrl);
      
      // Store that we're in the process of SSO login
      localStorage.setItem('sso_login_pending', 'true');
      localStorage.setItem('sso_login_timestamp', Date.now().toString());
      
      // First try using the API to get the login URL and other potential URLs
      try {
        const response = await authAPI.startSSOLogin(redirectUrl);
        console.log("SSO login URLs:", response.data);
        
        // We have multiple options for login URLs - let's use the direct login URL
        // which should lead directly to the access portal instead of the start URL
        const loginUrl = response.data.login_url || "https://d-9067c603c9.awsapps.com/login";
        
        console.log("Navigating to direct login URL:", loginUrl);
        window.location.href = loginUrl;
        return;
      } catch (apiError) {
        console.error("Error getting SSO URLs from API:", apiError);
        // Fall through to direct navigation approach
      }

      // Direct approach - try the login URL instead of the start URL
      // This is the key change to go directly to the access portal
      console.log("Using direct access portal URL");
      window.location.href = "https://d-9067c603c9.awsapps.com/login";

      // Fallback approaches in case the direct approach doesn't work
      setTimeout(() => {
        // If we're still here after 2 seconds, let's try alternative URLs
        console.log("Direct login URL didn't immediately redirect, trying alternatives...");
        
        // Use the AWS SSO portal URL directly (this might vary by organization)
        try {
          window.location.href = "https://d-9067c603c9.awsapps.com/";
        } catch (e) {
          console.error("Failed to navigate to portal URL:", e);
          
          // Last resort - try the start URL
          window.location.href = "https://d-9067c603c9.awsapps.com/start";
        }
      }, 2000);

    } catch (error) {
      console.error('Browser SSO Login error:', error);

      // Make sure we only set a string as error message
      let errorMsg = 'Failed to start SSO login';
      if (error.response?.data?.detail) {
        // If detail exists and is a string, use it
        errorMsg = typeof error.response.data.detail === 'string'
          ? error.response.data.detail
          : JSON.stringify(error.response.data.detail);
      } else if (error.message) {
        // Fall back to error message if available
        errorMsg = error.message;
      }

      setErrorMessage(errorMsg);
      setIsLoading(false);
      setBrowserLoginStarted(false);
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

      // Ensure error message is a string
      let errorMsg = 'Authentication failed';
      if (error.response?.data?.detail) {
        errorMsg = typeof error.response.data.detail === 'string'
          ? error.response.data.detail
          : JSON.stringify(error.response.data.detail);
      } else if (error.message) {
        errorMsg = error.message;
      }

      setErrorMessage(errorMsg);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex h-screen">
      {/* Left panel - Branding */}
      <div className="hidden lg:flex lg:w-1/2 bg-gradient-to-br from-blue-900 to-gray-900 text-white flex-col justify-between">
        <div className="p-12">
          <div className={`transition-all duration-1000 transform ${logoAnimated ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
            <div className="flex items-center">
              <Shield className="h-12 w-12 text-blue-400 mr-4" />
              <div>
                <h1 className="text-4xl font-bold">GUARD</h1>
                <p className="text-blue-300">Secure PII Data Management</p>
              </div>
            </div>

            <p className="mt-8 text-lg max-w-md text-gray-300">
              Enterprise-grade security for your most sensitive personal information with end-to-end encryption and comprehensive access controls.
            </p>
          </div>
        </div>

        <div className="p-12">
          <div className="bg-blue-800 bg-opacity-30 rounded-xl p-6 border border-blue-700">
            <h3 className="flex items-center text-blue-300 font-medium mb-2">
              <Lock className="h-5 w-5 mr-2" />
              Security Tip
            </h3>
            <p className="text-gray-300">{securityTip}</p>
          </div>

          <div className="mt-8 text-sm text-gray-400">
            <p>© 2025 GUARD Security. All rights reserved.</p>
            <p className="mt-1">Industry standard compliance: GDPR, HIPAA, PCI DSS</p>
          </div>
        </div>
      </div>

      {/* Right panel - Login */}
      <div className="w-full lg:w-1/2 bg-gray-900 flex items-center justify-center p-6">
        <div className={`max-w-md w-full transition-all duration-1000 ${formAnimated ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-12'}`}>
          {/* Mobile logo - only shown on smaller screens */}
          <div className="flex items-center justify-center mb-8 lg:hidden">
            <Shield className="h-10 w-10 text-blue-500 mr-3" />
            <h1 className="text-3xl font-bold text-white">GUARD</h1>
          </div>

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
                  onClick={handleBrowserSSOLogin}
                  className="w-full bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white py-3 px-4 rounded-lg flex items-center justify-center font-medium transition-all duration-200"
                  disabled={isLoading || browserLoginStarted}
                >
                  {isLoading ? (
                    <>
                      <svg className="animate-spin -ml-1 mr-2 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                      </svg>
                      Redirecting to AWS SSO...
                    </>
                  ) : (
                    <>
                      <div className="mr-3 bg-white bg-opacity-20 rounded-full p-1">
                        <ExternalLink className="h-5 w-5" />
                      </div>
                      One-Click AWS SSO Login
                    </>
                  )}
                </button>

                <div className="relative flex items-center">
                  <div className="flex-grow border-t border-gray-700"></div>
                  <span className="flex-shrink mx-3 text-gray-500 text-sm">or</span>
                  <div className="flex-grow border-t border-gray-700"></div>
                </div>

                <button
                  onClick={() => setLoginMethod('aws')}
                  className="w-full bg-blue-700 hover:bg-blue-600 text-white py-3 px-4 rounded-lg flex items-center justify-center font-medium transition-all duration-200"
                >
                  <div className="mr-3 bg-white bg-opacity-20 rounded-full p-1">
                    <Shield className="h-5 w-5" />
                  </div>
                  Sign in with AWS Credentials
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
                      <button
                        type="button"
                        className="text-blue-400 text-sm hover:text-blue-300"
                        onClick={() => alert('Password reset functionality would be implemented here')}
                      >
                        Forgot password?
                      </button>
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

                <p className="mt-4 text-center">
                  <button
                    onClick={() => setLoginMethod(null)}
                    className="text-gray-400 hover:text-white text-sm"
                  >
                    Back to authentication options
                  </button>
                </p>
              </div>
            )}
          </div>

          <p className="text-gray-500 text-sm text-center mt-6">
            Protected by GUARD's advanced encryption. Your credentials never leave your device.
          </p>
        </div>
      </div>
    </div>
  );
};

export default Login;