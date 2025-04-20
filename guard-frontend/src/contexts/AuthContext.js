import React, { createContext, useState, useEffect, useContext } from 'react';
import { authAPI } from '../services/api';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [currentUser, setCurrentUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    // Check if user is logged in
    const checkLoggedIn = async () => {
      const token = localStorage.getItem('accessToken');
      if (token) {
        try {
          const response = await authAPI.getCurrentUser();
          setCurrentUser(response.data);
        } catch (err) {
          // Token invalid - clear local storage
          localStorage.removeItem('accessToken');
          localStorage.removeItem('refreshToken');
        }
      }
      setLoading(false);
    };

    checkLoggedIn();
  }, []);

  const login = async (credentials, method = 'password') => {
    setError(null);
    try {
      let response;

      if (method === 'aws_sso') {
        console.log("Sending AWS SSO auth request with credentials:", {
          hasAccessKey: !!credentials.accessKey,
          hasSecretKey: !!credentials.secretKey,
          hasSessionToken: !!credentials.sessionToken
        });

        response = await authAPI.loginWithSSO(
          credentials.accessKey,
          credentials.secretKey,
          credentials.sessionToken
        );
      } else if (method === 'aws_sso_browser') {
        // This handle's the response after the SSO flow completes
        // The actual browser redirect is handled in startSSOBrowserLogin
        if (credentials.ssoCode) {
          response = await authAPI.completeSSOLogin(credentials.ssoCode);
        } else {
          throw new Error("No SSO code provided for browser login completion");
        }
      } else {
        response = await authAPI.loginWithPassword(
          credentials.username,
          credentials.password
        );
      }

      console.log("Auth response:", response.data);

      // Store tokens
      localStorage.setItem('accessToken', response.data.access_token);
      if (response.data.refresh_token) {
        localStorage.setItem('refreshToken', response.data.refresh_token);
      }

      setCurrentUser(response.data);
      return response.data;
    } catch (err) {
      console.error("Login error:", err);

      // Ensure we set a string as the error message
      let errorMsg = 'Authentication failed';
      if (err.response?.data?.detail) {
        errorMsg = typeof err.response.data.detail === 'string'
          ? err.response.data.detail
          : JSON.stringify(err.response.data.detail);
      } else if (err.message) {
        errorMsg = typeof err.message === 'string'
          ? err.message
          : JSON.stringify(err.message);
      }

      setError(errorMsg);
      throw err;
    }
  };

  const startSSOBrowserLogin = async (redirectUrl) => {
    setError(null);
    try {
      // Create or get redirect URL
      const finalRedirectUrl = redirectUrl || `${window.location.origin}/auth-callback`;
      console.log("Will redirect back to:", finalRedirectUrl);
      
      // Store that we're in the process of SSO login
      localStorage.setItem('sso_login_pending', 'true');
      localStorage.setItem('sso_login_timestamp', Date.now().toString());
      
      // Get the SSO URL from the API
      const response = await authAPI.startSSOLogin(finalRedirectUrl);
      console.log("Start SSO response:", response.data);

      // Check available URLs in order of preference:
      // 1. Direct login portal URL (preferred)
      // 2. Portal root URL
      // 3. SSO start URL
      // 4. Fallback URLs
      
      if (response.data.login_url) {
        // First choice: Direct login portal URL (leads directly to access portal)
        console.log("Using direct access portal URL:", response.data.login_url);
        window.location.href = response.data.login_url;
        return { success: true, message: "Redirecting to AWS SSO access portal", url: response.data.login_url };
      } 
      else if (response.data.portal_url) {
        // Second choice: Portal root URL
        console.log("Using portal root URL:", response.data.portal_url);
        window.location.href = response.data.portal_url;
        return { success: true, message: "Redirecting to AWS SSO portal", url: response.data.portal_url };
      }
      else if (response.data.start_url) {
        // Third choice: SSO start URL
        console.log("Using SSO start URL:", response.data.start_url);
        window.location.href = response.data.start_url;
        return { success: true, message: "Redirecting to AWS SSO start URL", url: response.data.start_url };
      }
      else if (response.data.alternative_urls && response.data.alternative_urls.length > 0) {
        // Fallback: Use first alternative URL
        const fallbackUrl = response.data.alternative_urls[0];
        console.log("Using fallback URL:", fallbackUrl);
        window.location.href = fallbackUrl;
        return { success: true, message: "Redirecting to fallback AWS SSO URL", url: fallbackUrl };
      }
      else {
        // Last resort: hardcoded direct login
        console.log("No URLs found in response, using hardcoded direct login URL");
        window.location.href = "https://d-9067c603c9.awsapps.com/login";
        return { success: true, message: "Redirecting to hardcoded AWS SSO login URL", url: "https://d-9067c603c9.awsapps.com/login" };
      }
    } catch (err) {
      console.error("Start SSO login error:", err);

      // Fallback on error - use direct access portal URL
      try {
        console.log("Error occurred, using direct AWS SSO access portal URL");

        // Use the AWS direct login portal URL
        window.location.href = "https://d-9067c603c9.awsapps.com/login";
        return { success: true, message: "Redirecting to fallback AWS SSO access portal", url: "https://d-9067c603c9.awsapps.com/login" };
      } catch (directUrlError) {
        // Only set error if both methods fail
        // Ensure we set a string as the error message
        let errorMsg = 'Failed to start SSO login';
        if (err.response?.data?.detail) {
          errorMsg = typeof err.response.data.detail === 'string'
            ? err.response.data.detail
            : JSON.stringify(err.response.data.detail);
        } else if (err.message) {
          errorMsg = typeof err.message === 'string'
            ? err.message
            : JSON.stringify(err.message);
        }

        setError(errorMsg);
        throw err;
      }
    }
  };

  const logout = async () => {
    try {
      await authAPI.logout();
    } catch (err) {
      console.error('Logout error:', err);
    } finally {
      // Clear local storage and state
      localStorage.removeItem('accessToken');
      localStorage.removeItem('refreshToken');
      setCurrentUser(null);
    }
  };

  const value = {
    currentUser,
    loading,
    error,
    login,
    logout,
    startSSOBrowserLogin,
    isAuthenticated: !!currentUser
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};