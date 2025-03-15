# API/unified_auth_service.py
class UnifiedAuthService:
    """
    Unified authentication service that handles both JWT and AWS SSO auth.
    
    This service is the single source of truth for authentication status,
    token management, and API authorization.
    """
    
    def __init__(self, api_base_url, session_manager=None):
        self.api_base_url = api_base_url
        self.session_manager = session_manager
        self.token = None
        self.token_expiration = None
        self.user_id = None
        self.auth_type = None
        self.token_refresh_callbacks = []
        
    def register_token_refresh_callback(self, callback):
        """Register a callback function to be called when token is refreshed."""
        self.token_refresh_callbacks.append(callback)
        
    def authenticate_with_password(self, username, password):
        """Authenticate with username/password and get JWT token."""
        # Implementation that calls the auth endpoint or creates JWT directly
        
    def authenticate_with_aws_sso(self):
        """Authenticate with AWS SSO using session manager."""
        # Implementation that gets token from session manager
        
    def refresh_token(self):
        """Refresh the current token."""
        # Implementation that refreshes JWT or checks AWS SSO token validity
        
    def make_authenticated_request(self, method, endpoint, data=None, params=None):
        """Make an authenticated request to the API."""
        # Implementation that handles auth headers and token refresh