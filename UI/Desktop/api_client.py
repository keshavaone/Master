"""
API client for the GUARD application.

This module provides a secure client for communicating with the GUARD API,
handling authentication, request formatting, and error handling.
"""

import os
import json
import logging
import asyncio
import aiohttp
from typing import Dict, Any, Optional, Tuple, List, Union
from urllib.parse import urljoin
import API.CONSTANTS as CONSTANTS

# Configure logging
logger = logging.getLogger("api_client")

class APIClient:
    """Client for communicating with the GUARD API securely."""
    
    def __init__(self, base_url: str = None, auth_service = None):
        """
        Initialize the API client.
        
        Args:
            base_url (str, optional): Base URL for the API server. Defaults to CONSTANTS.API_BASE_URL.
            auth_service: Authentication service to use for API requests.
        """
        self.base_url = base_url or CONSTANTS.API_BASE_URL
        self.auth_service = auth_service
        self.last_error = None
        self.logger = logging.getLogger("api_client")
        self.session = None
        
        # Initialize logger
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        
        self.logger.info(f"API client initialized for {self.base_url}")

    async def _initialize_session(self):
        """Initialize aiohttp session if needed."""
        if self.session is None:
            self.session = aiohttp.ClientSession()
    
    async def close(self):
        """Close the API client session."""
        if self.session is not None:
            await self.session.close()
            self.session = None

    async def make_request(self, method: str, endpoint: str, 
                           data: Any = None, params: Dict[str, Any] = None,
                           headers: Dict[str, str] = None) -> Tuple[bool, Any]:
        """
        Make an API request with proper authentication.
        
        Args:
            method (str): HTTP method (GET, POST, etc.)
            endpoint (str): API endpoint path (without base URL)
            data (Any, optional): Request body data
            params (Dict[str, Any], optional): Query parameters
            headers (Dict[str, str], optional): Additional headers
            
        Returns:
            Tuple[bool, Any]: (Success flag, response data or error)
        """
        await self._initialize_session()
        
        # Build URL
        url = urljoin(self.base_url, endpoint.lstrip('/'))
        
        # Get auth headers
        auth_headers = {}
        if self.auth_service:
            if hasattr(self.auth_service, 'get_auth_headers'):
                auth_headers = self.auth_service.get_auth_headers()
            else:
                self.logger.warning("Auth service does not have get_auth_headers method")
        
        # Merge with custom headers
        request_headers = {**auth_headers, **(headers or {})}
        
        # Log request details (exclude sensitive info)
        safe_headers = {k: v for k, v in request_headers.items() 
                         if k.lower() not in ('authorization', 'x-aws-secret-access-key')}
        self.logger.info(f"Making {method} request to {url}")
        self.logger.debug(f"Headers: {safe_headers}")
        if params:
            self.logger.debug(f"Params: {params}")
        
        try:
            # Handle JSON data
            json_data = None
            if data is not None:
                if isinstance(data, (dict, list)):
                    json_data = data
                    self.logger.debug(f"Request JSON data: {type(json_data)}")
                else:
                    self.logger.warning(f"Data is not JSON serializable: {type(data)}")
            
            # Make the request
            async with self.session.request(method=method.upper(), url=url,
                                           json=json_data, params=params,
                                           headers=request_headers) as response:
                
                # Log response status
                self.logger.info(f"Response status: {response.status}")
                
                # Process response based on content type
                content_type = response.headers.get('Content-Type', '')
                
                if 'application/json' in content_type:
                    response_data = await response.json()
                else:
                    response_data = await response.text()
                
                # Return based on status code
                if 200 <= response.status < 300:
                    return True, response_data
                else:
                    error_msg = f"Request failed: {response.status}"
                    if isinstance(response_data, dict) and 'detail' in response_data:
                        error_msg += f" - {response_data['detail']}"
                    elif isinstance(response_data, dict) and 'message' in response_data:
                        error_msg += f" - {response_data['message']}"
                    
                    self.last_error = error_msg
                    self.logger.error(error_msg)
                    return False, response_data
                    
        except aiohttp.ClientError as e:
            error_msg = f"API connection error: {str(e)}"
            self.last_error = error_msg
            self.logger.error(error_msg)
            return False, {"error": error_msg}
        except asyncio.TimeoutError:
            error_msg = "API request timed out"
            self.last_error = error_msg
            self.logger.error(error_msg)
            return False, {"error": error_msg}
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            self.last_error = error_msg
            self.logger.error(error_msg)
            return False, {"error": error_msg}
    
    async def make_authenticated_request(self, method: str, endpoint: str, 
                                      data: Any = None, params: Dict[str, Any] = None) -> Tuple[bool, Any]:
        """
        Make an authenticated request with automatic token refresh if needed.
        
        Args:
            method (str): HTTP method (GET, POST, etc.)
            endpoint (str): API endpoint path (without base URL)
            data (Any, optional): Request body data
            params (Dict[str, Any], optional): Query parameters
            
        Returns:
            Tuple[bool, Any]: (Success flag, response data or error)
        """
        # Check if we have auth service
        if not self.auth_service:
            self.logger.error("No authentication service provided")
            return False, {"error": "Authentication service not available"}
        
        # Check if auth service is authenticated
        if hasattr(self.auth_service, 'is_authenticated') and callable(self.auth_service.is_authenticated):
            if not self.auth_service.is_authenticated():
                self.logger.error("Not authenticated with auth service")
                return False, {"error": "Not authenticated"}
        
        # Make the initial request
        success, result = await self.make_request(method, endpoint, data, params)
        
        # If request failed with 401 Unauthorized, try to refresh token and retry
        if not success and isinstance(result, dict) and result.get('detail') == 'Invalid token or expired token':
            self.logger.info("Token expired, attempting to refresh")
            
            # Check if auth service can refresh token
            if hasattr(self.auth_service, 'refresh_token') and callable(self.auth_service.refresh_token):
                refresh_success = await self.auth_service.refresh_token()
                if refresh_success:
                    self.logger.info("Token refreshed, retrying request")
                    return await self.make_request(method, endpoint, data, params)
                else:
                    self.logger.error("Token refresh failed")
                    return False, {"error": "Authentication expired and refresh failed"}
        
        return success, result

    # PII Data Endpoints
    
    async def get_pii_data(self) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Get all PII data from the API.
        
        Returns:
            Tuple[bool, List[Dict]]: (Success flag, PII data or error)
        """
        return await self.make_authenticated_request("GET", "pii")
    
    async def add_pii_item(self, item_data: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Add a new PII data item.
        
        Args:
            item_data (Dict): PII item data with Category, Type, and PII fields
            
        Returns:
            Tuple[bool, Dict]: (Success flag, response data or error)
        """
        # Validate required fields
        required_fields = ['Category', 'Type', 'PII']
        missing_fields = [field for field in required_fields if field not in item_data]
        
        if missing_fields:
            error_msg = f"Missing required fields: {', '.join(missing_fields)}"
            self.logger.error(error_msg)
            return False, {"error": error_msg}
        
        return await self.make_authenticated_request("POST", "pii", data=item_data)
    
    async def update_pii_item(self, item_data: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Update an existing PII data item.
        
        Args:
            item_data (Dict): PII item data with _id, Category, Type, and PII fields
            
        Returns:
            Tuple[bool, Dict]: (Success flag, response data or error)
        """
        # Validate required fields
        required_fields = ['_id', 'Category', 'Type', 'PII']
        missing_fields = [field for field in required_fields if field not in item_data]
        
        if missing_fields:
            error_msg = f"Missing required fields: {', '.join(missing_fields)}"
            self.logger.error(error_msg)
            return False, {"error": error_msg}
        
        return await self.make_authenticated_request("PATCH", "pii", data=item_data)
    
    async def delete_pii_item(self, item_id: str, category: str = None, type_: str = None) -> Tuple[bool, Dict[str, Any]]:
        """
        Delete a PII data item.
        
        Args:
            item_id (str): ID of the item to delete
            category (str, optional): Category of the item
            type_ (str, optional): Type of the item
            
        Returns:
            Tuple[bool, Dict]: (Success flag, response data or error)
        """
        delete_data = {'_id': item_id}
        if category:
            delete_data['Category'] = category
        if type_:
            delete_data['Type'] = type_
        
        return await self.make_authenticated_request("DELETE", "pii", data=delete_data)
    
    async def get_pii_categories(self) -> Tuple[bool, List[str]]:
        """
        Get all unique PII data categories.
        
        Returns:
            Tuple[bool, List[str]]: (Success flag, list of categories or error)
        """
        success, data = await self.get_pii_data()
        
        if not success:
            return False, data
        
        # Extract unique categories
        try:
            if isinstance(data, list):
                categories = sorted(list(set(item.get('Category', '') for item in data if 'Category' in item)))
                return True, categories
            else:
                return False, {"error": "Unexpected data format"}
        except Exception as e:
            error_msg = f"Error extracting categories: {str(e)}"
            self.logger.error(error_msg)
            return False, {"error": error_msg}
    
    async def get_pii_types_by_category(self, category: str) -> Tuple[bool, List[str]]:
        """
        Get all PII data types for a specific category.
        
        Args:
            category (str): Category to get types for
            
        Returns:
            Tuple[bool, List[str]]: (Success flag, list of types or error)
        """
        success, data = await self.get_pii_data()
        
        if not success:
            return False, data
        
        # Filter by category and extract unique types
        try:
            if isinstance(data, list):
                types = sorted(list(set(item.get('Type', '') for item in data 
                                    if 'Type' in item and item.get('Category') == category)))
                return True, types
            else:
                return False, {"error": "Unexpected data format"}
        except Exception as e:
            error_msg = f"Error extracting types: {str(e)}"
            self.logger.error(error_msg)
            return False, {"error": error_msg}
    
    async def get_pii_item_by_id(self, item_id: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Get a specific PII item by ID.
        
        Args:
            item_id (str): ID of the item to retrieve
            
        Returns:
            Tuple[bool, Dict]: (Success flag, item data or error)
        """
        # Use the search endpoint with ID filter or fall back to getting all and filtering
        success, data = await self.get_pii_data()
        
        if not success:
            return False, data
        
        # Find the item with matching ID
        try:
            if isinstance(data, list):
                for item in data:
                    if item.get('_id') == item_id:
                        return True, item
                
                return False, {"error": f"Item with ID {item_id} not found"}
            else:
                return False, {"error": "Unexpected data format"}
        except Exception as e:
            error_msg = f"Error finding item: {str(e)}"
            self.logger.error(error_msg)
            return False, {"error": error_msg}
    
    # Authentication Endpoints
    
    async def login_with_password(self, username: str, password: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Login with username and password.
        
        Args:
            username (str): Username for authentication
            password (str): Password for authentication
            
        Returns:
            Tuple[bool, Dict]: (Success flag, token data or error)
        """
        try:
            # Call the token endpoint
            login_data = {"username": username, "password": password}
            
            # Try both header and body approaches since the backend supports both
            headers = {
                "Content-Type": "application/json",
                "username": username,
                "password": password
            }
            
            success, result = await self.make_request("POST", "auth/token", 
                                                    data=login_data, 
                                                    headers=headers)
            
            return success, result
        except Exception as e:
            error_msg = f"Login error: {str(e)}"
            self.logger.error(error_msg)
            return False, {"error": error_msg}
    
    async def login_with_aws_sso(self, credentials: Dict[str, str]) -> Tuple[bool, Dict[str, Any]]:
        """
        Login with AWS SSO credentials.
        
        Args:
            credentials (Dict): AWS credentials with AccessKeyId, SecretAccessKey, SessionToken
            
        Returns:
            Tuple[bool, Dict]: (Success flag, token data or error)
        """
        try:
            # Prepare headers with AWS credentials
            headers = {
                "X-AWS-Access-Key-ID": credentials.get('AccessKeyId', ''),
                "X-AWS-Secret-Access-Key": credentials.get('SecretAccessKey', '')
            }
            
            # Add session token if available
            if 'SessionToken' in credentials:
                headers["X-AWS-Session-Token"] = credentials.get('SessionToken')
            
            # Call the AWS SSO auth endpoint
            success, result = await self.make_request("POST", "auth/aws-sso", headers=headers)
            
            return success, result
        except Exception as e:
            error_msg = f"AWS SSO login error: {str(e)}"
            self.logger.error(error_msg)
            return False, {"error": error_msg}
    
    async def verify_token(self, token: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Verify if a token is valid.
        
        Args:
            token (str): Token to verify
            
        Returns:
            Tuple[bool, Dict]: (Success flag, verification result or error)
        """
        try:
            # Prepare headers with token
            headers = {"Authorization": f"Bearer {token}"}
            
            # Call the verify endpoint
            success, result = await self.make_request("GET", "auth/user", headers=headers)
            
            return success, result
        except Exception as e:
            error_msg = f"Token verification error: {str(e)}"
            self.logger.error(error_msg)
            return False, {"error": error_msg}
    
    async def refresh_token(self, token: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Refresh an authentication token.
        
        Args:
            token (str): Current token to refresh
            
        Returns:
            Tuple[bool, Dict]: (Success flag, new token data or error)
        """
        try:
            # Prepare headers with token
            headers = {"Authorization": f"Bearer {token}"}
            
            # Call the refresh endpoint
            success, result = await self.make_request("POST", "auth/token/refresh", headers=headers)
            
            return success, result
        except Exception as e:
            error_msg = f"Token refresh error: {str(e)}"
            self.logger.error(error_msg)
            return False, {"error": error_msg}
    
    # System Endpoints
    
    async def get_health_status(self) -> Tuple[bool, Dict[str, Any]]:
        """
        Check API health status.
        
        Returns:
            Tuple[bool, Dict]: (Success flag, health status or error)
        """
        return await self.make_request("GET", "health")
    
    async def get_system_info(self) -> Tuple[bool, Dict[str, Any]]:
        """
        Get system information (admin only).
        
        Returns:
            Tuple[bool, Dict]: (Success flag, system info or error)
        """
        return await self.make_authenticated_request("GET", "system/info")

    # Synchronous compatibility methods for easier integration with existing code
    
    def sync_make_authenticated_request(self, method: str, endpoint: str, 
                                     data: Any = None, params: Dict[str, Any] = None) -> Tuple[bool, Any]:
        """
        Synchronous version of make_authenticated_request.
        
        This method runs the async method in a new event loop for easy integration with
        synchronous code. For production use, prefer the async version.
        
        Args:
            method (str): HTTP method (GET, POST, etc.)
            endpoint (str): API endpoint path (without base URL)
            data (Any, optional): Request body data
            params (Dict[str, Any], optional): Query parameters
            
        Returns:
            Tuple[bool, Any]: (Success flag, response data or error)
        """
        async def _async_wrapper():
            return await self.make_authenticated_request(method, endpoint, data, params)
        
        # Create a new event loop to run the async function
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(_async_wrapper())
            return result
        finally:
            loop.close()
    
    def sync_get_pii_data(self) -> Tuple[bool, List[Dict[str, Any]]]:
        """Synchronous version of get_pii_data."""
        return self.sync_make_authenticated_request("GET", "pii")
    
    def sync_add_pii_item(self, item_data: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Synchronous version of add_pii_item."""
        return self.sync_make_authenticated_request("POST", "pii", data=item_data)
    
    def sync_update_pii_item(self, item_data: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Synchronous version of update_pii_item."""
        return self.sync_make_authenticated_request("PATCH", "pii", data=item_data)
    
    def sync_delete_pii_item(self, item_id: str, category: str = None, type_: str = None) -> Tuple[bool, Dict[str, Any]]:
        """Synchronous version of delete_pii_item."""
        delete_data = {'_id': item_id}
        if category:
            delete_data['Category'] = category
        if type_:
            delete_data['Type'] = type_
        
        return self.sync_make_authenticated_request("DELETE", "pii", data=delete_data)


# Example usage
if __name__ == "__main__":
    import asyncio
    
    async def test_api():
        # Create auth service (this would normally be your auth_service instance)
        from API.auth_service import AuthService
        auth_service = AuthService(CONSTANTS.API_BASE_URL)
        
        # Login with password (for testing)
        username = os.environ.get('USER', 'admin')
        password = CONSTANTS.APP_PASSWORD
        success, _ = auth_service.authenticate_with_password(username, password)
        
        if not success:
            print("Authentication failed")
            return
        
        # Create API client
        client = APIClient(auth_service=auth_service)
        
        # Test health endpoint
        print("Testing health endpoint...")
        success, health = await client.get_health_status()
        print(f"Health: {success}, {health}")
        
        # Test get PII data
        print("Testing get PII data...")
        success, data = await client.get_pii_data()
        print(f"Got {len(data) if success and isinstance(data, list) else 0} PII items")
        
        # Clean up
        await client.close()
    
    # Run the test
    asyncio.run(test_api())