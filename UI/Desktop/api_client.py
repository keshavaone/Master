"""
Enhanced API client for the GUARD application.

This module provides a secure client for communicating with the GUARD API,
handling authentication, request formatting, and error handling with robust
response handling for all data types.
"""

import json
import logging
import asyncio
import requests
import traceback
from typing import Dict, Any, Tuple, List, Union
from urllib.parse import urljoin
import API.CONSTANTS as CONSTANTS

# Configure logging
logger = logging.getLogger("api_client")
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

class APIClient:
    """Client for communicating with the GUARD API securely."""
    
    def __init__(self, base_url: str = None, auth_service = None):
        """
        Initialize the API client.
        
        Args:
            base_url (str, optional): Base URL for the API server. Defaults to CONSTANTS.API_BASE_URL.
            auth_service: Authentication service to use for API requests.
        """
        self.base_url = base_url or CONSTANTS.API_BASE_URL or "http://localhost:8000"
        self.auth_service = auth_service
        self.last_error = None
        self._loop = None
        self._loop_owner = False
        
        logger.info(f"API client initialized for {self.base_url}")
    
    def _get_event_loop(self):
        """
        Get an event loop safely, creating a new one if necessary.
        
        Returns:
            asyncio.AbstractEventLoop: The event loop
        """
        try:
            # Try to get the current running loop
            loop = asyncio.get_running_loop()
            self._loop_owner = False  # We're using someone else's loop
            return loop
        except RuntimeError:
            # No running event loop, create a new one
            if self._loop is None or self._loop.is_closed():
                self._loop = asyncio.new_event_loop()
                self._loop_owner = True  # We own this loop
            return self._loop

    def sync_make_request(self, method: str, endpoint: str, 
                       data: Any = None, params: Dict[str, Any] = None,
                       headers: Dict[str, str] = None) -> Tuple[bool, Any]:
        """
        Synchronous version of make_request.
        
        This method safely handles event loops for executing async code.
        
        Args:
            method (str): HTTP method (GET, POST, etc.)
            endpoint (str): API endpoint path (without base URL)
            data (Any, optional): Request body data
            params (Dict[str, Any], optional): Query parameters
            headers (Dict[str, str], optional): Additional headers
            
        Returns:
            Tuple[bool, Any]: (Success flag, response data or error)
        """
        # Build URL for requests
        url = urljoin(self.base_url, endpoint.lstrip('/'))
        
        # Get auth headers
        auth_headers = {}
        if self.auth_service:
            if hasattr(self.auth_service, 'get_auth_headers'):
                auth_headers = self.auth_service.get_auth_headers()
            else:
                logger.warning("Auth service does not have get_auth_headers method")
        
        # Merge with custom headers
        request_headers = {**auth_headers, **(headers or {})}
        
        # Log request details (exclude sensitive info)
        safe_headers = {k: v for k, v in request_headers.items() 
                        if k.lower() not in ('authorization', 'x-aws-secret-access-key')}
        logger.info(f"Making {method} request to {url}")
        logger.debug(f"Headers: {safe_headers}")
        if params:
            logger.debug(f"Params: {params}")
        
        # Handle JSON data
        if data is not None and isinstance(data, (dict, list)):
            logger.debug(f"Request JSON data: {type(data)}")
        elif data is not None:
            logger.warning(f"Data is not JSON serializable: {type(data)}")
        
        try:
            # We'll use the requests library for synchronous requests
            # This avoids any asyncio event loop issues
            response = requests.request(
                method=method.upper(),
                url=url,
                json=data if isinstance(data, (dict, list)) else None,
                data=data if not isinstance(data, (dict, list)) else None,
                params=params,
                headers=request_headers,
                timeout=30  # Add a reasonable timeout
            )
            
            # Log response status
            logger.info(f"Response status: {response.status_code}")
            
            # Process response based on content type
            content_type = response.headers.get('Content-Type', '')
            
            if 'application/json' in content_type:
                try:
                    response_data = response.json()
                except json.JSONDecodeError:
                    # If Content-Type is JSON but content isn't valid JSON
                    response_data = response.text
                    logger.warning(f"Response claimed to be JSON but wasn't: {response_data[:100]}...")
            else:
                response_data = response.text
                # Try to parse as JSON anyway if it looks like it
                if response_data.strip().startswith('{') or response_data.strip().startswith('['):
                    try:
                        response_data = json.loads(response_data)
                    except json.JSONDecodeError:
                        pass  # Keep as text if parsing fails
            
            # Return based on status code
            if 200 <= response.status_code < 300:
                return True, response_data
            else:
                error_msg = f"Request failed: {response.status_code}"
                if isinstance(response_data, dict):
                    if 'detail' in response_data:
                        error_msg += f" - {response_data['detail']}"
                    elif 'message' in response_data:
                        error_msg += f" - {response_data['message']}"
                    elif 'error' in response_data:
                        error_msg += f" - {response_data['error']}"
                
                self.last_error = error_msg
                logger.error(error_msg)
                return False, response_data
                
        except requests.RequestException as e:
            error_msg = f"API connection error: {str(e)}"
            self.last_error = error_msg
            logger.error(error_msg)
            return False, {"error": error_msg}
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            self.last_error = error_msg
            logger.error(f"{error_msg}\n{traceback.format_exc()}")
            return False, {"error": error_msg}
    
    def sync_make_authenticated_request(self, method: str, endpoint: str, 
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
            logger.error("No authentication service provided")
            return False, {"error": "Authentication service not available"}
        
        # Check if auth service is authenticated
        if hasattr(self.auth_service, 'is_authenticated') and callable(self.auth_service.is_authenticated):
            if not self.auth_service.is_authenticated():
                logger.error("Not authenticated with auth service")
                return False, {"error": "Not authenticated"}
        
        # Make the initial request
        success, result = self.sync_make_request(method, endpoint, data, params)
        
        # If request failed with 401 Unauthorized, try to refresh token and retry
        if not success and isinstance(result, dict) and (
            result.get('detail') == 'Invalid token or expired token' or 
            result.get('detail') == 'Not authenticated' or
            result.get('error') == 'Authentication expired'
        ):
            logger.info("Token expired, attempting to refresh")
            
            # Check if auth service can refresh token
            if hasattr(self.auth_service, 'refresh_token') and callable(self.auth_service.refresh_token):
                try:
                    # Handle both synchronous and asynchronous refresh_token methods
                    if asyncio.iscoroutinefunction(self.auth_service.refresh_token):
                        # Async method requires event loop
                        loop = self._get_event_loop()
                        refresh_success = loop.run_until_complete(self.auth_service.refresh_token())
                    else:
                        # Synchronous method
                        refresh_success = self.auth_service.refresh_token()
                        
                    if refresh_success:
                        logger.info("Token refreshed, retrying request")
                        return self.sync_make_request(method, endpoint, data, params)
                    else:
                        logger.error("Token refresh failed")
                        return False, {"error": "Authentication expired and refresh failed"}
                except Exception as e:
                    logger.error(f"Error during token refresh: {str(e)}")
                    return False, {"error": f"Token refresh error: {str(e)}"}
        
        return success, result
    
    # Convenience methods for PII data operations
    
    def sync_get_pii_data(self) -> Tuple[bool, Union[List[Dict[str, Any]], str, Dict[str, Any]]]:
        """
        Synchronous method to get all PII data with robust response handling.
        
        Returns:
            Tuple[bool, List[Dict] or str or Dict]: (Success flag, PII data or error message)
        """
        response = self.sync_make_authenticated_request("GET", "pii")
        
        # Unpack the response
        success, data = response
        
        if success:
            # Handle different types of successful responses
            if isinstance(data, list):
                logger.info(f"Received list data with {len(data)} items")
                return True, data
            elif isinstance(data, dict):
                logger.info("Received dictionary data, wrapping in list")
                return True, [data]
            elif isinstance(data, str):
                logger.warning(f"Received string response: {data[:100]}...")
                
                # Try to parse as JSON
                try:
                    parsed = json.loads(data)
                    if isinstance(parsed, list):
                        logger.info(f"Successfully parsed string as JSON list with {len(parsed)} items")
                        return True, parsed
                    elif isinstance(parsed, dict):
                        logger.info("Successfully parsed string as JSON dict, wrapping in list")
                        return True, [parsed]
                    else:
                        # Return parsed data as is
                        logger.info(f"Successfully parsed string as JSON {type(parsed)}")
                        return True, parsed
                except json.JSONDecodeError:
                    # Not JSON, return as string
                    logger.warning("String response is not valid JSON")
                    return True, data
            else:
                # Other types - convert to string
                logger.warning(f"Unexpected response type: {type(data)}")
                return True, str(data)
        else:
            # For failures, return the original response
            return response
    
    def sync_add_pii_item(self, item_data: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Synchronous method to add a new PII data item.
        
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
            logger.error(error_msg)
            return False, {"error": error_msg}
        
        return self.sync_make_authenticated_request("POST", "pii", data=item_data)
    
    def sync_update_pii_item(self, item_data: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Synchronous method to update an existing PII data item.
        
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
            logger.error(error_msg)
            return False, {"error": error_msg}
        
        return self.sync_make_authenticated_request("PATCH", "pii", data=item_data)
    
    def sync_delete_pii_item(self, item_id: str, category: str = None, type_: str = None) -> Tuple[bool, Dict[str, Any]]:
        """
        Synchronous method to delete a PII data item.
        
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
        
        return self.sync_make_authenticated_request("DELETE", "pii", data=delete_data)

    # Async versions of methods - kept for compatibility if needed
    
    async def make_request(self, method: str, endpoint: str, 
                         data: Any = None, params: Dict[str, Any] = None,
                         headers: Dict[str, str] = None) -> Tuple[bool, Any]:
        """
        Make an async API request with proper authentication.
        
        Args:
            method (str): HTTP method (GET, POST, etc.)
            endpoint (str): API endpoint path (without base URL)
            data (Any, optional): Request body data
            params (Dict[str, Any], optional): Query parameters
            headers (Dict[str, str], optional): Additional headers
            
        Returns:
            Tuple[bool, Any]: (Success flag, response data or error)
        """
        # This is now a wrapper around the sync version using concurrent.futures
        from concurrent.futures import ThreadPoolExecutor
        import functools
        
        with ThreadPoolExecutor() as executor:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                executor,
                functools.partial(
                    self.sync_make_request,
                    method=method,
                    endpoint=endpoint,
                    data=data,
                    params=params,
                    headers=headers
                )
            )
            return result
    
    async def make_authenticated_request(self, method: str, endpoint: str, 
                                       data: Any = None, params: Dict[str, Any] = None) -> Tuple[bool, Any]:
        """
        Make an async authenticated request.
        
        Args:
            method (str): HTTP method (GET, POST, etc.)
            endpoint (str): API endpoint path (without base URL)
            data (Any, optional): Request body data
            params (Dict[str, Any], optional): Query parameters
            
        Returns:
            Tuple[bool, Any]: (Success flag, response data or error)
        """
        # This is now a wrapper around the sync version using concurrent.futures
        from concurrent.futures import ThreadPoolExecutor
        import functools
        
        with ThreadPoolExecutor() as executor:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                executor,
                functools.partial(
                    self.sync_make_authenticated_request,
                    method=method,
                    endpoint=endpoint,
                    data=data,
                    params=params
                )
            )
            return result