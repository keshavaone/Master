"""
Session Integration and UI Component Connector for GUARD Application

This module integrates the AWS SSO session management with the enhanced UI components
and provides the connector that makes everything work seamlessly together.
"""

import os
import sys
import logging
import time
from typing import Dict, Any, Optional, Tuple, List, Callable
import asyncio
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QDialog, QMessageBox, QApplication
)
from PyQt5.QtCore import Qt, pyqtSignal, QSize, QObject, QTimer

# Configure logging
logger = logging.getLogger("session_integration")
logger.setLevel(logging.INFO)

class GuardSessionIntegrator(QObject):
    """
    Integrator class that connects the session management and UI components.
    
    This class serves as the glue between various components of the GUARD application:
    - AWS SSO Session Manager
    - Authentication Service
    - UI Components for Data Management
    - CRUD Operations
    
    It provides a single interface for the main application to interact with
    all these components together.
    """
    
    # Define signals
    data_refreshed = pyqtSignal()
    auth_status_changed = pyqtSignal(bool, str)  # is_authenticated, auth_type
    
    def __init__(self, parent=None):
        """
        Initialize the session integrator.
        
        Args:
            parent: Parent QObject
        """
        super().__init__(parent)
        self.parent = parent
        
        # Components (will be set later)
        self.aws_sso_manager = None
        self.auth_service = None
        self.agent = None
        self.crud_helper = None
        
        # Status
        self.is_authenticated = False
        self.last_error = None
        
        # Setup refresh timer
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.check_status)
        self.refresh_timer.start(10000)  # Check every 10 seconds
        
        # Initialize logging
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        logger.info("GUARD Session Integrator initialized")
    
    def initialize_components(self, api_base_url: str):
        """
        Initialize all the required components.
        
        Args:
            api_base_url (str): The base URL for the API
        """
        try:
            # Import the enhanced modules
            logger.info("Initializing session components")
            
            # Initialize AWS SSO Session Manager
            from aws_sso_session_manager import AwsSsoSessionManager
            self.aws_sso_manager = AwsSsoSessionManager(self)
            
            # Connect AWS SSO signals
            self.aws_sso_manager.auth_success.connect(self.handle_aws_auth_success)
            self.aws_sso_manager.auth_failure.connect(self.handle_auth_failure)
            self.aws_sso_manager.session_expired.connect(self.handle_session_expired)
            
            # Initialize Enhanced Auth Service
            from enhanced_auth_service import EnhancedAuthService
            self.auth_service = EnhancedAuthService(
                api_base_url=api_base_url,
                session_manager=self.aws_sso_manager
            )
            
            # Initialize CRUD Helper
            from modern_data_management import CRUDHelper
            self.crud_helper = CRUDHelper()
            
            logger.info("All components initialized successfully")
            return True
        except ImportError as e:
            logger.error(f"Failed to import required components: {str(e)}")
            self.last_error = f"Missing component: {str(e)}"
            return False
        except Exception as e:
            logger.error(f"Error initializing components: {str(e)}")
            self.last_error = f"Initialization error: {str(e)}"
            return False
    
    def authenticate_with_aws_sso(self, parent_widget=None) -> bool:
        """
        Authenticate with AWS SSO.
        
        Args:
            parent_widget: Parent widget for dialogs
            
        Returns:
            bool: True if authentication was successful
        """
        if not self.aws_sso_manager:
            logger.error("AWS SSO manager not initialized")
            return False
        
        try:
            # Authenticate with AWS SSO
            success = self.aws_sso_manager.authenticate_aws_sso(parent_widget)
            
            if success:
                # Authentication successful, update state
                self.is_authenticated = True
                
                # Update auth service with SSO credentials
                if self.auth_service:
                    auth_success, message = self.auth_service.authenticate_with_aws_sso()
                    
                    if not auth_success:
                        logger.warning(f"Auth service SSO authentication failed: {message}")
                        # Continue since we can still use AWS credentials directly
                
                # Emit authentication status
                self.auth_status_changed.emit(True, "aws_sso")
                
                return True
            else:
                logger.error("AWS SSO authentication failed")
                return False
        except Exception as e:
            logger.error(f"Error during AWS SSO authentication: {str(e)}")
            return False
    
    def authenticate_with_password(self, username: str, password: str, parent_widget=None) -> bool:
        """
        Authenticate with username and password.
        
        Args:
            username (str): Username for authentication
            password (str): Password for authentication
            parent_widget: Parent widget for dialogs
            
        Returns:
            bool: True if authentication was successful
        """
        if not self.auth_service:
            logger.error("Auth service not initialized")
            return False
        
        try:
            # Show authentication progress
            if parent_widget:
                QApplication.setOverrideCursor(Qt.WaitCursor)
            
            # Authenticate with the service
            success, message = self.auth_service.authenticate_with_password(username, password)
            
            # Restore cursor
            if parent_widget:
                QApplication.restoreOverrideCursor()
            
            if not success:
                if parent_widget:
                    QMessageBox.warning(
                        parent_widget,
                        "Authentication Failed",
                        f"Error: {message}"
                    )
                self.last_error = message
                return False
            
            # Authentication successful, update state
            self.is_authenticated = True
            
            # Initialize agent if needed
            self._initialize_agent()
            
            # Emit authentication status
            self.auth_status_changed.emit(True, "password")
            
            return True
        except Exception as e:
            # Restore cursor
            if parent_widget:
                QApplication.restoreOverrideCursor()
            
            logger.error(f"Error during password authentication: {str(e)}")
            self.last_error = str(e)
            
            if parent_widget:
                QMessageBox.critical(
                    parent_widget,
                    "Authentication Error",
                    f"An unexpected error occurred: {str(e)}"
                )
            
            return False
    
    def _initialize_agent(self):
        """Initialize the backend agent if necessary."""
        try:
            # Import and initialize Agent if needed
            if not self.agent:
                try:
                    from API.Backend import Agent
                    import API.CONSTANTS as CONSTANTS
                    
                    # Create agent with required parameters
                    self.agent = Agent(
                        s3=CONSTANTS.AWS_S3,
                        file_name=CONSTANTS.AWS_FILE
                    )
                    
                    # Set auth context if we have user info
                    if self.auth_service and self.auth_service.user_id:
                        user_id = self.auth_service.user_id
                        auth_type = self.auth_service.auth_type
                        client_ip = None
                        
                        # Try to get client IP from session manager
                        if hasattr(self.aws_sso_manager, 'auth_ip'):
                            client_ip = self.aws_sso_manager.auth_ip
                        
                        self.agent.set_auth_context(user_id, auth_type, client_ip)
                    
                    logger.info("Backend agent initialized successfully")
                    return True
                except ImportError:
                    logger.warning("Agent module not found, continuing without direct agent")
                    return False
                except Exception as e:
                    logger.error(f"Error initializing agent: {str(e)}")
                    return False
            return True
        except Exception as e:
            logger.error(f"Unexpected error in agent initialization: {str(e)}")
            return False
    
    def show_data_dialog(self, parent_widget=None, title="Your Guard Data"):
        """
        Show the modern data dialog with full CRUD functionality.
        
        Args:
            parent_widget: Parent widget for the dialog
            title (str): Dialog title
            
        Returns:
            bool: True if dialog was shown and closed successfully
        """
        if not self.is_authenticated:
            if parent_widget:
                QMessageBox.warning(
                    parent_widget,
                    "Not Authenticated",
                    "You are not authenticated. Please log in first."
                )
            return False
        
        try:
            # Import the modern data dialog
            from modern_data_management import ModernDataDialog
            
            # Create and configure the dialog
            dialog = ModernDataDialog(parent_widget, title, on_refresh=self.refresh_data)
            
            # Set up CRUD helper and services
            dialog.set_crud_helper(self.crud_helper, self.auth_service, self.agent)
            
            # Connect download button
            dialog.download_btn.clicked.connect(self.download_data)
            
            # Get initial data
            data = self.get_all_data()
            
            if data:
                dialog.set_data(data)
            
            # Show the dialog
            result = dialog.exec_()
            
            # Refresh the data if requested
            if hasattr(dialog, 'needs_refresh') and dialog.needs_refresh:
                self.refresh_data()
            
            return result == QDialog.Accepted
        except ImportError as e:
            logger.error(f"Failed to import modern data dialog: {str(e)}")
            if parent_widget:
                QMessageBox.critical(
                    parent_widget,
                    "Component Error",
                    f"Failed to load the data management component: {str(e)}"
                )
            return False
        except Exception as e:
            logger.error(f"Error showing data dialog: {str(e)}")
            if parent_widget:
                QMessageBox.critical(
                    parent_widget,
                    "Error",
                    f"An error occurred while showing the data: {str(e)}"
                )
            return False
    
    def get_all_data(self):
        """
        Get all data items.
        
        Returns:
            list: List of data items or None if error
        """
        try:
            # Try agent first if available
            if self.agent:
                try:
                    data = self.agent.get_all_data()
                    if data is not None:
                        return data
                except Exception as e:
                    logger.warning(f"Agent get_all_data error: {str(e)}")
            
            # Try auth service
            if self.auth_service:
                try:
                    # Check if method is async
                    import inspect
                    if inspect.iscoroutinefunction(self.auth_service.make_authenticated_request):
                        # Need to run in async context
                        loop = asyncio.new_event_loop()
                        try:
                            success, data = loop.run_until_complete(
                                self.auth_service.make_authenticated_request("GET", "pii")
                            )
                        finally:
                            loop.close()
                    else:
                        # Synchronous method
                        success, data = self.auth_service.make_authenticated_request("GET", "pii")
                    
                    if success and data:
                        return data
                    else:
                        logger.warning(f"Auth service data request failed: {data}")
                except Exception as e:
                    logger.warning(f"Auth service request error: {str(e)}")
            
            logger.error("Failed to get data using available methods")
            return None
        except Exception as e:
            logger.error(f"Unexpected error getting data: {str(e)}")
            return None
    
    def download_data(self):
        """
        Download data to Excel file.
        
        Returns:
            bool: True if download was successful
        """
        try:
            # Try agent first if available
            if self.agent:
                try:
                    success = self.agent.download_excel()
                    if success:
                        logger.info("Data downloaded successfully using agent")
                        return True
                except Exception as e:
                    logger.warning(f"Agent download error: {str(e)}")
            
            # Try to download using API
            if self.auth_service:
                try:
                    # This would require a specific download endpoint
                    # For now, just get the data and save it
                    data = self.get_all_data()
                    if data:
                        import pandas as pd
                        import os
                        
                        # Convert to DataFrame
                        df = pd.DataFrame(data)
                        
                        # Save to file
                        desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
                        file_path = os.path.join(desktop_path, "guard_data.xlsx")
                        
                        df.to_excel(file_path, index=False)
                        logger.info(f"Data downloaded to {file_path}")
                        return True
                except Exception as e:
                    logger.warning(f"Manual download error: {str(e)}")
            
            logger.error("Failed to download data using available methods")
            return False
        except Exception as e:
            logger.error(f"Unexpected error downloading data: {str(e)}")
            return False
    
    def refresh_data(self):
        """Refresh the data and emit refresh signal."""
        logger.info("Refreshing data")
        self.data_refreshed.emit()
    
    def check_status(self):
        """Check authentication status and update state."""
        # Check AWS SSO first
        if self.aws_sso_manager and hasattr(self.aws_sso_manager, 'is_session_valid'):
            if not self.aws_sso_manager.is_session_valid() and self.is_authenticated:
                logger.warning("AWS SSO session expired")
                self.is_authenticated = False
                self.auth_status_changed.emit(False, "aws_sso")
                return
        
        # Check auth service
        if self.auth_service and hasattr(self.auth_service, 'is_authenticated'):
            is_auth = self.auth_service.is_authenticated()
            if is_auth != self.is_authenticated:
                logger.info(f"Authentication status changed: {is_auth}")
                self.is_authenticated = is_auth
                auth_type = self.auth_service.auth_type if hasattr(self.auth_service, 'auth_type') else "unknown"
                self.auth_status_changed.emit(is_auth, auth_type)
    
    def handle_aws_auth_success(self, auth_type):
        """
        Handle successful AWS authentication.
        
        Args:
            auth_type (str): Authentication type
        """
        logger.info(f"AWS authentication successful: {auth_type}")
        self.is_authenticated = True
        self._initialize_agent()
        self.auth_status_changed.emit(True, auth_type)
    
    def handle_auth_failure(self, error_message):
        """
        Handle authentication failure.
        
        Args:
            error_message (str): Error message
        """
        logger.error(f"Authentication failed: {error_message}")
        self.last_error = error_message
        self.is_authenticated = False
        self.auth_status_changed.emit(False, "failed")
    
    def handle_session_expired(self):
        """Handle session expiration."""
        logger.warning("Session expired")
        self.is_authenticated = False
        self.auth_status_changed.emit(False, "expired")
    
    def logout(self):
        """
        Perform logout operations.
        
        Returns:
            bool: True if logout was successful
        """
        success = True
        
        # Logout from AWS SSO manager
        if self.aws_sso_manager:
            try:
                aws_success = self.aws_sso_manager.logout()
                if not aws_success:
                    logger.warning("AWS SSO logout failed")
                    success = False
            except Exception as e:
                logger.error(f"Error during AWS SSO logout: {str(e)}")
                success = False
        
        # Logout from auth service
        if self.auth_service:
            try:
                auth_success = self.auth_service.logout()
                if not auth_success:
                    logger.warning("Auth service logout failed")
                    success = False
            except Exception as e:
                logger.error(f"Error during auth service logout: {str(e)}")
                success = False
        
        # Reset agent
        self.agent = None
        
        # Update state
        self.is_authenticated = False
        self.auth_status_changed.emit(False, "logged_out")
        
        return success
    
    def get_session_info(self):
        """
        Get comprehensive session information.
        
        Returns:
            dict: Session information from all components
        """
        info = {
            "is_authenticated": self.is_authenticated,
            "last_error": self.last_error
        }
        
        # Get AWS SSO info
        if self.aws_sso_manager:
            try:
                aws_info = self.aws_sso_manager.get_session_info()
                info["aws_sso"] = aws_info
            except Exception as e:
                logger.error(f"Error getting AWS SSO info: {str(e)}")
                info["aws_sso_error"] = str(e)
        
        # Get auth service info
        if self.auth_service:
            try:
                if hasattr(self.auth_service, 'get_session_info'):
                    auth_info = self.auth_service.get_session_info()
                    info["auth_service"] = auth_info
                else:
                    info["auth_service"] = {
                        "user_id": self.auth_service.user_id if hasattr(self.auth_service, 'user_id') else None,
                        "auth_type": self.auth_service.auth_type if hasattr(self.auth_service, 'auth_type') else None,
                        "is_authenticated": self.auth_service.is_authenticated() if hasattr(self.auth_service, 'is_authenticated') else False,
                        "token_expiration": self.auth_service.token_expiration if hasattr(self.auth_service, 'token_expiration') else None
                    }
            except Exception as e:
                logger.error(f"Error getting auth service info: {str(e)}")
                info["auth_service_error"] = str(e)
        
        # Get agent info
        if self.agent:
            try:
                info["agent"] = {
                    "initialized": True
                }
                
                # Get additional info if available
                if hasattr(self.agent, 'get_encryption_context'):
                    try:
                        info["agent"]["encryption_context"] = self.agent.get_encryption_context()
                    except:
                        pass
            except Exception as e:
                logger.error(f"Error getting agent info: {str(e)}")
                info["agent_error"] = str(e)
        
        return info


# Main integration function for the application
def integrate_with_main_application(main_window, api_base_url):
    """
    Integrate the enhanced session management and UI components with the main application.
    
    Args:
        main_window: The main application window
        api_base_url: Base URL for the API
        
    Returns:
        GuardSessionIntegrator: The integrator instance
    """
    logger.info("Integrating session management with main application")
    
    # Create the integrator
    integrator = GuardSessionIntegrator(main_window)
    
    # Initialize components
    success = integrator.initialize_components(api_base_url)
    
    if not success:
        logger.error(f"Failed to initialize components: {integrator.last_error}")
        return None
    
    # Connect signals to main window if it has the appropriate slots
    if hasattr(main_window, 'handle_auth_status_changed'):
        integrator.auth_status_changed.connect(main_window.handle_auth_status_changed)
    
    if hasattr(main_window, 'handle_data_refreshed'):
        integrator.data_refreshed.connect(main_window.handle_data_refreshed)
    
    # Return the integrator for further use
    return integrator