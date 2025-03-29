"""
Stabilized Desktop application for secure PII data management with authentication.

This module provides a streamlined graphical user interface for managing PII
(Personally Identifiable Information) data with proper authentication, encryption,
and secure storage capabilities.
"""

# Standard library imports
import sys
import os
import logging
from logging.handlers import RotatingFileHandler

# Third-party imports
import pandas as pd
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QLabel, QTableWidget, QHeaderView, QTableWidgetItem,
    QLineEdit, QMessageBox, QInputDialog, QDialog, 
    QMenu, QTabWidget, QStatusBar,
    QProgressDialog, QFrame
)
from PyQt5.QtGui import QCursor
from PyQt5.QtCore import Qt, QTimer, QDateTime

# Application imports
import api.CONSTANTS as CONSTANTS
from UI.Desktop.session_manager import SessionManager
from UI.Desktop.auth_service import AuthenticationService
from UI.Desktop.api_client import APIClient
from UI.Desktop.modern_components import (
    ModernButton, ModernDataDialog, SessionStatusWidget, CRUDHelper
)

# Setup logging with rotation
handler = RotatingFileHandler('application.log', maxBytes=1000000, backupCount=3)
logging.basicConfig(handlers=[handler], level=logging.INFO)
logger = logging.getLogger('PIIWindow')


class PIIWindow(QMainWindow):
    """
    Enhanced main window for the PII data management application.
    
    This class handles the user interface with streamlined authentication,
    data display, and CRUD operations.
    """

    def __init__(self):
        """Initialize the main window and UI components."""
        super().__init__()
        self.setWindowTitle('GUARD Data')
        self.setGeometry(100, 100, 1000, 600)
        
        # Initialize variables
        self.modified = False
        self.auth_service = None
        self.api_client = None
        
        # Initialize logger
        self.logger = logging.getLogger('PIIWindow')
        self.logger.setLevel(logging.INFO)

        # Initialize session manager and auth service
        self.setup_session_manager()
        self.setup_auth_service()
        
        # Set up status bar
        self.setup_status_bar()
        
        # Set up UI
        self.setup_ui()
        
        # Show the window
        self.show()
        self.showMaximized()
        
        # Connect the close event to the cleanup function
        self.close_event = self.cleanup_on_exit

    def setup_ui(self):
        """Initialize and set up the UI components."""
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create tab widget for multiple tabs
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # Create PII Data tab
        self.setup_pii_tab()
        
        # Log initialization
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        self.update_log(timestamp, "Application initialized")

    def setup_pii_tab(self):
        """Set up the PII data management tab."""
        # Create tab widget and layout
        self.pii_tab = QWidget()
        pii_layout = QVBoxLayout(self.pii_tab)
        
        # Add session status widget if available
        if hasattr(self, 'session_manager'):
            self.session_status = SessionStatusWidget(self, self.session_manager)
            pii_layout.addWidget(self.session_status, alignment=Qt.AlignCenter)
        
        # Welcome text
        self.welcome_text = QLabel(f"Welcome to GUARD: {os.environ.get('USER', 'USER').upper()}", self.pii_tab)
        self.welcome_text.setStyleSheet("font-size: 15px; font-weight: bold;")
        self.welcome_text.setVisible(False)
        pii_layout.addWidget(self.welcome_text, alignment=Qt.AlignCenter)
        
        # Connect server button
        self.btn_connect_server = ModernButton('Connect to Server', self, primary=True)
        self.btn_connect_server.setToolTip('Click to connect to server')
        self.btn_connect_server.setShortcut('Ctrl+Q')
        self.btn_connect_server.clicked.connect(self.show_auth_options)
        pii_layout.addWidget(self.btn_connect_server, alignment=Qt.AlignCenter)
        
        # Data table
        self.data_table = self.create_table(columncount=1, hlabels=['Item Name'])
        self.data_table.itemSelectionChanged.connect(self.on_data_table_selection)
        pii_layout.addWidget(self.data_table)
        
        # Log table
        self.log_table = self.create_table(columncount=2, hlabels=['Timestamp', 'Action/Task Performed'])
        pii_layout.addWidget(self.log_table)
        
        # Button layout
        button_layout = QHBoxLayout()
        
        # Display data button
        self.btn_display_data = self.create_button(
            'Display Data',
            'Click to display data',
            'Ctrl+D',
            self.show_data_window,
            style="background-color: gray; color: black;"
        )
        button_layout.addWidget(self.btn_display_data)
        
        # Add entry button
        self.btn_add_entry = self.create_button(
            'Add New Entry',
            'Click to add a new entry',
            'Ctrl+N',
            self.add_new_entry
        )
        button_layout.addWidget(self.btn_add_entry)
        
        # Session info button (initially hidden)
        self.btn_session_info = QPushButton('Session Info', self)
        self.btn_session_info.setCursor(QCursor(Qt.PointingHandCursor))
        self.btn_session_info.setStyleSheet("background-color: #4682B4; color: white;")
        self.btn_session_info.clicked.connect(self.show_session_info)
        self.btn_session_info.setToolTip('View current session information')
        self.btn_session_info.setVisible(False)
        button_layout.addWidget(self.btn_session_info)
        
        button_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        pii_layout.addLayout(button_layout)
        
        # Add the PII tab to tab widget
        self.tab_widget.addTab(self.pii_tab, "PII Data Management")

    def create_table(self, columncount, hlabels):
        """
        Create and configure a table widget.
        
        Args:
            columncount (int): Number of columns
            hlabels (list): Column header labels
            
        Returns:
            QTableWidget: The configured table
        """
        table = QTableWidget(self)
        table.setColumnCount(columncount)
        table.setVisible(False)
        table.setHorizontalHeaderLabels(hlabels)
        table.horizontalHeader().setStretchLastSection(True)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.setAlternatingRowColors(True)
        table.setContextMenuPolicy(Qt.CustomContextMenu)
        table.customContextMenuRequested.connect(self.show_context_menu)
        return table

    def create_button(self, text, tooltip, shortcut, callback, visible=False, style="background-color: green; color: white;"):
        """
        Create and configure a button.
        
        Args:
            text (str): Button text
            tooltip (str): Tooltip text
            shortcut (str): Keyboard shortcut
            callback (function): Function to connect to
            visible (bool): Initial visibility
            style (str): CSS style
            
        Returns:
            QPushButton: The configured button
        """
        btn = QPushButton(text, self)
        btn.setVisible(visible)
        btn.setToolTip(tooltip)
        btn.setCursor(QCursor(Qt.PointingHandCursor))
        btn.setStyleSheet(style)
        btn.setShortcut(shortcut)
        btn.clicked.connect(callback)
        return btn

    def setup_session_manager(self):
        """Set up the session manager and connect signals."""
        # Create session manager with 1-hour session timeout
        self.session_manager = SessionManager(self, token_ttl=3600)
        
        # Connect signals
        self.session_manager.session_expired.connect(self.handle_session_expired)
        self.session_manager.token_refreshed.connect(self.handle_token_refreshed)
        self.session_manager.session_expiring_soon.connect(self.handle_session_expiring_soon)
        
        # Log initialization
        logger.info("Session manager initialized")

    def setup_auth_service(self):
        """Set up the authentication service."""
        # Create authentication service
        self.auth_service = AuthenticationService(self)
        
        # Connect it to the session manager
        if hasattr(self, 'session_manager'):
            self.auth_service.set_session_manager(self.session_manager)
        
        # Log initialization
        logger.info("Authentication service initialized")

    def setup_status_bar(self):
        """Set up status bar with session information."""
        # Create status bar
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        
        # Add session timer display
        self.session_timer_label = QLabel("Not logged in")
        self.statusBar.addPermanentWidget(self.session_timer_label)
        
        # Add session type indicator
        self.session_type_label = QLabel("")
        self.statusBar.addPermanentWidget(self.session_type_label)
        
        # Set up timer to update status bar
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_session_status)
        self.status_timer.start(10000)  # Update every 10 seconds

    def update_session_status(self):
        """Update the session status display in the status bar."""
        if not hasattr(self, 'session_manager') or not self.session_manager.is_authenticated:
            self.session_timer_label.setText("Not logged in")
            self.session_type_label.setText("")
            return
        
        # Get session info
        session_info = self.session_manager.get_session_info()
        
        # Update session time remaining
        if session_info["remaining_seconds"] is not None:
            self.session_timer_label.setText(f"Session: {session_info['remaining_formatted']} remaining")
            
            # Set color based on remaining time
            if session_info["remaining_seconds"] < 300:  # Less than 5 minutes
                self.session_timer_label.setStyleSheet("color: red; font-weight: bold")
            elif session_info["remaining_seconds"] < 600:  # Less than 10 minutes
                self.session_timer_label.setStyleSheet("color: orange; font-weight: bold")
            else:
                self.session_timer_label.setStyleSheet("")
        
        # Update auth type indicator
        auth_type = session_info["auth_type"]
        if auth_type == "aws_sso":
            self.session_type_label.setText("AWS SSO")
            self.session_type_label.setStyleSheet("color: blue; font-weight: bold")
        elif auth_type == "password":
            self.session_type_label.setText("Password")
            self.session_type_label.setStyleSheet("")

    def show_auth_options(self):
        """Show authentication options with only AWS SSO login."""
        self.btn_connect_server.setText('Authenticating...')
        self.btn_connect_server.setDisabled(True)
        
        # Create login options layout
        login_options_layout = QHBoxLayout()
        
        # SSO Login button
        btn_sso_login = QPushButton('AWS SSO Login', self)
        btn_sso_login.setCursor(QCursor(Qt.PointingHandCursor))
        btn_sso_login.setStyleSheet("background-color: #0066CC; color: white;")
        btn_sso_login.clicked.connect(self.authenticate_with_sso)
        login_options_layout.addWidget(btn_sso_login)
        
        # Add login options to layout
        if hasattr(self, 'login_options_container'):
            # Remove old container if it exists
            self.login_options_container.setParent(None)
            self.login_options_container.deleteLater()
        
        self.login_options_container = QWidget(self)
        self.login_options_container.setLayout(login_options_layout)
        self.centralWidget().layout().addWidget(self.login_options_container)

    def authenticate_with_sso(self):
        """Authenticate using AWS SSO with proper credential handling."""
        self.update_log(
            QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
            "Starting AWS SSO authentication..."
        )
        
        # Show a progress dialog
        progress = QProgressDialog("Authenticating with AWS SSO...", None, 0, 100, self)
        progress.setWindowTitle("AWS SSO Authentication")
        progress.setWindowModality(Qt.WindowModal)
        progress.setValue(10)
        progress.show()
        QApplication.processEvents()
        
        try:
            # First authenticate with session manager to get AWS credentials
            progress.setValue(20)
            progress.setLabelText("Connecting to AWS SSO...")
            QApplication.processEvents()
            
            sso_success = self.session_manager.authenticate_aws_sso(self)
            
            if not sso_success:
                progress.close()
                QMessageBox.warning(
                    self, 
                    "Authentication Error", 
                    "Failed to authenticate with AWS SSO. Please try again."
                )
                self.btn_connect_server.setText('Connect to Server')
                self.btn_connect_server.setDisabled(False)
                return
            
            # Verify we have credentials
            if not self.session_manager.credentials:
                progress.close()
                QMessageBox.warning(
                    self, 
                    "Authentication Error", 
                    "AWS SSO authentication succeeded but no credentials were obtained."
                )
                self.btn_connect_server.setText('Connect to Server')
                self.btn_connect_server.setDisabled(False)
                return
                
            # Log credential info (safely)
            credentials = self.session_manager.credentials
            access_key = credentials.get('AccessKeyId', '')
            has_secret = 'SecretAccessKey' in credentials
            has_token = 'SessionToken' in credentials
            
            self.update_log(
                QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
                f"Obtained AWS credentials: AccessKey={access_key[:4]}*** Secret={has_secret} Token={has_token}"
            )
            
            # Then authenticate with the API using these credentials
            progress.setValue(60)
            progress.setLabelText("Authenticating with server...")
            QApplication.processEvents()
            
            api_success, message = self.auth_service.authenticate_with_aws_sso()
            
            if not api_success:
                progress.close()
                QMessageBox.warning(self, "Authentication Error", f"API authentication failed: {message}")
                self.btn_connect_server.setText('Connect to Server')
                self.btn_connect_server.setDisabled(False)
                return
            
            # Setup API client
            self.setup_api_client()
            
            progress.setValue(90)
            progress.setLabelText("Loading data...")
            QApplication.processEvents()
            
            # Complete connection process
            self.connect_after_authentication()
            
            progress.setValue(100)
            progress.close()
            
            # Show success message
            self.update_log(
                QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
                "AWS SSO authentication successful"
            )
            
        except Exception as e:
            progress.close()
            logger.error(f"AWS SSO authentication error: {str(e)}")
            QMessageBox.critical(self, "Authentication Error", f"AWS SSO authentication failed: {str(e)}")
            self.btn_connect_server.setText('Connect to Server')
            self.btn_connect_server.setDisabled(False)

    def setup_api_client(self):
        """Set up the API client."""
        self.api_client = APIClient(
            base_url=CONSTANTS.API_BASE_URL,
            auth_service=self.auth_service
        )
        logger.info("API client initialized")

    def connect_after_authentication(self):
        """Complete the connection process after successful authentication."""
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        self.update_log(timestamp, "Authentication successful")
        
        # Update UI elements
        self.btn_connect_server.setVisible(False)
        self.welcome_text.setVisible(True)
        self.log_table.setVisible(True)
        self.data_table.setVisible(True)
        self.btn_display_data.setVisible(True)
        self.btn_add_entry.setVisible(True)
        self.btn_session_info.setVisible(True)
        
        # Create logout button
        self.create_logout_button()
        
        # Fetch initial data
        self.fetch_initial_data()
        
        # Update logs
        self.update_log(timestamp, "Connected to server")
        self.update_log(timestamp, "Display Data button activated")
        self.update_log(timestamp, "Add New Entry button activated")

    def create_logout_button(self):
        """Create and position the logout button."""
        # Create button container in the top right corner
        button_container = QWidget(self)
        button_layout = QHBoxLayout(button_container)
        button_layout.setContentsMargins(0, 0, 10, 0)  # Right margin of 10
        
        # Session info button
        self.btn_session_info.setParent(button_container)
        button_layout.addWidget(self.btn_session_info)
        
        # Logout button
        self.btn_logout = QPushButton('Logout', button_container)
        self.btn_logout.setCursor(QCursor(Qt.PointingHandCursor))
        self.btn_logout.clicked.connect(self.logout_user)
        self.btn_logout.setShortcut("Ctrl+W")
        self.btn_logout.setStyleSheet("background-color: orange; color: white;")
        self.btn_logout.setToolTip('Click to Logout')
        button_layout.addWidget(self.btn_logout)
        
        # Position button container in top right
        button_container.setGeometry(self.width() - 230, 10, 220, 50)
        button_container.show()

    def fetch_initial_data(self):
        """Fetch initial data from the server."""
        try:
            # Show a progress dialog
            progress = QProgressDialog("Fetching data...", None, 0, 100, self)
            progress.setWindowTitle("Loading Data")
            progress.setWindowModality(Qt.WindowModal)
            progress.setValue(10)
            progress.show()
            QApplication.processEvents()
            
            # Fetch data using API client
            progress.setValue(30)
            QApplication.processEvents()
            
            success, data = self.api_client.sync_get_pii_data()
            progress.setValue(70)
            QApplication.processEvents()
            
            if success:
                # Convert to DataFrame if needed
                if isinstance(data, list):
                    df = pd.DataFrame(data)
                else:
                    df = pd.DataFrame([data])
                
                # Populate the data table
                self.populate_data_table(df)
                
                progress.setValue(100)
                QApplication.processEvents()
                progress.close()
            else:
                progress.close()
                QMessageBox.warning(
                    self,
                    "Data Fetch Error",
                    f"Failed to fetch data: {data}"
                )
        except Exception as e:
            progress.close()
            logger.error(f"Error fetching initial data: {str(e)}")
            QMessageBox.warning(
                self,
                "Data Fetch Error",
                f"Error fetching data: {str(e)}"
            )

    def populate_data_table(self, data):
        """
        Populate the data table with categories.
        
        Args:
            data (DataFrame): Data to populate the table with
        """
        if 'Category' not in data.columns:
            QMessageBox.warning(
                self,
                "Data Error",
                "Category column missing in data"
            )
            return
        
        categories = data['Category'].unique()
        self.data_table.setRowCount(len(categories))
        for row, item in enumerate(categories):
            self.data_table.setItem(row, 0, QTableWidgetItem(item))

    def show_data_window(self):
        """Show data in a modern dialog window."""
        if not hasattr(self, 'auth_service') or not self.auth_service.is_authenticated():
            QMessageBox.warning(self, "Error", "Not connected to server.")
            return
        
        try:
            # Log the operation
            timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
            self.update_log(timestamp, "Opening data display window")
            
            # Create and show the modern data dialog
            data_dialog = ModernDataDialog(self, "Your GUARD Data", self.fetch_latest_data)
            
            # Set the CRUD helper and services
            data_dialog.set_crud_helper(
                CRUDHelper,
                auth_service=self.auth_service
            )
            
            # Get data
            success, data = self.api_client.sync_get_pii_data()
            
            if success:
                # Convert to list if needed
                if isinstance(data, pd.DataFrame):
                    data_list = data.to_dict(orient='records')
                elif not isinstance(data, list):
                    # Try to convert to list if it's not already one
                    try:
                        data_list = list(data)
                    except:
                        data_list = [data]
                else:
                    data_list = data
                
                # Set the data
                data_dialog.set_data(data_list)
                
                # Show the dialog
                data_dialog.exec_()
            else:
                QMessageBox.warning(self, "Data Error", f"Failed to fetch data: {data}")
                
        except Exception as e:
            logger.error(f"Error displaying data: {str(e)}")
            QMessageBox.critical(
                self,
                "Error",
                f"An error occurred when trying to display data: {str(e)}"
            )

    def fetch_latest_data(self):
        """Fetch the latest data and update any open dialogs."""
        try:
            # Get fresh data
            success, data = self.api_client.sync_get_pii_data()
            
            if success:
                # Convert to list format if needed
                if isinstance(data, pd.DataFrame):
                    data_list = data.to_dict(orient='records')
                elif not isinstance(data, list):
                    # Try to convert to list if it's not already one
                    try:
                        data_list = list(data)
                    except:
                        data_list = [data]
                else:
                    data_list = data
                
                # Find any open ModernDataDialog instances and update them
                for dialog in self.findChildren(ModernDataDialog):
                    dialog.set_data(data_list)
                
                # Log the refresh
                timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
                self.update_log(timestamp, "Data refreshed successfully")
            else:
                logger.warning(f"Error fetching data during refresh: {data}")
        except Exception as e:
            logger.error(f"Error refreshing data: {str(e)}")

    def add_new_entry(self):
        """Show dialog to add a new entry using the modern dialog."""
        if not hasattr(self, 'auth_service') or not self.auth_service.is_authenticated():
            QMessageBox.warning(self, "Error", "Not connected to server.")
            return
        
        try:
            # Log the operation
            timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
            self.update_log(timestamp, "Opening add new entry dialog")
            
            # Create and show the modern data dialog in "add" mode
            data_dialog = ModernDataDialog(self, "Add New Entry", self.fetch_latest_data)
            
            # Set the CRUD helper and services
            data_dialog.set_crud_helper(
                CRUDHelper,
                auth_service=self.auth_service
            )
            
            # Show the add dialog
            data_dialog.show_add_item_dialog()
            data_dialog.exec_()
                
        except Exception as e:
            logger.error(f"Error adding new entry: {str(e)}")
            QMessageBox.critical(
                self,
                "Error",
                f"An error occurred when trying to add a new entry: {str(e)}"
            )

    def on_data_table_selection(self):
        """Handle selection in the data table."""
        selected_items = self.data_table.selectedItems()
        if not selected_items:
            return
        
        selected_item_text = selected_items[0].text()
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        self.update_log(timestamp, f"Selected category: {selected_item_text}")
        
        try:
            # Get items for the selected category
            success, all_data = self.api_client.sync_get_pii_data()
            
            if not success:
                QMessageBox.warning(self, "Data Error", f"Failed to fetch data: {all_data}")
                return
            
            # Convert to list if needed
            if isinstance(all_data, pd.DataFrame):
                data_list = all_data.to_dict(orient='records')
            elif not isinstance(all_data, list):
                # Try to convert to list if it's not already one
                try:
                    data_list = list(all_data)
                except:
                    data_list = [all_data]
            else:
                data_list = all_data
            
            # Filter by selected category
            filtered_items = [item for item in data_list if item.get('Category') == selected_item_text]
            
            if not filtered_items:
                QMessageBox.information(self, "No Items", f"No items found for category: {selected_item_text}")
                return
            
            # Show data using the modern data dialog
            data_dialog = ModernDataDialog(self, f"Items in {selected_item_text}", self.fetch_latest_data)
            data_dialog.set_crud_helper(
                CRUDHelper,
                auth_service=self.auth_service
            )
            data_dialog.set_data(filtered_items)
            data_dialog.exec_()
            
        except Exception as e:
            logger.error(f"Error processing selection: {str(e)}")
            QMessageBox.warning(
                self,
                "Selection Error",
                f"Error processing selection: {str(e)}"
            )

    def show_context_menu(self, position):
        """
        Show context menu for data table.
        
        Args:
            position: Position for the menu
        """
        selected_items = self.data_table.selectedItems()
        if not selected_items:
            return
        
        menu = QMenu(self)
        
        # Add actions
        view_action = menu.addAction("View Items")
        refresh_action = menu.addAction("Refresh Data")
        
        # Show the menu
        action = menu.exec_(self.data_table.mapToGlobal(position))
        
        # Handle actions
        if action == view_action:
            self.on_data_table_selection()
        elif action == refresh_action:
            self.fetch_initial_data()

    def show_session_info(self):
        """Show current session information."""
        if not hasattr(self, 'session_manager') or not self.session_manager.is_authenticated:
            QMessageBox.information(
                self,
                "Session Info",
                "You are not currently logged in."
            )
            return
        
        # Get session info from both managers
        session_info = self.session_manager.get_session_info()
        api_info = self.auth_service.get_session_info() if hasattr(self, 'auth_service') else {}
        
        # Create message
        message = (
            f"Session Information:\n"
            f"User ID: {session_info['user_id']}\n"
            f"Authentication Type: {session_info['auth_type']}\n"
            f"Session Started: {session_info['auth_timestamp']}\n"
            f"Client IP: {session_info['auth_ip']}\n"
            f"Session Expires: {session_info['remaining_formatted']} from now\n"
            f"({session_info['expiration_time']})"
        )
        
        # Add API auth info if available
        if api_info:
            message += (
                f"\n\nAPI Authentication:\n"
                f"User ID: {api_info.get('user_id', 'N/A')}\n"
                f"Authentication Type: {api_info.get('auth_type', 'N/A')}\n"
                f"Token Expires: {api_info.get('token_expires_at', 'N/A')}"
            )
        
        QMessageBox.information(self, "Session Info", message)

    def logout_user(self):
        """Perform logout operations with proper cleanup."""
        try:
            # Check if actually logged in
            if not hasattr(self, 'auth_service') or not self.auth_service.is_authenticated():
                QMessageBox.information(self, "Logout", "You are not currently logged in.")
                return
            
            # Confirm logout
            reply = QMessageBox.question(
                self,
                "Confirm Logout",
                "Are you sure you want to log out?",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply != QMessageBox.Yes:
                return
            
            # Log logout
            timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
            self.update_log(timestamp, "Logging out...")
            
            # Perform logout operations
            if hasattr(self, 'auth_service'):
                self.auth_service.logout()
            
            if hasattr(self, 'session_manager'):
                self.session_manager.logout()
            
            # Reset UI to initial state
            self.reset_ui()
            
            # Log success
            self.update_log(timestamp, "Logged out successfully")
            
            # Show confirmation
            QMessageBox.information(self, "Logout", "You have been logged out successfully.")
            
        except Exception as e:
            logger.error(f"Error during logout: {str(e)}")
            QMessageBox.warning(
                self,
                "Logout Error",
                f"An error occurred during logout: {str(e)}"
            )
            
            # Force logout
            self.reset_ui()

    def reset_ui(self):
        """Reset the UI to initial state."""
        # Hide data components
        self.welcome_text.setVisible(False)
        self.data_table.setVisible(False)
        self.log_table.setVisible(False)
        
        # Reset buttons
        self.btn_connect_server.setText('Connect to Server')
        self.btn_connect_server.setDisabled(False)
        self.btn_connect_server.setVisible(True)
        self.btn_display_data.setVisible(False)
        self.btn_add_entry.setVisible(False)
        
        # Hide logout button if it exists
        if hasattr(self, 'btn_logout') and self.btn_logout:
            self.btn_logout.setVisible(False)
        
        # Hide session info button
        self.btn_session_info.setVisible(False)
        
        # Reset session status
        self.update_session_status()
        
        # Clear login options if present
        if hasattr(self, 'login_options_container'):
            self.login_options_container.setVisible(False)
        
        # Reset authentication state
        self.auth_service = AuthenticationService(self)
        if hasattr(self, 'session_manager'):
            self.auth_service.set_session_manager(self.session_manager)
        
        # Clear API client
        self.api_client = None

    def update_log(self, timestamp, message):
        """
        Update the log table with a new entry.
        
        Args:
            timestamp (str): Timestamp for the log entry
            message (str): Log message
        """
        # Log to file
        logger.info(f"{timestamp} - {message}")
        
        # Update UI if log table exists and is visible
        if hasattr(self, 'log_table') and self.log_table.isVisible():
            row_position = self.log_table.rowCount()
            self.log_table.insertRow(row_position)
            
            timestamp_item = QTableWidgetItem(timestamp)
            message_item = QTableWidgetItem(message)
            
            self.log_table.setItem(row_position, 0, timestamp_item)
            self.log_table.setItem(row_position, 1, message_item)
            
            # Scroll to the bottom
            self.log_table.scrollToBottom()

    def handle_session_expired(self):
        """Handle session expiration."""
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        self.update_log(timestamp, "Session expired")
        
        QMessageBox.warning(
            self,
            "Session Expired",
            "Your session has expired. Please log in again."
        )
        
        # Force logout
        self.logout_user()

    def handle_token_refreshed(self):
        """Handle token refresh event."""
        if not hasattr(self, 'session_manager'):
            return
        
        session_info = self.session_manager.get_session_info()
        
        # Log the refresh
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        self.update_log(
            timestamp,
            f"Session token refreshed. New expiration: {session_info['remaining_formatted']} from now"
        )
        
        # Update status display
        self.update_session_status()

    def handle_session_expiring_soon(self, minutes_remaining):
        """
        Handle notification that session is expiring soon.
        
        Args:
            minutes_remaining (int): Minutes until session expires
        """
        QMessageBox.information(
            self,
            "Session Expiring Soon",
            f"Your session will expire in {minutes_remaining} minute{'s' if minutes_remaining != 1 else ''}.\n"
            f"Please save your work. You will be logged out when the session expires."
        )

    def cleanup_on_exit(self, event=None):
        """
        Clean up resources when exiting the application.
        
        Args:
            event: Close event, if any
        """
        # Log application exit
        logger.info("Application exiting, performing cleanup")
        
        # Logout if authenticated
        if hasattr(self, 'auth_service') and self.auth_service.is_authenticated():
            try:
                self.auth_service.logout()
            except:
                pass
        
        # Stop timers
        if hasattr(self, 'status_timer') and self.status_timer:
            self.status_timer.stop()
        
        if event:
            event.accept()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PIIWindow()
    sys.exit(app.exec_())