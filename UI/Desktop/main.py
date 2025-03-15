#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Desktop application for secure PII data management with authentication.

This module provides a graphical user interface for managing PII (Personally
Identifiable Information) data with proper authentication, encryption,
and secure storage capabilities.
"""

# Standard library imports
import sys
import os
import time
import ast
import json
import logging
import subprocess
from logging.handlers import RotatingFileHandler

# Third-party imports
import pandas as pd
import requests
from PyQt5.QtWidgets import (
    QLineEdit, QMessageBox, QInputDialog, QMainWindow, QWidget,
    QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTableWidget,
    QHeaderView, QTableWidgetItem, QDialog, QScrollArea, QSizePolicy,
    QAbstractItemView, QApplication, QMenu, QAction, QTabWidget,
    QProgressBar, QStatusBar, QProgressDialog
)
from UI.Desktop.session_manager import SessionManager
from API.auth_service import EnhancedAuthService as AuthService
from PyQt5.QtGui import QIcon, QCursor, QGuiApplication
from PyQt5.QtCore import Qt, QTimer, QDateTime
from UI.Desktop.modern_components import ModernButton, SessionStatusWidget, ModernDataDialog, CRUDHelper, DataItemEditDialog

# Local application imports
from API.Backend import Agent
from API.youtube_download import YouTubeDownloaderWidget, integrate_youtube_downloader
from API.assistant import Assistant
import API.CONSTANTS as CONSTANTS

# Setup logging with rotation
handler = RotatingFileHandler(
    'application.log', maxBytes=1000000, backupCount=3)
logging.basicConfig(handlers=[handler], level=logging.INFO)

class CRUDHelper:
    """
    Helper class for consistent CRUD operations across the application.
    
    This class provides utility functions for extracting data from UI elements
    and performing CRUD operations with proper validation and error handling.
    """
    
    @staticmethod
    def extract_row_data(table_widget, row_index):
        """
        Extract all column data from a specific row in a table widget.
        
        Args:
            table_widget (QTableWidget): The table widget
            row_index (int): The row index to extract data from
            
        Returns:
            dict: A dictionary of column name: cell value pairs
        """
        row_data = {}
        
        # Check all columns in this row
        for col in range(table_widget.columnCount()):
            header = table_widget.horizontalHeaderItem(col)
            if not header:
                continue
                
            column_name = header.text()
            cell_item = table_widget.item(row_index, col)
            
            if not cell_item:
                continue
                
            # Store the cell value
            row_data[column_name] = cell_item.text()
            
        return row_data
    
    @staticmethod
    def validate_required_fields(data, required_fields, logger=None):
        """
        Validate that required fields exist in the data.
        
        Args:
            data (dict): The data to validate
            required_fields (list): List of field names that must exist
            logger (callable, optional): Logging function
            
        Returns:
            tuple: (is_valid, error_message)
        """
        if not isinstance(data, dict):
            error_msg = f"Invalid data type: {type(data).__name__}, expected dict"
            if logger:
                logger(error_msg)
            return False, error_msg
            
        missing_fields = [field for field in required_fields if field not in data or not data[field]]
        
        if missing_fields:
            error_msg = f"Missing required fields: {', '.join(missing_fields)}"
            if logger:
                logger(error_msg)
            return False, error_msg
            
        return True, ""
    
    @staticmethod
    def perform_operation(operation, data, agent=None, auth_service=None, auth_manager=None, logger=None):
        """
        Perform a CRUD operation using available services.
        
        This method tries different services in order of preference:
        1. Direct agent (if available)
        2. auth_service (if available)
        3. auth_manager (if available)
        
        Args:
            operation (str): The operation to perform ('create', 'read', 'update', 'delete')
            data (dict): The data to use for the operation
            agent (object, optional): Agent object with CRUD methods
            auth_service (object, optional): Authentication service
            auth_manager (object, optional): Authentication manager
            logger (callable, optional): Logging function
            
        Returns:
            tuple: (success, result_or_error_message)
        """
        if logger:
            logger(f"Performing {operation} operation")
            
        # Validate _id for update and delete operations
        if operation in ('update', 'delete'):
            valid, error_msg = CRUDHelper.validate_required_fields(data, ['_id'], logger)
            if not valid:
                return False, error_msg
        
        # Try agent first (most direct)
        if agent:
            try:
                if logger:
                    logger(f"Using agent.{operation}_one_data directly")
                    
                # Call the appropriate method based on operation
                if operation == 'create':
                    response = agent.insert_new_data(data)
                elif operation == 'read':
                    response = agent.get_all_data()
                elif operation == 'update':
                    response = agent.update_one_data(data)
                elif operation == 'delete':
                    response = agent.delete_one_data(data)
                else:
                    return False, f"Unknown operation: {operation}"
                    
                # Handle response
                if response is True or (isinstance(response, dict) and 'error' not in response):
                    if logger:
                        logger(f"{operation.capitalize()} operation successful")
                    return True, response
                elif isinstance(response, dict) and 'error' in response:
                    if logger:
                        logger(f"Agent {operation} error: {response['error']}")
                    # Continue to next method
                else:
                    if logger:
                        logger(f"Agent {operation} returned: {response}")
                    # Continue to next method
            except Exception as e:
                if logger:
                    logger(f"Agent {operation} error: {str(e)}")
                # Continue to next method
        
        # Try auth_service next
        if auth_service:
            try:
                if logger:
                    logger(f"Using auth_service for {operation} request")
                    
                # Map operation to HTTP method
                method_map = {
                    'create': 'POST',
                    'read': 'GET',
                    'update': 'PATCH',
                    'delete': 'DELETE'
                }
                
                # Make authenticated request
                success, response_data = auth_service.make_authenticated_request(
                    method=method_map[operation],
                    endpoint="pii",
                    data=data if operation != 'read' else None
                )
                
                if success:
                    if logger:
                        logger(f"Auth service {operation} successful")
                    return True, response_data
                else:
                    error_msg = response_data.get('error', str(response_data)) if isinstance(response_data, dict) else str(response_data)
                    if logger:
                        logger(f"Auth service {operation} failed: {error_msg}")
                    
                    # Only continue if we have auth_manager
                    if auth_manager:
                        # Continue to next method
                        pass
                    else:
                        return False, error_msg
            except Exception as e:
                if logger:
                    logger(f"Auth service {operation} error: {str(e)}")
                # Continue to next method if we have auth_manager
                if not auth_manager:
                    return False, str(e)
        
        # Try auth_manager as last authenticated option
        if auth_manager and auth_manager.token:
            try:
                if logger:
                    logger(f"Using auth_manager for {operation} request")
                    
                # Map operation to HTTP method
                method_map = {
                    'create': 'POST',
                    'read': 'GET',
                    'update': 'PATCH',
                    'delete': 'DELETE'
                }
                
                # Make authenticated request
                success, response_data = auth_manager.make_authenticated_request(
                    method=method_map[operation],
                    endpoint="pii",
                    data=data if operation != 'read' else None
                )
                
                if success:
                    if logger:
                        logger(f"Auth manager {operation} successful")
                    return True, response_data
                else:
                    error_msg = response_data.get('error', str(response_data)) if isinstance(response_data, dict) else str(response_data)
                    if logger:
                        logger(f"Auth manager {operation} failed: {error_msg}")
                    return False, error_msg
            except Exception as e:
                if logger:
                    logger(f"Auth manager {operation} error: {str(e)}")
                return False, str(e)
        
        # If we get here, all methods failed or weren't available
        return False, "No suitable authentication method available"


class PIIWindow(QMainWindow):
    """
    Main window for the PII data management application.

    This class handles the user interface for secure data management,
    including authentication, data display, and CRUD operations.
    """

    def __init__(self):
        """Initialize the main window and UI components."""
        super().__init__()
        self.setWindowTitle('Guard Data')
        self.setGeometry(100, 100, 1000, 600)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f8fbd9;
            }
            QPushButton {
                background-color: #4CAF50; 
                color: white; 
                font-size: 16px; 
                padding: 10px;
                border-radius: 5px;
            }
        """)
        # Initialize variables
        self.modified = False
        self.agent = None
        self.assistant = None
        self.option = None
        self.columns = None
        self.btn_logout = None
        self.table_widget = None
        self.pii_table_start_time = None
        self.time_update_start_time = None
        self.timer = None
        self.start_time = None
        
        # Initialize logger
        self.logger = logging.getLogger('PIIWindow')
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        
        # Initialize session manager and status bar
        self.setup_session_manager()
        self.setup_status_bar()
            
        # Set up UI
        self.ui_components()
        self.show()
        self.showMaximized()

        # Connect the close event to the cleanup function
        self.close_event = self.cleanup_on_exit
    
    def add_new_entry(self):
        """Show dialog to add a new entry."""
        # Create empty item template
        new_item = {
            "Category": "",
            "Type": "",
            "PII": str([{"Item Name": "", "Data": ""}])
        }
        
        # Create and show the edit dialog
        dialog = DataItemEditDialog(new_item, self)
        
        if dialog.exec_() == QDialog.Accepted:
            # Get the new item data
            item_data = dialog.get_updated_data()
            
            if item_data:
                # Remove ID field for new items
                if "_id" in item_data:
                    del item_data["_id"]
                
                # Use CRUDHelper to create the item
                success, response = CRUDHelper.perform_operation(
                    'create', 
                    item_data,
                    agent=self.agent if hasattr(self, 'agent') else None,
                    auth_service=self.auth_service if hasattr(self, 'auth_service') else None,
                    logger=lambda msg: self.update_log(
                        self.assistant.get_current_time() if hasattr(self, 'assistant') else 
                        QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
                        msg
                    )
                )
                
                if success:
                    QMessageBox.information(self, "Success", "Item added successfully")
                    
                    # Refresh data display if needed
                    if hasattr(self, 'data_table'):
                        self.populate_data_table(self.process_request())
                else:
                    QMessageBox.warning(self, "Error", f"Failed to add item: {response}")
                
    def ui_components(self):
        """Initialize and set up the UI components."""
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create main layout
        main_layout = QVBoxLayout(central_widget)
        
        # Create tab widget for multiple tabs
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # Create PII Data tab widget and layout
        self.pii_tab = QWidget()
        pii_layout = QVBoxLayout(self.pii_tab)
        
        if hasattr(self, 'session_manager'):
            self.session_status = SessionStatusWidget(self, self.session_manager)
            pii_layout.addWidget(self.session_status, alignment=Qt.AlignCenter)
        
        # Welcome text
        self.welcome_text = QLabel(
            f"Welcome to GUARD: {os.environ.get('USER', 'USER').upper()}",
            self.pii_tab
        )
        self.welcome_text.setStyleSheet("font-size: 15px; font-weight: bold;")
        self.welcome_text.setVisible(False)
        pii_layout.addWidget(self.welcome_text, alignment=Qt.AlignCenter)

        # Connect server button
        self.btn_connect_server = ModernButton(
            'Connect to Server',
            self,
            primary=True
        )
        self.btn_connect_server.setToolTip('Click to connect to server')
        self.btn_connect_server.setShortcut('Ctrl+Q')
        self.btn_connect_server.clicked.connect(self.show_password_input)
        self.btn_connect_server.setVisible(True)
        pii_layout.addWidget(self.btn_connect_server, alignment=Qt.AlignCenter)

        # Password input
        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.returnPressed.connect(
            self.authenticate_and_connect
        )
        self.password_input.setHidden(True)
        pii_layout.addWidget(self.password_input)

        # SSO Login button (initially hidden)
        self.btn_sso_login = QPushButton('AWS SSO Login', self)
        self.btn_sso_login.setCursor(QCursor(Qt.PointingHandCursor))
        self.btn_sso_login.setStyleSheet(
            "background-color: #0066CC; color: white;"
        )
        self.btn_sso_login.clicked.connect(self.authenticate_with_sso)
        self.btn_sso_login.setVisible(False)
        pii_layout.addWidget(self.btn_sso_login)

        # Data table
        self.data_table = self.set_table(columncount=1, hlabels=['Item Name'])
        self.data_table.itemSelectionChanged.connect(
            self.on_data_table_selection
        )
        pii_layout.addWidget(self.data_table)

        # Log table
        self.log_table = self.set_table(
            columncount=2,
            hlabels=['Timestamp', 'Action/Task Performed']
        )
        pii_layout.addWidget(self.log_table)

        # Button layout
        button_layout = QHBoxLayout()

        # Display data button
        self.btn_display_data = self.set_button(
            'Display Data',
            'Click to display data',
            'Ctrl+D',
            self.enhanced_show_data_window,
            style="background-color: gray; color: black;"
        )
        button_layout.addWidget(self.btn_display_data)

        # Add entry button
        self.btn_add_entry = self.set_button(
            'Add New Entry',
            'Click to add a new entry',
            'Ctrl+N',
            self.add_new_entry
        )
        button_layout.addWidget(self.btn_add_entry)

        # Session info button
        self.btn_session_info = QPushButton('Session Info', self)
        self.btn_session_info.setCursor(QCursor(Qt.PointingHandCursor))
        self.btn_session_info.setStyleSheet(
            "background-color: #4682B4; color: white;"
        )
        self.btn_session_info.clicked.connect(self.show_session_info)
        self.btn_session_info.setToolTip('View current session information')
        self.btn_session_info.setVisible(False)
        button_layout.addWidget(self.btn_session_info)
        
        button_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        pii_layout.addLayout(button_layout)
        
        # Add the PII tab to tab widget
        self.tab_widget.addTab(self.pii_tab, "PII Data Management")
        
        # Create and add YouTube Downloader tab
        if not hasattr(self, 'downloader_widget'):
            self.downloader_widget = YouTubeDownloaderWidget(
                parent=self,
                log_callback=lambda msg: self.update_log(
                    self.assistant.get_current_time() if hasattr(self, 'assistant') and self.assistant is not None else 
                    QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
                    f"YouTube Downloader: {msg}"
                ) if hasattr(self, 'update_log') else None
            )
        
        # Add YouTube downloader tab
        self.tab_widget.addTab(self.downloader_widget, "YouTube Downloader")
        
        # Set YouTube downloader as the default tab
        self.tab_widget.setCurrentIndex(1)
        
        # Log the initialization of the YouTube downloader
        QTimer.singleShot(500, lambda: self.log_youtube_init())

    def log_youtube_init(self):
        """Log the initialization of the YouTube downloader component."""
        try:
            if hasattr(self, 'update_log'):
                timestamp = self.assistant.get_current_time() if hasattr(self, 'assistant') and self.assistant is not None else \
                        QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
                self.update_log(timestamp, "YouTube Downloader component initialized")
        except Exception as e:
            print(f"Error logging YouTube init: {e}")

    # Modify the logout_user method to keep the YouTube downloader tab accessible
    def logout_user(self):
        """Perform logout operations."""
        if not self.assistant:
            QMessageBox.warning(self, "Logout Error",
                                "Not currently logged in.")
            return

        self.update_log(self.assistant.get_current_time(), 'Logging Out...')
        
        # Switch to YouTube downloader tab before logout
        if hasattr(self, 'tab_widget'):
            downloader_tab_index = self.tab_widget.indexOf(self.downloader_widget)
            self.tab_widget.setCurrentIndex(downloader_tab_index)
        
        self.ui_components()
        self.update_log(
            self.assistant.get_current_time(),
            'Logged Out Successfully.'
        )
        self.cleanup_on_exit()
        self.modified = False
        if self.btn_logout:
            self.btn_logout.setVisible(False)
        self.assistant.logout()
        self.agent = None
        
        # Switch to YouTube downloader tab again to ensure it's visible
        if hasattr(self, 'tab_widget') and hasattr(self, 'downloader_widget'):
            downloader_tab_index = self.tab_widget.indexOf(self.downloader_widget)
            self.tab_widget.setCurrentIndex(downloader_tab_index)       
    def set_button(self, btn_name, tooltip, shortcut, connect,
                   visible_true=False,
                   style="background-color: green; color: white;"):
        """
        Create and configure a button.

        Args:
            btn_name (str): Name of the button
            tooltip (str): Tooltip text
            shortcut (str): Keyboard shortcut
            connect (function): Function to connect to
            visible_true (bool): Initial visibility
            style (str): CSS style

        Returns:
            QPushButton: The configured button
        """
        btn = QPushButton(btn_name, self)
        btn.setVisible(visible_true)
        btn.setToolTip(tooltip)
        btn.setCursor(QCursor(Qt.PointingHandCursor))
        btn.setIcon(QIcon(f'{btn_name.lower()}.png'))
        btn.setStyleSheet(style)
        btn.setShortcut(shortcut)
        btn.clicked.connect(connect)
        return btn

    def set_table(self, columncount, hlabels):
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
        return table

    def logout_user(self):
        """Perform logout operations."""
        if not self.assistant:
            QMessageBox.warning(self, "Logout Error",
                                "Not currently logged in.")
            return

        self.update_log(self.assistant.get_current_time(), 'Logging Out...')
        self.ui_components()
        self.update_log(
            self.assistant.get_current_time(),
            'Logged Out Successfully.'
        )
        self.cleanup_on_exit()
        self.modified = False
        if self.btn_logout:
            self.btn_logout.setVisible(False)
        self.assistant.logout()
        self.agent = None

    def add_new_entry(self):
        """Show dialog to add a new entry."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Add New Entry")
        main_layout = QVBoxLayout(dialog)

        # Category input
        category_label = QLabel("Category:", dialog)
        category_input = QLineEdit(dialog)
        main_layout.addWidget(category_label)
        main_layout.addWidget(category_input)

        # Type input
        type_label = QLabel("Type:", dialog)
        type_input = QLineEdit(dialog)
        main_layout.addWidget(type_label)
        main_layout.addWidget(type_input)

        # Your Guard section
        pii_label = QLabel("Your Guard:", dialog)
        main_layout.addWidget(pii_label)

        pii_layout = QVBoxLayout()
        pii_items = []

        def add_pii_item(default_name='', default_data=''):
            """Add a new PII item to the dialog."""
            item_layout = QHBoxLayout()

            item_name_input = QLineEdit(dialog)
            if default_name:
                item_name_input.setText(default_name)
            item_data_input = QLineEdit(dialog)
            if default_data:
                item_data_input.setText(default_data)

            item_layout.addWidget(QLabel("Item Name:", dialog))
            item_layout.addWidget(item_name_input)
            item_layout.addWidget(QLabel("Data:", dialog))
            item_layout.addWidget(item_data_input)

            remove_button = QPushButton("-", dialog)
            remove_button.setFixedSize(35, 25)
            remove_button.clicked.connect(
                lambda: remove_pii_item(
                    item_layout, item_name_input, item_data_input)
            )
            item_layout.addWidget(remove_button)

            # Increase the font size for better visibility
            font = remove_button.font()
            font.setPointSize(5)  # Adjust the font size as needed
            remove_button.setFont(font)

            pii_layout.addLayout(item_layout)
            pii_items.append((item_name_input, item_data_input))

        def remove_pii_item(item_layout, item_name_input, item_data_input):
            """Remove a PII item from the dialog."""
            for i in reversed(range(item_layout.count())):
                widget = item_layout.itemAt(i).widget()
                if widget is not None:
                    widget.deleteLater()
            pii_layout.removeItem(item_layout)
            pii_items.remove((item_name_input, item_data_input))

        # Add default Guard Data item
        add_pii_item()

        # Button to add new Guard Data items
        add_button = QPushButton("+", dialog)
        add_button.setFixedSize(35, 30)

        # Increase the font size for better visibility
        font = add_button.font()
        font.setPointSize(5)  # Adjust the font size as needed
        add_button.setFont(font)

        add_button.clicked.connect(add_pii_item)
        main_layout.addWidget(add_button)  # Corrected to use main_layout
        main_layout.addLayout(pii_layout)

        # OK and Cancel buttons
        button_layout = QHBoxLayout()
        ok_button = QPushButton("OK", dialog)
        cancel_button = QPushButton("Cancel", dialog)
        button_layout.addWidget(ok_button)
        button_layout.addWidget(cancel_button)
        main_layout.addLayout(button_layout)

        def get_pii_data():
            """Get PII data from input fields."""
            pii_list = []
            for name_input, data_input in pii_items:
                name = name_input.text()
                data = data_input.text()
                if name and data:
                    pii_list.append({"Item Name": name, "Data": data})
            return pii_list

        def handle_ok():
            """Handle OK button click."""
            category = category_input.text().strip()
            type_ = type_input.text().strip()
            pii_data = get_pii_data()

            error_messages = []

            if not category:
                error_messages.append("Category is required.")
            if not type_:
                error_messages.append("Type is required.")
            for i, (name_input, data_input) in enumerate(pii_items):
                name = name_input.text().strip()
                data = data_input.text().strip()
                if not name or not data:
                    error_messages.append(
                        f"Guard's Item {i+1} requires both 'Item Name' and 'Data'."
                    )

            if error_messages:
                QMessageBox.warning(
                    dialog, "Validation Errors", "\n".join(error_messages)
                )
            else:
                self.insert_to_db(dialog, category, type_, pii_data)

        ok_button.clicked.connect(handle_ok)
        cancel_button.clicked.connect(dialog.reject)

        dialog.exec_()

    def process_request(self):
        """Process API request to get data with authentication."""
        try:
            # Check for auth_service first (preferred method)
            if hasattr(self, 'auth_service'):
                self.update_log(
                    self.assistant.get_current_time() if hasattr(self, 'assistant') else
                    QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
                    "Using auth_service for API request"
                )
                
                # Import the APIClient if not already available
                from UI.Desktop.api_client import APIClient
                
                # Create API client if it doesn't exist
                if not hasattr(self, 'api_client'):
                    self.api_client = APIClient(
                        base_url=CONSTANTS.API_BASE_URL,
                        auth_service=self.auth_service
                    )
                
                # Use synchronous method to fetch data
                success, data = self.api_client.sync_get_pii_data()
                
                if not success:
                    # Handle different error response formats
                    if isinstance(data, dict) and 'error' in data:
                        error_msg = data['error']
                    elif isinstance(data, str):
                        # Handle string responses from the API
                        error_msg = data
                    else:
                        error_msg = str(data)
                        
                    QMessageBox.warning(self, "Error", f"Failed to fetch data: {error_msg}")
                    return None
                
                # Handle different successful response formats
                if isinstance(data, list):
                    return pd.DataFrame(data)
                elif isinstance(data, str):
                    # Try to parse string response as JSON
                    self.update_log(
                        self.assistant.get_current_time() if hasattr(self, 'assistant') else
                        QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
                        "Received string response, attempting to parse as JSON"
                    )
                    try:
                        import json
                        parsed_data = json.loads(data)
                        if isinstance(parsed_data, list):
                            return pd.DataFrame(parsed_data)
                        else:
                            return pd.DataFrame([parsed_data])
                    except json.JSONDecodeError:
                        # If not valid JSON, display in a single row dataframe
                        QMessageBox.warning(self, "Data Format Warning", 
                            "Received unexpected string response from server. Displaying as raw data.")
                        return pd.DataFrame([{"Raw Response": data}])
                else:
                    # For any other type, convert to DataFrame if possible
                    try:
                        return pd.DataFrame(data)
                    except:
                        QMessageBox.warning(self, "Data Format Error", 
                            f"Received unexpected data type: {type(data)}. Cannot display.")
                        return None
                    
            # Fall back to auth_manager
            elif hasattr(self, 'auth_manager') and self.auth_manager.token:
                self.update_log(
                    self.assistant.get_current_time() if hasattr(self, 'assistant') else
                    QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
                    "Using auth_manager for API request"
                )
                
                # Make authenticated request
                success, data = self.auth_manager.make_authenticated_request(
                    method="GET",
                    endpoint="pii"
                )
                
                if not success:
                    if isinstance(data, dict) and 'error' in data:
                        error_msg = data['error']
                    elif isinstance(data, str):
                        error_msg = data
                    else:
                        error_msg = str(data)
                    QMessageBox.warning(self, "Error", f"Failed to fetch data: {error_msg}")
                    return None
                    
                # Handle different response formats
                if isinstance(data, list):
                    return pd.DataFrame(data)
                elif isinstance(data, str):
                    # Try to parse as JSON
                    try:
                        import json
                        parsed_data = json.loads(data)
                        if isinstance(parsed_data, list):
                            return pd.DataFrame(parsed_data)
                        else:
                            return pd.DataFrame([parsed_data])
                    except:
                        return pd.DataFrame([{"Raw Response": data}])
                else:
                    try:
                        return pd.DataFrame(data)
                    except:
                        QMessageBox.warning(self, "Data Format Error", 
                            f"Received unexpected data type: {type(data)}. Cannot display.")
                        return None
                    
            # Last resort: try to get data directly from agent
            elif hasattr(self, 'agent') and self.agent:
                self.update_log(
                    self.assistant.get_current_time() if hasattr(self, 'assistant') else
                    QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
                    "Getting data directly from agent"
                )
                
                data = self.agent.get_all_data()
                
                # Convert to DataFrame if needed
                if isinstance(data, list):
                    return pd.DataFrame(data)
                elif isinstance(data, str):
                    # Try to parse as JSON
                    try:
                        import json
                        parsed_data = json.loads(data)
                        if isinstance(parsed_data, list):
                            return pd.DataFrame(parsed_data)
                        else:
                            return pd.DataFrame([parsed_data])
                    except:
                        return pd.DataFrame([{"Raw Response": data}])
                else:
                    try:
                        return pd.DataFrame(data)
                    except:
                        QMessageBox.warning(self, "Data Format Error", 
                            f"Received unexpected data type: {type(data)}. Cannot display.")
                        return None
                    
            else:
                QMessageBox.warning(self, "Error", "Not authenticated. Please connect first.")
                return None
                    
        except Exception as e:
            self.update_log(
                self.assistant.get_current_time() if hasattr(self, 'assistant') else
                QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
                f"Error fetching data: {str(e)}"
            )
            QMessageBox.warning(self, "Error", f"Failed to fetch data: {str(e)}")
            return None

    def insert_to_db(self, dialog, category, type_, pii):
        """
        Insert new entry to the database with authentication.

        Args:
            dialog (QDialog): The parent dialog
            category (str): Category for the new entry
            type_ (str): Type for the new entry
            pii (list): List of PII data items
        """
        try:
            if not hasattr(self, 'auth_service'):
                QMessageBox.warning(
                    self,
                    "Error",
                    "Not authenticated. Please connect to the server first."
                )
                return
                
            new_entry = {
                "Category": category,
                "Type": type_,
                "PII": str(pii)
            }
            
            success, response = self.auth_service.make_authenticated_request(
                method="POST",
                endpoint="pii",
                data=new_entry
            )
            
            if success:
                QMessageBox.information(
                    self,
                    "Insertion Successful",
                    "New entry has been inserted successfully!"
                )
                new_entry.update({'PII': 'Hidden'})
                self.update_log(
                    self.assistant.get_current_time(),
                    f"Inserted new entry: {new_entry}"
                )
                dialog.accept()
                data = self.process_request()
                if data is not None:
                    self.populate_data_table(data)
            else:
                QMessageBox.warning(
                    self,
                    "Insertion Failed",
                    f"Failed to insert new entry: {response}"
                )
        except Exception as e:
            QMessageBox.warning(
                self,
                "Invalid Input",
                f"Please check the Error Below.\n\n{str(e)}"
            )

    def download_pii(self):
        """Download and decrypt PII data."""
        if not self.agent:
            QMessageBox.warning(self, "Error", "Not connected to server.")
            return

        self.update_log(
            self.assistant.get_current_time(),
            "Guard Data Download Attempted"
        )
        pre_download_time_stamp = time.time()
        
        # Try to download using authenticated methods first
        try:
            # Try auth_service first
            if hasattr(self, 'auth_service'):
                self.update_log(
                    self.assistant.get_current_time(),
                    "Downloading data using auth_service"
                )
                
                # Trigger Excel download via API endpoint
                success, result = self.auth_service.make_authenticated_request(
                    method="GET",
                    endpoint="pii/download"  # Assuming you have a download endpoint
                )
                
                if success:
                    # Handle successful download
                    download_time = time.time() - pre_download_time_stamp
                    self.update_log(
                        self.assistant.get_current_time(),
                        "Guard Data Download Time: %.2f Seconds" % download_time
                    )
                    self.update_log(
                        self.assistant.get_current_time(),
                        "Guard Data Download Function Response: Success"
                    )
                    QMessageBox.information(
                        self,
                        "Download Complete",
                        "Data downloaded and decrypted successfully!"
                    )
                    return
                else:
                    # Auth service method failed, continue to fallback methods
                    self.update_log(
                        self.assistant.get_current_time(),
                        f"Auth service download failed, falling back to agent method: {result}"
                    )
        except Exception as e:
            # Log error but continue to fallback method
            self.update_log(
                self.assistant.get_current_time(),
                f"Auth service download error: {str(e)}, falling back to agent method"
            )
        
        # If we get here, try the agent's native download method
        try:
            response = self.agent.download_excel()
            download_time = time.time() - pre_download_time_stamp
            self.update_log(
                self.assistant.get_current_time(),
                "Guard Data Download Time: %.2f Seconds" % download_time
            )
            self.update_log(
                self.assistant.get_current_time(),
                "Guard Data Download Function Response: " + str(response)
            )
            if response:
                QMessageBox.information(
                    self,
                    "Download Complete",
                    "Data downloaded and decrypted successfully!"
                )
            else:
                QMessageBox.warning(
                    self,
                    "Download Failed",
                    "Failed to download data!"
                )
        except Exception as e:
            download_time = time.time() - pre_download_time_stamp
            self.update_log(
                self.assistant.get_current_time(),
                "Guard Data Download Time: %.2f Seconds (Error)" % download_time
            )
            self.update_log(
                self.assistant.get_current_time(),
                f"Guard Data Download Error: {str(e)}"
            )
            QMessageBox.critical(
                self,
                "Download Error",
                f"An error occurred during download: {str(e)}"
            )

    def show_password_input(self):
        """Show password input and login options for authentication."""
        self.btn_connect_server.setText('Authenticating...')
        self.btn_connect_server.setDisabled(True)
        self.btn_connect_server.setStyleSheet(
            "background-color: gray; color: white;"
        )
        self.password_input.setHidden(False)  # Make password input visible
        
        # Create login options layout
        login_options_layout = QHBoxLayout()
        
        # SSO Login button
        self.btn_sso_login = QPushButton('AWS SSO Login', self)
        self.btn_sso_login.setCursor(QCursor(Qt.PointingHandCursor))
        self.btn_sso_login.setStyleSheet(
            "background-color: #0066CC; color: white;"
        )
        self.btn_sso_login.clicked.connect(self.authenticate_with_sso)
        login_options_layout.addWidget(self.btn_sso_login)
        
        # Direct Login button
        self.btn_direct_login = QPushButton('Direct Login', self)
        self.btn_direct_login.setCursor(QCursor(Qt.PointingHandCursor))
        self.btn_direct_login.setStyleSheet(
            "background-color: #4CAF50; color: white;"
        )
        self.btn_direct_login.clicked.connect(self.direct_authenticate)
        login_options_layout.addWidget(self.btn_direct_login)
        
        # Add login options to layout
        if hasattr(self, 'login_options_container'):
            # Remove old container if it exists
            self.login_options_container.setParent(None)
            self.login_options_container.deleteLater()
        
        self.login_options_container = QWidget(self)
        self.login_options_container.setLayout(login_options_layout)
        self.centralWidget().layout().addWidget(self.login_options_container)
        
        self.password_input.setFocus()
        self.btn_connect_server.clicked.disconnect(self.show_password_input)
        self.btn_connect_server.clicked.connect(self.authenticate_and_connect)

    def direct_authenticate(self):
        """Authenticate directly using password without attempting AWS SSO."""
        username = os.environ.get('USER', 'admin')  # Default to 'admin' if USER not set
        password = self.password_input.text()
        
        if not password:
            QMessageBox.warning(
                self,
                "Authentication Error",
                "Please enter a password."
            )
            return
        
        try:
            # Import the authentication solution
            from API.complete_auth_solution import AuthService
            
            # Initialize the auth service
            self.auth_service = AuthService(CONSTANTS.API_BASE_URL)
            
            # Display authenticating message
            if hasattr(self, 'btn_direct_login'):
                self.btn_direct_login.setText('Authenticating...')
                self.btn_direct_login.setDisabled(True)
            
            # Log the authentication attempt
            logging.info(f"Attempting direct authentication for user: {username}")
            
            # Authenticate with the service
            success, message = self.auth_service.authenticate(username, password)
            
            if not success:
                QMessageBox.warning(
                    self,
                    "Authentication Failed",
                    f"Error: {message}"
                )
                self.password_input.clear()
                if hasattr(self, 'btn_direct_login'):
                    self.btn_direct_login.setText('Direct Login')
                    self.btn_direct_login.setDisabled(False)
                return
            
            # Authentication successful
            self.password_input.clear()
            
            # Create agent with session token
            self.agent = Agent(
                s3=CONSTANTS.AWS_S3,
                file_name=CONSTANTS.AWS_FILE
            )
            self.assistant = Assistant(CONSTANTS.AWS_S3)
            
            # Complete connection process
            self.connect_after_authentication()
            
        except Exception as e:
            logging.error(f"Direct authentication error: {e}")
            QMessageBox.critical(
                self,
                "Authentication Error",
                f"An unexpected error occurred: {str(e)}"
            )
            if hasattr(self, 'btn_direct_login'):
                self.btn_direct_login.setText('Direct Login')
                self.btn_direct_login.setDisabled(False)

    def handle_data_response(self, response):
        """
        Handle API response and parse data.

        Args:
            response: API response object

        Returns:
            pd.DataFrame or None: Parsed data or None if error
        """
        if response.status_code != 200:
            raise ValueError(
                f"Error response from server. Status code: {response.status_code}"
            )

        response_data = response.json()
        data_frame = pd.DataFrame(response_data)
        self.columns = data_frame.columns
        self.update_log(
            self.assistant.get_current_time(),
            'Guard Data Displaying...'
        )
        return data_frame

    def populate_table_widget(self, data_frame):
        """
        Populate the table widget with data from DataFrame.

        Args:
            data_frame (pd.DataFrame): Data to display
        """
        num_rows, num_columns = data_frame.shape
        self.table_widget.setRowCount(num_rows)
        self.table_widget.setColumnCount(num_columns)
        self.table_widget.setHorizontalHeaderLabels(
            data_frame.columns.tolist()
        )
        self.table_widget.setEditTriggers(
            QAbstractItemView.NoEditTriggers
        )

        for row in range(num_rows):
            for col in range(num_columns):
                value = data_frame.iat[row, col]

                # Check if the column is 'PII' and contains a list of dictionaries
                if data_frame.columns[col] == 'PII' and isinstance(value, str):
                    try:
                        pii_list = ast.literal_eval(value)
                        if (isinstance(pii_list, list) and
                                all(isinstance(d, dict) for d in pii_list)):
                            formatted_value = '\n'.join(
                                f"{d['Item Name']} - {str(d['Data'])}"
                                for d in pii_list
                                if 'Item Name' in d and 'Data' in d
                            )
                            item = QTableWidgetItem(formatted_value)
                        else:
                            item = QTableWidgetItem(str(value))
                    except (ValueError, SyntaxError):
                        item = QTableWidgetItem(str(value))
                else:
                    item = QTableWidgetItem(str(value))

                self.table_widget.setItem(row, col, item)

    def configure_table_widget(self):
        """Configure table widget properties and appearance."""
        self.table_widget.resizeColumnsToContents()
        self.table_widget.resizeRowsToContents()
        self.table_widget.setSortingEnabled(True)
        self.table_widget.sortByColumn(0, Qt.AscendingOrder)
        self.table_widget.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table_widget.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table_widget.horizontalHeader().setStretchLastSection(True)
        self.table_widget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_widget.verticalHeader().setVisible(False)
        self.table_widget.setAlternatingRowColors(True)
        self.table_widget.setStyleSheet("QTableWidget::item { padding: 5px; }")

    def fetch_latest_data(self):
        """Fetch the latest data and update the dialog."""
        try:
            # Get fresh data 
            data = self.process_request()
            
            # Find any open ModernDataDialog instances and update them
            for dialog in self.findChildren(ModernDataDialog):
                dialog.set_data(data)
                
            # Log the refresh
            self.update_log(
                self.assistant.get_current_time() if hasattr(self, 'assistant') else 
                QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
                "Data refreshed successfully"
            )
        except Exception as e:
            self.update_log(
                self.assistant.get_current_time() if hasattr(self, 'assistant') else 
                QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
                f"Error refreshing data: {str(e)}"
            )
        
    def enhanced_show_data_window(self):
        """Show enhanced data dialog with CRUD capabilities and error handling."""
        if not hasattr(self, 'assistant') or not self.assistant:
            QMessageBox.warning(self, "Error", "Not connected to server.")
            return

        try:
            # Log the operation
            self.update_log(
                self.assistant.get_current_time() if hasattr(self, 'assistant') else 
                QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
                "Opening data display window"
            )
            
            # Check if we have an API client, create one if not
            if not hasattr(self, 'api_client') or self.api_client is None:
                from UI.Desktop.api_client import APIClient
                self.api_client = APIClient(
                    base_url=CONSTANTS.API_BASE_URL,
                    auth_service=self.auth_service if hasattr(self, 'auth_service') else None
                )
                
                # Log client creation
                self.update_log(
                    self.assistant.get_current_time() if hasattr(self, 'assistant') else 
                    QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
                    "Created API client for data operations"
                )
            
            # Fetch data first to check if we can connect
            self.update_log(
                self.assistant.get_current_time() if hasattr(self, 'assistant') else 
                QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
                "Pre-fetching data to verify connection"
            )
            
            try:
                # Use QProgressDialog instead for better control
                progress = QProgressDialog("Connecting to server and fetching data...", "Cancel", 0, 100, self)
                progress.setWindowTitle("Fetching Data")
                progress.setWindowModality(Qt.WindowModal)
                progress.setMinimumDuration(0)  # Show immediately
                progress.setValue(10)
                progress.show()
                QApplication.processEvents()  # Keep UI responsive
                
                # Attempt to get data
                progress.setValue(30)
                QApplication.processEvents()
                success, data = self.api_client.sync_get_pii_data()
                
                # Ensure progress dialog is closed
                progress.setValue(100)
                progress.close()
                progress = None  # Explicitly release the reference
                
                if not success:
                    error_msg = data.get('error', str(data)) if isinstance(data, dict) else str(data)
                    raise ValueError(f"Failed to fetch data: {error_msg}")
                
            except Exception as e:
                self.update_log(
                    self.assistant.get_current_time() if hasattr(self, 'assistant') else 
                    QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
                    f"Error fetching data: {str(e)}"
                )
                
                # Try direct agent access as fallback
                if hasattr(self, 'agent') and self.agent:
                    self.update_log(
                        self.assistant.get_current_time() if hasattr(self, 'assistant') else 
                        QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
                        "Falling back to direct agent access"
                    )
                    data = self.agent.get_all_data()
                    if not data:
                        raise ValueError("Could not fetch data from any source")
                else:
                    QMessageBox.critical(self, "Connection Error", f"Failed to fetch data: {str(e)}")
                    return
            
            # Create and show the enhanced data dialog
            try:
                # Try to import the enhanced dialog
                from UI.Desktop.enhanced_data_dialog import EnhancedDataDialog
                
                data_dialog = EnhancedDataDialog(
                    self,
                    api_client=self.api_client,
                    auth_service=self.auth_service if hasattr(self, 'auth_service') else None,
                    agent=self.agent if hasattr(self, 'agent') else None
                )
                
                # Connect download button to download function
                data_dialog.download_btn.clicked.connect(self.download_pii)
                
                # Show the dialog
                data_dialog.exec_()
                
            except ImportError:
                # Fall back to modern_components dialog if enhanced dialog is not available
                self.update_log(
                    self.assistant.get_current_time() if hasattr(self, 'assistant') else 
                    QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
                    "Enhanced dialog not available, using ModernDataDialog instead"
                )
                
                from UI.Desktop.modern_components import ModernDataDialog, CRUDHelper
                
                # Create and show the modern data dialog
                data_dialog = ModernDataDialog(self, "Your Guard Data", self.fetch_latest_data)
                
                # Set the CRUD helper and services
                data_dialog.set_crud_helper(
                    CRUDHelper,  # The helper class itself
                    auth_service=self.auth_service if hasattr(self, 'auth_service') else None,
                    agent=self.agent if hasattr(self, 'agent') else None
                )
                
                # Set the data (convert to list if needed)
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
                    
                data_dialog.set_data(data_list)
                
                # Connect download button to download function
                data_dialog.download_btn.clicked.connect(self.download_pii)
                
                # Show the dialog
                data_dialog.exec_()
                
        except Exception as e:
            self.update_log(
                self.assistant.get_current_time() if hasattr(self, 'assistant') else 
                QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
                f'Error displaying data: {str(e)}'
            )
            
            # Show detailed error message
            import traceback
            error_details = traceback.format_exc()
            self.update_log(
                self.assistant.get_current_time() if hasattr(self, 'assistant') else 
                QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
                f'Error details: {error_details}'
            )
            
            QMessageBox.critical(
                self,
                "Error",
                f"An unexpected error occurred when trying to display data:\n\n{str(e)}\n\n"
                f"Please check the application logs for more details."
            )
    def open_context_menu(self, position):
        """
        Show context menu for table items.

        Args:
            position: Position for the menu
        """
        try:
            # Check if there are selected items
            if not self.table_widget.selectedItems():
                return
                
            # Create context menu
            menu = QMenu()

            # Add Copy action
            copy_action = QAction('Copy', self)
            copy_action.triggered.connect(self.copy_selected_row)
            menu.addAction(copy_action)

            # Add Edit action
            edit_action = QAction('Edit', self)
            edit_action.triggered.connect(self.edit_selected_row)
            menu.addAction(edit_action)

            # Add Delete action
            delete_action = QAction('Delete', self)
            delete_action.triggered.connect(self.delete_item)
            menu.addAction(delete_action)

            # Show the menu at the cursor position
            menu.exec_(self.table_widget.viewport().mapToGlobal(position))
            
        except Exception as e:
            self.update_log(
                self.assistant.get_current_time(),
                f"Error showing context menu: {str(e)}"
            )

    def edit_selected_row(self):
        """Edit the selected row data."""
        if not hasattr(self, 'table_widget') or not self.table_widget:
            return

        selected_items = self.table_widget.selectedItems()
        if not selected_items:
            return

        # Log which row we're editing
        row = selected_items[0].row()
        self.update_log(
            self.assistant.get_current_time(),
            f"Editing row {row}"
        )
        
        # Verify row has an _id field
        id_col = -1
        for col in range(self.table_widget.columnCount()):
            header = self.table_widget.horizontalHeaderItem(col)
            if header and header.text() == '_id':
                id_col = col
                break
        
        if id_col >= 0:
            id_item = self.table_widget.item(row, id_col)
            if id_item is None or not id_item.text():
                self.update_log(
                    self.assistant.get_current_time(),
                    "Error: Selected row has no _id value"
                )
                QMessageBox.warning(
                    self,
                    "Edit Error",
                    "Cannot edit this row because it has no ID value"
                )
                return
                
            self.update_log(
                self.assistant.get_current_time(),
                f"Row has ID: {id_item.text()}"
            )
        else:
            self.update_log(
                self.assistant.get_current_time(),
                "Warning: Table does not have an _id column"
            )

        # Find the PII column
        pii_col = -1
        for col in range(self.table_widget.columnCount()):
            header = self.table_widget.horizontalHeaderItem(col)
            if header and header.text() == 'PII':
                pii_col = col
                item = self.table_widget.item(row, col)
                break
        
        if pii_col == -1 or item is None:
            self.update_log(
                self.assistant.get_current_time(),
                "Error: PII column not found or empty"
            )
            QMessageBox.warning(
                self,
                "Edit Error",
                "Cannot find PII data to edit"
            )
            return

        old_value = item.text()
        self.show_edit_dialog(selected_items, item, old_value)

    def show_edit_dialog(self, selected_items, item, old_value):
        """
        Show dialog for editing PII data.

        Args:
            selected_items: Selected table items
            item: The specific item to edit
            old_value: Current value of the item
        """
        # Create dialog
        dialog = QDialog(self)
        dialog.setWindowTitle("Edit Guard Data")
        layout = QVBoxLayout()

        # Process old_value into multiple item name-data pairs
        list_of_pairs = []
        for pair in old_value.split('\n'):
            parts = pair.split(' - ', 1)
            if len(parts) == 2:
                list_of_pairs.append(parts)
            elif len(parts) == 1:
                # Handle case where there's no ' - '
                list_of_pairs.append([parts[0], ""])

        # Create input fields for each pair with side-by-side layout
        edits = []
        for item_name, data in list_of_pairs:
            hbox = QHBoxLayout()

            item_name_label = QLabel("Item Name:")
            item_name_edit = QLineEdit(item_name)
            hbox.addWidget(item_name_label)
            hbox.addWidget(item_name_edit)

            data_label = QLabel("Data:")
            data_edit = QLineEdit(data)
            hbox.addWidget(data_label)
            hbox.addWidget(data_edit)

            layout.addLayout(hbox)
            edits.append((item_name_edit, data_edit))

        # Function to add new item-data pair
        def add_new_item_data():
            """Add a new item-data pair to the edit dialog."""
            hbox = QHBoxLayout()

            item_name_label = QLabel("Item Name:")
            item_name_edit = QLineEdit("")
            hbox.addWidget(item_name_label)
            hbox.addWidget(item_name_edit)

            data_label = QLabel("Data:")
            data_edit = QLineEdit("")
            hbox.addWidget(data_label)
            hbox.addWidget(data_edit)

            layout.insertLayout(layout.count() - 1, hbox)
            edits.append((item_name_edit, data_edit))

        # Add OK and Cancel buttons
        button_layout = QHBoxLayout()
        ok_button = QPushButton("Update")
        add_button = QPushButton("Add New Item")
        add_button.clicked.connect(add_new_item_data)
        button_layout.addWidget(ok_button)
        button_layout.addWidget(add_button)
        layout.addLayout(button_layout)
        dialog.setLayout(layout)

        # Connect buttons to appropriate slots
        ok_button.clicked.connect(dialog.accept)

        # Show the dialog and handle the result
        if dialog.exec_() == QDialog.Accepted:
            self.process_edit_result(selected_items, item, edits)

    def process_edit_result(self, selected_items, item, edits):
        """
        Process the result of editing PII data with improved ID handling.
        """
        try:
            # Log start of update
            self.update_log(
                self.assistant.get_current_time(),
                "Starting update process..."
            )

            # Format the edited data
            new_values = []
            for item_name_edit, data_edit in edits:
                new_item_name = item_name_edit.text()
                new_data = data_edit.text()
                new_values.append(f"{new_item_name} - {new_data}")

            # Update UI display with new values
            new_value = '\n'.join(new_values)
            item.setText(new_value)

            # Convert edited entries into JSON format
            final_value_list = [
                {"Item Name": item_name_edit.text(), "Data": data_edit.text()}
                for item_name_edit, data_edit in edits
            ]
            final_value = json.dumps(final_value_list)

            # Extract data from selected row
            row = selected_items[0].row()
            update_data = {}
            
            # First, get all values from the row
            for col in range(self.table_widget.columnCount()):
                header = self.table_widget.horizontalHeaderItem(col)
                if not header:
                    continue
                    
                column_name = header.text()
                cell_item = self.table_widget.item(row, col)
                
                if not cell_item:
                    self.update_log(
                        self.assistant.get_current_time(),
                        f"Warning: Cell for column '{column_name}' is empty"
                    )
                    continue
                    
                # Store the cell value in our update data
                update_data[column_name] = cell_item.text()
            
            # Validate _id field - this is critical
            if '_id' not in update_data or not update_data['_id']:
                self.update_log(
                    self.assistant.get_current_time(), 
                    "Error: No _id found in selected row"
                )
                QMessageBox.warning(
                    self, 
                    "Update Error", 
                    "Cannot update this record: No ID value found"
                )
                return

            # Set updated PII value
            update_data["PII"] = final_value.replace('"', "'")
            
            # Log the update data we're going to send
            self.update_log(
                self.assistant.get_current_time(),
                f"Sending update for ID: {update_data['_id']}"
            )
            self.update_log(
                self.assistant.get_current_time(),
                f"Update data includes fields: {', '.join(update_data.keys())}"
            )
            
            # Set timer for measuring update time
            self.time_update_start_time = time.time()

            # Try direct agent update first (most reliable)
            if hasattr(self, 'agent') and self.agent:
                try:
                    self.update_log(
                        self.assistant.get_current_time(),
                        "Using agent.update_one_data directly"
                    )
                    
                    # Create a minimal update payload with just the necessary fields
                    minimal_update = {
                        '_id': update_data['_id'],
                        'Category': update_data.get('Category', ''),
                        'Type': update_data.get('Type', ''),
                        'PII': update_data['PII']
                    }
                    
                    # Log what we're sending to update_one_data
                    self.update_log(
                        self.assistant.get_current_time(),
                        f"Using minimal update data: {minimal_update}"
                    )
                    
                    response = self.agent.update_one_data(minimal_update)
                    
                    update_time = time.time() - self.time_update_start_time
                    self.update_log(
                        self.assistant.get_current_time(),
                        "Update Time: %.2f Seconds" % update_time
                    )
                    self.update_log(
                        self.assistant.get_current_time(),
                        f"Update Function Response: {response}"
                    )
                    self.modified = True
                    QMessageBox.information(
                        self,
                        "Update Successful",
                        "Data updated successfully!"
                    )
                    return
                except Exception as e:
                    # Log the error but continue to try other methods
                    self.update_log(
                        self.assistant.get_current_time(),
                        f"Agent update_one_data error: {str(e)}"
                    )
            
            # Fall back to auth_service if agent direct update failed
            if hasattr(self, 'auth_service'):
                self.update_log(
                    self.assistant.get_current_time(),
                    "Using auth_service for update request"
                )
                
                # Make authenticated request with all fields in update_data
                success, response_data = self.auth_service.make_authenticated_request(
                    method="PATCH",
                    endpoint="pii",
                    data=update_data
                )
                
                if success:
                    update_time = time.time() - self.time_update_start_time
                    self.update_log(
                        self.assistant.get_current_time(),
                        "Update Time: %.2f Seconds" % update_time
                    )
                    self.update_log(
                        self.assistant.get_current_time(),
                        f"Update Function Response: {response_data}"
                    )
                    self.modified = True
                    QMessageBox.information(
                        self,
                        "Update Successful",
                        "Data updated successfully!"
                    )
                    return
                else:
                    # Log the error but continue to try other methods
                    error_msg = response_data.get('error', str(response_data)) if isinstance(response_data, dict) else str(response_data)
                    self.update_log(
                        self.assistant.get_current_time(),
                        f"Auth service update failed: {error_msg}"
                    )
                    
                    # Show error if this was our last resort
                    if not hasattr(self, 'auth_manager') or not self.auth_manager.token:
                        QMessageBox.warning(
                            self,
                            "Update Failed",
                            f"Failed to update data: {error_msg}"
                        )
                        return
            
            # Fall back to auth_manager if other methods failed
            if hasattr(self, 'auth_manager') and self.auth_manager.token:
                self.update_log(
                    self.assistant.get_current_time(),
                    "Using auth_manager for update request"
                )
                
                # Make authenticated request
                success, response_data = self.auth_manager.make_authenticated_request(
                    method="PATCH",
                    endpoint="pii",
                    data=update_data
                )
                
                if success:
                    update_time = time.time() - self.time_update_start_time
                    self.update_log(
                        self.assistant.get_current_time(),
                        "Update Time: %.2f Seconds" % update_time
                    )
                    self.update_log(
                        self.assistant.get_current_time(),
                        f"Update Function Response: {response_data}"
                    )
                    self.modified = True
                    QMessageBox.information(
                        self,
                        "Update Successful",
                        "Data updated successfully!"
                    )
                else:
                    error_msg = response_data.get('error', str(response_data)) if isinstance(response_data, dict) else str(response_data)
                    QMessageBox.warning(
                        self,
                        "Update Failed",
                        f"Failed to update data: {error_msg}"
                    )
                    self.update_log(
                        self.assistant.get_current_time(),
                        f"Update failed: {error_msg}"
                    )
                    
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"An error occurred while updating: {str(e)}"
            )
            self.update_log(
                self.assistant.get_current_time(),
                f"Update process error: {str(e)}"
            )
        
    def copy_selected_row(self):
        """Copy selected row data to clipboard."""
        if not hasattr(self, 'table_widget') or not self.table_widget:
            return

        selected_items = self.table_widget.selectedItems()
        if selected_items:
            clipboard = QApplication.clipboard()
            clipboard.setText('\t'.join(item.text()
                              for item in selected_items))

    def authenticate_and_connect(self):
        """Authenticate user and connect to server with the reliable auth solution."""
        username = os.environ.get('USER', 'admin')  # Default to 'admin' if USER not set
        password = self.password_input.text()
        
        if not password:
            QMessageBox.warning(
                self,
                "Authentication Error",
                "Please enter a password."
            )
            return
        
        self.btn_connect_server.setText('Authenticating...')
        
        try:
            # Import the new authentication solution
            from API.complete_auth_solution import AuthService
            
            # Initialize the auth service
            self.auth_service = AuthService(CONSTANTS.API_BASE_URL)
            
            # Authenticate with the service
            success, message = self.auth_service.authenticate(username, password)
            
            if not success:
                QMessageBox.warning(
                    self,
                    "Authentication Failed",
                    f"Error: {message}"
                )
                self.password_input.clear()
                self.btn_connect_server.setText('Connect to Server')
                self.btn_connect_server.setDisabled(False)
                return
            
            # Authentication successful
            self.password_input.clear()
            
            # Create agent with session token
            self.agent = Agent(
                s3=CONSTANTS.AWS_S3,
                file_name=CONSTANTS.AWS_FILE
            )
            self.assistant = Assistant(CONSTANTS.AWS_S3)
            
            # Complete connection process
            self.connect_after_authentication()
            
        except ImportError:
            # Fall back to original authentication if the solution module is not available
            logging.warning("New auth solution not available, falling back to original method")
            
            # Initialize auth manager if not already done
            if not hasattr(self, 'auth_manager'):
                from UI.Desktop.auth_manager import AuthenticationManager
                self.auth_manager = AuthenticationManager(self)
            
            # Attempt standard authentication
            if self.auth_manager.authenticate_with_password(username, password):
                # Authentication successful
                self.connect_to_server()
                self.password_input.clear()
                self.update_log(
                    QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
                    f"Authentication successful for user: {self.auth_manager.user_id}"
                )
            else:
                # Authentication failed
                self.btn_connect_server.setText('Connect to Server')
                self.btn_connect_server.setDisabled(False)
                self.password_input.clear()
        except Exception as e:
            logging.error(f"Authentication error: {e}")
            QMessageBox.critical(
                self,
                "Authentication Error",
                f"An unexpected error occurred: {str(e)}"
            )
            self.btn_connect_server.setText('Connect to Server')
            self.btn_connect_server.setDisabled(False)
            self.password_input.clear()

    def connect_after_authentication(self):
        """Complete the connection process after successful authentication."""
        # Update UI
        self.btn_connect_server.setText('Connected')
        self.btn_connect_server.setDisabled(True)
        self.btn_connect_server.setStyleSheet(
            "background-color: green; color: white;"
        )
        self.btn_display_data.setStyleSheet(
            "background-color: green; color: white;"
        )
        self.btn_display_data.setVisible(True)
        self.btn_add_entry.setVisible(True)
        self.log_table.setVisible(True)
        self.welcome_text.setVisible(True)
        self.data_table.setVisible(True)
        self.btn_add_entry.setStyleSheet(
            "background-color: green; color: white;"
        )
        self.btn_display_data.setToolTip('Click to download data')
        self.btn_connect_server.setToolTip(
            'You are Connected Successfully. Button Disabled'
        )
        
        # Clear password input
        self.password_input.setHidden(True)
        
        # Show session info button
        self.btn_session_info.setVisible(True)

        # Create logout button
        self.create_logout_button()

        # Set up timer for status updates
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.fetch_status)
        self.timer.start(1000)

        # Get initial data
        try:
            success, data = self.auth_service.make_request(
                method="GET",
                endpoint="pii"
            )
            
            if success and data is not None:
                # Convert to DataFrame if needed
                if not isinstance(data, pd.DataFrame):
                    data = pd.DataFrame(data)
                self.populate_data_table(data)
            else:
                error_msg = data.get("error", "Unknown error")
                logging.warning(f"Error fetching initial data: {error_msg}")
                QMessageBox.warning(
                    self,
                    "Data Fetch Warning",
                    f"Connected successfully but couldn't fetch initial data: {error_msg}"
                )
        except Exception as e:
            logging.error(f"Error fetching initial data: {e}")
            QMessageBox.warning(
                self,
                "Data Fetch Warning",
                f"Connected successfully but couldn't fetch initial data: {str(e)}"
            )

        # Log successful connection
        timestamp = self.assistant.get_current_time() if hasattr(self, 'assistant') else QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        self.update_log(timestamp, "Connected to Server.")
        self.update_log(timestamp, 'Display Data Button: Activated')
        self.update_log(timestamp, 'Add New Entry Button: Activated')
        
        # Switch to PII tab
        self.tab_widget.setCurrentIndex(0)

    def connect_after_authentication(self):
        """Complete the connection process after successful authentication."""
        # Update UI
        self.btn_connect_server.setText('Connected')
        self.btn_connect_server.setDisabled(True)
        self.btn_connect_server.setStyleSheet(
            "background-color: green; color: white;"
        )
        self.btn_display_data.setStyleSheet(
            "background-color: green; color: white;"
        )
        self.btn_display_data.setVisible(True)
        self.btn_add_entry.setVisible(True)
        self.log_table.setVisible(True)
        self.welcome_text.setVisible(True)
        self.data_table.setVisible(True)
        self.btn_add_entry.setStyleSheet(
            "background-color: green; color: white;"
        )
        self.btn_display_data.setToolTip('Click to download data')
        self.btn_connect_server.setToolTip(
            'You are Connected Successfully. Button Disabled'
        )
        
        # Clear password input
        self.password_input.clear()
        self.password_input.setHidden(True)
        
        # Show session info button
        self.btn_session_info.setVisible(True)

        # Create logout button
        self.create_logout_button()

        # Set up timer for status updates
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.fetch_status)
        self.timer.start(1000)

        # Get initial data
        try:
            success, data = self.auth_service.make_authenticated_request(
                method="GET",
                endpoint="pii"
            )
            
            if success and data is not None:
                # Convert to DataFrame if needed
                if not isinstance(data, pd.DataFrame):
                    data = pd.DataFrame(data)
                self.populate_data_table(data)
        except Exception as e:
            self.logger.error(f"Error fetching initial data: {e}")
            QMessageBox.warning(
                self,
                "Data Fetch Warning",
                f"Connected successfully but couldn't fetch initial data: {str(e)}"
            )

        # Log successful connection
        timestamp = self.assistant.get_current_time() if hasattr(self, 'assistant') else QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        self.update_log(timestamp, "Connected to Server.")
        self.update_log(timestamp, 'Display Data Button: Activated')
        self.update_log(timestamp, 'Add New Entry Button: Activated')
        
        # Switch to PII tab
        self.tab_widget.setCurrentIndex(0)

    def connect_to_server(self):
        """Connect to the backend server with enhanced security and fallback authentication."""
        self.btn_connect_server.setDisabled(True)
        try:
            # Ensure we have a session manager
            if not hasattr(self, 'session_manager'):
                self.session_manager = SessionManager(self)
            
            # Initialize the authentication service if not already done
            if not hasattr(self, 'auth_service'):
                self.auth_service = AuthService(
                    api_base_url=CONSTANTS.API_BASE_URL,
                    session_manager=self.session_manager
                )
            
            # First try AWS SSO authentication if it's available
            aws_sso_available = False
            
            if hasattr(self, 'session_manager') and self.session_manager.is_authenticated:
                # Use existing SSO session
                aws_sso_available = True
                self.logger.info("Using existing AWS SSO session")
                success, message = self.auth_service.authenticate_with_aws_sso()
                
                if not success:
                    self.logger.warning(f"AWS SSO authentication failed: {message}")
                    aws_sso_available = False
            
            # If AWS SSO is not available or failed, fall back to password authentication
            if not aws_sso_available:
                self.logger.info("Falling back to password authentication")
                
                # For password auth, we need to get a token from the API
                success, message = self.auth_service.authenticate_with_password(
                    username=os.environ.get('USER', 'default_user'),
                    password=self.password_input.text()
                )
                
                if not success:
                    raise ValueError(f"Password authentication failed: {message}")
            
            # Create agent with session token
            self.agent = Agent(
                s3=CONSTANTS.AWS_S3,
                file_name=CONSTANTS.AWS_FILE
            )
            self.assistant = Assistant(CONSTANTS.AWS_S3)

            # Update button states
            self.btn_connect_server.setText('Connected')
            self.btn_connect_server.setDisabled(True)
            self.btn_connect_server.setStyleSheet(
                "background-color: green; color: white;"
            )
            self.btn_display_data.setStyleSheet(
                "background-color: green; color: white;"
            )
            self.btn_display_data.setVisible(True)
            self.btn_add_entry.setVisible(True)
            self.log_table.setVisible(True)
            self.welcome_text.setVisible(True)
            self.data_table.setVisible(True)
            self.btn_add_entry.setStyleSheet(
                "background-color: green; color: white;"
            )
            self.btn_display_data.setToolTip('Click to download data')
            self.btn_connect_server.setToolTip(
                'You are Connected Successfully. Button Disabled'
            )
            
            # Show session info button
            self.btn_session_info.setVisible(True)

            # Create logout button
            self.create_logout_button()

            # Set up timer for status updates
            self.timer = QTimer(self)
            self.timer.timeout.connect(self.fetch_status)
            self.timer.start(1000)

            # Get initial data using the authenticated service
            success, data = self.auth_service.make_synchronous_request(
                method="GET",
                endpoint="pii"
            )
            
            if success and data is not None:
                # Convert to DataFrame if needed
                if not isinstance(data, pd.DataFrame):
                    data = pd.DataFrame(data)
                self.populate_data_table(data)
            else:
                raise ValueError(f"Failed to fetch data: {data}")

            # Update session display
            self.update_session_status()

            # Log successful connection
            timestamp = self.assistant.get_current_time()
            self.update_log(timestamp, "Connected to Server.")
            self.update_log(timestamp, 'Display Data Button: Activated')
            self.update_log(timestamp, 'Add New Entry Button: Activated')
            
            # Switch to PII tab
            self.tab_widget.setCurrentIndex(0)
            
        except Exception as e:
            QMessageBox.critical(
                self,
                "Connection Error",
                f"Failed to connect to server: {str(e)}"
            )
            self.btn_connect_server.setText('Connect to Server')
            self.btn_connect_server.setDisabled(False)
            self.btn_connect_server.clicked.disconnect(
                self.authenticate_and_connect
            )
            self.btn_connect_server.clicked.connect(self.show_password_input)
            
            # Logout from session manager
            if hasattr(self, 'session_manager'):
                self.session_manager.logout()

    def create_logout_button(self):
        """Create and position the logout button."""
        # Create button container in the top right corner
        button_container = QWidget(self)
        button_layout = QHBoxLayout(button_container)
        button_layout.setContentsMargins(0, 0, 10, 0)  # Right margin of 10
        
        # Session info button
        if hasattr(self, 'btn_session_info'):
            self.btn_session_info.setParent(button_container)
            button_layout.addWidget(self.btn_session_info)
        else:
            self.btn_session_info = QPushButton('Session Info', button_container)
            self.btn_session_info.setCursor(QCursor(Qt.PointingHandCursor))
            self.btn_session_info.clicked.connect(self.show_session_info)
            self.btn_session_info.setShortcut("Ctrl+I")
            self.btn_session_info.setStyleSheet(
                "background-color: #4682B4; color: white;"
            )
            self.btn_session_info.setToolTip('View session information')
            button_layout.addWidget(self.btn_session_info)
        
        # Logout button
        self.btn_logout = QPushButton('Logout', button_container)
        self.btn_logout.setCursor(QCursor(Qt.PointingHandCursor))
        self.btn_logout.clicked.connect(self.logout_user)
        self.btn_logout.setShortcut("Ctrl+W")
        self.btn_logout.setStyleSheet(
            "background-color: orange; color: white;"
        )
        self.btn_logout.setToolTip('Click to Logout')
        button_layout.addWidget(self.btn_logout)
        
        # Position button container in top right
        button_container.setGeometry(
            self.width() - 230, 10, 220, 50
        )
        button_container.show()

    def show_password_input(self):
        """Show password input and SSO login option for authentication."""
        self.btn_connect_server.setText('Authenticating...')
        self.btn_connect_server.setDisabled(True)
        self.btn_connect_server.setStyleSheet(
            "background-color: gray; color: white;"
        )
        self.password_input.setHidden(False)  # Make password input visible
        self.btn_sso_login.setVisible(True)   # Make SSO login button visible
        self.password_input.setFocus()
        self.btn_connect_server.clicked.disconnect(self.show_password_input)
        self.btn_connect_server.clicked.connect(self.authenticate_and_connect)

    def on_data_table_selection(self):
        """Handle selection in the data table to show sub-options."""
        if not self.agent:
            return

        selected_items = self.data_table.selectedItems()
        if not selected_items:
            return

        selected_item_text = selected_items[0].text()
        try:
            # Log the selected category
            self.update_log(
                self.assistant.get_current_time(),
                f"Selected item: {selected_item_text}"
            )

            # Get sub-options for the selected category
            sub_options = self.agent.get_sub_options_to_choose(selected_item_text)
            
            # Ensure sub_options is a list of strings
            if not isinstance(sub_options, list):
                self.update_log(
                    self.assistant.get_current_time(),
                    f"Error: get_sub_options_to_choose returned non-list: {type(sub_options)}"
                )
                QMessageBox.warning(
                    self,
                    "Data Format Error",
                    f"Unexpected data format for sub-options: {type(sub_options)}"
                )
                return
                
            # Ensure we have sub-options to display
            if not sub_options:
                self.update_log(
                    self.assistant.get_current_time(),
                    f"No sub-options found for {selected_item_text}"
                )
                QMessageBox.information(
                    self,
                    "No Sub-Options",
                    f"No sub-options available for {selected_item_text}"
                )
                return

            # Show dialog to select sub-option
            sub_option, ok_pressed = QInputDialog.getItem(
                self,
                "Choose Sub Option",
                f"Sub options for {selected_item_text}:"+"  "*45,
                sub_options,
                0,
                False,  # Editable flag set to False
                Qt.WindowFlags(
                    Qt.WindowTitleHint |
                    Qt.WindowSystemMenuHint |
                    Qt.WindowCloseButtonHint
                )
            )

            if ok_pressed and sub_option:
                # Get data for the selected sub-option
                self.update_log(
                    self.assistant.get_current_time(),
                    f"Selected {selected_item_text}'s sub option: {sub_option}"
                )
                
                # Get the output data
                output = self.agent.get_final_output(sub_option)
                
                # Show the output data
                self.show_output_dialog(sub_option, output)
        except Exception as e:
            self.update_log(
                self.assistant.get_current_time(),
                f"Error processing selection: {str(e)}"
            )
            QMessageBox.warning(
                self,
                "Selection Error",
                f"Error processing selection: {str(e)}"
            )

    def show_output_dialog(self, sub_option, output):
        """
        Show dialog with output data.

        Args:
            sub_option (str): The selected sub-option
            output (list or str): The output data to display
        """
        self.start_time = time.time()
        self.option = sub_option  # Store selected option for later reference

        def on_close_event(event):
            """Handle dialog close event."""
            event.accept()
            end_time = time.time() - self.start_time
            self.update_log(
                self.assistant.get_current_time(),
                f"{self.option}'s dialog closed after {end_time:.2f} seconds"
            )

        # Create dialog
        dialog = QDialog(self)
        dialog.setWindowTitle(sub_option)
        dialog.closeEvent = on_close_event

        # Calculate the dialog size
        # Ensure output is a list to safely calculate its length
        if not isinstance(output, list):
            # Convert to a list with a single item if it's not already a list
            output = [output]
            
        num_items = len(output)
        item_height = 50  # Approximate height for each item
        base_height = 100  # Base height for dialog components
        width = 700  # Fixed width
        height = min(400, item_height * num_items + base_height)

        # Set dialog geometry
        screen_geometry = QGuiApplication.primaryScreen().availableGeometry()
        x = (screen_geometry.width() - width) // 2
        y = (screen_geometry.height() - height) // 2
        dialog.setGeometry(x, y, width, height)

        # Set up dialog layout
        dialog_layout = QVBoxLayout(dialog)
        
        # Log before setting up dialog content
        self.update_log(
            self.assistant.get_current_time(),
            f"Setting up dialog for {self.option}, output type: {type(output)}, length: {len(output)}"
        )
        
        self.setup_dialog_content(dialog, dialog_layout, output)

        # Show dialog
        dialog.exec_()

    def setup_dialog_content(self, dialog, dialog_layout, output):
        """
        Set up the content of the output dialog.

        Args:
            dialog: The dialog to set up
            dialog_layout: Layout of the dialog
            output: Data to display
        """
        # Set up scroll area
        scroll_area = QScrollArea(dialog)
        scroll_area.setWidgetResizable(True)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)

        # Process output data
        try:
            if isinstance(output, list):
                if not output:
                    # Empty list
                    label = QLabel("No data available.", dialog)
                    label.setWordWrap(True)
                    scroll_layout.addWidget(label)
                else:
                    # Process each item in the list
                    for i, item in enumerate(output):
                        h_layout = QHBoxLayout()
                        
                        # Handle string items
                        if isinstance(item, str):
                            label = QLabel(item, dialog)
                            label.setWordWrap(True)
                            h_layout.addWidget(label)
                            scroll_layout.addLayout(h_layout)
                            scroll_layout.addSpacing(10)
                        # Handle dictionary items
                        elif isinstance(item, dict):
                            self.add_dict_item_to_layout(dialog, h_layout, scroll_layout, item)
                        # Handle other types
                        else:
                            label = QLabel(str(item), dialog)
                            label.setWordWrap(True)
                            h_layout.addWidget(label)
                            scroll_layout.addLayout(h_layout)
                            scroll_layout.addSpacing(10)
            else:
                # Handle non-list output (string, etc.)
                label = QLabel(str(output), dialog)
                label.setWordWrap(True)
                scroll_layout.addWidget(label)
        except Exception as e:
            # Handle any errors that occur while processing output
            error_label = QLabel(f"Error displaying data: {str(e)}", dialog)
            error_label.setWordWrap(True)
            error_label.setStyleSheet("color: red;")
            scroll_layout.addWidget(error_label)
            
            # Log the error
            self.update_log(
                self.assistant.get_current_time(),
                f"Error in setup_dialog_content: {str(e)}"
            )

        # Log display action
        self.update_log(
            self.assistant.get_current_time(),
            f"Displaying... {self.option}"
        )

        # Set up scroll area
        scroll_content.setLayout(scroll_layout)
        scroll_area.setWidget(scroll_content)
        dialog_layout.addWidget(scroll_area)

        # Add close button
        close_button = QPushButton('Close', dialog)
        close_button.clicked.connect(dialog.close)
        dialog_layout.addWidget(close_button)
        dialog_layout.setAlignment(close_button, Qt.AlignRight)

        # Add accept handler
        def on_accept():
            """Handle dialog acceptance."""
            end_time = time.time()
            duration = end_time - self.start_time
            self.update_log(
                self.assistant.get_current_time(),
                f"{self.option}'s dialog was visible for {duration:.2f} seconds"
            )
            dialog.accept()

        close_button.clicked.connect(on_accept)

    def add_dict_item_to_layout(self, dialog, h_layout, scroll_layout, item):
        """
        Add a dictionary item to the dialog layout.

        Args:
            dialog: Parent dialog
            h_layout: Horizontal layout to add to
            scroll_layout: Scroll area layout
            item: Dictionary item to add
        """
        # Handle dictionary items safely
        try:
            # Extract item data
            item_name = str(item.get('Item Name', 'N/A'))
            item_data = str(item.get('Data', 'N/A'))
            
            # Create label with item data
            label = QLabel(f"{item_name} : {item_data}", dialog)
            
            # Create copy button
            copy_button = QPushButton('Copy', dialog)
            copy_button.setToolTip('Click to copy the data')
            copy_button.setCursor(QCursor(Qt.PointingHandCursor))
            
            # Store button reference in item for later use
            item_copy = item.copy()  # Make a copy to avoid modifying the original
            item_copy["Button"] = copy_button
            
            # Connect button to copy function
            copy_button.clicked.connect(
                lambda checked, data=item_copy: self.copy_to_clipboard(data)
            )
            
            # Style components
            label.setWordWrap(True)
            copy_button.setStyleSheet("background-color: White; color: Black;")
            label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
            
            # Add to layout
            h_layout.addWidget(label)
            h_layout.addWidget(copy_button)
            scroll_layout.addLayout(h_layout)
            scroll_layout.addSpacing(10)
        except Exception as e:
            # Handle any errors that occur while adding the item
            error_label = QLabel(f"Error displaying item: {str(e)}", dialog)
            error_label.setWordWrap(True)
            error_label.setStyleSheet("color: red;")
            h_layout.addWidget(error_label)
            scroll_layout.addLayout(h_layout)
            scroll_layout.addSpacing(10)
            
            # Log the error
            self.update_log(
                self.assistant.get_current_time(),
                f"Error in add_dict_item_to_layout: {str(e)}"
            )

    def setup_dialog_content(self, dialog, dialog_layout, output):
        """
        Set up the content of the output dialog.

        Args:
            dialog: The dialog to set up
            dialog_layout: Layout of the dialog
            output: Data to display
        """
        # Set up scroll area
        scroll_area = QScrollArea(dialog)
        scroll_area.setWidgetResizable(True)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)

        # Process output data
        if isinstance(output, list):
            for item in output:
                h_layout = QHBoxLayout()

                if isinstance(item, dict):
                    # Handle dictionary items (most common case)
                    self.add_dict_item_to_layout(
                        dialog, h_layout, scroll_layout, item)
                else:
                    # Handle non-dictionary items
                    label = QLabel(str(item), dialog)
                    label.setWordWrap(True)
                    h_layout.addWidget(label)
                    scroll_layout.addLayout(h_layout)
                    scroll_layout.addSpacing(10)
        else:
            # Handle error case
            QMessageBox.warning(
                self,
                "Error Code: 404 and 503 WARNING MESSAGE",
                "You are Not Allowed to view this here."
            )
            return

        # Log display action
        self.update_log(
            self.assistant.get_current_time(),
            f"Displaying... {self.option}"
        )

        # Set up scroll area
        scroll_content.setLayout(scroll_layout)
        scroll_area.setWidget(scroll_content)
        dialog_layout.addWidget(scroll_area)

        # Add close button
        close_button = QPushButton('Close', dialog)
        close_button.clicked.connect(dialog.close)
        dialog_layout.addWidget(close_button)
        dialog_layout.setAlignment(close_button, Qt.AlignRight)

        # Add accept handler
        def on_accept():
            """Handle dialog acceptance."""
            end_time = time.time()
            duration = end_time - self.start_time
            self.update_log(
                self.assistant.get_current_time(),
                f"{self.option}'s dialog was visible for {duration:.2f} seconds"
            )
            dialog.accept()

        close_button.clicked.connect(on_accept)

    def add_dict_item_to_layout(self, dialog, h_layout, scroll_layout, item):
        """
        Add a dictionary item to the dialog layout.

        Args:
            dialog: Parent dialog
            h_layout: Horizontal layout to add to
            scroll_layout: Scroll area layout
            item: Dictionary item to add
        """
        # Create label with item data
        item_name = item.get('Item Name', 'N/A')
        item_data = str(item.get('Data', 'N/A'))
        label = QLabel(f"{item_name} : {item_data}", dialog)

        # Create copy button
        copy_button = QPushButton('Copy', dialog)
        copy_button.setToolTip('Click to copy the data')
        copy_button.setCursor(QCursor(Qt.PointingHandCursor))
        item["Button"] = copy_button

        # Connect button to copy function
        copy_button.clicked.connect(
            lambda checked, data=item: self.copy_to_clipboard(data)
        )

        # Style components
        label.setWordWrap(True)
        copy_button.setStyleSheet("background-color: White; color: Black;")
        label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

        # Add to layout
        h_layout.addWidget(label)
        h_layout.addWidget(copy_button)
        scroll_layout.addLayout(h_layout)
        scroll_layout.addSpacing(10)

    def copy_to_clipboard(self, data):
        """
        Copy data to clipboard.

        Args:
            data (dict): Data to copy
        """
        clipboard = QApplication.clipboard()
        clipboard.setText(str(data.get('Data', '')))
        data["Button"].setText("Copied")
        data["Button"].setStyleSheet(
            "background-color: green; color: white; font-weight: bold;"
        )
        self.update_log(
            self.assistant.get_current_time(),
            f"Copied {self.option}'s {data.get('Item Name', 'N/A')} to Clipboard."
        )
        QTimer.singleShot(3000, lambda: self.reset_button_text(data))

    def reset_button_text(self, data):
        """
        Reset the button text after copying.

        Args:
            data (dict): Data containing the button
        """
        if "Button" in data:
            data["Button"].setText("Copy")
            data["Button"].setStyleSheet(
                "background-color: White; color: Black;"
            )

    def update_log(self, task_time, task_name):
        """
        Update the log table.

        Args:
            task_time (str): Timestamp for the log
            task_name (str): Task name/description
        """
        # Check if log_table exists
        if not hasattr(self, 'log_table') or self.log_table is None:
            # Just log to file without updating the table
            logging.info("%s - %s", task_time, task_name)
            return

        row_position = self.log_table.rowCount()
        self.log_table.insertRow(row_position)

        timestamp_item = QTableWidgetItem(task_time)
        message_item = QTableWidgetItem(task_name)

        self.log_table.setItem(row_position, 0, timestamp_item)
        self.log_table.setItem(row_position, 1, message_item)

        # Use % formatting for logging
        logging.info("%s - %s", task_time, task_name)

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

    def delete_item(self):
        """Delete the selected item using the CRUD Helper."""
        if not hasattr(self, 'table_widget') or not self.table_widget:
            QMessageBox.warning(self, "Delete Error", "Data table not available.")
            return

        selected_items = self.table_widget.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Delete Error", "No item selected to delete.")
            return

        # Extract row data
        row = selected_items[0].row()
        delete_data = CRUDHelper.extract_row_data(self.table_widget, row)
        
        # Log the delete attempt
        self.update_log(
            self.assistant.get_current_time(),
            f"Attempting to delete item with ID: {delete_data.get('_id', 'unknown')}"
        )
        
        # Confirm deletion
        if not self.confirm_delete(delete_data):
            return
        
        # Use CRUD Helper to perform the operation
        success, response = CRUDHelper.perform_operation(
            'delete',
            delete_data,
            agent=self.agent if hasattr(self, 'agent') else None,
            auth_service=self.auth_service if hasattr(self, 'auth_service') else None,
            auth_manager=self.auth_manager if hasattr(self, 'auth_manager') else None,
            logger=lambda msg: self.update_log(self.assistant.get_current_time(), msg)
        )
        
        if success:
            QMessageBox.information(self, "Deletion Complete", "Item deleted successfully!")
            self.table_widget.removeRow(row)
            self.modified = True
        else:
            QMessageBox.warning(self, "Delete Failed", f"Failed to delete item: {response}")

    def get_item_info_from_selection(self, selected_items):
        """
        Extract item information from selected items.

        Args:
            selected_items: Selected table items

        Returns:
            dict: Item information
        """
        item_info = {'Category': '', 'Type': '', '_id': ''}
        
        if not selected_items:
            return item_info
            
        # Get the row of the first selected item
        row = selected_items[0].row()
        
        # Log what row we're examining
        self.update_log(
            self.assistant.get_current_time(),
            f"Extracting info from row {row}"
        )
        
        # Check all columns in this row
        for column in range(self.table_widget.columnCount()):
            header = self.table_widget.horizontalHeaderItem(column)
            if not header:
                continue
                
            column_name = header.text()
            cell_item = self.table_widget.item(row, column)
            
            if not cell_item:
                self.update_log(
                    self.assistant.get_current_time(),
                    f"Warning: Cell for column '{column_name}' is empty"
                )
                continue
                
            cell_value = cell_item.text()
            
            # Store values for key fields
            if column_name in item_info:
                item_info[column_name] = cell_value
                
        # Log what we found
        field_info = ", ".join([f"{k}: {v}" for k, v in item_info.items() if v])
        self.update_log(
            self.assistant.get_current_time(),
            f"Extracted fields: {field_info}"
        )
        
        # Check if we have the essential fields
        missing_fields = [k for k, v in item_info.items() if not v]
        if missing_fields:
            self.update_log(
                self.assistant.get_current_time(),
                f"Warning: Missing fields: {', '.join(missing_fields)}"
            )
        
        return item_info

    def confirm_delete(self, item_info):
        """
        Confirm deletion with user.

        Args:
            item_info: Information about the item to delete

        Returns:
            bool: True if confirmed, False otherwise
        """
        # Confirm deletion with the user
        message = (
            f"Are you sure you want to delete the item '{item_info['Category']}' "
            f"with type '{item_info['Type']}'?\n\n"
            f"Note: This Action is Irreversible!"
        )

        reply = QMessageBox.question(
            self,
            "Confirm Delete",
            message,
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        return reply == QMessageBox.Yes

    def perform_delete_operation(self, item_info, row):
        """
        Perform the actual delete operation.

        Args:
            item_info: Information about the item
            row: Row index in the table
        """
        self.modified = True
        delete_data = {
            '_id': item_info['_id'],
            'Category': item_info['Category'],
            'Type': item_info['Type']
        }

        try:
            response = requests.delete(CONSTANTS.URL, json=delete_data)
            if response.status_code == 200:
                QMessageBox.information(
                    self,
                    "Deletion Complete",
                    "Item deleted successfully!"
                )
                self.update_log(
                    self.assistant.get_current_time(),
                    f"Deleted Item: {item_info['Category']} - {item_info['Type']}"
                )
                self.table_widget.removeRow(row)
            else:
                error_msg = f"Failed to delete the item. Status code: {response.status_code}"
                QMessageBox.warning(self, "Delete Error", error_msg)
                self.update_log(
                    self.assistant.get_current_time(),
                    "Failed to delete the item."
                )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Delete Error",
                f"Error deleting item: {str(e)}"
            )
            self.update_log(
                self.assistant.get_current_time(),
                f"Error deleting item: {str(e)}"
            )

    def update_item(self, item):
        """
        Update an item in the data table.

        Args:
            item (QTableWidgetItem): The item to update
        """
        self.data_table.setCurrentItem(item, QAbstractItemView.Select)
        self.on_data_table_selection()
        self.data_table.setCurrentItem(None)
        self.data_table.clearSelection()
        self.data_table.update()
        self.data_table.repaint()
        self.data_table.viewport().update()
        self.data_table.viewport().repaint()

    def fetch_status(self):
        """Fetch status updates from the agent."""
        try:
            if (hasattr(self, 'agent') and self.agent and
                    hasattr(self.agent, 'status')):
                for task_name, task_time in self.agent.status.items():
                    self.update_log(task_time, task_name)
                self.agent.status = {}
        except AttributeError:
            pass

    def cleanup_on_exit(self, event=None):
        """
        Clean up resources when exiting the application.

        Args:
            event: Close event, if any
        """
        log_files = ['application.log']
        for log_file in log_files:
            if os.path.exists(log_file):
                try:
                    if self.assistant:
                        self.update_log(
                            self.assistant.get_current_time(),
                            "Processing Logging Data..."
                        )
                        pre_log_time = time.time()
                        self.assistant.collect_logs()
                        backup_time = time.time() - pre_log_time
                        self.update_log(
                            self.assistant.get_current_time(),
                            "Log Data Backedup in %.2f Seconds" % backup_time
                        )
                except (AttributeError, Exception) as e:
                    logging.info("Error during cleanup: %s", str(e))
                    logging.info(
                        "EVNT_FLRE: Closed the Application without Login."
                    )

        # Clean up timer if it exists
        if hasattr(self, 'timer') and self.timer:
            self.timer.stop()

        if event:
            event.accept()
        
    def setup_session_manager(self):
        """Set up the session manager and connect signals."""
        # Create session manager with 1-hour session timeout
        self.session_manager = SessionManager(self, token_ttl=3600)  # 1 hour session
        
        # Connect signals
        self.session_manager.session_expired.connect(self.handle_session_expired)
        self.session_manager.token_refreshed.connect(self.handle_token_refreshed)
        self.session_manager.session_expiring_soon.connect(self.handle_session_expiring_soon)
        
        # Log initialization
        if hasattr(self, 'update_log'):
            timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
            self.update_log(timestamp, "Session manager initialized")

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

    def handle_session_expired(self):
        """Handle expired session."""
        # Log the expiration
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        if hasattr(self, 'update_log'):
            self.update_log(timestamp, "Session expired - logging out")
        
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
        if hasattr(self, 'assistant') and self.assistant:
            timestamp = self.assistant.get_current_time()
            
        if hasattr(self, 'update_log'):
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
        # Only notify if we're on the PII data tab (not YouTube downloader)
        if not hasattr(self, 'tab_widget') or self.tab_widget.currentIndex() != 0:
            return
            
        QMessageBox.information(
            self,
            "Session Expiring Soon",
            f"Your session will expire in {minutes_remaining} minute{'s' if minutes_remaining != 1 else ''}.\n"
            f"Please save your work. You will be logged out when the session expires."
        )

    def show_session_info(self):
        """Show current session information including API auth status."""
        if not hasattr(self, 'session_manager') or not self.session_manager.is_authenticated:
            QMessageBox.information(
                self,
                "Session Info",
                "You are not currently logged in."
            )
            return
        
        session_info = self.session_manager.get_session_info()
        
        # Add API authentication info if available
        api_auth_info = ""
        if hasattr(self, 'auth_service'):
            user_info = self.auth_service.get_session_info()
            if user_info.get("is_authenticated"):
                api_auth_info = (
                    f"\n\nAPI Authentication:\n"
                    f"User ID: {user_info['user_id']}\n"
                    f"Authentication Type: {user_info['auth_type']}\n"
                    f"Token Expires: {user_info['token_expires_at']}"
                )
        
        QMessageBox.information(
            self,
            "Session Info",
            f"Session Information:\n"
            f"User ID: {session_info['user_id']}\n"
            f"Authentication Type: {session_info['auth_type']}\n"
            f"Session Started: {session_info['auth_timestamp']}\n"
            f"Client IP: {session_info['auth_ip']}\n"
            f"Session Expires: {session_info['remaining_formatted']} from now\n"
            f"({session_info['expiration_time']})"
            f"{api_auth_info}"
        )

    # In the authenticate_and_connect method of UI/Desktop/main.py

    def authenticate_and_connect(self):
        """Authenticate user and connect to server."""
        username = os.environ.get('USER', 'default_user')
        password = self.password_input.text()
        
        # Initialize auth manager if not already done
        if not hasattr(self, 'auth_manager'):
            from UI.Desktop.auth_manager import AuthenticationManager
            self.auth_manager = AuthenticationManager(self)
        
        # Attempt authentication
        if self.auth_manager.authenticate_with_password(username, password):
            # Authentication successful
            self.connect_to_server()
            self.password_input.clear()
            self.update_log(
                QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
                f"Authentication successful for user: {self.auth_manager.user_id}"
            )
        else:
            # Authentication failed
            self.btn_connect_server.setText('Connect to Server')
            self.btn_connect_server.setDisabled(False)
            self.password_input.clear()

    # Update the authenticate_with_sso method:
    def authenticate_with_sso(self, parent_widget=None) -> bool:
        """Authenticate using AWS SSO."""
        self.btn_sso_login.setText('Authenticating with SSO...')
        self.btn_sso_login.setDisabled(True)
        
        # Attempt AWS SSO authentication
        auth_success = self.session_manager.authenticate_aws_sso(self)
        
        if auth_success:
            # Connect to server
            self.connect_to_server()
            
            # Update session status
            self.update_session_status()
            
            # Log successful authentication
            session_info = self.session_manager.get_session_info()
            timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
            self.update_log(
                timestamp,
                f"AWS SSO authentication successful - Session valid for {session_info['remaining_formatted']}"
            )
        else:
            # Reset button state
            self.btn_sso_login.setText('AWS SSO Login')
            self.btn_sso_login.setDisabled(False)

    # Update the logout_user method:
    def logout_user(self):
        """Perform logout operations."""
        if not self.assistant:
            QMessageBox.warning(self, "Logout Error",
                            "Not currently logged in.")
            return

        timestamp = self.assistant.get_current_time()
        self.update_log(timestamp, 'Logging Out...')
        
        # Switch to YouTube downloader tab before logout
        if hasattr(self, 'tab_widget') and hasattr(self, 'downloader_widget'):
            downloader_tab_index = self.tab_widget.indexOf(self.downloader_widget)
            self.tab_widget.setCurrentIndex(downloader_tab_index)
        
        self.ui_components()
        self.update_log(timestamp, 'Logged Out Successfully.')
        
        # Cleanup
        self.cleanup_on_exit()
        self.modified = False
        
        # Hide logout button
        if hasattr(self, 'btn_logout') and self.btn_logout:
            self.btn_logout.setVisible(False)
        
        # Logout from session manager
        if hasattr(self, 'session_manager'):
            self.session_manager.logout()
            self.update_session_status()
        
        # Cleanup assistants
        if hasattr(self, 'assistant') and self.assistant:
            self.assistant.logout()
        self.agent = None
        
        # Switch to YouTube downloader tab again to ensure it's visible
        if hasattr(self, 'tab_widget') and hasattr(self, 'downloader_widget'):
            downloader_tab_index = self.tab_widget.indexOf(self.downloader_widget)
            self.tab_widget.setCurrentIndex(downloader_tab_index)



if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PIIWindow()
    sys.exit(app.exec_())

# export PYTHONPATH=$PYTHONPATH:$(pwd)