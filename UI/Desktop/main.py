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
import hashlib
import subprocess
import threading
from logging.handlers import RotatingFileHandler
from UI.Desktop.session_manager import SessionManager

# Third-party imports
import pandas as pd
import requests
from PyQt5.QtWidgets import (
    QLineEdit, QMessageBox, QInputDialog, QMainWindow, QWidget,
    QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTableWidget,
    QHeaderView, QTableWidgetItem, QDialog, QScrollArea, QSizePolicy,
    QAbstractItemView, QApplication, QMenu, QAction, QTabWidget
)
from PyQt5.QtGui import QIcon, QCursor, QGuiApplication
from PyQt5.QtCore import Qt, QTimer, QDateTime

# Local application imports
from API.backend import Agent
from API.youtube_download import YouTubeDownloaderWidget, integrate_youtube_downloader
from API.assistant import Assistant
import API.CONSTANTS as CONSTANTS

# Setup logging with rotation
handler = RotatingFileHandler(
    'application.log', maxBytes=1000000, backupCount=3)
logging.basicConfig(handlers=[handler], level=logging.INFO)


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
        
        self.session_manager = SessionManager(self, token_ttl=3600)  # 1 hour session
        self.session_manager.session_expired.connect(self.handle_session_expired)
        self.session_manager.token_refreshed.connect(self.handle_token_refreshed)

        # Set up UI
        self.ui_components()
        self.show()
        self.showMaximized()

        # Connect the close event to the cleanup function
        self.close_event = self.cleanup_on_exit

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
        
        # Welcome text
        self.welcome_text = QLabel(
            f"Welcome to GUARD: {os.environ.get('USER', 'USER').upper()}",
            self.pii_tab
        )
        self.welcome_text.setStyleSheet("font-size: 15px; font-weight: bold;")
        self.welcome_text.setVisible(False)
        pii_layout.addWidget(self.welcome_text, alignment=Qt.AlignCenter)

        # Connect server button
        self.btn_connect_server = self.set_button(
            'Connect to Server',
            'Click to connect to server',
            'Ctrl+Q',
            self.show_password_input,
            visible_true=True
        )
        pii_layout.addWidget(self.btn_connect_server, alignment=Qt.AlignCenter)

        # Password input
        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.returnPressed.connect(
            self.authenticate_and_connect
        )
        self.password_input.setHidden(True)
        pii_layout.addWidget(self.password_input)

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
            self.show_data_window,
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
        # Add this in your ui_components method, right after initializing other buttons
        self.btn_sso_login = QPushButton('AWS SSO Login', self)
        self.btn_sso_login.setCursor(QCursor(Qt.PointingHandCursor))
        self.btn_sso_login.setStyleSheet(
            "background-color: #0066CC; color: white;"
        )
        self.btn_sso_login.clicked.connect(self.authenticate_with_sso)
        self.btn_sso_login.setVisible(False)
        button_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        pii_layout.addLayout(button_layout)
        
        # Add the PII tab to tab widget
        self.tab_widget.addTab(self.pii_tab, "PII Data Management")
        
        # Create and add YouTube Downloader tab
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
        """
        Process API request to get data.

        Returns:
            DataFrame or None: The processed data or None if error
        """
        try:
            response = requests.get(CONSTANTS.URL)
            if response.status_code != 200:
                QMessageBox.warning(
                    self,
                    "Error",
                    f"Failed to fetch data from server. Status code: {response.status_code}"
                )
                return None
            data = pd.DataFrame.from_records(response.json())
            return data
        except Exception as e:
            QMessageBox.warning(
                self,
                "Error",
                f"Failed to fetch data from server: {str(e)}"
            )
            return None

    def insert_to_db(self, dialog, category, type_, pii):
        """
        Insert new entry to the database.

        Args:
            dialog (QDialog): The parent dialog
            category (str): Category for the new entry
            type_ (str): Type for the new entry
            pii (list): List of PII data items
        """
        try:
            new_entry = {
                "Category": category,
                "Type": type_,
                "PII": str(pii)
            }
            response = requests.post(CONSTANTS.URL, json=new_entry)
            if response.status_code == 200:
                # We don't need to store the response data in this case
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
                    f"Failed to insert new entry. Status code: {response.status_code}"
                )
        except (ValueError, SyntaxError) as e:
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

    def show_password_input(self):
        """Show password input and SSO login option for authentication."""
        self.btn_connect_server.setText('Authenticating...')
        self.btn_connect_server.setDisabled(True)
        self.btn_connect_server.setStyleSheet(
            "background-color: gray; color: white;"
        )
        self.password_input.setHidden(False)  # Make the password input visible
        if hasattr(self, 'btn_sso_login'):  # Check if attribute exists
            self.btn_sso_login.setVisible(True)   # Make the SSO login button visible
        self.password_input.setFocus()
        self.btn_connect_server.clicked.disconnect(self.show_password_input)
        self.btn_connect_server.clicked.connect(self.authenticate_and_connect)

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

    def show_data_window(self):
        """Show window with data table."""
        if not self.assistant:
            QMessageBox.warning(self, "Error", "Not connected to server.")
            return

        try:
            # Secure the window by disabling certain features
            data_window = QMainWindow(self)
            data_window.setWindowTitle("Your Guard Data")
            window_flags = (Qt.Window | Qt.CustomizeWindowHint | Qt.WindowTitleHint |
                            Qt.WindowCloseButtonHint | Qt.WindowMinimizeButtonHint)
            data_window.setWindowFlags(window_flags)

            central_widget = QWidget(data_window)
            data_window.setCentralWidget(central_widget)
            layout = QVBoxLayout(central_widget)

            self.table_widget = QTableWidget()
            layout.addWidget(self.table_widget)

            # Fetch and process data
            try:
                response = requests.get(CONSTANTS.URL)
                data_frame = self.handle_data_response(response)
            except json.JSONDecodeError as jde:
                self.update_log(
                    self.assistant.get_current_time(),
                    f'JSON Error: {str(jde)}'
                )
                QMessageBox.warning(
                    self,
                    "Data Error",
                    "Received data is not in JSON format."
                )
                return
            except (subprocess.CalledProcessError, ValueError) as e:
                self.update_log(
                    self.assistant.get_current_time(),
                    f'Error: {str(e)}'
                )
                QMessageBox.warning(
                    self,
                    "Connection Error",
                    "Invalid server response or connection issue. Please check the server."
                )
                return

            # Set DataFrame data to QTableWidget
            if isinstance(data_frame, pd.DataFrame):
                self.populate_table_widget(data_frame)
                self.table_widget.setContextMenuPolicy(Qt.CustomContextMenu)
                self.table_widget.customContextMenuRequested.connect(
                    self.open_context_menu
                )

            # Add download button
            btn_download = QPushButton('Download Data', data_window)
            btn_download.setCursor(QCursor(Qt.PointingHandCursor))
            btn_download.setIcon(QIcon('download.png'))
            btn_download.clicked.connect(self.download_pii)
            layout.addWidget(btn_download)

            # Configure table appearance
            self.configure_table_widget()

            # Show window
            self.pii_table_start_time = time.time()
            data_window.showMaximized()
            data_window.show()

            # Define window close event handler
            def on_close_event(event):
                """Handle data window close event."""
                event.accept()
                close_event_start_time = time.time()
                self.update_log(
                    self.assistant.get_current_time(),
                    'Guard Window Closed'
                )

                if self.modified:
                    self.update_log(
                        self.assistant.get_current_time(),
                        'Data Backup Initiated...'
                    )
                    # Use updated method signature without parameters
                    self.agent.upload_securely()
                    self.update_log(
                        self.assistant.get_current_time(),
                        'Refreshing Data...'
                    )
                    refresh_time = time.time()
                    data = self.process_request()
                    if data is not None:
                        refresh_duration = time.time() - refresh_time
                        self.update_log(
                            self.assistant.get_current_time(),
                            'Data Refreshed in %.2f Seconds' % refresh_duration
                        )
                        self.populate_data_table(data)
                        backup_duration = time.time() - close_event_start_time
                        self.update_log(
                            self.assistant.get_current_time(),
                            'Data Backed Up in %.2f Seconds' % backup_duration
                        )

                close_event_time = close_event_start_time - self.pii_table_start_time
                self.update_log(
                    self.assistant.get_current_time(),
                    'Guard Window Closed after %.2f Seconds' % close_event_time
                )

            data_window.closeEvent = on_close_event

        except subprocess.CalledProcessError as e:
            if 'ConnectionError' in str(e):
                self.update_log(
                    self.assistant.get_current_time(),
                    'Connection Error: Unable to reach server.'
                )
                QMessageBox.warning(
                    self,
                    "Connection Error",
                    "Please run the Server. Application unable to detect SERVER"
                )
                return

            QMessageBox.warning(
                self,
                "Connection Error",
                "Please run the Server. Application unable to detect SERVER"
            )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"An unexpected error occurred: {str(e)}"
            )

    def open_context_menu(self, position):
        """
        Show context menu for table items.

        Args:
            position: Position for the menu
        """
        menu = QMenu()

        copy_action = QAction('Copy', self)
        copy_action.triggered.connect(self.copy_selected_row)
        menu.addAction(copy_action)

        edit_action = QAction('Edit', self)
        edit_action.triggered.connect(self.edit_selected_row)
        menu.addAction(edit_action)

        delete_action = QAction('Delete', self)
        delete_action.triggered.connect(self.delete_item)
        menu.addAction(delete_action)

        menu.exec_(self.table_widget.viewport().mapToGlobal(position))

    def edit_selected_row(self):
        """Edit the selected row data."""
        if not hasattr(self, 'table_widget') or not self.table_widget:
            return

        selected_items = self.table_widget.selectedItems()
        if not selected_items:
            return

        row = selected_items[0].row()
        # Find the PII column
        for col in range(self.table_widget.columnCount()):
            header = self.table_widget.horizontalHeaderItem(col).text()
            if header == 'PII':
                item = self.table_widget.item(row, col)
                break
        else:
            return  # PII column not found

        if item is None:
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
        Process the result of editing PII data.

        Args:
            selected_items: Selected table items
            item: The specific item being edited
            edits: List of edit field pairs (name, data)
        """
        new_values = []
        for item_name_edit, data_edit in edits:
            new_item_name = item_name_edit.text()
            new_data = data_edit.text()
            new_values.append(f"{new_item_name} - {new_data}")

        new_value = '\n'.join(new_values)
        item.setText(new_value)

        # Convert edited entries into JSON format
        final_value_list = [
            {"Item Name": item_name_edit.text(), "Data": data_edit.text()}
            for item_name_edit, data_edit in edits
        ]
        final_value = json.dumps(final_value_list)

        final_item = {}
        for i in selected_items:
            row = i.row()
            column = i.column()
            column_name = self.table_widget.horizontalHeaderItem(column).text()
            final_item[column_name] = self.table_widget.item(
                row, column).text()

        final_item["PII"] = final_value.replace('"', "\'")
        self.time_update_start_time = time.time()

        try:
            response = requests.patch(CONSTANTS.URL, json=final_item)
            if response.status_code == 200:
                response_data = response.json()
                update_time = time.time() - self.time_update_start_time
                self.update_log(
                    self.assistant.get_current_time(),
                    "Update Time: %.2f Seconds" % update_time
                )
                self.update_log(
                    self.assistant.get_current_time(),
                    f"Update Function Response: {response_data}"
                )
                self.update_log(
                    self.assistant.get_current_time(),
                    f"Modified: {final_item['Category']}'s {final_item['Type']} - Guard Data"
                )
                self.modified = True
                QMessageBox.information(
                    self,
                    "Update Successful",
                    "Data updated successfully!"
                )
            else:
                QMessageBox.warning(
                    self,
                    "Update Failed",
                    f"Failed to update data! Status code: {response.status_code}"
                )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"An error occurred while updating: {str(e)}"
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
        """Authenticate user and connect to server."""
        password = self.password_input.text()
        env_password = CONSTANTS.APP_PASSWORD
        self.btn_connect_server.setText('Logging in...')

        if not env_password:
            QMessageBox.warning(
                self,
                "Security Warning",
                "Please Activate your Secure Environment before performing operations"
            )
            self.btn_connect_server.setText('Connect to Server')
            self.btn_connect_server.setDisabled(False)
            self.password_input.setHidden(True)
            return

        hashed_input_password = hashlib.sha256(password.encode()).hexdigest()
        hashed_env_password = hashlib.sha256(env_password.encode()).hexdigest()

        if hashed_input_password == hashed_env_password:
            self.btn_connect_server.setStyleSheet(
                "background-color: orange; color: white;"
            )
            self.password_input.clear()
            self.password_input.setHidden(True)
            self.connect_to_server()
            self.update_log(
                self.assistant.get_current_time(),
                'Authentication Successful'
            )
        else:
            QMessageBox.warning(
                self,
                "Authentication Failed",
                "Incorrect Password!"
            )
            self.password_input.clear()
            self.btn_connect_server.setText('Connect to Server')
            self.btn_connect_server.setDisabled(False)
            self.btn_connect_server.clicked.disconnect(
                self.authenticate_and_connect
            )
            self.btn_connect_server.clicked.connect(self.show_password_input)

    def connect_to_server(self):
        """Connect to the backend server and set up the interface."""
        self.btn_connect_server.setDisabled(True)
        try:
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

            # Create logout button
            self.create_logout_button()

            # Set up timer for status updates
            self.timer = QTimer(self)
            self.timer.timeout.connect(self.fetch_status)
            self.timer.start(1000)

            # Get initial data
            data = self.process_request()
            if data is not None:
                self.populate_data_table(data)

            # Log successful connection
            self.update_log(
                self.assistant.get_current_time(),
                "Connected to Server."
            )
            self.update_log(
                self.assistant.get_current_time(),
                'Display Data Button: Activated'
            )
            self.update_log(
                self.assistant.get_current_time(),
                'Add New Entry Button: Activated'
            )
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

    def create_logout_button(self):
        """Create and position the logout button."""
        self.btn_logout = QPushButton('LogOut', self)
        self.btn_logout.setCursor(QCursor(Qt.PointingHandCursor))
        self.btn_logout.clicked.connect(self.logout_user)
        self.btn_logout.setShortcut("Ctrl+W")
        self.btn_logout.resize(100, 40)
        self.btn_logout.show()
        self.btn_logout.setStyleSheet(
            "background-color: orange; color: white;"
        )
        self.btn_logout.setDisabled(False)
        self.btn_logout.setToolTip('Click to Logout')
        # Position the logout to right side corner in the Top Right Corner
        self.btn_logout.move(
            self.width() - self.btn_logout.width() - 10,
            10
        )

    def on_data_table_selection(self):
        """Handle selection in the data table to show sub-options."""
        if not self.agent:
            return

        selected_items = self.data_table.selectedItems()
        if not selected_items:
            return

        selected_item_text = selected_items[0].text()
        try:
            sub_options = self.agent.get_sub_options_to_choose(
                selected_item_text
            )
            self.update_log(
                self.assistant.get_current_time(),
                f"Selected item: {selected_item_text}"
            )

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
                output = self.agent.get_final_output(sub_option)
                self.update_log(
                    self.assistant.get_current_time(),
                    f"Selected {selected_item_text}'s sub option: {sub_option}"
                )
                self.show_output_dialog(sub_option, output)
        except Exception as e:
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
            output (list): The output data to display
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
        num_items = len(output) if isinstance(output, list) else 1
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
        """Delete the selected item from the database."""
        if not hasattr(self, 'table_widget') or not self.table_widget:
            QMessageBox.warning(
                self,
                "Delete Error",
                "Data table not available."
            )
            return

        selected_items = self.table_widget.selectedItems()
        if not selected_items:
            QMessageBox.warning(
                self,
                "Delete Error",
                "No item selected to delete."
            )
            return

        # Get item information from table
        item_info = self.get_item_info_from_selection(selected_items)
        if not self.confirm_delete(item_info):
            return

        # Perform deletion
        self.perform_delete_operation(item_info, selected_items[0].row())

    def get_item_info_from_selection(self, selected_items):
        """
        Extract item information from selected items.

        Args:
            selected_items: Selected table items

        Returns:
            dict: Item information
        """
        item_info = {'Category': '', 'Type': '', '_id': ''}
        row = selected_items[0].row()

        # Find Category, Type and _id columns
        for column in range(self.table_widget.columnCount()):
            header = self.table_widget.horizontalHeaderItem(column).text()
            item = self.table_widget.item(row, column)
            if not item:
                continue

            if header == 'Category':
                item_info['Category'] = item.text()
            elif header == 'Type':
                item_info['Type'] = item.text()
            elif header == '_id':
                item_info['_id'] = item.text()

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
            
    def handle_session_expired(self):
        """Handle expired session."""
        QMessageBox.warning(
            self,
            "Session Expired",
            "Your session has expired. Please log in again."
        )
        self.logout_user()

    def handle_token_refreshed(self):
        """Handle token refresh event."""
        session_info = self.session_manager.get_session_info()
        self.update_log(
            self.assistant.get_current_time() if self.assistant else 
            QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
            f"Session token refreshed. New expiration: {session_info['remaining_formatted']}"
        )

    def show_session_info(self):
        """Show current session information."""
        if not self.session_manager.is_authenticated:
            QMessageBox.information(
                self,
                "Session Info",
                "You are not currently logged in."
            )
            return
        
        session_info = self.session_manager.get_session_info()
        
        QMessageBox.information(
            self,
            "Session Info",
            f"Authentication Type: {session_info['auth_type']}\n"
            f"Session Expires: {session_info['remaining_formatted']} from now\n"
            f"({session_info['expiration_time']})"
        )

# Modify the authenticate_and_connect method:
    def authenticate_and_connect(self):
        """Authenticate user and connect to server."""
        password = self.password_input.text()
        env_password = CONSTANTS.APP_PASSWORD
        self.btn_connect_server.setText('Logging in...')

        if not env_password:
            QMessageBox.warning(
                self,
                "Security Warning",
                "Please Activate your Secure Environment before performing operations"
            )
            self.btn_connect_server.setText('Connect to Server')
            self.btn_connect_server.setDisabled(False)
            self.password_input.setHidden(True)
            return

        # Authenticate using password
        hashed_env_password = hashlib.sha256(env_password.encode()).hexdigest()
        auth_success = self.session_manager.authenticate_password(password, hashed_env_password)
        
        if auth_success:
            self.btn_connect_server.setStyleSheet(
                "background-color: orange; color: white;"
            )
            self.password_input.clear()
            self.password_input.setHidden(True)
            self.connect_to_server()
            
            session_info = self.session_manager.get_session_info()
            self.update_log(
                self.assistant.get_current_time() if self.assistant else 
                QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
                f"Authentication Successful - Session valid for {session_info['remaining_formatted']}"
            )
        else:
            QMessageBox.warning(
                self,
                "Authentication Failed",
                "Incorrect Password!"
            )
            self.password_input.clear()
            self.btn_connect_server.setText('Connect to Server')
            self.btn_connect_server.setDisabled(False)
            self.btn_connect_server.clicked.disconnect(
                self.authenticate_and_connect
            )
            self.btn_connect_server.clicked.connect(self.show_password_input)

# Modify the logout_user method:
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
        
        # Logout from session manager
        self.session_manager.logout()
        
        self.assistant.logout()
        self.agent = None
        
        # Switch to YouTube downloader tab again to ensure it's visible
        if hasattr(self, 'tab_widget') and hasattr(self, 'downloader_widget'):
            downloader_tab_index = self.tab_widget.indexOf(self.downloader_widget)
            self.tab_widget.setCurrentIndex(downloader_tab_index)

# Add AWS SSO login option in the create_logout_button method:
    def create_logout_button(self):
        """Create and position the logout button."""
        # Create button layout in the top right corner
        button_layout = QHBoxLayout()
        button_layout.setContentsMargins(0, 0, 10, 0)  # Right margin of 10
        
        # Session info button
        self.btn_session_info = QPushButton('Session Info', self)
        self.btn_session_info.setCursor(QCursor(Qt.PointingHandCursor))
        self.btn_session_info.clicked.connect(self.show_session_info)
        self.btn_session_info.setShortcut("Ctrl+I")
        self.btn_session_info.resize(100, 40)
        self.btn_session_info.setStyleSheet(
            "background-color: #4682B4; color: white;"
        )
        self.btn_session_info.setToolTip('View session information')
        button_layout.addWidget(self.btn_session_info)
        
        # Logout button
        self.btn_logout = QPushButton('LogOut', self)
        self.btn_logout.setCursor(QCursor(Qt.PointingHandCursor))
        self.btn_logout.clicked.connect(self.logout_user)
        self.btn_logout.setShortcut("Ctrl+W")
        self.btn_logout.resize(100, 40)
        self.btn_logout.setStyleSheet(
            "background-color: orange; color: white;"
        )
        self.btn_logout.setToolTip('Click to Logout')
        button_layout.addWidget(self.btn_logout)
        
        # Create a container widget for the buttons
        container = QWidget(self)
        container.setLayout(button_layout)
        container.setGeometry(
            self.width() - 230, 10, 220, 50
        )
        container.show()
        
        # Add AWS SSO option to connect dialog
        self.btn_sso_login = QPushButton('AWS SSO Login', self)
        self.btn_sso_login.setCursor(QCursor(Qt.PointingHandCursor))
        self.btn_sso_login.setStyleSheet(
            "background-color: #0066CC; color: white;"
        )
        self.btn_sso_login.clicked.connect(self.authenticate_with_sso)
        self.btn_sso_login.setVisible(False)
        
        # Find the password input in the layout and add SSO button below it
        for i in range(self.pii_tab.layout().count()):
            item = self.pii_tab.layout().itemAt(i)
            if item and item.widget() == self.password_input:
                self.pii_tab.layout().insertWidget(i+1, self.btn_sso_login)
                break

# Add a new method for SSO authentication:
    def authenticate_with_sso(self):
        """Authenticate using AWS SSO."""
        self.btn_sso_login.setText('Authenticating with SSO...')
        self.btn_sso_login.setDisabled(True)
        
        # Start authentication in a separate thread to keep UI responsive
        def auth_thread():
            auth_success = self.session_manager.authenticate_aws_sso(self)
            
            # Update UI in main thread
            if auth_success:
                # Connect to server and update UI
                QTimer.singleShot(0, lambda: self.connect_to_server())
                
                # Update session info in logs
                session_info = self.session_manager.get_session_info()
                QTimer.singleShot(0, lambda: self.update_log(
                    QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
                    f"AWS SSO Authentication Successful - Session valid for {session_info['remaining_formatted']}"
                ))
            else:
                # Reset button state
                QTimer.singleShot(0, lambda: self.btn_sso_login.setText('AWS SSO Login'))
                QTimer.singleShot(0, lambda: self.btn_sso_login.setDisabled(False))
        
        # Start the thread
        threading.Thread(target=auth_thread, daemon=True).start()

# Modify the show_password_input method to also show the SSO login option:
    def show_password_input(self):
        """Show password input and SSO login option for authentication."""
        self.btn_connect_server.setText('Authenticating...')
        self.btn_connect_server.setDisabled(True)
        self.btn_connect_server.setStyleSheet(
            "background-color: gray; color: white;"
        )
        self.password_input.setHidden(False)  # Make the password input visible
        self.btn_sso_login.setVisible(True)   # Make the SSO login button visible
        self.password_input.setFocus()
        self.btn_connect_server.clicked.disconnect(self.show_password_input)
        self.btn_connect_server.clicked.connect(self.authenticate_and_connect)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PIIWindow()
    sys.exit(app.exec_())

# export PYTHONPATH=$PYTHONPATH:$(pwd)