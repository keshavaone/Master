"""
Enhanced data dialog with proper CRUD functionality for PII data management.
"""

import os
import logging
import ast
import json
import time
import traceback
from typing import Any, Dict, List, Tuple, Optional, Union

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem, 
    QPushButton, QLabel, QLineEdit, QComboBox, QMessageBox, QFrame,
    QHeaderView, QAbstractItemView, QApplication, QSplitter, QWidget,
    QGroupBox, QFormLayout, QTextEdit, QScrollArea, QSizePolicy, QStyle,
    QProgressDialog, QMenu, QDialogButtonBox
)
from PyQt5.QtCore import Qt, QSize, QTimer, QDateTime
from PyQt5.QtGui import QIcon, QColor, QPalette, QFont
import pandas as pd

class EnhancedDataDialog(QDialog):
    """Enhanced dialog for displaying and managing PII data."""
    
    def __init__(self, parent=None, api_client=None, auth_service=None, agent=None):
        """
        Initialize the enhanced data dialog.
        
        Args:
            parent: Parent widget
            api_client: API client for data operations
            auth_service: Authentication service for API requests
            agent: Backend agent for direct operations
        """
        super().__init__(parent)
        self.parent = parent
        self.api_client = api_client
        self.auth_service = auth_service
        self.agent = agent
        self.data = None
        self.filtered_data = None
        self.current_item = None
        
        # Set up logger
        self.logger = logging.getLogger('EnhancedDataDialog')
        self.logger.setLevel(logging.INFO)
        
        # Set window properties
        self.setWindowTitle("Your GUARD Data")
        self.resize(1000, 700)
        
        # Set up UI
        self.setup_ui()
        
        # Fetch initial data
        self.fetch_data()
        
    def setup_ui(self):
        """Set up the user interface with improved styling for better readability."""
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # Header with filters and actions - styled for better visibility
        header_frame = QFrame()
        header_frame.setFrameShape(QFrame.StyledPanel)
        header_frame.setStyleSheet("""
            QFrame {
                background-color: #f0f4f8;
                border: 1px solid #d0d8e0;
                border-radius: 8px;
            }
        """)
        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(15, 10, 15, 10)
        
        # Filter section
        filter_group = QGroupBox("Data Filters")
        filter_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #c0c0c0;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 5px;
                color: #0066cc;
            }
        """)
        
        filter_layout = QHBoxLayout(filter_group)
        filter_layout.setContentsMargins(10, 10, 10, 10)
        filter_layout.setSpacing(10)
        
        # Category filter with improved styling
        category_label = QLabel("Category:")
        category_label.setStyleSheet("font-weight: bold;")
        self.category_filter = QComboBox()
        self.category_filter.addItem("All Categories")
        self.category_filter.setStyleSheet("""
            QComboBox {
                border: 1px solid #c0c0c0;
                border-radius: 4px;
                padding: 5px;
                min-width: 150px;
            }
            QComboBox::drop-down {
                border-left: 1px solid #c0c0c0;
                width: 20px;
            }
        """)
        self.category_filter.currentIndexChanged.connect(self.apply_filters)
        
        # Type filter with improved styling
        type_label = QLabel("Type:")
        type_label.setStyleSheet("font-weight: bold;")
        self.type_filter = QComboBox()
        self.type_filter.addItem("All Types")
        self.type_filter.setStyleSheet("""
            QComboBox {
                border: 1px solid #c0c0c0;
                border-radius: 4px;
                padding: 5px;
                min-width: 150px;
            }
            QComboBox::drop-down {
                border-left: 1px solid #c0c0c0;
                width: 20px;
            }
        """)
        self.type_filter.currentIndexChanged.connect(self.apply_filters)
        
        # Search field with improved styling
        search_label = QLabel("Search:")
        search_label.setStyleSheet("font-weight: bold;")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search in all fields...")
        self.search_input.setStyleSheet("""
            QLineEdit {
                border: 1px solid #c0c0c0;
                border-radius: 4px;
                padding: 5px;
                background-color: white;
                min-width: 200px;
            }
            QLineEdit:focus {
                border: 1px solid #0066cc;
            }
        """)
        self.search_input.textChanged.connect(self.apply_filters)
        
        # Add filters to layout
        filter_layout.addWidget(category_label)
        filter_layout.addWidget(self.category_filter)
        filter_layout.addWidget(type_label)
        filter_layout.addWidget(self.type_filter)
        filter_layout.addWidget(search_label)
        filter_layout.addWidget(self.search_input)
        
        # Add filter section to header
        header_layout.addWidget(filter_group)
        
        # Action buttons section
        button_frame = QFrame()
        button_frame.setStyleSheet("background: transparent;")
        button_layout = QHBoxLayout(button_frame)
        button_layout.setContentsMargins(10, 0, 0, 0)
        button_layout.setSpacing(10)
        
        # Refresh button with improved styling
        self.refresh_btn = QPushButton("🔄 Refresh Data")
        self.refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #388E3C;
            }
            QPushButton:pressed {
                background-color: #2E7D32;
            }
        """)
        self.refresh_btn.clicked.connect(self.fetch_data)
        
        # Add new button with improved styling
        self.add_btn = QPushButton("➕ Add New Item")
        self.add_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton:pressed {
                background-color: #0D47A1;
            }
        """)
        self.add_btn.clicked.connect(self.add_new_item)
        
        # Download button with improved styling
        self.download_btn = QPushButton("⬇️ Download All Data")
        self.download_btn.setStyleSheet("""
            QPushButton {
                background-color: #9C27B0;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #7B1FA2;
            }
            QPushButton:pressed {
                background-color: #6A1B9A;
            }
        """)
        # Download button will be connected by the main window
        
        # Add buttons to layout
        button_layout.addWidget(self.refresh_btn)
        button_layout.addWidget(self.add_btn)
        button_layout.addWidget(self.download_btn)
        
        # Add button section to header
        header_layout.addWidget(button_frame)
        
        # Add header to main layout
        main_layout.addWidget(header_frame)
        
        # Data count label
        self.data_count_label = QLabel("Loading data...")
        self.data_count_label.setStyleSheet("""
            font-weight: bold;
            color: #0066cc;
            padding: 5px;
            background-color: #e6f2ff;
            border-radius: 4px;
            margin: 5px 0;
        """)
        main_layout.addWidget(self.data_count_label)
        
        # Create a splitter for the main content area
        self.splitter = QSplitter(Qt.Vertical)
        self.splitter.setChildrenCollapsible(False)
        
        # Table widget in the top section of the splitter
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(['ID', 'Category', 'Type', 'PII Preview'])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet("""
            QTableWidget {
                gridline-color: #d0d0d0;
                selection-background-color: #b3d9ff;
                selection-color: black;
            }
            QHeaderView::section {
                background-color: #f0f4f8;
                padding: 5px;
                font-weight: bold;
                border: 1px solid #d0d0d0;
                border-left: 0px;
                border-top: 0px;
            }
            QTableWidget::item {
                padding: 5px;
            }
        """)
        self.table.setSortingEnabled(True)
        self.table.itemSelectionChanged.connect(self.item_selected)
        
        # Enable context menu for the table
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        
        # Also create table_widget as an alias to self.table for backward compatibility
        self.table_widget = self.table
        
        # Add table to the splitter
        self.splitter.addWidget(self.table)
        
        # Details container for the bottom section of the splitter
        self.details_container = QWidget()
        self.details_container.setVisible(False)  # Initially hidden until a row is selected
        
        # Details group box inside the container
        details_layout = QVBoxLayout(self.details_container)
        details_layout.setContentsMargins(0, 0, 0, 0)
        details_layout.setSpacing(0)
        
        self.details_group = QGroupBox("Item Details")
        self.details_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #c0c0c0;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 5px;
                color: #0066cc;
            }
        """)
        
        # Make the details section scrollable
        details_scroll = QScrollArea()
        details_scroll.setWidgetResizable(True)
        details_scroll.setFrameShape(QFrame.NoFrame)
        
        details_content = QWidget()
        details_content_layout = QVBoxLayout(details_content)
        
        # Form layout for basic info
        form_layout = QFormLayout()
        form_layout.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        form_layout.setContentsMargins(10, 10, 10, 5)
        form_layout.setSpacing(8)
        
        # ID field (read-only)
        self.id_field = QLineEdit()
        self.id_field.setReadOnly(True)
        self.id_field.setStyleSheet("background-color: #f0f0f0;")
        form_layout.addRow("ID:", self.id_field)
        
        # Category field
        self.category_field = QLineEdit()
        form_layout.addRow("Category:", self.category_field)
        
        # Type field
        self.type_field = QLineEdit()
        form_layout.addRow("Type:", self.type_field)
        
        details_content_layout.addLayout(form_layout)
        
        # PII Data section
        pii_group = QGroupBox("PII Data")
        pii_group.setStyleSheet("""
            QGroupBox {
                border: 1px solid #c0c0c0;
                border-radius: 5px;
                margin-top: 5px;
                padding-top: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 5px;
                color: #0066cc;
            }
        """)
        pii_layout = QVBoxLayout(pii_group)
        
        # Create a scroll area specifically for PII items
        pii_scroll = QScrollArea()
        pii_scroll.setWidgetResizable(True)
        pii_container = QWidget()
        self.pii_layout = QVBoxLayout(pii_container)
        pii_scroll.setWidget(pii_container)
        pii_scroll.setMinimumHeight(200)
        pii_layout.addWidget(pii_scroll)
        
        details_content_layout.addWidget(pii_group)
        
        details_scroll.setWidget(details_content)
        
        # Add scroll area to details layout
        details_group_layout = QVBoxLayout(self.details_group)
        details_group_layout.addWidget(details_scroll)
        
        # Buttons for details
        buttons_layout = QHBoxLayout()
        
        clear_btn = QPushButton("🗑️ Clear")
        clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #9E9E9E;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #757575;
            }
        """)
        clear_btn.clicked.connect(self.clear_details)
        
        self.save_btn = QPushButton("💾 Save Changes")
        self.save_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #388E3C;
            }
            QPushButton:disabled {
                background-color: #A5D6A7;
                color: #E8F5E9;
            }
        """)
        self.save_btn.setEnabled(False)
        self.save_btn.clicked.connect(self.save_item)
        
        self.delete_btn = QPushButton("❌ Delete Item")
        self.delete_btn.setStyleSheet("""
            QPushButton {
                background-color: #F44336;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #D32F2F;
            }
            QPushButton:disabled {
                background-color: #FFCDD2;
                color: #FFEBEE;
            }
        """)
        self.delete_btn.setEnabled(False)
        self.delete_btn.clicked.connect(self.delete_item)
        
        buttons_layout.addWidget(clear_btn)
        buttons_layout.addStretch()
        buttons_layout.addWidget(self.save_btn)
        buttons_layout.addWidget(self.delete_btn)
        
        details_group_layout.addLayout(buttons_layout)
        
        # Add details group to the container
        details_layout.addWidget(self.details_group)
        
        # Add the details container to the splitter
        self.splitter.addWidget(self.details_container)
        
        # Set initial sizes for the splitter (70% table, 30% details)
        self.splitter.setSizes([700, 300])
        
        # Add the splitter to the main layout
        main_layout.addWidget(self.splitter, stretch=1)
        
        # Status bar
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #666; font-style: italic;")
        main_layout.addWidget(self.status_label)
        
    def fetch_data(self):
        """Fetch PII data from the server with robust error handling and protection against widget deletion."""
        # Show loading indicator
        try:
            self.setCursor(Qt.WaitCursor)
        except RuntimeError:
            # Widget may have been deleted
            return
        
        # Update status label if it exists
        try:
            if hasattr(self, 'status_label') and self.status_label is not None:
                self.status_label.setText("Connecting to server...")
        except RuntimeError:
            # Widget may have been deleted
            pass
            
        # Show progress dialog - create locally to avoid reference issues
        try:
            progress = QProgressDialog("Fetching data from server...", "Cancel", 0, 100, self)
            progress.setWindowTitle("Loading Data")
            progress.setWindowModality(Qt.WindowModal)
            progress.setMinimumDuration(0)  # Show immediately
            progress.setValue(10)
            progress.show()
            QApplication.processEvents()
        except RuntimeError:
            # Widget creation failed
            self.logger.error("Failed to create progress dialog")
            return
        
        try:
            # Try API client first
            if self.api_client:
                self.logger.info("Fetching data using API client")
                try:
                    if hasattr(self, 'status_label') and self.status_label is not None:
                        self.status_label.setText("Fetching data using API client...")
                except RuntimeError:
                    pass
                
                try:
                    progress.setValue(30)
                    QApplication.processEvents()
                except RuntimeError:
                    pass
                    
                success, data = self.api_client.sync_get_pii_data()
                
                try:
                    progress.setValue(70)
                    QApplication.processEvents()
                except RuntimeError:
                    pass
                    
                if success:
                    if isinstance(data, list):
                        self.data = data
                    else:
                        # Handle non-list response
                        if isinstance(data, dict):
                            self.data = [data]
                        else:
                            # Try to convert to list
                            try:
                                self.data = list(data)
                            except:
                                self.data = [{"Raw Data": str(data)}]
                    
                    self.logger.info(f"Fetched {len(self.data)} PII items")
                    try:
                        if hasattr(self, 'status_label') and self.status_label is not None:
                            self.status_label.setText(f"Successfully loaded {len(self.data)} items")
                    except RuntimeError:
                        pass
                        
                    try:
                        progress.setValue(90)
                        QApplication.processEvents()
                    except RuntimeError:
                        pass
                    
                    # Update filters and table safely
                    try:
                        self.update_filters()
                        self.apply_filters()
                    except RuntimeError:
                        self.logger.warning("Widget error during UI update")
                    
                    # Finish progress
                    try:
                        progress.setValue(100)
                        QApplication.processEvents()
                    except RuntimeError:
                        pass
                else:
                    error_msg = data.get('error', str(data)) if isinstance(data, dict) else str(data)
                    self.logger.error(f"API client error: {error_msg}")
                    
                    # Update status label with error
                    try:
                        if hasattr(self, 'status_label') and self.status_label is not None:
                            self.status_label.setText(f"Error: {error_msg}")
                            self.status_label.setStyleSheet("color: red; font-weight: bold;")
                    except RuntimeError:
                        pass
                    
                    try:
                        progress.close()
                    except RuntimeError:
                        pass
                        
                    raise ValueError(f"API client error: {error_msg}")
            
            # Fall back to auth_service
            elif self.auth_service:
                # Similar error handling for the auth_service section...
                self.logger.info("Fetching data using auth service")
                try:
                    if hasattr(self, 'status_label') and self.status_label is not None:
                        self.status_label.setText("Fetching data using auth service...")
                except RuntimeError:
                    pass
                
                try:
                    progress.setValue(30)
                    QApplication.processEvents()
                except RuntimeError:
                    pass
                
                # Handle both synchronous and asynchronous make_authenticated_request
                import inspect
                if hasattr(self.auth_service, 'make_authenticated_request'):
                    if inspect.iscoroutinefunction(self.auth_service.make_authenticated_request):
                        # Async method
                        import asyncio
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        try:
                            success, data = loop.run_until_complete(
                                self.auth_service.make_authenticated_request("GET", "pii")
                            )
                        finally:
                            loop.close()
                    else:
                        # Sync method
                        success, data = self.auth_service.make_authenticated_request("GET", "pii")
                elif hasattr(self.auth_service, 'make_synchronous_request'):
                    success, data = self.auth_service.make_synchronous_request("GET", "pii")
                else:
                    raise ValueError("Auth service does not have a suitable request method")
                
                try:
                    progress.setValue(70)
                    QApplication.processEvents()
                except RuntimeError:
                    pass
                
                if success:
                    if isinstance(data, list):
                        self.data = data
                    else:
                        # Handle non-list response
                        if isinstance(data, dict):
                            self.data = [data]
                        else:
                            # Try to convert to list
                            try:
                                self.data = list(data)
                            except:
                                self.data = [{"Raw Data": str(data)}]
                    
                    self.logger.info(f"Fetched {len(self.data)} PII items")
                    try:
                        if hasattr(self, 'status_label') and self.status_label is not None:
                            self.status_label.setText(f"Successfully loaded {len(self.data)} items")
                    except RuntimeError:
                        pass
                        
                    try:
                        progress.setValue(90)
                        QApplication.processEvents()
                    except RuntimeError:
                        pass
                    
                    # Update filters and table safely
                    try:
                        self.update_filters()
                        self.apply_filters()
                    except RuntimeError:
                        self.logger.warning("Widget error during UI update")
                    
                    # Finish progress
                    try:
                        progress.setValue(100)
                        QApplication.processEvents()
                    except RuntimeError:
                        pass
                else:
                    error_msg = data.get('error', str(data)) if isinstance(data, dict) else str(data)
                    self.logger.error(f"Auth service error: {error_msg}")
                    
                    # Update status label with error
                    try:
                        if hasattr(self, 'status_label') and self.status_label is not None:
                            self.status_label.setText(f"Error: {error_msg}")
                            self.status_label.setStyleSheet("color: red; font-weight: bold;")
                    except RuntimeError:
                        pass
                    
                    try:
                        progress.close()
                    except RuntimeError:
                        pass
                        
                    raise ValueError(f"Auth service error: {error_msg}")
                
            # Last resort: try agent directly
            elif self.agent:
                self.logger.info("Fetching data using direct agent access")
                try:
                    if hasattr(self, 'status_label') and self.status_label is not None:
                        self.status_label.setText("Fetching data using direct agent access...")
                except RuntimeError:
                    pass
                
                try:
                    progress.setValue(30)
                    QApplication.processEvents()
                except RuntimeError:
                    pass
                
                data = self.agent.get_all_data()
                
                try:
                    progress.setValue(70)
                    QApplication.processEvents()
                except RuntimeError:
                    pass
                
                if data:
                    if isinstance(data, list):
                        self.data = data
                    else:
                        # Handle non-list response
                        if isinstance(data, dict):
                            self.data = [data]
                        elif isinstance(data, pd.DataFrame):
                            self.data = data.to_dict(orient='records')
                        else:
                            # Try to convert to list
                            try:
                                self.data = list(data)
                            except:
                                self.data = [{"Raw Data": str(data)}]
                    
                    self.logger.info(f"Fetched {len(self.data)} PII items")
                    try:
                        if hasattr(self, 'status_label') and self.status_label is not None:
                            self.status_label.setText(f"Successfully loaded {len(self.data)} items")
                    except RuntimeError:
                        pass
                        
                    try:
                        progress.setValue(90)
                        QApplication.processEvents()
                    except RuntimeError:
                        pass
                    
                    # Update filters and table safely
                    try:
                        self.update_filters()
                        self.apply_filters()
                    except RuntimeError:
                        self.logger.warning("Widget error during UI update")
                    
                    # Finish progress
                    try:
                        progress.setValue(100)
                        QApplication.processEvents()
                    except RuntimeError:
                        pass
                else:
                    error_msg = "No data returned from agent"
                    self.logger.error(error_msg)
                    
                    # Update status label with error
                    try:
                        if hasattr(self, 'status_label') and self.status_label is not None:
                            self.status_label.setText(f"Error: {error_msg}")
                            self.status_label.setStyleSheet("color: red; font-weight: bold;")
                    except RuntimeError:
                        pass
                    
                    try:
                        progress.close()
                    except RuntimeError:
                        pass
                        
                    raise ValueError(error_msg)
                
            else:
                try:
                    if hasattr(self, 'status_label') and self.status_label is not None:
                        self.status_label.setText("Error: No data source available")
                        self.status_label.setStyleSheet("color: red; font-weight: bold;")
                except RuntimeError:
                    pass
                    
                try:
                    progress.close()
                except RuntimeError:
                    pass
                    
                raise ValueError("No data source available (API client, auth service, or agent)")
                
        except Exception as e:
            self.logger.error(f"Error fetching data: {str(e)}")
            
            # Show error dialog with detailed information
            try:
                error_dialog = QMessageBox(self)
                error_dialog.setWindowTitle("Data Fetch Error")
                error_dialog.setIcon(QMessageBox.Critical)
                error_dialog.setText("Failed to fetch data from server")
                error_dialog.setInformativeText(str(e))
                error_dialog.setDetailedText(traceback.format_exc())
                error_dialog.setStandardButtons(QMessageBox.Ok)
                error_dialog.exec_()
            except RuntimeError:
                # Dialog creation failed - widget issues
                self.logger.error("Could not create error dialog due to widget issue")
            
        finally:
            # Ensure progress dialog is closed
            try:
                progress.close()
            except (RuntimeError, NameError):
                pass
            
            # Reset cursor
            try:
                self.setCursor(Qt.ArrowCursor)
            except RuntimeError:
                pass
                
    def populate_table(self):
        """
        Populate the table with filtered data using improved styling and formatting.
        This method ensures consistent appearance and optimal readability.
        """
        # Check if table exists
        if not hasattr(self, 'table') or self.table is None:
            return
        
        # Define theme colors for UI consistency
        class StandardTheme:
            PRIMARY = "#1976D2"
            PRIMARY_LIGHT = "#BBDEFB"
            GRAY_100 = "#F5F5F5"
            GRAY_300 = "#E0E0E0"
            GRAY_400 = "#BDBDBD"
            TEXT_PRIMARY = "#212121"
            BG_DEFAULT = "#FFFFFF"
        
        # Clear existing rows
        self.table.setRowCount(0)
        
        if not self.filtered_data:
            return
        
        # Apply standardized styling to table
        self.table.setStyleSheet("""
            QTableWidget {
                gridline-color: """ + StandardTheme.GRAY_300 + """;
                border: 1px solid """ + StandardTheme.GRAY_300 + """;
                border-radius: 4px;
                selection-background-color: """ + StandardTheme.PRIMARY_LIGHT + """;
                selection-color: """ + StandardTheme.TEXT_PRIMARY + """;
                alternate-background-color: """ + StandardTheme.GRAY_100 + """;
            }
            QHeaderView::section {
                background-color: """ + StandardTheme.PRIMARY_LIGHT + """;
                padding: 6px;
                border: 1px solid """ + StandardTheme.GRAY_300 + """;
                font-weight: bold;
                color: """ + StandardTheme.PRIMARY + """;
            }
            QTableWidget::item {
                padding: 6px;
            }
            QTableWidget::item:selected {
                color: """ + StandardTheme.TEXT_PRIMARY + """;
            }
        """)
        
        # Configure for alternating row colors
        self.table.setAlternatingRowColors(True)
        
        # Add data with improved styling
        for row, item in enumerate(self.filtered_data):
            self.table.insertRow(row)
            
            # ID column with monospace font for better readability
            id_item = QTableWidgetItem(item.get('_id', ''))
            id_item.setTextAlignment(Qt.AlignCenter)
            id_item.setFont(QFont("Monospace"))
            self.table.setItem(row, 0, id_item)
            
            # Category column
            category_item = QTableWidgetItem(item.get('Category', ''))
            category_item.setTextAlignment(Qt.AlignCenter)
            category_item.setFont(QFont("", -1, QFont.Bold))
            self.table.setItem(row, 1, category_item)
            
            # Type column
            type_item = QTableWidgetItem(item.get('Type', ''))
            type_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 2, type_item)
            
            # PII Data preview with enhanced formatting
            pii_text = self.get_pii_preview(item.get('PII', ''))
            pii_item = QTableWidgetItem(pii_text)
            self.table.setItem(row, 3, pii_item)
        
        # Optimize column widths
        self.table.resizeColumnsToContents()
        
        # Ensure columns are not too narrow or too wide
        header = self.table.horizontalHeader()
        
        # Set minimum and maximum column widths
        min_widths = [120, 100, 100, 200]  # ID, Category, Type, PII
        max_widths = [200, 200, 200, 400]  # ID, Category, Type, PII
        
        for col in range(min(self.table.columnCount(), len(min_widths))):
            width = header.sectionSize(col)
            width = max(width, min_widths[col])
            width = min(width, max_widths[col])
            header.resizeSection(col, width)
        
        # Allow PII column to stretch
        header.setSectionResizeMode(3, QHeaderView.Stretch)
    
    def get_pii_preview(self, pii_data):
        """
        Get an enhanced preview of PII data for table display with improved formatting.
        
        Args:
            pii_data: PII data to preview
            
        Returns:
            str: Enhanced preview text with better formatting
        """
        try:
            # If it's a string, try to parse it as structured data
            if isinstance(pii_data, str):
                try:
                    parsed_data = ast.literal_eval(pii_data)
                    
                    if isinstance(parsed_data, list):
                        # Count total items
                        item_count = len(parsed_data)
                        
                        # Show first few items with better formatting
                        preview_items = []
                        max_preview_items = min(item_count, 3)  # Show up to 3 items
                        
                        for i, item in enumerate(parsed_data[:max_preview_items]):
                            if isinstance(item, dict) and 'Item Name' in item and 'Data' in item:
                                # Format: "Item Name: Data" with length limits
                                item_name = item['Item Name']
                                item_data = str(item['Data'])
                                
                                # Limit data length for preview
                                if len(item_data) > 30:
                                    item_data = item_data[:27] + "..."
                                    
                                preview_items.append(f"{item_name}: {item_data}")
                            else:
                                # Handle non-standard items
                                item_str = str(item)
                                if len(item_str) > 30:
                                    item_str = item_str[:27] + "..."
                                preview_items.append(item_str)
                        
                        # Format the preview with bullet points
                        formatted_preview = ""
                        for i, preview in enumerate(preview_items):
                            formatted_preview += f"• {preview}\n"
                        
                        # Add count if there are more items
                        if item_count > max_preview_items:
                            additional = item_count - max_preview_items
                            formatted_preview += f"(+ {additional} more item{'s' if additional != 1 else ''})"
                        
                        return formatted_preview.strip()
                    elif isinstance(parsed_data, dict):
                        # For dictionaries, show key-value pairs
                        preview_items = []
                        for k, v in list(parsed_data.items())[:3]:  # Show up to 3 key-value pairs
                            v_str = str(v)
                            if len(v_str) > 30:
                                v_str = v_str[:27] + "..."
                            preview_items.append(f"{k}: {v_str}")
                        
                        # Format with bullet points
                        formatted_preview = ""
                        for i, preview in enumerate(preview_items):
                            formatted_preview += f"• {preview}\n"
                        
                        # Add indicator if there are more items
                        if len(parsed_data) > 3:
                            additional = len(parsed_data) - 3
                            formatted_preview += f"(+ {additional} more key{'s' if additional != 1 else ''})"
                        
                        return formatted_preview.strip()
                    else:
                        # For other types, just convert to string
                        result = str(parsed_data)
                        if len(result) > 100:
                            result = result[:97] + "..."
                        return result
                except (SyntaxError, ValueError):
                    # If parsing fails, just return the string with length limit
                    if len(pii_data) > 100:
                        return pii_data[:97] + "..."
                    return pii_data
            elif isinstance(pii_data, dict):
                # For dictionaries, show key-value pairs
                preview_items = []
                for k, v in list(pii_data.items())[:3]:  # Show up to 3 key-value pairs
                    v_str = str(v)
                    if len(v_str) > 30:
                        v_str = v_str[:27] + "..."
                    preview_items.append(f"{k}: {v_str}")
                
                # Format with bullet points
                formatted_preview = ""
                for i, preview in enumerate(preview_items):
                    formatted_preview += f"• {preview}\n"
                
                # Add indicator if there are more items
                if len(pii_data) > 3:
                    additional = len(pii_data) - 3
                    formatted_preview += f"(+ {additional} more key{'s' if additional != 1 else ''})"
                
                return formatted_preview.strip()
            elif isinstance(pii_data, list):
                # Format list items
                preview_items = []
                max_items = min(len(pii_data), 3)
                
                for i in range(max_items):
                    item_str = str(pii_data[i])
                    if len(item_str) > 30:
                        item_str = item_str[:27] + "..."
                    preview_items.append(item_str)
                
                # Format with bullet points
                formatted_preview = ""
                for i, preview in enumerate(preview_items):
                    formatted_preview += f"• {preview}\n"
                
                # Add count if there are more items
                if len(pii_data) > max_items:
                    additional = len(pii_data) - max_items
                    formatted_preview += f"(+ {additional} more item{'s' if additional != 1 else ''})"
                
                return formatted_preview.strip()
            else:
                # For other types, just convert to string with length limit
                result = str(pii_data)
                if len(result) > 100:
                    result = result[:97] + "..."
                return result
        except Exception as e:
            # In case of errors, return a safe fallback
            return f"Preview unavailable ({type(pii_data).__name__})"
            
    def display_item_details(self, item):
        """
        Display item details in the form with highly improved PII data visualization.
        Protects against widget deletion.
        
        Args:
            item: The item to display
        """
        # Clear existing details first
        try:
            self.clear_pii_fields()
        except RuntimeError:
            self.logger.warning("Error clearing details - widget may have been deleted")
            return
        
        # Set basic fields safely
        try:
            if hasattr(self, 'id_field') and self.id_field is not None:
                self.id_field.setText(item.get('_id', ''))
        except RuntimeError:
            pass
            
        try:
            if hasattr(self, 'category_field') and self.category_field is not None:
                self.category_field.setText(item.get('Category', ''))
        except RuntimeError:
            pass
            
        try:
            if hasattr(self, 'type_field') and self.type_field is not None:
                self.type_field.setText(item.get('Type', ''))
        except RuntimeError:
            pass
        
        # Parse and display PII data
        pii_data = item.get('PII', '')
        pii_items = []
        
        try:
            # Try to parse PII data
            if isinstance(pii_data, str):
                try:
                    pii_items = ast.literal_eval(pii_data)
                    
                    # Check if we got a list of dicts
                    if not isinstance(pii_items, list):
                        pii_items = [{"Item Name": "Data", "Data": str(pii_items)}]
                    elif not all(isinstance(item, dict) for item in pii_items):
                        # Handle list of non-dicts
                        pii_items = [{"Item Name": f"Item {i+1}", "Data": str(item)} for i, item in enumerate(pii_items)]
                except (SyntaxError, ValueError):
                    # If parsing fails, treat as raw text
                    pii_items = [{"Item Name": "Raw Data", "Data": pii_data}]
            else:
                # For non-string data
                pii_items = [{"Item Name": "Data", "Data": str(pii_data)}]
                
            # Check if pii_layout exists and is valid
            try:
                if not hasattr(self, 'pii_layout') or self.pii_layout is None:
                    self.logger.error("PII layout is not available")
                    return
                    
                # Add header for PII data section with count
                header_frame = QFrame()
                header_frame.setStyleSheet("""
                    QFrame {
                        background-color: #e6f2ff;
                        border: 1px solid #99ccff;
                        border-radius: 5px;
                    }
                """)
                header_layout = QHBoxLayout(header_frame)
                
                header_label = QLabel(f"PII Data Items ({len(pii_items)} entries)")
                header_label.setStyleSheet("font-weight: bold; font-size: 14px; color: #0066cc;")
                header_layout.addWidget(header_label)
                
                self.pii_layout.addWidget(header_frame)
                
                # Add a spacer for visual separation
                self.pii_layout.addSpacing(10)
            except RuntimeError:
                self.logger.warning("Error adding PII header - widget may have been deleted")
                return
            
            # Add fields for each PII item with enhanced styling
            for index, pii_item in enumerate(pii_items):
                try:
                    # Create a frame for this item with better styling
                    item_frame = QFrame()
                    item_frame.setFrameShape(QFrame.StyledPanel)
                    item_frame.setFrameShadow(QFrame.Raised)
                    
                    # Alternate colors for better readability
                    if index % 2 == 0:
                        bg_color = "#f8f8f8"
                        border_color = "#e0e0e0"
                    else:
                        bg_color = "#ffffff"
                        border_color = "#d0d0d0"
                        
                    item_frame.setStyleSheet(f"""
                        QFrame {{
                            border: 2px solid {border_color};
                            border-radius: 8px;
                            background-color: {bg_color};
                            margin: 4px;
                        }}
                        QFrame:hover {{
                            border-color: #4361ee;
                            background-color: #f5f8ff;
                        }}
                    """)
                    
                    # Item layout
                    item_layout = QVBoxLayout(item_frame)
                    item_layout.setContentsMargins(12, 12, 12, 12)
                    item_layout.setSpacing(8)
                    
                    # Item header with number and better spacing
                    header_layout = QHBoxLayout()
                    
                    # Item number label with better styling
                    item_number = QLabel(f"Item #{index + 1}")
                    item_number.setStyleSheet("""
                        font-weight: bold; 
                        color: #4361ee; 
                        font-size: 13px;
                        padding: 3px 8px;
                        background-color: #eef2ff;
                        border-radius: 4px;
                    """)
                    header_layout.addWidget(item_number)
                    header_layout.addStretch()
                    
                    # Copy entire item button
                    copy_item_btn = QPushButton("Copy Item")
                    copy_item_btn.setToolTip("Copy the entire item data")
                    copy_item_btn.setStyleSheet("""
                        QPushButton {
                            background-color: #e0e0e0;
                            border: none;
                            padding: 4px 8px;
                            border-radius: 4px;
                        }
                        QPushButton:hover {
                            background-color: #d0d0d0;
                        }
                    """)
                    copy_item_data = f"Name: {pii_item.get('Item Name', '')}\nData: {pii_item.get('Data', '')}"
                    copy_item_btn.clicked.connect(lambda checked, data=copy_item_data: self.copy_to_clipboard(data))
                    header_layout.addWidget(copy_item_btn)
                    
                    # Remove button for this item
                    remove_btn = QPushButton("×")
                    remove_btn.setToolTip("Remove this item")
                    remove_btn.setFixedSize(24, 24)
                    remove_btn.setStyleSheet("""
                        QPushButton {
                            background-color: #ff5555;
                            color: white;
                            font-weight: bold;
                            border-radius: 12px;
                            border: none;
                        }
                        QPushButton:hover {
                            background-color: #ff3333;
                        }
                    """)
                    remove_btn.clicked.connect(lambda checked, frame=item_frame: self.remove_pii_field(frame))
                    header_layout.addWidget(remove_btn)
                    
                    # Add header to item layout
                    item_layout.addLayout(header_layout)
                    
                    # Add separator line
                    line = QFrame()
                    line.setFrameShape(QFrame.HLine)
                    line.setFrameShadow(QFrame.Sunken)
                    line.setStyleSheet("background-color: #e0e0e0;")
                    item_layout.addWidget(line)
                    
                    # Item name with label
                    name_layout = QHBoxLayout()
                    name_label = QLabel("Name:")
                    name_label.setStyleSheet("font-weight: bold; color: #333; min-width: 60px;")
                    name_layout.addWidget(name_label)
                    
                    name_value = QLineEdit(pii_item.get("Item Name", ""))
                    name_value.setReadOnly(False)  # Allow editing
                    name_value.setStyleSheet("""
                        QLineEdit {
                            border: 1px solid #ccc;
                            border-radius: 4px;
                            padding: 5px;
                            background-color: white;
                        }
                    """)
                    name_layout.addWidget(name_value)
                    
                    # Add name layout to item layout
                    item_layout.addLayout(name_layout)
                    
                    # Item value with label - use different widgets based on content
                    value_layout = QHBoxLayout()
                    value_label = QLabel("Value:")
                    value_label.setStyleSheet("font-weight: bold; color: #333; min-width: 60px; align-self: start;")
                    value_layout.addWidget(value_label)
                    
                    # Get the value
                    value_text = str(pii_item.get("Data", ""))
                    
                    # Determine if we need a text edit or line edit
                    if len(value_text) > 50 or '\n' in value_text:
                        # Long text - use text edit
                        value_widget = QTextEdit()
                        value_widget.setPlainText(value_text)
                        value_widget.setMinimumHeight(80)
                        value_widget.setStyleSheet("""
                            QTextEdit {
                                border: 1px solid #ccc;
                                border-radius: 4px;
                                padding: 5px;
                                background-color: white;
                            }
                        """)
                    else:
                        # Short text - use line edit
                        value_widget = QLineEdit(value_text)
                        value_widget.setStyleSheet("""
                            QLineEdit {
                                border: 1px solid #ccc;
                                border-radius: 4px;
                                padding: 5px;
                                background-color: white;
                            }
                        """)
                    
                    value_layout.addWidget(value_widget)
                    
                    # Add value layout to item layout
                    item_layout.addLayout(value_layout)
                    
                    # Add buttons for value operations
                    buttons_layout = QHBoxLayout()
                    buttons_layout.addStretch()
                    
                    # Copy value button
                    copy_value_btn = QPushButton("Copy Value")
                    copy_value_btn.setToolTip("Copy just the value")
                    copy_value_btn.setStyleSheet("""
                        QPushButton {
                            background-color: #4caf50;
                            color: white;
                            border: none;
                            padding: 4px 12px;
                            border-radius: 4px;
                            font-weight: bold;
                        }
                        QPushButton:hover {
                            background-color: #388e3c;
                        }
                    """)
                    copy_value_btn.clicked.connect(lambda checked, val=value_text: self.copy_to_clipboard(val))
                    buttons_layout.addWidget(copy_value_btn)
                    
                    # Add buttons to item layout
                    item_layout.addLayout(buttons_layout)
                    
                    # Add the frame to the PII layout
                    self.pii_layout.addWidget(item_frame)
                except RuntimeError:
                    self.logger.warning(f"Error adding PII item {index+1} - widget may have been deleted")
                    continue
                
            # Add a button to add new PII items
            try:
                add_btn = QPushButton("➕ Add New PII Item")
                add_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #007bff;
                        color: white;
                        border: none;
                        padding: 8px 16px;
                        border-radius: 5px;
                        font-weight: bold;
                        margin-top: 10px;
                    }
                    QPushButton:hover {
                        background-color: #0056b3;
                    }
                """)
                add_btn.clicked.connect(self.add_pii_field)
                self.pii_layout.addWidget(add_btn, alignment=Qt.AlignCenter)
            except RuntimeError:
                self.logger.warning("Error adding 'Add PII Item' button - widget may have been deleted")
                
        except Exception as e:
            self.logger.error(f"Error parsing PII data: {str(e)}")
            # Add a single field with error message
            try:
                error_label = QLabel(f"Could not parse PII data: {str(e)}")
                error_label.setStyleSheet("color: red; font-weight: bold; padding: 10px; background-color: #ffeeee; border: 1px solid #ffaaaa; border-radius: 5px;")
                self.pii_layout.addWidget(error_label)
                
                # Add raw data display as fallback
                raw_data = QTextEdit()
                raw_data.setPlainText(str(pii_data))
                raw_data.setReadOnly(True)
                raw_data.setMinimumHeight(200)
                raw_data.setStyleSheet("""
                    QTextEdit {
                        border: 1px solid #ccc;
                        border-radius: 4px;
                        padding: 10px;
                        background-color: #f9f9f9;
                        font-family: monospace;
                    }
                """)
                self.pii_layout.addWidget(QLabel("Raw Data:"))
                self.pii_layout.addWidget(raw_data)
            except RuntimeError:
                self.logger.warning("Error adding error information - widget may have been deleted")    
        
    def copy_to_clipboard(self, data):
        """
        Copy data to clipboard with visual confirmation.
        
        Args:
            data: The data to copy
        """
        clipboard = QApplication.clipboard()
        clipboard.setText(str(data))
        
        # Show a temporary status message with better styling
        status_frame = QFrame(self)
        status_frame.setStyleSheet("""
            QFrame {
                background-color: #4CAF50;
                border-radius: 6px;
                border: 1px solid #388E3C;
            }
        """)
        status_layout = QHBoxLayout(status_frame)
        
        icon_label = QLabel("✓")
        icon_label.setStyleSheet("color: white; font-size: 16px; font-weight: bold;")
        status_layout.addWidget(icon_label)
        
        text_label = QLabel("Copied to clipboard!")
        text_label.setStyleSheet("color: white; font-weight: bold;")
        status_layout.addWidget(text_label)
        
        # Position in the center of the window
        status_frame.setFixedWidth(200)
        status_frame.setFixedHeight(40)
        parent_rect = self.geometry()
        status_frame.move(
            parent_rect.width() // 2 - status_frame.width() // 2,
            parent_rect.height() // 2 - status_frame.height() // 2
        )
        
        status_frame.show()
        
        # Remove after 1.5 seconds
        QTimer.singleShot(1500, lambda: status_frame.deleteLater())
        
        self.logger.info(f"Copied data to clipboard: {str(data)[:30]}...")

    def clear_pii_fields(self):
        """Clear all PII fields."""
        # Remove all widgets from the PII layout
        if hasattr(self, 'pii_layout'):
            while self.pii_layout.count():
                item = self.pii_layout.takeAt(0)
                if item.widget():
                    item.widget().deleteLater()
                
    def add_pii_field(self, name="", value=""):
        """
        Add a field for PII data with improved visual styling.
        
        Args:
            name (str): Field name
            value (str): Field value
            
        Returns:
            QFrame: The created field frame
        """
        # Create a frame for this field with enhanced styling
        field_frame = QFrame()
        field_frame.setFrameShape(QFrame.StyledPanel)
        field_frame.setFrameShadow(QFrame.Raised)
        
        # Get the current item count for styling
        item_count = 0
        for i in range(self.pii_layout.count()):
            widget = self.pii_layout.itemAt(i).widget()
            if isinstance(widget, QFrame) and widget != field_frame:
                item_count += 1
        
        # Set alternating styles for better visibility
        if item_count % 2 == 0:
            bg_color = "#f8f8f8"
            border_color = "#e0e0e0"
        else:
            bg_color = "#ffffff"
            border_color = "#d0d0d0"
            
        field_frame.setStyleSheet(f"""
            QFrame {{
                border: 2px solid {border_color};
                border-radius: 8px;
                background-color: {bg_color};
                margin: 4px;
            }}
            QFrame:hover {{
                border-color: #4361ee;
                background-color: #f5f8ff;
            }}
        """)
        
        # Create layout for the frame
        field_layout = QVBoxLayout(field_frame)
        field_layout.setContentsMargins(12, 12, 12, 12)
        field_layout.setSpacing(8)
        
        # Item header with "New Item" label
        header_layout = QHBoxLayout()
        
        # Item label with "NEW" badge
        item_label = QLabel(f"New Item #{item_count + 1}")
        item_label.setStyleSheet("""
            font-weight: bold; 
            color: #4361ee; 
            font-size: 13px;
            padding: 3px 8px;
            background-color: #eef2ff;
            border-radius: 4px;
        """)
        header_layout.addWidget(item_label)
        
        # Add a "NEW" badge
        new_badge = QLabel("NEW")
        new_badge.setStyleSheet("""
            background-color: #28a745;
            color: white;
            font-weight: bold;
            font-size: 10px;
            padding: 2px 6px;
            border-radius: 10px;
        """)
        header_layout.addWidget(new_badge)
        header_layout.addStretch()
        
        # Remove button
        remove_btn = QPushButton("×")
        remove_btn.setToolTip("Remove this item")
        remove_btn.setFixedSize(24, 24)
        remove_btn.setStyleSheet("""
            QPushButton {
                background-color: #ff5555;
                color: white;
                font-weight: bold;
                border-radius: 12px;
                border: none;
            }
            QPushButton:hover {
                background-color: #ff3333;
            }
        """)
        remove_btn.clicked.connect(lambda: self.remove_pii_field(field_frame))
        header_layout.addWidget(remove_btn)
        
        # Add header to field layout
        field_layout.addLayout(header_layout)
        
        # Add separator line
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        line.setStyleSheet("background-color: #e0e0e0;")
        field_layout.addWidget(line)
        
        # Name input with label
        name_layout = QHBoxLayout()
        name_label = QLabel("Name:")
        name_label.setStyleSheet("font-weight: bold; color: #333; min-width: 60px;")
        name_layout.addWidget(name_label)
        
        name_input = QLineEdit(name)
        name_input.setPlaceholderText("Enter field name...")
        name_input.setStyleSheet("""
            QLineEdit {
                border: 1px solid #ccc;
                border-radius: 4px;
                padding: 5px;
                background-color: white;
            }
            QLineEdit:focus {
                border: 1px solid #4361ee;
            }
        """)
        name_layout.addWidget(name_input)
        
        # Add name layout to field layout
        field_layout.addLayout(name_layout)
        
        # Value input with label
        value_layout = QHBoxLayout()
        value_label = QLabel("Value:")
        value_label.setStyleSheet("font-weight: bold; color: #333; min-width: 60px;")
        value_layout.addWidget(value_label)
        
        value_input = QLineEdit(value)
        value_input.setPlaceholderText("Enter field value...")
        value_input.setStyleSheet("""
            QLineEdit {
                border: 1px solid #ccc;
                border-radius: 4px;
                padding: 5px;
                background-color: white;
            }
            QLineEdit:focus {
                border: 1px solid #4361ee;
            }
        """)
        value_layout.addWidget(value_input)
        
        # Add value layout to field layout
        field_layout.addLayout(value_layout)
        
        # Help text at the bottom
        help_text = QLabel("Fill in the name and value fields, then click Save Changes")
        help_text.setStyleSheet("""
            font-style: italic;
            color: #666;
            font-size: 10px;
            padding-top: 5px;
        """)
        field_layout.addWidget(help_text)
        
        # Add the frame to the PII layout, before the "Add" button if it exists
        add_button_index = -1
        for i in range(self.pii_layout.count()):
            widget = self.pii_layout.itemAt(i).widget()
            if isinstance(widget, QPushButton) and widget.text().endswith("Add New PII Item"):
                add_button_index = i
                break
        
        if add_button_index >= 0:
            # Insert before the add button
            self.pii_layout.insertWidget(add_button_index, field_frame)
        else:
            # Add to the end
            self.pii_layout.addWidget(field_frame)
        
        # Enable save button
        self.save_btn.setEnabled(True)
        
        return field_frame
        
    def remove_pii_field(self, field_frame):
        """
        Remove a PII field.
        
        Args:
            field_frame: The frame to remove
        """
        field_frame.setParent(None)
        field_frame.deleteLater()
        
        # Update UI state
        self.save_btn.setEnabled(True)
        
    def collect_pii_fields(self):
        """
        Collect data from all PII fields with robust error handling.
        
        Returns:
            list: List of PII items
        """
        pii_items = []
        
        # Iterate through all widgets in the PII layout
        for i in range(self.pii_layout.count()):
            widget = self.pii_layout.itemAt(i).widget()
            
            # Skip non-frame widgets (like labels)
            if not isinstance(widget, QFrame):
                continue
                
            # Process frame widgets that contain PII fields
            try:
                # Find the input fields in this frame
                name_input = None
                value_input = None
                
                # Search through the widget hierarchy for QLineEdit fields
                frame_layout = widget.layout()
                if not frame_layout:
                    continue
                    
                # Search for QLineEdit or QTextEdit widgets in the layout
                name_inputs = widget.findChildren(QLineEdit, options=Qt.FindChildrenRecursively)
                text_editors = widget.findChildren(QTextEdit, options=Qt.FindChildrenRecursively)
                
                # Usually the first QLineEdit is the name input
                if name_inputs:
                    name_input = name_inputs[0]
                    # If there's more than one, the second might be a value input
                    if len(name_inputs) > 1:
                        value_input = name_inputs[1]
                        
                # If we have a text editor, that's likely the value input
                if text_editors and not value_input:
                    value_input = text_editors[0]
                
                # If we found both inputs, add to our PII items
                if name_input and value_input:
                    name = name_input.text().strip()
                    
                    # Get value from either QLineEdit or QTextEdit
                    if isinstance(value_input, QLineEdit):
                        value = value_input.text()
                    else:  # QTextEdit
                        value = value_input.toPlainText()
                    
                    if name:  # Only add if name is not empty
                        pii_items.append({
                            "Item Name": name,
                            "Data": value
                        })
                elif name_input:  # Only found name input
                    name = name_input.text().strip()
                    if name:  # Only add if name is not empty
                        pii_items.append({
                            "Item Name": name,
                            "Data": ""
                        })
                        
            except Exception as e:
                self.logger.error(f"Error collecting PII field: {str(e)}")
                # Continue to next field
        
        return pii_items

    def save_item(self):
        """Save the current item with enhanced validation and user feedback."""
        # Get basic fields
        item_id = self.id_field.text().strip()
        category = self.category_field.text().strip()
        type_ = self.type_field.text().strip()
        
        # Validate required fields
        if not category:
            QMessageBox.warning(self, "Validation Error", "Category is required")
            self.category_field.setFocus()
            return
                
        if not type_:
            QMessageBox.warning(self, "Validation Error", "Type is required")
            self.type_field.setFocus()
            return
                
        # Collect PII data
        pii_items = self.collect_pii_fields()
        
        if not pii_items:
            # Add a message asking if they want to continue with no PII data
            reply = QMessageBox.question(
                self,
                "No PII Data",
                "No PII fields were found. Do you want to continue saving with no PII data?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply != QMessageBox.Yes:
                return
        
        # Create item data
        item_data = {
            "Category": category,
            "Type": type_,
            "PII": str(pii_items)
        }
        
        # Add ID for updates
        if item_id:
            item_data["_id"] = item_id
                
        # Show progress dialog
        progress = QProgressDialog(
            f"{'Updating' if item_id else 'Creating'} item...", 
            "Cancel", 0, 100, self
        )
        progress.setWindowTitle(f"{'Update' if item_id else 'Create'} Item")
        progress.setWindowModality(Qt.WindowModal)
        progress.setValue(10)
        progress.show()
        QApplication.processEvents()
        
        try:
            # Determine if this is an update or create
            is_update = bool(item_id)
            
            if is_update:
                self.logger.info(f"Updating item with ID: {item_id}")
                progress.setValue(30)
                QApplication.processEvents()
                success, result = self.update_item(item_data)
                progress.setValue(70)
                QApplication.processEvents()
            else:
                self.logger.info("Creating new item")
                progress.setValue(30)
                QApplication.processEvents()
                success, result = self.create_item(item_data)
                progress.setValue(70)
                QApplication.processEvents()
                    
            if success:
                progress.setValue(100)
                QApplication.processEvents()
                
                QMessageBox.information(
                    self, 
                    "Success", 
                    f"Item {'updated' if is_update else 'created'} successfully"
                )
                
                # Refresh data
                self.fetch_data()
                
                # Clear form if this was a new item
                if not is_update:
                    self.clear_details()
                    self.details_container.setVisible(False)
            else:
                error_msg = result.get('error', str(result)) if isinstance(result, dict) else str(result)
                raise ValueError(error_msg)
                    
        except Exception as e:
            self.logger.error(f"Error saving item: {str(e)}")
            QMessageBox.critical(self, "Save Error", f"Failed to save item: {str(e)}")
                
        finally:
            # Ensure progress dialog is closed
            progress.close()
            
    def create_item(self, item_data: Dict[str, Any]) -> Tuple[bool, Any]:
        """
        Create a new item.
        
        Args:
            item_data (dict): Item data to create
            
        Returns:
            tuple: (success, result)
        """
        # Try API client first
        if self.api_client:
            return self.api_client.sync_add_pii_item(item_data)
            
        # Fall back to auth_service
        elif self.auth_service:
            # Use direct sync method if available
            if hasattr(self.auth_service, 'make_synchronous_request'):
                return self.auth_service.make_synchronous_request(
                    method="POST",
                    endpoint="pii",
                    data=item_data
                )
            # Otherwise use async method with workaround
            elif hasattr(self.auth_service, 'make_authenticated_request'):
                import asyncio
                loop = asyncio.new_event_loop()
                try:
                    return loop.run_until_complete(
                        self.auth_service.make_authenticated_request(
                            method="POST",
                            endpoint="pii",
                            data=item_data
                        )
                    )
                finally:
                    loop.close()
                    
        # Last resort: try agent directly
        elif self.agent:
            result = self.agent.insert_new_data(item_data)
            
            # Handle different return types
            if result is True:
                return True, {"message": "Item created successfully"}
            elif isinstance(result, Exception):
                return False, {"error": str(result)}
            else:
                # Assume success if not clearly an error
                return True, result
                
        # No available methods
        return False, {"error": "No data source available (API client, auth service, or agent)"}
    
    def update_item(self, item_data: Dict[str, Any]) -> Tuple[bool, Any]:
        """
        Update an existing item.
        
        Args:
            item_data (dict): Item data to update
            
        Returns:
            tuple: (success, result)
        """
        # Try API client first
        if self.api_client:
            return self.api_client.sync_update_pii_item(item_data)
            
        # Fall back to auth_service
        elif self.auth_service:
            # Use direct sync method if available
            if hasattr(self.auth_service, 'make_synchronous_request'):
                return self.auth_service.make_synchronous_request(
                    method="PATCH",
                    endpoint="pii",
                    data=item_data
                )
            # Otherwise use async method with workaround
            elif hasattr(self.auth_service, 'make_authenticated_request'):
                import asyncio
                loop = asyncio.new_event_loop()
                try:
                    return loop.run_until_complete(
                        self.auth_service.make_authenticated_request(
                            method="PATCH",
                            endpoint="pii",
                            data=item_data
                        )
                    )
                finally:
                    loop.close()
                    
        # Last resort: try agent directly
        elif self.agent:
            result = self.agent.update_one_data(item_data)
            
            # Handle different return types
            if result is True:
                return True, {"message": "Item updated successfully"}
            elif isinstance(result, Exception):
                return False, {"error": str(result)}
            else:
                # Assume success if not clearly an error
                return True, result
                
        # No available methods
        return False, {"error": "No data source available (API client, auth service, or agent)"}
            
    def delete_item(self):
        """Delete the current item with confirmation."""
        # Get item ID to delete
        item_id = self.id_field.text().strip()
        if not item_id:
            QMessageBox.warning(self, "Delete Error", "No item selected to delete")
            return
        
        # Get item details for confirmation
        category = self.category_field.text().strip()
        type_ = self.type_field.text().strip()
        
        # Confirm deletion
        reply = QMessageBox.question(
            self, 
            "Confirm Deletion",
            f"Are you sure you want to delete this item?\n\n"
            f"ID: {item_id}\n"
            f"Category: {category}\n"
            f"Type: {type_}\n\n"
            f"This action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            return
        
        # Show progress dialog
        progress = QProgressDialog("Deleting item...", "Cancel", 0, 100, self)
        progress.setWindowTitle("Delete Item")
        progress.setWindowModality(Qt.WindowModal)
        progress.setValue(10)
        progress.show()
        QApplication.processEvents()
        
        # Create delete data payload
        delete_data = {
            "_id": item_id,
            "Category": category,
            "Type": type_
        }
        
        try:
            # Try API client first
            if self.api_client:
                self.logger.info(f"Deleting item with ID {item_id} using API client")
                progress.setValue(30)
                QApplication.processEvents()
                
                success, result = self.api_client.sync_delete_pii_item(
                    item_id=item_id,
                    category=category,
                    type_=type_
                )
                
            # Fall back to auth_service
            elif self.auth_service:
                self.logger.info(f"Deleting item with ID {item_id} using auth service")
                progress.setValue(30)
                QApplication.processEvents()
                
                # Use direct sync method if available
                if hasattr(self.auth_service, 'make_synchronous_request'):
                    success, result = self.auth_service.make_synchronous_request(
                        method="DELETE",
                        endpoint="pii",
                        data=delete_data
                    )
                # Otherwise use async method with workaround
                elif hasattr(self.auth_service, 'make_authenticated_request'):
                    import asyncio
                    loop = asyncio.new_event_loop()
                    try:
                        success, result = loop.run_until_complete(
                            self.auth_service.make_authenticated_request(
                                method="DELETE",
                                endpoint="pii",
                                data=delete_data
                            )
                        )
                    finally:
                        loop.close()
                else:
                    raise ValueError("Auth service does not have a suitable request method")
                
            # Last resort: try agent directly
            elif self.agent:
                self.logger.info(f"Deleting item with ID {item_id} using direct agent")
                progress.setValue(30)
                QApplication.processEvents()
                
                result = self.agent.delete_one_data(delete_data)
                
                # Handle different return types
                if result is True:
                    success = True
                    result = {"message": "Item deleted successfully"}
                elif isinstance(result, Exception):
                    success = False
                    result = {"error": str(result)}
                else:
                    # Assume success if not clearly an error
                    success = True
            else:
                raise ValueError("No data source available (API client, auth service, or agent)")
            
            # Process result
            progress.setValue(70)
            QApplication.processEvents()
            
            if success:
                progress.setValue(100)
                QApplication.processEvents()
                
                QMessageBox.information(
                    self, 
                    "Success", 
                    "Item deleted successfully"
                )
                
                # Clear details
                self.clear_details()
                self.details_container.setVisible(False)
                
                # Refresh data
                self.fetch_data()
            else:
                error_msg = result.get('error', str(result)) if isinstance(result, dict) else str(result)
                raise ValueError(error_msg)
                
        except Exception as e:
            self.logger.error(f"Error deleting item: {str(e)}")
            QMessageBox.critical(self, "Delete Error", f"Failed to delete item: {str(e)}")
            
        finally:
            # Ensure progress dialog is closed
            progress.close()
                
    def apply_filters(self):
        """
        Apply filters to the data with advanced search capabilities and robust error handling.
        Supports multi-term search, category and type filtering with real-time feedback.
        """
        if not self.data:
            return
        
        # Define theme colors for UI styling
        class StandardTheme:
            PRIMARY = "#1976D2"
            SUCCESS = "#4CAF50"
            SUCCESS_LIGHT = "#E8F5E9" 
            DANGER = "#F44336"
            DANGER_LIGHT = "#FFEBEE"
            WARNING = "#FF9800"
            WARNING_LIGHT = "#FFF3E0"
            TEXT_PRIMARY = "#212121"
                
        # Get filter values safely with defaults
        category = "All Categories"
        type_ = "All Types" 
        search_text = ""
        
        try:
            category = self.category_filter.currentText()
        except (RuntimeError, AttributeError):
            pass
            
        try:
            type_ = self.type_filter.currentText()
        except (RuntimeError, AttributeError):
            pass
            
        try:
            search_text = self.search_input.text().lower().strip()
        except (RuntimeError, AttributeError):
            pass
        
        # Measure performance
        start_time = time.time()
        
        # Apply filters efficiently
        # Pre-check if we need to filter at all to avoid unnecessary processing
        if category == "All Categories" and type_ == "All Types" and not search_text:
            self.filtered_data = self.data.copy() if hasattr(self.data, 'copy') else list(self.data)
        else:
            # Apply filters in order of expected efficiency (most restrictive first)
            filtered_data = []
            
            for item in self.data:
                # Apply category filter (fast exact match)
                if category != "All Categories" and item.get('Category', '') != category:
                    continue
                    
                # Apply type filter (fast exact match)
                if type_ != "All Types" and item.get('Type', '') != type_:
                    continue
                    
                # Apply search filter (more intensive)
                if search_text:
                    # Split into terms for multi-term search
                    search_terms = search_text.split()
                    
                    # Check if ALL terms are found in ANY field
                    found_all_terms = True
                    
                    for term in search_terms:
                        term_found = False
                        
                        # Check in all item fields
                        for key, value in item.items():
                            if term in str(value).lower():
                                term_found = True
                                break
                        
                        # If any term isn't found, this item doesn't match
                        if not term_found:
                            found_all_terms = False
                            break
                    
                    if not found_all_terms:
                        continue
                
                # If we get here, the item passed all filters
                filtered_data.append(item)
            
            self.filtered_data = filtered_data
        
        # Calculate filter time for optimization
        filter_time = time.time() - start_time
        
        # Log performance if it's slow
        if filter_time > 0.1:  # Only log if filtering took more than 100ms
            self.logger.info(f"Filter applied in {filter_time:.3f}s ({len(self.filtered_data)} of {len(self.data)} items)")
        
        # Update UI to reflect filter results
        try:
            if hasattr(self, 'data_count_label') and self.data_count_label is not None:
                total_count = len(self.data)
                filtered_count = len(self.filtered_data)
                
                # Use more descriptive message based on filter results
                if filtered_count == 0:
                    self.data_count_label.setText(f"No items match the current filters (from {total_count} total)")
                    self.data_count_label.setStyleSheet(f"""
                        font-weight: bold;
                        color: {StandardTheme.DANGER};
                        padding: 5px;
                        background-color: {StandardTheme.DANGER_LIGHT};
                        border-radius: 4px;
                        margin: 5px 0;
                    """)
                elif filtered_count == total_count:
                    self.data_count_label.setText(f"Showing all {total_count} items")
                    self.data_count_label.setStyleSheet(f"""
                        font-weight: bold;
                        color: {StandardTheme.SUCCESS};
                        padding: 5px;
                        background-color: {StandardTheme.SUCCESS_LIGHT};
                        border-radius: 4px;
                        margin: 5px 0;
                    """)
                else:
                    percent = (filtered_count / total_count) * 100
                    self.data_count_label.setText(
                        f"Filtered: {filtered_count} of {total_count} items ({percent:.1f}%)"
                    )
                    self.data_count_label.setStyleSheet(f"""
                        font-weight: bold;
                        color: {StandardTheme.WARNING};
                        padding: 5px;
                        background-color: {StandardTheme.WARNING_LIGHT};
                        border-radius: 4px;
                        margin: 5px 0;
                    """)
        except (RuntimeError, AttributeError):
            pass
                    
        # Update table with filtered data
        try:
            self.populate_table()
        except (RuntimeError, AttributeError):
            pass
        
        # Update status message with more details
        try:
            if hasattr(self, 'status_label') and self.status_label is not None:
                if self.filtered_data:
                    # Count how many categories and types are represented in the filtered data
                    categories = set(item.get('Category', '') for item in self.filtered_data)
                    types = set(item.get('Type', '') for item in self.filtered_data)
                    
                    # Also count total PII fields
                    total_pii_count = 0
                    for item in self.filtered_data:
                        pii_data = item.get('PII', '')
                        try:
                            if isinstance(pii_data, str):
                                parsed = ast.literal_eval(pii_data)
                                if isinstance(parsed, list):
                                    total_pii_count += len(parsed)
                        except (SyntaxError, ValueError):
                            # Skip parsing errors
                            pass
                    
                    status_text = (
                        f"Found {len(self.filtered_data)} items in {len(categories)} "
                        f"{'category' if len(categories) == 1 else 'categories'} with "
                        f"{len(types)} {'type' if len(types) == 1 else 'types'}, "
                        f"containing ~{total_pii_count} PII fields"
                    )
                    
                    # Add search term info if searching
                    if search_text:
                        search_terms = search_text.split()
                        if len(search_terms) > 1:
                            status_text += f" (matched {len(search_terms)} search terms)"
                    
                    self.status_label.setText(status_text)
                    self.status_label.setStyleSheet(f"color: {StandardTheme.TEXT_PRIMARY}; font-style: italic;")
                else:
                    search_hint = ""
                    if search_text:
                        search_hint = " Try using fewer or more general search terms."
                        
                    self.status_label.setText(
                        f"No items match the current filters.{search_hint} Try adjusting your criteria."
                    )
                    self.status_label.setStyleSheet(f"color: {StandardTheme.DANGER}; font-weight: bold;")
        except (RuntimeError, AttributeError):
            pass
            
    def update_filters(self):
        """
        Update filter dropdowns with available options, ensuring filters work correctly.
        This method rebuilds the filter lists while preserving selections when possible.
        """
        if not self.data:
            return
                    
        # Save current selections only if widgets are still valid
        try:
            current_category = self.category_filter.currentText()
        except (RuntimeError, AttributeError):
            current_category = "All Categories"
                
        try:
            current_type = self.type_filter.currentText()
        except (RuntimeError, AttributeError):
            current_type = "All Types"
        
        # Get unique categories and types with counts
        categories = {}
        types = {}
        
        for item in self.data:
            category = item.get('Category', '')
            type_ = item.get('Type', '')
            
            if category:
                categories[category] = categories.get(category, 0) + 1
            if type_:
                types[type_] = types.get(type_, 0) + 1
        
        # Check if widgets are still valid before updating
        try:
            # Clear and repopulate category filter
            self.category_filter.blockSignals(True)  # Block signals to prevent multiple updates
            self.category_filter.clear()
            self.category_filter.addItem("All Categories")
            
            # Add categories with counts
            for category, count in sorted(categories.items()):
                self.category_filter.addItem(f"{category}")
            
            # Restore previous selection or close match
            if current_category != "All Categories":
                # First try exact match
                index = self.category_filter.findText(current_category)
                if index < 0:
                    # Try match without the count
                    base_category = current_category.split(" (")[0]
                    for i in range(self.category_filter.count()):
                        item_text = self.category_filter.itemText(i)
                        if item_text.startswith(base_category + " ("):
                            index = i
                            break
                
                if index >= 0:
                    self.category_filter.setCurrentIndex(index)
                else:
                    self.category_filter.setCurrentIndex(0)  # Default to "All"
            
            self.category_filter.blockSignals(False)  # Unblock signals
        except (RuntimeError, AttributeError):
            pass
        
        try:
            # Clear and repopulate type filter
            self.type_filter.blockSignals(True)  # Block signals to prevent multiple updates
            self.type_filter.clear()
            self.type_filter.addItem("All Types")
            
            # Add types with counts
            for type_, count in sorted(types.items()):
                self.type_filter.addItem(f"{type_}")
            
            # Restore previous selection or close match
            if current_type != "All Types":
                # First try exact match
                index = self.type_filter.findText(current_type)
                if index < 0:
                    # Try match without the count
                    base_type = current_type.split(" (")[0]
                    for i in range(self.type_filter.count()):
                        item_text = self.type_filter.itemText(i)
                        if item_text.startswith(base_type + " ("):
                            index = i
                            break
                
                if index >= 0:
                    self.type_filter.setCurrentIndex(index)
                else:
                    self.type_filter.setCurrentIndex(0)  # Default to "All"
            
            self.type_filter.blockSignals(False)  # Unblock signals
        except (RuntimeError, AttributeError):
            pass

    def item_selected(self):
        """Handle item selection in the table with protection against widget deletion."""
        try:
            selected_rows = self.table.selectedItems()
            if not selected_rows:
                # Clear details if nothing selected
                self.clear_details()
                self.details_container.setVisible(False)
                return
                    
            # Get the row of the first selected item
            row = selected_rows[0].row()
            
            # Get the item ID from the first column
            item_id = self.table.item(row, 0).text()
            
            # Find this item in our data
            item = next((item for item in self.filtered_data if item.get('_id', '') == item_id), None)
            
            if item:
                # Store current item
                self.current_item = item
                
                # Display item details
                self.display_item_details(item)
                
                # Make details section visible
                self.details_container.setVisible(True)
                
                # Enable edit/delete buttons safely
                try:
                    if hasattr(self, 'save_btn'):
                        self.save_btn.setEnabled(True)
                except RuntimeError:
                    pass
                    
                try:
                    if hasattr(self, 'delete_btn'):
                        self.delete_btn.setEnabled(True)
                except RuntimeError:
                    pass
            else:
                self.clear_details()
                self.details_container.setVisible(False)
        except RuntimeError:
            self.logger.warning("Error during item selection, widget may have been deleted")
        except Exception as e:
            self.logger.error(f"Error selecting item: {str(e)}")

    def clear_details(self):
        """Clear all details fields with protection against widget deletion."""
        # Clear basic fields safely
        try:
            if hasattr(self, 'id_field'):
                self.id_field.setText("")
        except RuntimeError:
            pass
            
        try:
            if hasattr(self, 'category_field'):
                self.category_field.setText("")
        except RuntimeError:
            pass
            
        try:
            if hasattr(self, 'type_field'):
                self.type_field.setText("")
        except RuntimeError:
            pass
        
        # Clear PII fields
        self.clear_pii_fields()
        
        # Disable buttons safely
        try:
            if hasattr(self, 'save_btn'):
                self.save_btn.setEnabled(False)
        except RuntimeError:
            pass
            
        try:
            if hasattr(self, 'delete_btn'):
                self.delete_btn.setEnabled(False)
        except RuntimeError:
            pass
        
        # Clear current item
        self.current_item = None

    def add_new_item(self):
        """Show empty form to add a new item."""
        # Clear details
        self.clear_details()
        
        # Make details section visible
        self.details_container.setVisible(True)
        
        # Add default PII field
        self.add_pii_field("New Field", "")
        
        # Enable save button
        self.save_btn.setEnabled(True)
        
    def show_context_menu(self, position):
        """
        Show a context menu when right-clicking on a table row.
        
        Args:
            position: The position where the right-click occurred
        """
        # Only show if there's a row selected
        selected_rows = self.table.selectedItems()
        if not selected_rows:
            return
            
        # Create context menu
        context_menu = QMenu(self)
        
        # Add View action
        view_action = context_menu.addAction("👁️ View Details")
        
        # Add Edit action  
        edit_action = context_menu.addAction("✏️ Edit")
        
        # Add Delete action
        delete_action = context_menu.addAction("🗑️ Delete")
        
        # Get action
        action = context_menu.exec_(self.table.mapToGlobal(position))
        
        # Handle actions
        if action == view_action:
            # Show details without making them editable
            if hasattr(self, 'category_field'):
                self.category_field.setReadOnly(True)
            if hasattr(self, 'type_field'):
                self.type_field.setReadOnly(True)
            self.save_btn.setEnabled(False)
        elif action == edit_action:
            # Enable editing
            if hasattr(self, 'category_field'):
                self.category_field.setReadOnly(False)
            if hasattr(self, 'type_field'):
                self.type_field.setReadOnly(False)
            self.save_btn.setEnabled(True)
        elif action == delete_action:
            # Delete the selected item
            self.delete_item()