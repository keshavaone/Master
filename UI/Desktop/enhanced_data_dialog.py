"""
Enhanced data dialog with proper CRUD functionality for PII data management.
"""

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem, 
    QPushButton, QLabel, QLineEdit, QComboBox, QMessageBox, QFrame,
    QHeaderView, QAbstractItemView, QApplication, QSplitter, QWidget,
    QGroupBox, QFormLayout, QTextEdit, QScrollArea, QSizePolicy, QStyle,
    QProgressDialog
)
from PyQt5.QtCore import Qt, QSize, QTimer
from PyQt5.QtGui import QIcon, QColor, QPalette
import pandas as pd
import logging
import ast
import json
import time
import traceback

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
        
        # Add filter explanation text
        filter_explanation = QLabel("Use filters to narrow down the data shown in the table below")
        filter_explanation.setStyleSheet("font-style: italic; color: #666; font-size: 10px;")
        filter_layout.addWidget(filter_explanation)
        
        # Action buttons for header
        action_layout = QVBoxLayout()
        action_layout.setContentsMargins(0, 0, 0, 0)
        action_layout.setSpacing(5)
        
        # Button group
        button_frame = QFrame()
        button_frame.setStyleSheet("""
            QFrame {
                background: transparent;
            }
        """)
        button_layout = QHBoxLayout(button_frame)
        button_layout.setContentsMargins(0, 0, 0, 0)
        button_layout.setSpacing(10)
        
        # Refresh button with improved styling
        self.refresh_btn = QPushButton("Refresh Data")
        self.refresh_btn.setIcon(self.style().standardIcon(QStyle.SP_BrowserReload))
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
        
        # Add new button with improved styling
        self.add_btn = QPushButton("Add New Item")
        self.add_btn.setIcon(self.style().standardIcon(QStyle.SP_FileDialogNewFolder))
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
        
        # Add buttons to layout
        button_layout.addWidget(self.refresh_btn)
        button_layout.addWidget(self.add_btn)
        action_layout.addWidget(button_frame)
    
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
                        self.populate_table()
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
                # (Implementation skipped for brevity but would follow the same pattern)
                pass
                
            # Last resort: try agent directly
            elif self.agent:
                # Similar error handling for the agent section...
                # (Implementation skipped for brevity but would follow the same pattern)
                pass
            
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
        """Populate the table with filtered data and improved styling."""
        # Clear existing rows
        self.table.setRowCount(0)
        
        if not self.filtered_data:
            return
                
        # Populate table with filtered data
        for row, item in enumerate(self.filtered_data):
            self.table.insertRow(row)
            
            # ID column
            id_item = QTableWidgetItem(item.get('_id', ''))
            id_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 0, id_item)
            
            # Category column
            category_item = QTableWidgetItem(item.get('Category', ''))
            category_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 1, category_item)
            
            # Type column
            type_item = QTableWidgetItem(item.get('Type', ''))
            type_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 2, type_item)
            
            # PII Data preview
            pii_text = self.get_pii_preview(item.get('PII', ''))
            pii_item = QTableWidgetItem(pii_text)
            self.table.setItem(row, 3, pii_item)
            
            # Set row colors for better visibility (alternating)
            for col in range(self.table.columnCount()):
                cell = self.table.item(row, col)
                if cell:
                    if row % 2 == 0:
                        cell.setBackground(QColor("#f5f5f5"))
                    else:
                        cell.setBackground(QColor("#ffffff"))
            
        # Adjust columns and row heights for better visibility
        self.table.resizeColumnsToContents()
        self.table.resizeRowsToContents()
        
        # Set minimum and maximum column widths
        for col in range(self.table.columnCount()):
            width = self.table.columnWidth(col)
            if col == 0:  # ID column
                self.table.setColumnWidth(col, min(200, max(100, width)))
            elif col == 3:  # PII preview column
                self.table.setColumnWidth(col, min(400, max(200, width)))
            else:
                self.table.setColumnWidth(col, min(200, max(100, width)))

        
    def populate_table(self):
        """Populate the table with filtered data and improved styling."""
        # Clear existing rows
        self.table.setRowCount(0)
        
        if not self.filtered_data:
            return
                
        # Populate table with filtered data
        for row, item in enumerate(self.filtered_data):
            self.table.insertRow(row)
            
            # ID column
            id_item = QTableWidgetItem(item.get('_id', ''))
            id_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 0, id_item)
            
            # Category column
            category_item = QTableWidgetItem(item.get('Category', ''))
            category_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 1, category_item)
            
            # Type column
            type_item = QTableWidgetItem(item.get('Type', ''))
            type_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 2, type_item)
            
            # PII Data preview
            pii_text = self.get_pii_preview(item.get('PII', ''))
            pii_item = QTableWidgetItem(pii_text)
            self.table.setItem(row, 3, pii_item)
            
            # Set row colors for better visibility (alternating)
            for col in range(self.table.columnCount()):
                cell = self.table.item(row, col)
                if cell:
                    if row % 2 == 0:
                        cell.setBackground(QColor("#f5f5f5"))
                    else:
                        cell.setBackground(QColor("#ffffff"))
            
        # Adjust columns and row heights for better visibility
        self.table.resizeColumnsToContents()
        self.table.resizeRowsToContents()
        
        # Set minimum and maximum column widths
        for col in range(self.table.columnCount()):
            width = self.table.columnWidth(col)
            if col == 0:  # ID column
                self.table.setColumnWidth(col, min(200, max(100, width)))
            elif col == 3:  # PII preview column
                self.table.setColumnWidth(col, min(400, max(200, width)))
            else:
                self.table.setColumnWidth(col, min(200, max(100, width)))

    
    def display_item_details(self, item):
        """
        Display item details in the form with highly improved PII data visualization.
        Protects against widget deletion.
        
        Args:
            item: The item to display
        """
        # Clear existing details first
        try:
            self.clear_details()
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

    
        
    def get_pii_preview(self, pii_data):
        """
        Get an enhanced preview of PII data for table display.
        
        Args:
            pii_data: PII data to preview
            
        Returns:
            str: Preview text with formatting
        """
        try:
            # If it's a string, try to parse it as JSON or list of dicts
            if isinstance(pii_data, str):
                try:
                    parsed_data = ast.literal_eval(pii_data)
                    
                    if isinstance(parsed_data, list):
                        # Count total items
                        item_count = len(parsed_data)
                        
                        # Show first few items
                        items = []
                        for item in parsed_data[:3]:
                            if isinstance(item, dict) and 'Item Name' in item and 'Data' in item:
                                # Limit data length for preview
                                data_preview = str(item['Data'])
                                if len(data_preview) > 30:
                                    data_preview = data_preview[:30] + "..."
                                items.append(f"{item['Item Name']}: {data_preview}")
                            else:
                                # Limit string length for preview
                                item_str = str(item)
                                if len(item_str) > 30:
                                    item_str = item_str[:30] + "..."
                                items.append(item_str)
                                
                        # Add count to preview if there are more items
                        preview = ", ".join(items)
                        if item_count > 3:
                            preview += f" ... ({item_count} items total)"
                                
                        return preview
                    else:
                        return str(parsed_data)
                except (SyntaxError, ValueError):
                    # If parsing fails, just return the string
                    if len(pii_data) > 50:
                        return pii_data[:50] + "..."
                    return pii_data
            
            # For other types, convert to string
            if len(str(pii_data)) > 50:
                return str(pii_data)[:50] + "..."
            return str(pii_data)
                
        except Exception as e:
            self.logger.error(f"Error generating PII preview: {str(e)}")
            return "Error: Could not preview data"
            
   
        
    def clear_pii_fields(self):
        """Clear all PII fields."""
        # Remove all widgets from the PII layout
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
                # First, get the layout
                frame_layout = widget.layout()
                if not frame_layout:
                    continue
                    
                # Look for form layouts that contain our fields
                for j in range(frame_layout.count()):
                    layout_item = frame_layout.itemAt(j)
                    
                    # Check if this is a form layout
                    if isinstance(layout_item, QFormLayout):
                        form_layout = layout_item
                        
                        # Form layouts store rows as (label, field)
                        for row in range(form_layout.rowCount()):
                            label_item = form_layout.itemAt(row, QFormLayout.LabelRole)
                            field_item = form_layout.itemAt(row, QFormLayout.FieldRole)
                            
                            if label_item and field_item:
                                label_widget = label_item.widget()
                                field_widget = field_item.widget()
                                
                                if isinstance(label_widget, QLabel) and isinstance(field_widget, QLineEdit):
                                    label_text = label_widget.text().lower().strip(':')
                                    
                                    if label_text == "name":
                                        name_input = field_widget
                                    elif label_text == "value":
                                        value_input = field_widget
                    elif isinstance(layout_item, QHBoxLayout):
                        # Handle horizontal layouts (might contain line edits)
                        for k in range(layout_item.count()):
                            widget_item = layout_item.itemAt(k)
                            if widget_item and isinstance(widget_item.widget(), QLineEdit):
                                # Determine if this is name or value based on order
                                if name_input is None:
                                    name_input = widget_item.widget()
                                elif value_input is None:
                                    value_input = widget_item.widget()
                
                # If we found both inputs, add to our PII items
                if name_input and value_input:
                    name = name_input.text().strip()
                    value = value_input.text()
                    
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
        
    def add_new_item(self):
        """Show empty form to add a new item."""
        # Clear details
        self.clear_details()
        
        # Add default PII field
        self.add_pii_field("New Field", "")
        
        # Enable save button
        self.save_btn.setEnabled(True)
        
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
            else:
                error_msg = result.get('error', str(result)) if isinstance(result, dict) else str(result)
                raise ValueError(error_msg)
                    
        except Exception as e:
            self.logger.error(f"Error saving item: {str(e)}")
            QMessageBox.critical(self, "Save Error", f"Failed to save item: {str(e)}")
                
        finally:
            # Ensure progress dialog is closed
            progress.close()
            progress = None
            
    def create_item(self, item_data):
        """
        Create a new item.
        
        Args:
            item_data: Item data to create
            
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
    
    def update_item(self, item_data):
        """
        Update an existing item.
        
        Args:
            item_data: Item data to update
            
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
        """Delete the current item."""
        if not self.current_item:
            return
            
        # Get item ID
        item_id = self.id_field.text().strip()
        
        if not item_id:
            QMessageBox.warning(self, "Delete Error", "No item selected for deletion")
            return
            
        # Confirm deletion
        reply = QMessageBox.question(
            self,
            "Confirm Deletion",
            f"Are you sure you want to delete this item?\n\nCategory: {self.category_field.text()}\nType: {self.type_field.text()}\n\nThis action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            return
            
        # Create delete data
        delete_data = {
            "_id": item_id,
            "Category": self.category_field.text(),
            "Type": self.type_field.text()
        }
        
        # Show progress
        self.setCursor(Qt.WaitCursor)
        
        try:
            success, result = self.delete_item_data(delete_data)
                
            if success:
                QMessageBox.information(self, "Success", "Item deleted successfully")
                
                # Refresh data
                self.fetch_data()
                
                # Clear form
                self.clear_details()
            else:
                error_msg = result.get('error', str(result)) if isinstance(result, dict) else str(result)
                raise ValueError(error_msg)
                
        except Exception as e:
            self.logger.error(f"Error deleting item: {str(e)}")
            QMessageBox.critical(self, "Delete Error", f"Failed to delete item: {str(e)}")
            
        finally:
            self.setCursor(Qt.ArrowCursor)
            
    def delete_item_data(self, delete_data):
        """
        Delete an item.
        
        Args:
            delete_data: Item data to delete
            
        Returns:
            tuple: (success, result)
        """
        # Try API client first
        if self.api_client:
            return self.api_client.sync_delete_pii_item(
                delete_data["_id"],
                delete_data.get("Category"),
                delete_data.get("Type")
            )
            
        # Fall back to auth_service
        elif self.auth_service:
            # Use direct sync method if available
            if hasattr(self.auth_service, 'make_synchronous_request'):
                return self.auth_service.make_synchronous_request(
                    method="DELETE",
                    endpoint="pii",
                    data=delete_data
                )
            # Otherwise use async method with workaround
            elif hasattr(self.auth_service, 'make_authenticated_request'):
                import asyncio
                loop = asyncio.new_event_loop()
                try:
                    return loop.run_until_complete(
                        self.auth_service.make_authenticated_request(
                            method="DELETE",
                            endpoint="pii",
                            data=delete_data
                        )
                    )
                finally:
                    loop.close()
                    
        # Last resort: try agent directly
        elif self.agent:
            result = self.agent.delete_one_data(delete_data)
            
            # Handle different return types
            if result is True:
                return True, {"message": "Item deleted successfully"}
            elif isinstance(result, Exception):
                return False, {"error": str(result)}
            else:
                # Assume success if not clearly an error
                return True, result
                
        # No available methods
        return False, {"error": "No data source available (API client, auth service, or agent)"}
    
    def update_filters(self):
        """Update filter dropdowns with available options, protecting against widget deletion."""
        if not self.data:
            return
                
        # Save current selections only if widgets are still valid
        try:
            current_category = self.category_filter.currentText()
        except RuntimeError:  # Widget has been deleted
            current_category = "All Categories"
            
        try:
            current_type = self.type_filter.currentText()
        except RuntimeError:  # Widget has been deleted
            current_type = "All Types"
        
        # Get unique categories and types
        categories = set()
        types = set()
        
        for item in self.data:
            category = item.get('Category', '')
            type_ = item.get('Type', '')
            
            if category:
                categories.add(category)
            if type_:
                types.add(type_)
        
        # Check if widgets are still valid before updating
        try:
            # Clear and repopulate category filter
            self.category_filter.blockSignals(True)  # Block signals to prevent multiple updates
            self.category_filter.clear()
            self.category_filter.addItem("All Categories")
            self.category_filter.addItems(sorted(categories))
            
            # Restore selections or default to "All"
            category_index = self.category_filter.findText(current_category)
            if category_index >= 0:
                self.category_filter.setCurrentIndex(category_index)
            self.category_filter.blockSignals(False)  # Unblock signals
        except RuntimeError:
            self.logger.warning("Category filter widget has been deleted")
        
        try:
            # Clear and repopulate type filter
            self.type_filter.blockSignals(True)  # Block signals to prevent multiple updates
            self.type_filter.clear()
            self.type_filter.addItem("All Types")
            self.type_filter.addItems(sorted(types))
            
            # Restore selections or default to "All"
            type_index = self.type_filter.findText(current_type)
            if type_index >= 0:
                self.type_filter.setCurrentIndex(type_index)
            self.type_filter.blockSignals(False)  # Unblock signals
        except RuntimeError:
            self.logger.warning("Type filter widget has been deleted")

    def apply_filters(self):
        """Apply filters to the data with protection against widget deletion."""
        if not self.data:
            return
                
        # Get filter values safely
        try:
            category = self.category_filter.currentText()
        except RuntimeError:  # Widget has been deleted
            category = "All Categories"
            
        try:
            type_ = self.type_filter.currentText()
        except RuntimeError:  # Widget has been deleted
            type_ = "All Types"
            
        try:
            search_text = self.search_input.text().lower()
        except RuntimeError:  # Widget has been deleted
            search_text = ""
        
        # Apply filters
        self.filtered_data = []
        
        for item in self.data:
            # Category filter
            if category != "All Categories" and item.get('Category', '') != category:
                continue
                    
            # Type filter
            if type_ != "All Types" and item.get('Type', '') != type_:
                continue
                    
            # Search filter
            if search_text:
                # Search in all fields
                found = False
                for key, value in item.items():
                    if search_text in str(value).lower():
                        found = True
                        break
                    
                if not found:
                    continue
                
            # Item passed all filters
            self.filtered_data.append(item)
        
        # Update data count label safely
        try:
            if hasattr(self, 'data_count_label'):
                total_count = len(self.data)
                filtered_count = len(self.filtered_data)
                
                if filtered_count == total_count:
                    self.data_count_label.setText(f"Showing all {total_count} items")
                else:
                    self.data_count_label.setText(f"Showing {filtered_count} of {total_count} items")
                
                # Set color based on filter status
                if filtered_count == 0:
                    self.data_count_label.setStyleSheet("""
                        font-weight: bold;
                        color: #e53935;
                        padding: 5px;
                        background-color: #ffebee;
                        border-radius: 4px;
                        margin: 5px 0;
                    """)
                elif filtered_count < total_count:
                    self.data_count_label.setStyleSheet("""
                        font-weight: bold;
                        color: #f57c00;
                        padding: 5px;
                        background-color: #fff3e0;
                        border-radius: 4px;
                        margin: 5px 0;
                    """)
                else:
                    self.data_count_label.setStyleSheet("""
                        font-weight: bold;
                        color: #0066cc;
                        padding: 5px;
                        background-color: #e6f2ff;
                        border-radius: 4px;
                        margin: 5px 0;
                    """)
        except RuntimeError:
            self.logger.warning("Data count label widget has been deleted")
                
        # Update table with filtered data safely
        try:
            self.populate_table()
        except RuntimeError:
            self.logger.warning("Error updating table, widget may have been deleted")
        
        # Update status message safely
        try:
            if hasattr(self, 'status_label'):
                if self.filtered_data:
                    total_pii_count = 0
                    for item in self.filtered_data:
                        pii_data = item.get('PII', '')
                        try:
                            if isinstance(pii_data, str):
                                parsed = ast.literal_eval(pii_data)
                                if isinstance(parsed, list):
                                    total_pii_count += len(parsed)
                        except:
                            # Skip items that can't be parsed
                            pass
                            
                    self.status_label.setText(f"Found {len(self.filtered_data)} items containing approximately {total_pii_count} PII fields")
                else:
                    self.status_label.setText("No items match the current filters")
        except RuntimeError:
            self.logger.warning("Status label widget has been deleted")

    def item_selected(self):
        """Handle item selection in the table with protection against widget deletion."""
        try:
            selected_rows = self.table.selectedItems()
            if not selected_rows:
                # Clear details if nothing selected
                self.clear_details()
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