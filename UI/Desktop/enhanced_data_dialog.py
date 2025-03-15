"""
Enhanced data dialog with proper CRUD functionality for PII data management.
"""

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem, 
    QPushButton, QLabel, QLineEdit, QComboBox, QMessageBox, QFrame,
    QHeaderView, QAbstractItemView, QApplication, QSplitter, QWidget,
    QGroupBox, QFormLayout, QTextEdit, QScrollArea, QSizePolicy, QStyle
)
from PyQt5.QtCore import Qt, QSize, QTimer
from PyQt5.QtGui import QIcon, QColor, QPalette
import pandas as pd
import logging
import ast
import json
import time

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
        """Set up the user interface."""
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # Header with filters and actions
        header_layout = QHBoxLayout()
        
        # Filter section
        filter_group = QGroupBox("Filters")
        filter_layout = QHBoxLayout(filter_group)
        
        # Category filter
        category_label = QLabel("Category:")
        self.category_filter = QComboBox()
        self.category_filter.addItem("All Categories")
        self.category_filter.currentIndexChanged.connect(self.apply_filters)
        
        # Type filter
        type_label = QLabel("Type:")
        self.type_filter = QComboBox()
        self.type_filter.addItem("All Types")
        self.type_filter.currentIndexChanged.connect(self.apply_filters)
        
        # Search field
        search_label = QLabel("Search:")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search in all fields...")
        self.search_input.textChanged.connect(self.apply_filters)
        
        # Add filters to layout
        filter_layout.addWidget(category_label)
        filter_layout.addWidget(self.category_filter)
        filter_layout.addWidget(type_label)
        filter_layout.addWidget(self.type_filter)
        filter_layout.addWidget(search_label)
        filter_layout.addWidget(self.search_input)
        
        # Action buttons for header
        action_layout = QHBoxLayout()
        
        # Refresh button
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.setIcon(self.style().standardIcon(QStyle.SP_BrowserReload))
        self.refresh_btn.clicked.connect(self.fetch_data)
        
        # Add new button
        self.add_btn = QPushButton("Add New Item")
        self.add_btn.setIcon(self.style().standardIcon(QStyle.SP_FileDialogNewFolder))
        self.add_btn.clicked.connect(self.add_new_item)
        
        # Add buttons to layout
        action_layout.addWidget(self.refresh_btn)
        action_layout.addWidget(self.add_btn)
        
        # Add filter and action sections to header
        header_layout.addWidget(filter_group, 3)
        header_layout.addLayout(action_layout, 1)
        
        # Add header to main layout
        main_layout.addLayout(header_layout)
        
        # Create splitter for table and details
        splitter = QSplitter(Qt.Horizontal)
        
        # Data table section (left side)
        table_widget = QWidget()
        table_layout = QVBoxLayout(table_widget)
        table_layout.setContentsMargins(0, 0, 0, 0)
        
        # Table view
        self.table = QTableWidget()
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["ID", "Category", "Type", "PII Data"])
        
        # Connect selection change
        self.table.itemSelectionChanged.connect(self.item_selected)
        
        # Add table to layout
        table_layout.addWidget(self.table)
        
        # Details section (right side)
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        
        # Details header
        details_header = QLabel("Item Details")
        details_header.setStyleSheet("font-weight: bold; font-size: 14px;")
        details_layout.addWidget(details_header)
        
        # Item details form
        details_form = QGroupBox()
        form_layout = QFormLayout(details_form)
        
        # ID field (read-only)
        self.id_field = QLineEdit()
        self.id_field.setReadOnly(True)
        form_layout.addRow("Item ID:", self.id_field)
        
        # Category field
        self.category_field = QLineEdit()
        form_layout.addRow("Category:", self.category_field)
        
        # Type field
        self.type_field = QLineEdit()
        form_layout.addRow("Type:", self.type_field)
        
        # Add form to layout
        details_layout.addWidget(details_form)
        
        # PII Data section
        pii_group = QGroupBox("PII Data")
        pii_layout = QVBoxLayout(pii_group)
        
        # Scroll area for PII fields
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        self.pii_widget = QWidget()
        self.pii_layout = QVBoxLayout(self.pii_widget)
        scroll.setWidget(self.pii_widget)
        pii_layout.addWidget(scroll)
        
        # Add button to add PII fields
        add_field_btn = QPushButton("Add Field")
        add_field_btn.clicked.connect(self.add_pii_field)
        pii_layout.addWidget(add_field_btn)
        
        # Add PII group to details
        details_layout.addWidget(pii_group)
        
        # Action buttons for details
        details_buttons = QHBoxLayout()
        
        # Save button
        self.save_btn = QPushButton("Save Changes")
        self.save_btn.setIcon(self.style().standardIcon(QStyle.SP_DialogSaveButton))
        self.save_btn.clicked.connect(self.save_item)
        self.save_btn.setEnabled(False)
        
        # Delete button
        self.delete_btn = QPushButton("Delete Item")
        self.delete_btn.setIcon(self.style().standardIcon(QStyle.SP_TrashIcon))
        self.delete_btn.clicked.connect(self.delete_item)
        self.delete_btn.setEnabled(False)
        
        # Add buttons to layout
        details_buttons.addWidget(self.save_btn)
        details_buttons.addWidget(self.delete_btn)
        details_layout.addLayout(details_buttons)
        
        # Add stretch to push everything up
        details_layout.addStretch()
        
        # Add widgets to splitter
        splitter.addWidget(table_widget)
        splitter.addWidget(details_widget)
        
        # Set initial sizes (40% table, 60% details)
        splitter.setSizes([400, 600])
        
        # Add splitter to main layout
        main_layout.addWidget(splitter)
        
        # Bottom action buttons
        bottom_layout = QHBoxLayout()
        
        # Download button
        self.download_btn = QPushButton("Download Data")
        self.download_btn.setIcon(self.style().standardIcon(QStyle.SP_ArrowDown))
        # Will be connected externally
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        
        # Add buttons to layout
        bottom_layout.addWidget(self.download_btn)
        bottom_layout.addStretch()
        bottom_layout.addWidget(close_btn)
        
        # Add bottom layout to main layout
        main_layout.addLayout(bottom_layout)
        
    def fetch_data(self):
        """Fetch PII data from the server."""
        # Show loading indicator
        self.setCursor(Qt.WaitCursor)
        
        try:
            # Try API client first
            if self.api_client:
                self.logger.info("Fetching data using API client")
                success, data = self.api_client.sync_get_pii_data()
                
                if success:
                    self.data = data
                    self.logger.info(f"Fetched {len(data)} PII items")
                    self.update_filters()
                    self.populate_table()
                else:
                    error_msg = data.get('error', str(data)) if isinstance(data, dict) else str(data)
                    raise ValueError(f"API client error: {error_msg}")
            
            # Fall back to auth_service
            elif self.auth_service:
                self.logger.info("Fetching data using auth_service")
                
                # Use direct sync method if available
                if hasattr(self.auth_service, 'make_synchronous_request'):
                    success, data = self.auth_service.make_synchronous_request(
                        method="GET",
                        endpoint="pii"
                    )
                # Otherwise use async method with workaround
                elif hasattr(self.auth_service, 'make_authenticated_request'):
                    import asyncio
                    loop = asyncio.new_event_loop()
                    try:
                        success, data = loop.run_until_complete(
                            self.auth_service.make_authenticated_request(
                                method="GET",
                                endpoint="pii"
                            )
                        )
                    finally:
                        loop.close()
                
                if success:
                    self.data = data
                    self.logger.info(f"Fetched {len(data)} PII items")
                    self.update_filters()
                    self.populate_table()
                else:
                    error_msg = data.get('error', str(data)) if isinstance(data, dict) else str(data)
                    raise ValueError(f"Auth service error: {error_msg}")
            
            # Last resort: try agent directly
            elif self.agent:
                self.logger.info("Fetching data using agent directly")
                data = self.agent.get_all_data()
                
                if data:
                    self.data = data
                    self.logger.info(f"Fetched {len(data)} PII items")
                    self.update_filters()
                    self.populate_table()
                else:
                    raise ValueError("Agent returned no data")
            
            else:
                raise ValueError("No data source available (API client, auth service, or agent)")
                
        except Exception as e:
            self.logger.error(f"Error fetching data: {str(e)}")
            QMessageBox.critical(self, "Data Error", f"Failed to fetch data: {str(e)}")
            
        finally:
            # Reset cursor
            self.setCursor(Qt.ArrowCursor)
            
    def update_filters(self):
        """Update filter dropdowns with available options."""
        if not self.data:
            return
            
        # Save current selections
        current_category = self.category_filter.currentText()
        current_type = self.type_filter.currentText()
        
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
        
        # Clear and repopulate category filter
        self.category_filter.clear()
        self.category_filter.addItem("All Categories")
        self.category_filter.addItems(sorted(categories))
        
        # Clear and repopulate type filter
        self.type_filter.clear()
        self.type_filter.addItem("All Types")
        self.type_filter.addItems(sorted(types))
        
        # Restore selections or default to "All"
        category_index = self.category_filter.findText(current_category)
        if category_index >= 0:
            self.category_filter.setCurrentIndex(category_index)
        
        type_index = self.type_filter.findText(current_type)
        if type_index >= 0:
            self.type_filter.setCurrentIndex(type_index)
            
    def apply_filters(self):
        """Apply filters to the data."""
        if not self.data:
            return
            
        # Get filter values
        category = self.category_filter.currentText()
        type_ = self.type_filter.currentText()
        search_text = self.search_input.text().lower()
        
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
            
        # Update table with filtered data
        self.populate_table()
        
    def populate_table(self):
        """Populate the table with filtered data."""
        # Clear existing rows
        self.table.setRowCount(0)
        
        if not self.filtered_data:
            return
            
        # Populate table with filtered data
        for row, item in enumerate(self.filtered_data):
            self.table.insertRow(row)
            
            # ID column
            id_item = QTableWidgetItem(item.get('_id', ''))
            self.table.setItem(row, 0, id_item)
            
            # Category column
            category_item = QTableWidgetItem(item.get('Category', ''))
            self.table.setItem(row, 1, category_item)
            
            # Type column
            type_item = QTableWidgetItem(item.get('Type', ''))
            self.table.setItem(row, 2, type_item)
            
            # PII Data preview
            pii_text = self.get_pii_preview(item.get('PII', ''))
            pii_item = QTableWidgetItem(pii_text)
            self.table.setItem(row, 3, pii_item)
            
        # Adjust columns
        self.table.resizeColumnsToContents()
        
    def get_pii_preview(self, pii_data):
        """
        Get a preview of PII data for table display.
        
        Args:
            pii_data: PII data to preview
            
        Returns:
            str: Preview text
        """
        try:
            # If it's a string, try to parse it as JSON or list of dicts
            if isinstance(pii_data, str):
                try:
                    parsed_data = ast.literal_eval(pii_data)
                    
                    if isinstance(parsed_data, list):
                        # Show first few items
                        items = []
                        for item in parsed_data[:3]:
                            if isinstance(item, dict) and 'Item Name' in item and 'Data' in item:
                                items.append(f"{item['Item Name']}: {item['Data']}")
                            else:
                                items.append(str(item))
                                
                        # Add ellipsis if there are more items
                        if len(parsed_data) > 3:
                            items.append("...")
                            
                        return ", ".join(items)
                    else:
                        return str(parsed_data)
                except (SyntaxError, ValueError):
                    # If parsing fails, just return the string
                    return pii_data[:50] + ("..." if len(pii_data) > 50 else "")
            
            # For other types, convert to string
            return str(pii_data)[:50] + ("..." if len(str(pii_data)) > 50 else "")
            
        except Exception as e:
            self.logger.error(f"Error generating PII preview: {str(e)}")
            return "Error: Could not preview data"
            
    def item_selected(self):
        """Handle item selection in the table."""
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
            
            # Enable edit/delete buttons
            self.save_btn.setEnabled(True)
            self.delete_btn.setEnabled(True)
        else:
            self.clear_details()
            
    def display_item_details(self, item):
        """
        Display item details in the form.
        
        Args:
            item: The item to display
        """
        # Clear existing details first
        self.clear_details()
        
        # Set basic fields
        self.id_field.setText(item.get('_id', ''))
        self.category_field.setText(item.get('Category', ''))
        self.type_field.setText(item.get('Type', ''))
        
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
                    pii_items = [{"Item Name": "Data", "Data": pii_data}]
            else:
                # For non-string data
                pii_items = [{"Item Name": "Data", "Data": str(pii_data)}]
                
            # Add fields for each PII item
            for pii_item in pii_items:
                self.add_pii_field(
                    pii_item.get("Item Name", ""),
                    pii_item.get("Data", "")
                )
                
        except Exception as e:
            self.logger.error(f"Error parsing PII data: {str(e)}")
            # Add a single field with error message
            self.add_pii_field("Error", f"Could not parse PII data: {str(e)}")
            
    def clear_details(self):
        """Clear all details fields."""
        # Clear basic fields
        self.id_field.setText("")
        self.category_field.setText("")
        self.type_field.setText("")
        
        # Clear PII fields
        self.clear_pii_fields()
        
        # Disable buttons
        self.save_btn.setEnabled(False)
        self.delete_btn.setEnabled(False)
        
        # Clear current item
        self.current_item = None
        
    def clear_pii_fields(self):
        """Clear all PII fields."""
        # Remove all widgets from the PII layout
        while self.pii_layout.count():
            item = self.pii_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
                
    def add_pii_field(self, name="", value=""):
        """
        Add a field for PII data.
        
        Args:
            name (str): Field name
            value (str): Field value
        """
        # Create a frame for this field
        field_frame = QFrame()
        field_frame.setFrameShape(QFrame.StyledPanel)
        field_frame.setFrameShadow(QFrame.Raised)
        
        field_layout = QHBoxLayout(field_frame)
        field_layout.setContentsMargins(5, 5, 5, 5)
        
        # Name input
        name_input = QLineEdit(name)
        name_input.setPlaceholderText("Field Name")
        
        # Value input
        value_input = QLineEdit(value)
        value_input.setPlaceholderText("Field Value")
        
        # Remove button
        remove_btn = QPushButton("×")
        remove_btn.setFixedSize(24, 24)
        remove_btn.clicked.connect(lambda: self.remove_pii_field(field_frame))
        
        # Add widgets to layout
        field_layout.addWidget(name_input, 1)
        field_layout.addWidget(value_input, 2)
        field_layout.addWidget(remove_btn)
        
        # Add to PII layout
        self.pii_layout.addWidget(field_frame)
        
        # Return a reference to update the UI state
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
        Collect data from all PII fields.
        
        Returns:
            list: List of PII items
        """
        pii_items = []
        
        # Iterate through all frames in the PII layout
        for i in range(self.pii_layout.count()):
            field_frame = self.pii_layout.itemAt(i).widget()
            
            if not field_frame:
                continue
                
            # Get the layout of this frame
            field_layout = field_frame.layout()
            
            # Get the name and value inputs
            name_input = field_layout.itemAt(0).widget()
            value_input = field_layout.itemAt(1).widget()
            
            # Add to PII items if name is not empty
            name = name_input.text().strip()
            value = value_input.text()
            
            if name:
                pii_items.append({
                    "Item Name": name,
                    "Data": value
                })
                
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
        """Save the current item."""
        # Get basic fields
        item_id = self.id_field.text().strip()
        category = self.category_field.text().strip()
        type_ = self.type_field.text().strip()
        
        # Validate required fields
        if not category:
            QMessageBox.warning(self, "Validation Error", "Category is required")
            return
            
        if not type_:
            QMessageBox.warning(self, "Validation Error", "Type is required")
            return
            
        # Collect PII data
        pii_items = self.collect_pii_fields()
        
        if not pii_items:
            QMessageBox.warning(self, "Validation Error", "At least one PII field is required")
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
            
        # Show progress
        self.setCursor(Qt.WaitCursor)
        
        try:
            # Determine if this is an update or create
            is_update = bool(item_id)
            
            if is_update:
                self.logger.info(f"Updating item with ID: {item_id}")
                success, result = self.update_item(item_data)
            else:
                self.logger.info("Creating new item")
                success, result = self.create_item(item_data)
                
            if success:
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
            self.setCursor(Qt.ArrowCursor)
            
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