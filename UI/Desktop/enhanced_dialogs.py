"""
Enhanced data item dialog with input validation.

This module provides an improved version of the data item edit dialog with
robust input validation, field-level feedback, and a more intuitive interface.
"""

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QGroupBox, QFrame, QMessageBox, QScrollArea, QSizePolicy, QWidget,
    QTextEdit, QFormLayout, QTableWidget, QHeaderView, QTableWidgetItem,
    QAbstractItemView, QCheckBox, QSpacerItem, QStyle
)
from PyQt5.QtCore import Qt, QSize, QRegExp, QTimer
from PyQt5.QtGui import QColor, QIcon, QRegExpValidator, QPixmap, QPalette
import ast
import re
import logging
import traceback
from typing import Dict, Any, List, Tuple, Optional, Union

from UI.Desktop.standard_theme import StandardTheme
from data_validation import InputValidator, DataValidator


# Configure logging
logger = logging.getLogger("guard.dialogs")


class ValidationLineEdit(QLineEdit):
    """Enhanced line edit with built-in validation."""
    
    def __init__(self, parent=None, validator_func=None):
        """
        Initialize the validation line edit.
        
        Args:
            parent: Parent widget
            validator_func: Function to validate input (returns bool, str)
        """
        super().__init__(parent)
        self.validator_func = validator_func
        self.valid = True
        self.error_message = ""
        
        # Create error label (initially hidden)
        self.error_label = QLabel("", parent)
        self.error_label.setStyleSheet("""
            color: #F44336;
            font-size: 11px;
            padding-left: 5px;
        """)
        self.error_label.setVisible(False)
        
        # Connect validator to text change
        self.textChanged.connect(self.validate_input)
        
        # Apply base styling
        self.setup_styling()
    
    def setup_styling(self):
        """Set initial styling for the input field."""
        self.setStyleSheet("""
            QLineEdit {
                border: 1px solid #BDBDBD;
                border-radius: 4px;
                padding: 6px;
                background-color: #FFFFFF;
            }
            QLineEdit:focus {
                border: 1px solid #1976D2;
            }
        """)
    
    def validate_input(self):
        """Validate the current input and update styling."""
        if self.validator_func:
            text = self.text()
            self.valid, self.error_message = self.validator_func(text)
            
            if self.valid:
                # Reset styling for valid input
                self.setStyleSheet("""
                    QLineEdit {
                        border: 1px solid #BDBDBD;
                        border-radius: 4px;
                        padding: 6px;
                        background-color: #FFFFFF;
                    }
                    QLineEdit:focus {
                        border: 1px solid #1976D2;
                    }
                """)
                self.error_label.setVisible(False)
            else:
                # Apply error styling
                self.setStyleSheet("""
                    QLineEdit {
                        border: 1px solid #F44336;
                        border-radius: 4px;
                        padding: 6px;
                        background-color: #FFEBEE;
                    }
                    QLineEdit:focus {
                        border: 1px solid #D32F2F;
                        background-color: #FFFFFF;
                    }
                """)
                self.error_label.setText(self.error_message)
                self.error_label.setVisible(True)
    
    def is_valid(self) -> bool:
        """
        Check if the current input is valid.
        
        Returns:
            bool: True if input is valid
        """
        return self.valid or not self.validator_func


class PIIFieldItem(QWidget):
    """Widget for a single PII field with name and value inputs."""
    
    def __init__(self, parent=None, name="", value="", index=0, can_remove=True):
        """
        Initialize the PII field item.
        
        Args:
            parent: Parent widget
            name: Initial name value
            value: Initial data value
            index: Field index
            can_remove: Whether the field can be removed
        """
        super().__init__(parent)
        self.index = index
        self.can_remove = can_remove
        
        # Set up layout
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        # Item name input with validation
        self.name_input = ValidationLineEdit(self, InputValidator.validate_pii_field_name)
        self.name_input.setPlaceholderText("Field name...")
        self.name_input.setText(name)
        
        # Value input (uses regular QLineEdit since we're less restrictive with values)
        self.value_input = QLineEdit(self)
        self.value_input.setPlaceholderText("Field value...")
        self.value_input.setText(value)
        
        # Create a form layout for better alignment
        form_layout = QFormLayout()
        form_layout.setContentsMargins(0, 0, 0, 0)
        form_layout.setSpacing(5)
        form_layout.addRow("Field Name:", self.name_input)
        
        # Add error label to form layout
        field_name_layout = QVBoxLayout()
        field_name_layout.setContentsMargins(0, 0, 0, 0)
        field_name_layout.setSpacing(0)
        field_name_layout.addWidget(self.name_input)
        field_name_layout.addWidget(self.name_input.error_label)
        
        # Add to form layout
        form_layout.addRow("Field Name:", field_name_layout)
        form_layout.addRow("Value:", self.value_input)
        
        # Add form layout to main layout
        layout.addLayout(form_layout, 1)  # Give stretch priority
        
        # Add remove button if allowed
        if can_remove:
            self.remove_button = QPushButton("×", self)
            self.remove_button.setFixedSize(24, 24)
            self.remove_button.setToolTip("Remove field")
            self.remove_button.setCursor(Qt.PointingHandCursor)
            self.remove_button.setStyleSheet("""
                QPushButton {
                    background-color: #F44336;
                    color: white;
                    border: none;
                    border-radius: 12px;
                    font-weight: bold;
                    font-size: 16px;
                }
                QPushButton:hover {
                    background-color: #D32F2F;
                }
            """)
            layout.addWidget(self.remove_button, 0, Qt.AlignTop)
        
        # Initial validation
        self.name_input.validate_input()
    
    def get_field_data(self) -> Dict[str, str]:
        """
        Get the field data as a dictionary.
        
        Returns:
            Dict[str, str]: Field data with name and value
        """
        return {
            "Item Name": self.name_input.text().strip(),
            "Data": self.value_input.text()
        }
    
    def is_valid(self) -> bool:
        """
        Check if the field inputs are valid.
        
        Returns:
            bool: True if inputs are valid
        """
        return self.name_input.is_valid()
    
    def is_empty(self) -> bool:
        """
        Check if the field is empty.
        
        Returns:
            bool: True if both name and value are empty
        """
        return not self.name_input.text().strip() and not self.value_input.text().strip()


class EnhancedDataItemDialog(QDialog):
    """
    Enhanced dialog for editing PII data items with validation.
    
    This dialog provides a user-friendly interface for creating and editing
    PII data items with field-level validation and feedback.
    """
    
    def __init__(self, item_data, parent=None):
        """
        Initialize the data item dialog.
        
        Args:
            item_data (dict): The data item to edit
            parent: Parent widget
        """
        super().__init__(parent)
        self.item_data = item_data.copy()  # Create a copy to avoid modifying the original
        self.result_data = None
        self.pii_fields = []
        
        # Set up UI
        self.setup_ui()
        self.setWindowTitle("Edit Data Item" if self.item_data.get('_id') else "Add New Data Item")
        self.resize(700, 500)
        
        # Set window modality
        self.setWindowModality(Qt.ApplicationModal)
    
    def setup_ui(self):
        """Set up the user interface."""
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(15)
        
        # Add title if creating new item
        if not self.item_data.get('_id'):
            title_label = QLabel("Add New Data Item", self)
            title_label.setStyleSheet("""
                font-size: 18px;
                font-weight: bold;
                color: #1976D2;
                margin-bottom: 10px;
            """)
            main_layout.addWidget(title_label, 0, Qt.AlignCenter)
        
        # Item metadata section
        metadata_group = QGroupBox("Item Information", self)
        metadata_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #E0E0E0;
                border-radius: 6px;
                margin-top: 12px;
                padding-top: 20px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                left: 10px;
                padding: 0 5px;
                color: #1976D2;
            }
        """)
        metadata_layout = QFormLayout(metadata_group)
        
        # Item ID (read-only)
        if self.item_data.get('_id'):
            self.id_input = QLineEdit(self.item_data.get('_id', ''), self)
            self.id_input.setReadOnly(True)
            self.id_input.setStyleSheet("""
                background-color: #F5F5F5;
                border: 1px solid #E0E0E0;
                border-radius: 4px;
                padding: 6px;
                color: #757575;
            """)
            metadata_layout.addRow("Item ID:", self.id_input)
        
        # Category input with validation
        self.category_input = ValidationLineEdit(self, InputValidator.validate_category_name)
        self.category_input.setText(self.item_data.get('Category', ''))
        self.category_input.setPlaceholderText("Enter category name...")
        
        # Add error label to layout
        category_layout = QVBoxLayout()
        category_layout.setContentsMargins(0, 0, 0, 0)
        category_layout.setSpacing(0)
        category_layout.addWidget(self.category_input)
        category_layout.addWidget(self.category_input.error_label)
        metadata_layout.addRow("Category:", category_layout)
        
        # Type input with validation
        self.type_input = ValidationLineEdit(self, InputValidator.validate_type_name)
        self.type_input.setText(self.item_data.get('Type', ''))
        self.type_input.setPlaceholderText("Enter type name...")
        
        # Add error label to layout
        type_layout = QVBoxLayout()
        type_layout.setContentsMargins(0, 0, 0, 0)
        type_layout.setSpacing(0)
        type_layout.addWidget(self.type_input)
        type_layout.addWidget(self.type_input.error_label)
        metadata_layout.addRow("Type:", type_layout)
        
        main_layout.addWidget(metadata_group)
        
        # PII data section
        pii_group = QGroupBox("PII Data Fields", self)
        pii_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                border: 1px solid #E0E0E0;
                border-radius: 6px;
                margin-top: 12px;
                padding-top: 20px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                left: 10px;
                padding: 0 5px;
                color: #1976D2;
            }
        """)
        
        # Create a scroll area for PII fields
        scroll_area = QScrollArea(pii_group)
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.NoFrame)
        
        # Create container for PII fields
        self.pii_container = QWidget(scroll_area)
        self.pii_layout = QVBoxLayout(self.pii_container)
        self.pii_layout.setContentsMargins(10, 10, 10, 10)
        self.pii_layout.setSpacing(15)
        
        # Add a stretch at the end for better layout
        self.pii_layout.addStretch()
        
        # Set the container as the scroll area widget
        scroll_area.setWidget(self.pii_container)
        
        # Add scroll area to the PII group
        pii_group_layout = QVBoxLayout(pii_group)
        pii_group_layout.addWidget(scroll_area)
        
        # Create a container for the "Add Field" button
        button_container = QWidget(pii_group)
        button_layout = QHBoxLayout(button_container)
        button_layout.setContentsMargins(10, 5, 10, 5)
        
        # Add the "Add Field" button
        add_field_button = QPushButton("Add Field", button_container)
        add_field_button.setCursor(Qt.PointingHandCursor)
        try:
            add_field_button.setStyleSheet(StandardTheme.get_button_style('secondary', 'small'))
        except:
            add_field_button.setStyleSheet("""
                QPushButton {
                    background-color: #607D8B;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    padding: 5px 10px;
                }
                QPushButton:hover {
                    background-color: #455A64;
                }
            """)
        
        add_field_button.setIcon(self.style().standardIcon(QStyle.SP_FileDialogNewFolder))
        add_field_button.clicked.connect(self.add_pii_field)
        button_layout.addStretch()
        button_layout.addWidget(add_field_button)
        
        # Add the button container to the PII group
        pii_group_layout.addWidget(button_container)
        
        # Add the PII group to the main layout
        main_layout.addWidget(pii_group, 1)  # Give stretch priority
        
        # Process existing PII data
        self.process_pii_data()
        
        # Dialog buttons
        button_layout = QHBoxLayout()
        button_layout.setContentsMargins(0, 10, 0, 0)
        
        self.cancel_button = QPushButton("Cancel", self)
        self.cancel_button.setCursor(Qt.PointingHandCursor)
        self.cancel_button.clicked.connect(self.reject)
        
        self.save_button = QPushButton("Save Changes", self)
        self.save_button.setCursor(Qt.PointingHandCursor)
        
        try:
            self.cancel_button.setStyleSheet(StandardTheme.get_button_style('secondary', 'medium'))
            self.save_button.setStyleSheet(StandardTheme.get_button_style('primary', 'medium'))
        except:
            self.cancel_button.setStyleSheet("""
                QPushButton {
                    background-color: #9E9E9E;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    padding: 8px 16px;
                }
                QPushButton:hover {
                    background-color: #757575;
                }
            """)
            self.save_button.setStyleSheet("""
                QPushButton {
                    background-color: #1976D2;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    padding: 8px 16px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #1565C0;
                }
            """)
        
        self.save_button.clicked.connect(self.accept_changes)
        
        button_layout.addWidget(self.cancel_button)
        button_layout.addStretch()
        button_layout.addWidget(self.save_button)
        
        main_layout.addLayout(button_layout)
    
    def process_pii_data(self, item: Dict[str, Any]) -> Tuple[bool, Union[Dict[str, Any], str]]:
        """
        Process and decrypt PII data in an item, handling both outer and inner encryption layers.
        
        Args:
            item (Dict): Item containing PII data
            
        Returns:
            Tuple[bool, Union[Dict, str]]: Success flag and processed item or error message
        """
        try:
            # Clone the item to avoid modifying the original
            processed_item = item.copy()
            
            # Identify the PII field
            pii_field = None
            if 'PII' in processed_item:
                pii_field = 'PII'
            elif 'Data' in processed_item:
                pii_field = 'Data'
                
            if not pii_field:
                return True, processed_item  # No PII field to process
                
            encrypted_data = processed_item[pii_field]
            print(f"Processing PII field: {pii_field}, type: {type(encrypted_data)}")
            
            # If it's a dict (DynamoDB native format), extract the value
            if isinstance(encrypted_data, dict):
                if 'S' in encrypted_data:
                    encrypted_data = encrypted_data['S']
                elif 'B' in encrypted_data:
                    encrypted_data = encrypted_data['B']
                    
            # Try to decrypt the outer layer
            if isinstance(encrypted_data, str):
                # Check if it's already JSON (not encrypted)
                if encrypted_data.startswith('{') or encrypted_data.startswith('['):
                    try:
                        import json
                        json.loads(encrypted_data)  # This will raise an exception if not valid JSON
                        print("PII data is already valid JSON")
                        pii_data = encrypted_data
                    except json.JSONDecodeError:
                        print("Looks like JSON but isn't valid, trying decryption")
                        # Try to decrypt
                        pii_data = self.kms_handler.decrypt_to_string(encrypted_data)
                else:
                    # Standard decryption
                    pii_data = self.kms_handler.decrypt_to_string(encrypted_data)
                    
                    # If standard decryption fails, try the specialized method
                    if not pii_data and hasattr(self.kms_handler, 'decrypt_pii_data'):
                        print("Trying specialized decrypt_pii_data method")
                        pii_data = self.kms_handler.decrypt_pii_data(encrypted_data)
            else:
                # Binary data
                decrypted = self.kms_handler.decrypt(encrypted_data)
                pii_data = decrypted.decode('utf-8') if decrypted else None
            
            if not pii_data:
                print("Failed to decrypt PII data, returning original item")
                return True, processed_item
                
            print(f"Successfully decrypted outer PII data: {pii_data[:50]}...")
            processed_item[pii_field] = pii_data
            
            # Now process inner fields if it's JSON
            try:
                import json
                import ast
                
                # Try to parse the PII data
                parsed_data = None
                if isinstance(pii_data, str):
                    if pii_data.startswith('[') or pii_data.startswith('{'):
                        try:
                            parsed_data = json.loads(pii_data)
                            print(f"Successfully parsed PII as JSON, type: {type(parsed_data)}")
                        except json.JSONDecodeError:
                            try:
                                parsed_data = ast.literal_eval(pii_data)
                                print(f"Successfully parsed PII using ast, type: {type(parsed_data)}")
                            except (ValueError, SyntaxError):
                                print("Failed to parse as JSON or Python literal")
                
                # If we have a list of dictionaries, check for encrypted values
                if isinstance(parsed_data, list):
                    any_value_decrypted = False
                    
                    for item_dict in parsed_data:
                        if isinstance(item_dict, dict) and 'value' in item_dict:
                            value = item_dict['value']
                            
                            # Check if value is encrypted (Z0FB pattern)
                            if isinstance(value, str) and value.startswith('Z0FB'):
                                print(f"Found encrypted inner value: {value[:20]}...")
                                
                                # Try to decrypt the value using our specialized method
                                if hasattr(self.kms_handler, 'decrypt_pii_data'):
                                    decrypted_value = self.kms_handler.decrypt_pii_data(value)
                                    if decrypted_value:
                                        item_dict['value'] = decrypted_value
                                        any_value_decrypted = True
                                        print(f"Successfully decrypted inner value: {decrypted_value[:20]}...")
                                    else:
                                        print("Failed to decrypt inner value")
                    
                    # If we decrypted any values, update the item
                    if any_value_decrypted:
                        processed_item[pii_field] = json.dumps(parsed_data)
                        print("Updated item with decrypted inner values")
            
            except Exception as parse_error:
                print(f"Error processing inner values: {parse_error}")
                # Continue with the item as is, with outer PII decrypted
                
            return True, processed_item
                
        except Exception as e:
            error_msg = f"Error processing PII data: {e}"
            print(error_msg)
            return False, error_msg
    
    def add_pii_field(self, name="", value="", index=None, can_remove=True):
        """
        Add a new PII field input to the dialog.
        
        Args:
            name: Initial field name
            value: Initial field value
            index: Field index (or None for new field)
            can_remove: Whether the field can be removed
        """
        # Calculate index for new field
        if index is None:
            index = len(self.pii_fields)
        
        # Create field item
        field_item = PIIFieldItem(self.pii_container, name, value, index, can_remove)
        
        # Connect remove button if available
        if can_remove and hasattr(field_item, 'remove_button'):
            field_item.remove_button.clicked.connect(lambda: self.remove_pii_field(field_item))
        
        # Add to layout and tracking list
        self.pii_layout.insertWidget(self.pii_layout.count() - 1, field_item)
        self.pii_fields.append(field_item)
    
    def remove_pii_field(self, field_item):
        """
        Remove a PII field from the dialog.
        
        Args:
            field_item: The field item to remove
        """
        # Check if this is the last field
        if len(self.pii_fields) <= 1:
            # Don't remove the last field, just clear it
            field_item.name_input.clear()
            field_item.value_input.clear()
            return
        
        # Remove from tracking list
        if field_item in self.pii_fields:
            self.pii_fields.remove(field_item)
        
        # Remove from layout
        field_item.setParent(None)
        field_item.deleteLater()
        
        # Update the layout
        self.pii_layout.update()
    
    def accept_changes(self):
        """Validate inputs and accept changes if valid."""
        # Validate category and type
        if not self.category_input.is_valid():
            QMessageBox.warning(self, "Validation Error", f"Category: {self.category_input.error_message}")
            self.category_input.setFocus()
            return
        
        if not self.type_input.is_valid():
            QMessageBox.warning(self, "Validation Error", f"Type: {self.type_input.error_message}")
            self.type_input.setFocus()
            return
        
        # Check if we have at least one PII field with both name and value
        has_valid_field = False
        for field in self.pii_fields:
            if field.name_input.text().strip() and field.value_input.text().strip():
                if not field.is_valid():
                    QMessageBox.warning(self, "Validation Error", f"Field name: {field.name_input.error_message}")
                    field.name_input.setFocus()
                    return
                has_valid_field = True
        
        if not has_valid_field:
            QMessageBox.warning(
                self,
                "Validation Error",
                "At least one PII field must have both a name and value"
            )
            return
        
        # Collect the PII data
        pii_items = []
        for field in self.pii_fields:
            # Skip completely empty fields
            if field.is_empty():
                continue
            
            pii_items.append(field.get_field_data())
        
        # Create updated item data
        new_data = {
            "Category": self.category_input.text().strip(),
            "Type": self.type_input.text().strip(),
            "PII": str(pii_items)
        }
        
        # Add ID if present
        if hasattr(self, 'id_input') and self.id_input.text():
            new_data["_id"] = self.id_input.text()
        
        # Perform full validation
        is_valid, error_message = DataValidator.validate_pii_item(new_data)
        if not is_valid:
            QMessageBox.warning(self, "Validation Error", error_message)
            return
        
        # Sanitize the data
        self.result_data = DataValidator.sanitize_pii_item(new_data)
        
        # Accept the dialog
        self.accept()
    
    def get_updated_data(self):
        """
        Get the updated item data.
        
        Returns:
            dict: The updated item data or None if cancelled
        """
        return self.result_data