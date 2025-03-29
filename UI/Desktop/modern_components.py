"""
Enhanced data management components with working edit and delete functionalities.
These components integrate with the existing backend while providing a more
modern, user-friendly interface.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QDialog, QLineEdit, QScrollArea, QFrame, QMessageBox,
    QProgressBar, QStyle, QComboBox, QToolTip,
    QGroupBox, QApplication, QGraphicsDropShadowEffect
)
from PyQt5.QtGui import QColor

from PyQt5.QtCore import Qt, QSize, QTimer, QDateTime, QPoint, QRect
import ast
import datetime
import logging

logger = logging.getLogger("modern_ui")


class ModernColors:
    """Modern color scheme for the application."""
    # Main colors
    PRIMARY = "#4361ee"
    SECONDARY = "#3a0ca3"
    ACCENT = "#7209b7"
    SUCCESS = "#4cc9f0"
    WARNING = "#f72585"
    DANGER = "#e63946"
    INFO = "#4895ef"

    # Background shades
    BG_LIGHT = "#f8f9fa"
    BG_MEDIUM = "#e9ecef"
    BG_DARK = "#dee2e6"

    # Text colors
    TEXT_PRIMARY = "#212529"
    TEXT_SECONDARY = "#495057"
    TEXT_MUTED = "#6c757d"
    TEXT_LIGHT = "#f8f9fa"

class SessionStatusWidget(QWidget):
    """
    Advanced session status widget with visual indicators and controls.
    
    This widget provides a comprehensive view of the current session state
    with visual indicators for session health, expiration countdown,
    and interactive controls for session management.
    """
    
    def __init__(self, parent=None, session_manager=None, auth_service=None):
        """
        Initialize the session status widget.
        
        Args:
            parent: Parent widget
            session_manager: Session manager to monitor
            auth_service: Authentication service for server communication
        """
        super().__init__(parent)
        self.session_manager = session_manager
        self.auth_service = auth_service
        self.parent = parent
        
        # Set up update timer
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_status)
        self.timer.start(1000)  # Update every second for accurate countdown
        
        # Setup UI
        self.setup_ui()
        
        # Initial update
        self.update_status()
    
    def setup_ui(self):
        """Set up the user interface with modern styling."""
        # Main layout
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(10, 5, 10, 5)
        main_layout.setSpacing(10)
        
        # Create card container with shadow effect
        self.status_card = QFrame(self)
        self.status_card.setObjectName("statusCard")
        self.status_card.setFrameShape(QFrame.StyledPanel)
        self.status_card.setStyleSheet("""
            #statusCard {
                background-color: #ffffff;
                border-radius: 8px;
                border: 1px solid #e0e0e0;
            }
        """)
        
        # Add shadow effect
        shadow = QGraphicsDropShadowEffect(self.status_card)
        shadow.setBlurRadius(10)
        shadow.setColor(QColor(0, 0, 0, 30))
        shadow.setOffset(0, 3)
        self.status_card.setGraphicsEffect(shadow)
        
        # Card layout
        card_layout = QHBoxLayout(self.status_card)
        card_layout.setContentsMargins(15, 10, 15, 10)
        card_layout.setSpacing(15)
        
        # Status indicator
        self.status_indicator = QFrame(self.status_card)
        self.status_indicator.setFixedSize(12, 12)
        self.status_indicator.setStyleSheet("""
            background-color: #bdbdbd;
            border-radius: 6px;
        """)
        card_layout.addWidget(self.status_indicator)
        
        # User info section
        user_info_layout = QVBoxLayout()
        user_info_layout.setSpacing(2)
        
        self.user_label = QLabel("Not authenticated", self.status_card)
        self.user_label.setStyleSheet("""
            font-family: 'Segoe UI', Arial, sans-serif;
            font-weight: bold;
            color: #424242;
            font-size: 13px;
        """)
        
        self.auth_type_label = QLabel("", self.status_card)
        self.auth_type_label.setStyleSheet("""
            font-family: 'Segoe UI', Arial, sans-serif;
            color: #757575;
            font-size: 11px;
        """)
        
        user_info_layout.addWidget(self.user_label)
        user_info_layout.addWidget(self.auth_type_label)
        card_layout.addLayout(user_info_layout)
        
        # Add spacer
        card_layout.addStretch()
        
        # Session time section
        session_time_layout = QVBoxLayout()
        session_time_layout.setSpacing(5)
        
        self.time_label = QLabel("Session: --:--", self.status_card)
        self.time_label.setStyleSheet("""
            font-family: 'Segoe UI', Arial, sans-serif;
            color: #424242;
            font-size: 12px;
            padding-right: 5px;
        """)
        self.time_label.setAlignment(Qt.AlignRight)
        
        # Progress bar for time remaining
        self.time_progress = QProgressBar(self.status_card)
        self.time_progress.setRange(0, 100)
        self.time_progress.setValue(0)
        self.time_progress.setTextVisible(False)
        self.time_progress.setFixedHeight(4)
        self.time_progress.setFixedWidth(100)
        self.time_progress.setStyleSheet("""
            QProgressBar {
                background-color: #e0e0e0;
                border-radius: 2px;
                border: none;
            }
            QProgressBar::chunk {
                background-color: #1976D2;
                border-radius: 2px;
            }
        """)
        
        session_time_layout.addWidget(self.time_label)
        session_time_layout.addWidget(self.time_progress)
        card_layout.addLayout(session_time_layout)
        
        # Button group
        button_layout = QHBoxLayout()
        button_layout.setSpacing(8)
        
        # Refresh button
        self.refresh_button = QPushButton(self.status_card)
        self.refresh_button.setIcon(self.style().standardIcon(QStyle.SP_BrowserReload))
        self.refresh_button.setToolTip("Refresh session")
        self.refresh_button.setFixedSize(28, 28)
        self.refresh_button.setCursor(Qt.PointingHandCursor)
        self.refresh_button.setStyleSheet("""
            QPushButton {
                background-color: #E3F2FD;
                border: 1px solid #BBDEFB;
                border-radius: 4px;
                padding: 4px;
            }
            QPushButton:hover {
                background-color: #BBDEFB;
            }
            QPushButton:pressed {
                background-color: #90CAF9;
            }
            QPushButton:disabled {
                background-color: #F5F5F5;
                border: 1px solid #E0E0E0;
            }
        """)
        self.refresh_button.clicked.connect(self.refresh_session)
        
        # Info button
        self.info_button = QPushButton(self.status_card)
        self.info_button.setIcon(self.style().standardIcon(QStyle.SP_MessageBoxInformation))
        self.info_button.setToolTip("Session information")
        self.info_button.setFixedSize(28, 28)
        self.info_button.setCursor(Qt.PointingHandCursor)
        self.info_button.setStyleSheet("""
            QPushButton {
                background-color: #E8F5E9;
                border: 1px solid #C8E6C9;
                border-radius: 4px;
                padding: 4px;
            }
            QPushButton:hover {
                background-color: #C8E6C9;
            }
            QPushButton:pressed {
                background-color: #A5D6A7;
            }
            QPushButton:disabled {
                background-color: #F5F5F5;
                border: 1px solid #E0E0E0;
            }
        """)
        self.info_button.clicked.connect(self.show_session_info)
        
        button_layout.addWidget(self.refresh_button)
        button_layout.addWidget(self.info_button)
        card_layout.addLayout(button_layout)
        
        # Add the card to the main layout
        main_layout.addWidget(self.status_card)
    
    def update_status(self):
        """Update the widget with current session status."""
        # Handle case when not authenticated
        if not self.session_manager or not hasattr(self.session_manager, 'is_authenticated') or not self.session_manager.is_authenticated:
            self.status_indicator.setStyleSheet("""
                background-color: #bdbdbd;
                border-radius: 6px;
            """)
            self.user_label.setText("Not authenticated")
            self.auth_type_label.setText("")
            self.time_label.setText("Session: --:--")
            self.time_progress.setValue(0)
            self.refresh_button.setEnabled(False)
            self.info_button.setEnabled(False)
            return
        
        # Get session information
        session_info = self.session_manager.get_session_info()
        
        # Update user information
        user_id = session_info.get("user_id", "Unknown")
        self.user_label.setText(f"User: {user_id}")
        
        # Update authentication type with friendlier display names
        auth_type = session_info.get("auth_type", "unknown")
        if auth_type == "aws_sso":
            auth_label = "AWS Single Sign-On"
            # Use a branded color for AWS
            self.status_indicator.setStyleSheet("""
                background-color: #FF9900;
                border-radius: 6px;
            """)
        elif auth_type == "password":
            auth_label = "Password Authentication"
            # Standard secure color
            self.status_indicator.setStyleSheet("""
                background-color: #4CAF50;
                border-radius: 6px;
            """)
        else:
            auth_label = auth_type.replace("_", " ").title()
            # Generic secure color
            self.status_indicator.setStyleSheet("""
                background-color: #2196F3;
                border-radius: 6px;
            """)
        
        self.auth_type_label.setText(auth_label)
        
        # Update time remaining display
        remaining_seconds = session_info.get("remaining_seconds", 0)
        if remaining_seconds is not None:
            # Format time remaining in human-readable format
            if remaining_seconds > 3600:
                hours, remainder = divmod(remaining_seconds, 3600)
                minutes, seconds = divmod(remainder, 60)
                time_text = f"{int(hours)}h {int(minutes)}m"
            elif remaining_seconds > 60:
                minutes, seconds = divmod(remaining_seconds, 60)
                time_text = f"{int(minutes)}m {int(seconds)}s"
            else:
                time_text = f"{int(remaining_seconds)}s"
            
            self.time_label.setText(f"Session: {time_text}")
            
            # Calculate percentage for progress bar
            # Determine max duration based on auth type
            if auth_type == "aws_sso":
                max_duration = 8 * 3600  # 8 hours for AWS SSO
            else:
                max_duration = 3600  # 1 hour default for password auth
            
            percentage = min(100, (remaining_seconds / max_duration) * 100)
            self.time_progress.setValue(int(percentage))
            
            # Update visual indicators based on remaining time
            if remaining_seconds < 300:  # Less than 5 minutes - critical
                self.time_progress.setStyleSheet("""
                    QProgressBar { background-color: #FFEBEE; border-radius: 2px; }
                    QProgressBar::chunk { background-color: #F44336; border-radius: 2px; }
                """)
                self.time_label.setStyleSheet("color: #D32F2F; font-weight: bold;")
            elif remaining_seconds < 600:  # Less than 10 minutes - warning
                self.time_progress.setStyleSheet("""
                    QProgressBar { background-color: #FFF8E1; border-radius: 2px; }
                    QProgressBar::chunk { background-color: #FFC107; border-radius: 2px; }
                """)
                self.time_label.setStyleSheet("color: #FFA000; font-weight: bold;")
            else:  # Healthy state
                self.time_progress.setStyleSheet("""
                    QProgressBar { background-color: #E0E0E0; border-radius: 2px; }
                    QProgressBar::chunk { background-color: #1976D2; border-radius: 2px; }
                """)
                self.time_label.setStyleSheet("color: #424242;")
        
        # Enable buttons when authenticated
        self.refresh_button.setEnabled(True)
        self.info_button.setEnabled(True)
    
    def refresh_session(self):
        """Attempt to refresh the session token."""
        if not self.session_manager:
            return
            
        # Visual feedback that refresh is being attempted
        self.refresh_button.setEnabled(False)
        self.refresh_button.setToolTip("Refreshing...")
        QApplication.processEvents()
        
        try:
            # Try both refresh methods if available
            refresh_succeeded = False
            
            # Try auth_service first if available
            if self.auth_service and hasattr(self.auth_service, 'refresh_token'):
                try:
                    refresh_succeeded = self.auth_service.refresh_token()
                except Exception as e:
                    self.logger.warning(f"Auth service refresh failed: {str(e)}")
            
            # Try session manager if auth_service failed or isn't available
            if not refresh_succeeded and hasattr(self.session_manager, 'refresh_token'):
                try:
                    refresh_succeeded = self.session_manager.refresh_token()
                except Exception as e:
                    self.logger.warning(f"Session manager refresh failed: {str(e)}")
            
            # Provide feedback based on success
            if refresh_succeeded:
                # Flash the indicator for success feedback
                original_style = self.status_indicator.styleSheet()
                self.status_indicator.setStyleSheet("""
                    background-color: #4CAF50; 
                    border-radius: 6px;
                    border: 2px solid #81C784;
                """)
                
                # Show a brief tooltip success message
                QToolTip.showText(
                    self.refresh_button.mapToGlobal(QPoint(0, self.refresh_button.height())),
                    "Session refreshed successfully",
                    self.refresh_button,
                    QRect(),
                    2000  # Hide after 2 seconds
                )
                
                # Reset style after animation
                QTimer.singleShot(1500, lambda: self.status_indicator.setStyleSheet(original_style))
            else:
                # Flash the indicator for failure feedback
                self.status_indicator.setStyleSheet("""
                    background-color: #F44336; 
                    border-radius: 6px;
                """)
                
                # Show error message
                QToolTip.showText(
                    self.refresh_button.mapToGlobal(QPoint(0, self.refresh_button.height())),
                    "Could not refresh session",
                    self.refresh_button,
                    QRect(),
                    2000  # Hide after 2 seconds
                )
                
                # Reset after animation
                QTimer.singleShot(1500, self.update_status)
        except Exception as e:
            # Log the error
            if hasattr(self, 'logger'):
                self.logger.error(f"Error refreshing session: {str(e)}")
            
            # Reset to normal state
            QTimer.singleShot(1500, self.update_status)
        finally:
            # Re-enable the button
            self.refresh_button.setEnabled(True)
            self.refresh_button.setToolTip("Refresh session")
    
    def show_session_info(self):
        """Show detailed session information dialog."""
        if not self.session_manager or not self.session_manager.is_authenticated:
            return
            
        # Get session information from both sources if available
        session_info = self.session_manager.get_session_info()
        auth_info = {}
        
        if self.auth_service and hasattr(self.auth_service, 'get_session_info'):
            auth_info = self.auth_service.get_session_info()
        
        # Format expiration time
        expiration_time = session_info.get('expiration_time', '')
        if expiration_time:
            # Try to format as local time if it's a string
            try:
                if isinstance(expiration_time, str):
                    # Parse ISO format
                    dt = datetime.datetime.fromisoformat(expiration_time.replace('Z', '+00:00'))
                    # Format in local time
                    expiration_formatted = dt.strftime('%Y-%m-%d %H:%M:%S (local time)')
                else:
                    expiration_formatted = expiration_time
            except:
                expiration_formatted = expiration_time
        else:
            expiration_formatted = "Unknown"
            
        # Create html formatted output
        info_html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 10px; }}
                h2 {{ color: #1976D2; font-size: 16px; margin-top: 15px; margin-bottom: 5px; }}
                .section {{ background-color: #F5F5F5; border-radius: 5px; padding: 10px; margin-bottom: 10px; }}
                .key {{ font-weight: bold; color: #424242; }}
                .value {{ color: #212121; }}
                .highlight {{ font-weight: bold; color: #1976D2; }}
                .warning {{ color: #F57C00; }}
                table {{ border-collapse: collapse; width: 100%; }}
                td {{ padding: 6px; vertical-align: top; }}
                td:first-child {{ width: 140px; }}
            </style>
        </head>
        <body>
            <div class="section">
                <h2>Session Information</h2>
                <table>
                    <tr><td class="key">User ID:</td><td class="value highlight">{session_info.get('user_id', 'Unknown')}</td></tr>
                    <tr><td class="key">Auth Type:</td><td class="value">{session_info.get('auth_type', 'Unknown')}</td></tr>
                    <tr><td class="key">IP Address:</td><td class="value">{session_info.get('auth_ip', 'Unknown')}</td></tr>
                    <tr><td class="key">Started:</td><td class="value">{session_info.get('auth_timestamp', 'Unknown')}</td></tr>
                    <tr><td class="key">Expires:</td><td class="value">{expiration_formatted}</td></tr>
                    <tr><td class="key">Remaining:</td><td class="value highlight">{session_info.get('remaining_formatted', 'Unknown')}</td></tr>
                </table>
            </div>
        """
        
        # Add API auth info if available
        if auth_info:
            info_html += f"""
            <div class="section">
                <h2>API Authentication</h2>
                <table>
                    <tr><td class="key">User ID:</td><td class="value">{auth_info.get('user_id', 'N/A')}</td></tr>
                    <tr><td class="key">Auth Type:</td><td class="value">{auth_info.get('auth_type', 'N/A')}</td></tr>
                    <tr><td class="key">Token Expires:</td><td class="value">{auth_info.get('token_expires_at', 'N/A')}</td></tr>
                </table>
            </div>
            """
            
        # Add AWS profile info if available
        if session_info.get('aws_profile'):
            info_html += f"""
            <div class="section">
                <h2>AWS Profile</h2>
                <table>
                    <tr><td class="key">Profile:</td><td class="value highlight">{session_info.get('aws_profile', 'N/A')}</td></tr>
                </table>
            </div>
            """
            
        # Add security notice
        info_html += """
            <div class="section" style="background-color: #E8F5E9;">
                <h2>Security Notice</h2>
                <p style="font-size: 12px;">Your session is secured with enterprise-grade encryption. All data is encrypted at rest and in transit.</p>
                <p style="font-size: 12px;" class="warning">Do not share your credentials or leave your session unattended. When finished, please log out.</p>
            </div>
        </body>
        </html>
        """
        
        # Create a message box with the formatted HTML
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Session Information")
        msg_box.setTextFormat(Qt.RichText)
        msg_box.setText(info_html)
        msg_box.setIcon(QMessageBox.Information)
        msg_box.setStandardButtons(QMessageBox.Ok)
        msg_box.exec_()


class ModernButton(QPushButton):
    """Enhanced button with modern styling and animations."""

    def __init__(self, text, parent=None, primary=True, icon=None, danger=False):
        """
        Initialize the modern button.

        Args:
            text (str): Button text
            parent: Parent widget
            primary (bool): If True, use primary color, otherwise secondary
            icon: Optional icon for the button
            danger (bool): If True, use danger color
        """
        super().__init__(text, parent)
        self.primary = primary and not danger
        self.danger = danger
        self.hovered = False

        if icon:
            self.setIcon(icon)
            self.setIconSize(QSize(18, 18))

        # Set initial style
        self.update_style()

        # Add hover effect
        self.setMouseTracking(True)

    def update_style(self):
        """Update the button style based on state."""
        if self.danger:
            bg_color = ModernColors.DANGER
            hover_color = "#c62828"  # Darker red
            text_color = "#ffffff"
        elif self.primary:
            bg_color = ModernColors.PRIMARY
            hover_color = ModernColors.SECONDARY
            text_color = "#ffffff"
        else:
            bg_color = ModernColors.BG_MEDIUM
            hover_color = ModernColors.BG_DARK
            text_color = ModernColors.TEXT_PRIMARY

        # Apply different style based on hover state
        if self.hovered:
            bg = hover_color
        else:
            bg = bg_color

        self.setStyleSheet(f"""
            QPushButton {{
                background-color: {bg};
                color: {text_color};
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
                text-align: center;
            }}
            QPushButton:pressed {{
                background-color: {hover_color};
            }}
            QPushButton:disabled {{
                background-color: {ModernColors.BG_MEDIUM};
                color: {ModernColors.TEXT_MUTED};
            }}
        """)

    def enterEvent(self, event):
        """Handle mouse enter events for hover effect."""
        self.hovered = True
        self.update_style()
        super().enterEvent(event)

    def leaveEvent(self, event):
        """Handle mouse leave events for hover effect."""
        self.hovered = False
        self.update_style()
        super().leaveEvent(event)


class DataItemEditDialog(QDialog):
    """Modern dialog for editing PII data items."""

    def __init__(self, item_data, parent=None):
        """
        Initialize the edit dialog.

        Args:
            item_data (dict): The data item to edit
            parent: Parent widget
        """
        super().__init__(parent)
        self.item_data = item_data.copy()  # Create a copy to avoid modifying the original
        self.result_data = None
        self.pii_input_fields = []

        self.setWindowTitle("Edit Data Item")
        self.setMinimumWidth(600)
        self.setup_ui()

    def setup_ui(self):
        """Set up the user interface."""
        # Main layout
        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        # Item metadata section
        metadata_group = QGroupBox("Item Information", self)
        metadata_layout = QVBoxLayout(metadata_group)

        # Item ID (read-only)
        id_layout = QHBoxLayout()
        id_label = QLabel("Item ID:", self)
        id_label.setStyleSheet(
            f"color: {ModernColors.TEXT_SECONDARY}; font-weight: bold;")
        self.id_input = QLineEdit(self.item_data.get('_id', ''), self)
        self.id_input.setReadOnly(True)
        self.id_input.setStyleSheet("background-color: #f0f0f0;")
        id_layout.addWidget(id_label)
        id_layout.addWidget(self.id_input)
        metadata_layout.addLayout(id_layout)

        # Category input
        category_layout = QHBoxLayout()
        category_label = QLabel("Category:", self)
        category_label.setStyleSheet(
            f"color: {ModernColors.TEXT_SECONDARY}; font-weight: bold;")
        self.category_input = QLineEdit(
            self.item_data.get('Category', ''), self)
        category_layout.addWidget(category_label)
        category_layout.addWidget(self.category_input)
        metadata_layout.addLayout(category_layout)

        # Type input
        type_layout = QHBoxLayout()
        type_label = QLabel("Type:", self)
        type_label.setStyleSheet(
            f"color: {ModernColors.TEXT_SECONDARY}; font-weight: bold;")
        self.type_input = QLineEdit(self.item_data.get('Type', ''), self)
        type_layout.addWidget(type_label)
        type_layout.addWidget(self.type_input)
        metadata_layout.addLayout(type_layout)

        layout.addWidget(metadata_group)

        # PII data section
        pii_group = QGroupBox("PII Data", self)
        self.pii_layout = QVBoxLayout(pii_group)

        # Process PII data
        try:
            pii_data = self.item_data.get('PII', '')

            # Try to parse PII data from string if needed
            pii_items = []
            if isinstance(pii_data, str):
                try:
                    pii_items = ast.literal_eval(pii_data)
                    if not isinstance(pii_items, list):
                        pii_items = [
                            {"Item Name": "Data", "Data": str(pii_items)}]
                except (ValueError, SyntaxError):
                    # If parsing fails, treat as raw text
                    pii_items = [{"Item Name": "Data", "Data": pii_data}]
            elif isinstance(pii_data, list):
                pii_items = pii_data
            else:
                pii_items = [{"Item Name": "Data", "Data": str(pii_data)}]

            # Create input fields for each PII item
            for item in pii_items:
                self.add_pii_field(
                    item.get("Item Name", ""),
                    item.get("Data", "")
                )
        except Exception as e:
            logger.error(f"Error processing PII data: {str(e)}")
            # Add a default empty field if parsing fails
            self.add_pii_field("", "")

        # Add button to add more fields
        add_field_button = ModernButton("Add Field", self, primary=False)
        add_field_button.setIcon(
            self.style().standardIcon(QStyle.SP_FileDialogNewFolder))
        add_field_button.clicked.connect(lambda: self.add_pii_field("", ""))
        self.pii_layout.addWidget(add_field_button, alignment=Qt.AlignRight)

        layout.addWidget(pii_group)

        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        cancel_button = ModernButton("Cancel", self, primary=False)
        cancel_button.clicked.connect(self.reject)

        save_button = ModernButton("Save Changes", self, primary=True)
        save_button.clicked.connect(self.accept_changes)

        button_layout.addWidget(cancel_button)
        button_layout.addWidget(save_button)

        layout.addLayout(button_layout)

    def add_pii_field(self, name, value):
        """
        Add a field for PII item name and value.

        Args:
            name (str): The item name
            value (str): The item data/value
        """
        field_layout = QHBoxLayout()

        # Item name input
        name_label = QLabel("Item Name:", self)
        name_input = QLineEdit(name, self)
        name_input.setPlaceholderText("Enter item name...")

        # Value input
        value_label = QLabel("Value:", self)
        value_input = QLineEdit(value, self)
        value_input.setPlaceholderText("Enter data value...")

        # Remove button
        remove_button = QPushButton("×", self)
        remove_button.setFixedSize(25, 25)
        remove_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {ModernColors.DANGER};
                color: white;
                border-radius: 12px;
                font-weight: bold;
                font-size: 16px;
            }}
        """)

        # Add to layout
        field_layout.addWidget(name_label)
        field_layout.addWidget(name_input)
        field_layout.addWidget(value_label)
        field_layout.addWidget(value_input)
        field_layout.addWidget(remove_button)

        # Save reference to inputs
        self.pii_input_fields.append(
            (name_input, value_input, remove_button, field_layout))

        # Connect remove button
        remove_button.clicked.connect(
            lambda: self.remove_pii_field(self.pii_input_fields[-1]))

        # Add to main layout
        self.pii_layout.addLayout(field_layout)

    def remove_pii_field(self, field_tuple):
        """
        Remove a PII field from the dialog.

        Args:
            field_tuple: Tuple containing the field widgets and layout
        """
        name_input, value_input, remove_button, layout = field_tuple

        # Remove from tracking list
        self.pii_input_fields.remove(field_tuple)

        # Remove widgets from layout
        for i in reversed(range(layout.count())):
            widget = layout.itemAt(i).widget()
            if widget:
                widget.deleteLater()

        # Remove empty layout
        self.pii_layout.removeItem(layout)

    def accept_changes(self):
        """Validate and accept the changes."""
        # Basic validation
        category = self.category_input.text().strip()
        type_value = self.type_input.text().strip()

        if not category:
            QMessageBox.warning(self, "Validation Error",
                                "Category is required")
            return

        if not type_value:
            QMessageBox.warning(self, "Validation Error", "Type is required")
            return

        # Check if we have at least one PII field with both name and value
        has_valid_field = False
        for name_input, value_input, _, _ in self.pii_input_fields:
            if name_input.text().strip() and value_input.text().strip():
                has_valid_field = True
                break

        if not has_valid_field:
            QMessageBox.warning(
                self,
                "Validation Error",
                "At least one PII field must have both a name and value"
            )
            return

        # Collect the data
        pii_items = []
        for name_input, value_input, _, _ in self.pii_input_fields:
            name = name_input.text().strip()
            value = value_input.text().strip()
            if name or value:  # Include if either is provided
                pii_items.append({
                    "Item Name": name,
                    "Data": value
                })

        # Create updated item data
        self.result_data = {
            "_id": self.id_input.text(),
            "Category": category,
            "Type": type_value,
            "PII": str(pii_items)
        }

        # Accept the dialog
        self.accept()

    def get_updated_data(self):
        """
        Get the updated item data.

        Returns:
            dict: The updated item data or None if cancelled
        """
        return self.result_data


class DeleteConfirmationDialog(QDialog):
    """Modern dialog for confirming item deletion."""

    def __init__(self, item_data, parent=None):
        """
        Initialize the delete confirmation dialog.

        Args:
            item_data (dict): The data item to delete
            parent: Parent widget
        """
        super().__init__(parent)
        self.item_data = item_data

        self.setWindowTitle("Confirm Deletion")
        self.setup_ui()

    def setup_ui(self):
        """Set up the user interface."""
        # Main layout
        layout = QVBoxLayout(self)
        layout.setSpacing(20)

        # Warning icon
        icon_label = QLabel(self)
        icon_label.setPixmap(self.style().standardIcon(
            QStyle.SP_MessageBoxWarning).pixmap(48, 48))
        layout.addWidget(icon_label, alignment=Qt.AlignHCenter)

        # Warning message
        message = (
            f"Are you sure you want to delete this item?\n\n"
            f"Category: {self.item_data.get('Category', 'Unknown')}\n"
            f"Type: {self.item_data.get('Type', 'Unknown')}\n\n"
            f"This action cannot be undone."
        )
        message_label = QLabel(message, self)
        message_label.setWordWrap(True)
        message_label.setStyleSheet("font-size: 14px;")
        layout.addWidget(message_label)

        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        cancel_button = ModernButton("Cancel", self, primary=False)
        cancel_button.clicked.connect(self.reject)

        delete_button = ModernButton("Delete", self, danger=True)
        delete_button.clicked.connect(self.accept)

        button_layout.addWidget(cancel_button)
        button_layout.addWidget(delete_button)

        layout.addLayout(button_layout)


class ModernDataDialog(QDialog):
    """Modern dialog for displaying PII data with full CRUD functionality."""

    def __init__(self, parent=None, title="Your Guard Data", on_refresh=None):
        """
        Initialize the data dialog.

        Args:
            parent: Parent widget
            title (str): Dialog title
            on_refresh: Callback when data is modified and needs refresh
        """
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(900, 700)
        self.data_items = []
        self.category_panels = {}
        self.filtered_items = []
        self.on_refresh_callback = on_refresh
        self.crud_helper = None  # Will be set by caller
        self.auth_service = None  # Will be set by caller
        self.agent = None  # Will be set by caller

        self.setup_ui()

    def setup_ui(self):
        """Set up the user interface."""
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Header with search and filters
        header_widget = QWidget(self)
        header_widget.setStyleSheet(
            f"background-color: {ModernColors.BG_MEDIUM};")
        header_layout = QHBoxLayout(header_widget)
        header_layout.setContentsMargins(15, 10, 15, 10)

        # Filter label
        filter_label = QLabel("Filter by:", self)
        filter_label.setStyleSheet(f"color: {ModernColors.TEXT_SECONDARY};")
        header_layout.addWidget(filter_label)

        # Category filter
        self.category_filter = QComboBox(self)
        self.category_filter.addItem("All Categories")
        self.category_filter.setMinimumWidth(150)
        self.category_filter.currentTextChanged.connect(self.apply_filters)
        header_layout.addWidget(self.category_filter)

        # Type filter
        type_label = QLabel("Type:", self)
        type_label.setStyleSheet(f"color: {ModernColors.TEXT_SECONDARY};")
        header_layout.addWidget(type_label)

        self.type_filter = QComboBox(self)
        self.type_filter.addItem("All Types")
        self.type_filter.setMinimumWidth(150)
        self.type_filter.currentTextChanged.connect(self.apply_filters)
        header_layout.addWidget(self.type_filter)

        header_layout.addStretch()

        # Add new item button
        self.add_item_button = ModernButton("Add New Item", self, primary=True)
        self.add_item_button.setIcon(
            self.style().standardIcon(QStyle.SP_FileDialogNewFolder))
        self.add_item_button.clicked.connect(self.show_add_item_dialog)
        header_layout.addWidget(self.add_item_button)

        # Add header to main layout
        main_layout.addWidget(header_widget)

        # Scroll area for content
        scroll_area = QScrollArea(self)
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.NoFrame)

        # Content widget
        self.content_widget = QWidget(scroll_area)
        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_layout.setContentsMargins(20, 20, 20, 20)
        self.content_layout.setSpacing(20)

        # Empty state message
        self.empty_message = QLabel("No data items found", self.content_widget)
        self.empty_message.setAlignment(Qt.AlignCenter)
        self.empty_message.setStyleSheet(
            f"color: {ModernColors.TEXT_MUTED}; font-size: 16px;")
        self.empty_message.setVisible(False)
        self.content_layout.addWidget(self.empty_message)

        # Add stretch to push content to the top
        self.content_layout.addStretch()

        scroll_area.setWidget(self.content_widget)
        main_layout.addWidget(scroll_area, 1)

        # Button area
        button_area = QWidget(self)
        button_area.setStyleSheet(
            f"background-color: {ModernColors.BG_MEDIUM};")
        button_layout = QHBoxLayout(button_area)
        button_layout.setContentsMargins(15, 10, 15, 10)

        # Add buttons
        self.refresh_btn = ModernButton("Refresh", self, primary=False)
        self.refresh_btn.setIcon(
            self.style().standardIcon(QStyle.SP_BrowserReload))
        self.refresh_btn.clicked.connect(self.refresh_data)

        button_layout.addWidget(self.refresh_btn)
        button_layout.addStretch()

        self.download_btn = ModernButton("Download Data", self, primary=True)
        self.download_btn.setIcon(
            self.style().standardIcon(QStyle.SP_ArrowDown))

        self.close_btn = ModernButton("Close", self, primary=False)
        self.close_btn.clicked.connect(self.accept)

        button_layout.addWidget(self.download_btn)
        button_layout.addWidget(self.close_btn)

        main_layout.addWidget(button_area)

    def set_crud_helper(self, crud_helper, auth_service=None, agent=None):
        """
        Set the CRUD helper for data operations.

        Args:
            crud_helper: Helper for CRUD operations
            auth_service: Authentication service
            agent: Backend agent for direct operations
        """
        self.crud_helper = crud_helper
        self.auth_service = auth_service
        self.agent = agent

    def set_data(self, data_items):
        """
        Set the data items to display.

        Args:
            data_items: Data items to display
        """
        # Store the original data
        self.data_items = data_items

        # Clear existing panels
        self.clear_panels()

        # Collect unique categories and types
        categories = set()
        types = set()

        for item in data_items:
            category = item.get('Category', 'Uncategorized')
            item_type = item.get('Type', 'Unknown')

            categories.add(category)
            types.add(item_type)

        # Update filter combos
        current_cat = self.category_filter.currentText()
        current_type = self.type_filter.currentText()

        self.category_filter.clear()
        self.category_filter.addItem("All Categories")
        self.category_filter.addItems(sorted(categories))

        self.type_filter.clear()
        self.type_filter.addItem("All Types")
        self.type_filter.addItems(sorted(types))

        # Restore selection or default to "All"
        cat_index = self.category_filter.findText(current_cat)
        self.category_filter.setCurrentIndex(max(0, cat_index))

        type_index = self.type_filter.findText(current_type)
        self.type_filter.setCurrentIndex(max(0, type_index))

        # Apply filters which will display the items
        self.apply_filters()
    
    def apply_filters(self):
        """
        Apply the selected filters to the data items.
        
        This method filters the data based on category and type selections
        and then displays the filtered items.
        """
        # Get the current filter values
        category = self.category_filter.currentText()
        type_ = self.type_filter.currentText()
        
        # Log filtering operation
        if hasattr(self, 'logger'):
            self.logger.info(f"Applying filters: Category={category}, Type={type_}")
        
        # Apply filters based on selection
        if category == "All Categories" and type_ == "All Types":
            # No filtering needed
            self.filtered_items = self.data_items
        else:
            # Apply filters
            self.filtered_items = []
            for item in self.data_items:
                item_category = item.get('Category', 'Uncategorized')
                item_type = item.get('Type', 'Unknown')
                
                # Check category filter
                if category != "All Categories" and item_category != category:
                    continue
                    
                # Check type filter
                if type_ != "All Types" and item_type != type_:
                    continue
                    
                # Item passed all filters
                self.filtered_items.append(item)
        
        # Update the empty message visibility
        if hasattr(self, 'empty_message'):
            self.empty_message.setVisible(not self.filtered_items)
        
        # Display the filtered items
        self.display_items()

    def display_items(self):
        """Display the filtered items in the UI."""
        # Clear existing items
        self.clear_panels()

        # Show empty message if no items
        if not self.filtered_items:
            self.empty_message.setVisible(True)
            return
        else:
            self.empty_message.setVisible(False)

        # Group items by category
        category_items = {}
        for item in self.filtered_items:
            category = item.get('Category', 'Uncategorized')

            if category not in category_items:
                category_items[category] = []

            category_items[category].append(item)

        # Create panels for each category
        for category, items in sorted(category_items.items()):
            category_panel = self.create_category_panel(category)

            # Create card for each item
            for item in items:
                self.add_item_card(category_panel, item)

            # Store the panel
            self.category_panels[category] = category_panel

    def create_category_panel(self, category):
        """
        Create a panel for a category.

        Args:
            category (str): Category name

        Returns:
            QWidget: The category panel
        """
        # Create the panel
        panel = QWidget(self.content_widget)
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(0, 0, 0, 0)
        panel_layout.setSpacing(10)

        # Create header
        header_layout = QHBoxLayout()

        # Category icon
        icon_label = QLabel(panel)
        icon_label.setPixmap(self.style().standardIcon(
            QStyle.SP_DirIcon).pixmap(16, 16))
        header_layout.addWidget(icon_label)

        # Category name
        name_label = QLabel(category, panel)
        name_label.setStyleSheet(f"""
            color: {ModernColors.TEXT_PRIMARY};
            font-weight: bold;
            font-size: 16px;
        """)
        header_layout.addWidget(name_label)

        # Item count (will be updated when items are added)
        self.count_label = QLabel("(0 items)", panel)
        self.count_label.setStyleSheet(f"color: {ModernColors.TEXT_MUTED};")
        header_layout.addWidget(self.count_label)

        header_layout.addStretch()
        panel_layout.addLayout(header_layout)

        # Create items container
        items_container = QWidget(panel)
        self.items_layout = QVBoxLayout(items_container)
        self.items_layout.setContentsMargins(10, 5, 10, 5)
        self.items_layout.setSpacing(10)

        panel_layout.addWidget(items_container)

        # Add the panel to the content layout
        self.content_layout.insertWidget(
            self.content_layout.count() - 1, panel)

        return panel

    def add_item_card(self, category_panel, item_data):
        """
        Add an item card to a category panel.

        Args:
            category_panel: Panel to add the card to
            item_data (dict): Data for the item
        """
        # Create a card frame
        card_frame = QFrame(category_panel)
        card_frame.setFrameShape(QFrame.StyledPanel)
        card_frame.setStyleSheet(f"""
            QFrame {{
                border: 1px solid {ModernColors.BG_DARK};
                border-radius: 8px;
                background-color: {ModernColors.BG_LIGHT};
            }}
            QFrame:hover {{
                border-color: {ModernColors.PRIMARY};
            }}
        """)

        card_layout = QVBoxLayout(card_frame)
        card_layout.setContentsMargins(15, 15, 15, 15)
        card_layout.setSpacing(10)

        # Item header
        header_layout = QHBoxLayout()

        # Type label
        type_value = item_data.get('Type', 'Unknown')
        type_label = QLabel(type_value, card_frame)
        type_label.setStyleSheet(f"""
            color: {ModernColors.TEXT_PRIMARY};
            font-weight: bold;
            font-size: 14px;
        """)
        header_layout.addWidget(type_label)

        # ID label
        id_value = item_data.get('_id', 'Unknown')
        id_label = QLabel(f"ID: {id_value}", card_frame)
        id_label.setStyleSheet(
            f"color: {ModernColors.TEXT_MUTED}; font-size: 12px;")
        header_layout.addWidget(id_label)

        header_layout.addStretch()

        # Action buttons
        edit_btn = QPushButton("Edit", card_frame)
        edit_btn.setIcon(self.style().standardIcon(
            QStyle.SP_FileDialogDetailedView))
        edit_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {ModernColors.BG_MEDIUM};
                border: none;
                border-radius: 4px;
                padding: 4px 8px;
            }}
            QPushButton:hover {{
                background-color: {ModernColors.PRIMARY};
                color: white;
            }}
        """)
        edit_btn.setCursor(Qt.PointingHandCursor)
        edit_btn.clicked.connect(lambda: self.edit_item(item_data))

        delete_btn = QPushButton("Delete", card_frame)
        delete_btn.setIcon(self.style().standardIcon(QStyle.SP_TrashIcon))
        delete_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {ModernColors.BG_MEDIUM};
                border: none;
                border-radius: 4px;
                padding: 4px 8px;
            }}
            QPushButton:hover {{
                background-color: {ModernColors.DANGER};
                color: white;
            }}
        """)
        delete_btn.setCursor(Qt.PointingHandCursor)
        delete_btn.clicked.connect(lambda: self.delete_item(item_data))

        header_layout.addWidget(edit_btn)
        header_layout.addWidget(delete_btn)

        card_layout.addLayout(header_layout)

        # Add divider
        divider = QFrame(card_frame)
        divider.setFrameShape(QFrame.HLine)
        divider.setStyleSheet(f"color: {ModernColors.BG_MEDIUM};")
        card_layout.addWidget(divider)

        # PII data content
        content_layout = QVBoxLayout()

        # Parse and display PII data
        try:
            pii_data = item_data.get('PII', '')

            if isinstance(pii_data, str):
                try:
                    # Try to parse as list of dictionaries
                    pii_items = ast.literal_eval(pii_data)

                    if isinstance(pii_items, list):
                        for pii_item in pii_items:
                            if isinstance(pii_item, dict):
                                name = pii_item.get("Item Name", "")
                                value = pii_item.get("Data", "")

                                if name and value:
                                    # Create item display
                                    item_layout = QHBoxLayout()

                                    name_label = QLabel(f"{name}:", card_frame)
                                    name_label.setStyleSheet(
                                        f"color: {ModernColors.TEXT_SECONDARY}; font-weight: bold;")

                                    value_label = QLabel(value, card_frame)
                                    value_label.setStyleSheet(
                                        f"color: {ModernColors.TEXT_PRIMARY};")
                                    value_label.setWordWrap(True)

                                    item_layout.addWidget(name_label)
                                    item_layout.addWidget(value_label, 1)

                                    content_layout.addLayout(item_layout)
                except (ValueError, SyntaxError):
                    # If parsing fails, show raw text
                    raw_label = QLabel(str(pii_data), card_frame)
                    raw_label.setWordWrap(True)
                    content_layout.addWidget(raw_label)
            else:
                # Handle non-string PII data
                raw_label = QLabel(str(pii_data), card_frame)
                raw_label.setWordWrap(True)
                content_layout.addWidget(raw_label)

        except Exception as e:
            # Show error message
            error_label = QLabel(
                f"Error displaying data: {str(e)}", card_frame)
            error_label.setStyleSheet("color: red;")
            content_layout.addWidget(error_label)

        card_layout.addLayout(content_layout)

        # Add the card to the items layout
        items_layout = category_panel.findChild(QWidget).layout()
        items_layout.addWidget(card_frame)

        # Update item count
        count_label = category_panel.findChild(
            QLabel, "", Qt.FindChildrenRecursively)
        if count_label and "items" in count_label.text():
            count = items_layout.count()
            count_label.setText(f"({count} items)")

    def clear_panels(self):
        """Clear all category panels."""
        # Remove all category panels
        for i in reversed(range(self.content_layout.count() - 1)):  # -1 to keep the stretch
            widget = self.content_layout.itemAt(i).widget()
            if widget and widget != self.empty_message:
                widget.deleteLater()

        self.category_panels = {}

    def edit_item(self, item_data):
        """
        Show dialog to edit an item.

        Args:
            item_data (dict): Data of the item to edit
        """
        # Create the edit dialog
        dialog = DataItemEditDialog(item_data, self)

        if dialog.exec_() == QDialog.Accepted:
            # Get the updated data
            updated_data = dialog.get_updated_data()

            if updated_data:
                # Use CRUD helper to update the item
                self.update_item_data(updated_data)

    def update_item_data(self, item_data):
        """
        Update an item in the database.

        Args:
            item_data (dict): Updated item data
        """
        if not self.crud_helper:
            QMessageBox.warning(self, "Error", "CRUD helper not set")
            return

        # Show progress dialog
        progress_dialog = QMessageBox(self)
        progress_dialog.setWindowTitle("Updating Data")
        progress_dialog.setText("Updating data item...")
        progress_dialog.setStandardButtons(QMessageBox.NoButton)
        progress_dialog.show()
        QApplication.processEvents()

        try:
            # Use CRUD helper to update the item
            success, response = self.crud_helper.perform_operation(
                'update',
                item_data,
                agent=self.agent,
                auth_service=self.auth_service,
                logger=logger.info
            )

            # Close progress dialog
            progress_dialog.close()

            if success:
                QMessageBox.information(
                    self, "Success", "Item updated successfully")

                # Refresh the data
                self.refresh_data()
            else:
                QMessageBox.warning(
                    self, "Error", f"Failed to update item: {response}")
        except Exception as e:
            progress_dialog.close()
            QMessageBox.critical(
                self, "Error", f"Error updating item: {str(e)}")

    def delete_item(self, item_data):
        """
        Show confirmation dialog and delete an item using the enhanced delete handler.

        Args:
            item_data (dict): Data of the item to delete
        """
        try:
            # Import the DeleteHandler
            from delete_handler import DeleteHandler

            # Create a log callback function
            def log_callback(message):
                if hasattr(self, 'update_log'):
                    timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
                    self.update_log(timestamp, message)
                else:
                    logger.info(message)

            # Define success callback
            def on_success():
                self.refresh_data()

            # Use the enhanced delete handler
            DeleteHandler.delete_item(
                parent=self,
                item_data=item_data,
                agent=self.agent if hasattr(self, 'agent') else None,
                auth_service=self.auth_service if hasattr(
                    self, 'auth_service') else None,
                auth_manager=None,  # Modern dialog doesn't use auth_manager
                api_client=None,    # Modern dialog doesn't use api_client directly
                on_success=on_success,
                log_callback=log_callback
            )
        except ImportError:
            # Fallback to original implementation if delete_handler.py is not available
            # Show confirmation dialog
            dialog = DeleteConfirmationDialog(item_data, self)

            if dialog.exec_() == QDialog.Accepted:
                # Show progress dialog
                progress_dialog = QMessageBox(self)
                progress_dialog.setWindowTitle("Deleting Data")
                progress_dialog.setText("Deleting data item...")
                progress_dialog.setStandardButtons(QMessageBox.NoButton)
                progress_dialog.show()
                QApplication.processEvents()

                try:
                    # Use CRUD helper to delete the item
                    success, response = self.crud_helper.perform_operation(
                        'delete',
                        item_data,
                        agent=self.agent if hasattr(self, 'agent') else None,
                        auth_service=self.auth_service if hasattr(
                            self, 'auth_service') else None,
                        logger=logger.info
                    )

                    # Close progress dialog
                    progress_dialog.close()

                    if success:
                        QMessageBox.information(
                            self, "Success", "Item deleted successfully")

                        # Refresh the data
                        self.refresh_data()
                    else:
                        QMessageBox.warning(
                            self, "Error", f"Failed to delete item: {response}")
                except Exception as e:
                    progress_dialog.close()
                    QMessageBox.critical(
                        self, "Error", f"Error deleting item: {str(e)}")

    def show_add_item_dialog(self):
        """Show dialog to add a new item."""
        # Create empty item data
        new_item = {
            "_id": "",  # Will be generated by the server
            "Category": "",
            "Type": "",
            "PII": str([{"Item Name": "", "Data": ""}])
        }

        # Create the edit dialog
        dialog = DataItemEditDialog(new_item, self)

        if dialog.exec_() == QDialog.Accepted:
            # Get the new item data
            item_data = dialog.get_updated_data()

            if item_data:
                # Remove ID field for new items
                if "_id" in item_data:
                    del item_data["_id"]

                # Add the new item
                self.add_new_item(item_data)

    def add_new_item(self, item_data):
        """
        Add a new item to the database.

        Args:
            item_data (dict): New item data
        """
        if not self.crud_helper:
            QMessageBox.warning(self, "Error", "CRUD helper not set")
            return

        # Show progress dialog
        progress_dialog = QMessageBox(self)
        progress_dialog.setWindowTitle("Adding Data")
        progress_dialog.setText("Adding new data item...")
        progress_dialog.setStandardButtons(QMessageBox.NoButton)
        progress_dialog.show()
        QApplication.processEvents()

        try:
            # Use CRUD helper to create the item
            success, response = self.crud_helper.perform_operation(
                'create',
                item_data,
                agent=self.agent,
                auth_service=self.auth_service,
                logger=logger.info
            )

            # Close progress dialog
            progress_dialog.close()

            if success:
                QMessageBox.information(
                    self, "Success", "Item added successfully")

                # Refresh the data
                self.refresh_data()
            else:
                QMessageBox.warning(
                    self, "Error", f"Failed to add item: {response}")
        except Exception as e:
            progress_dialog.close()
            QMessageBox.critical(self, "Error", f"Error adding item: {str(e)}")

    def refresh_data(self):
        """Refresh the data display."""
        # Trigger callback if provided
        if self.on_refresh_callback:
            self.on_refresh_callback()


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

        missing_fields = [
            field for field in required_fields if field not in data or not data[field]]

        if missing_fields:
            error_msg = f"Missing required fields: {', '.join(missing_fields)}"
            if logger:
                logger(error_msg)
            return False, error_msg

        return True, ""

    @staticmethod
    def perform_operation(operation, data, agent=None, auth_service=None, auth_manager=None, logger=None):
        """
        Perform a CRUD operation using available services with improved error handling.

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
            valid, error_msg = CRUDHelper.validate_required_fields(data, [
                                                                   '_id'], logger)
            if not valid:
                if logger:
                    logger(f"Validation error for {operation}: {error_msg}")
                return False, error_msg

        # Special validation for create
        if operation == 'create':
            valid, error_msg = CRUDHelper.validate_required_fields(
                data, ['Category', 'Type', 'PII'], logger)
            if not valid:
                if logger:
                    logger(f"Validation error for create: {error_msg}")
                return False, error_msg

        # Try agent first (most direct)
        if agent:
            try:
                if logger:
                    logger(f"Using agent directly for {operation} operation")

                # Call the appropriate method based on operation
                if operation == 'create':
                    response = agent.insert_new_data(data)
                elif operation == 'read':
                    response = agent.get_all_data()
                elif operation == 'update':
                    response = agent.update_one_data(data)
                elif operation == 'delete':
                    # Ensure we're passing a complete object for delete
                    if '_id' in data:
                        response = agent.delete_one_data(data)
                    else:
                        return False, "Missing _id field for delete operation"
                else:
                    return False, f"Unknown operation: {operation}"

                # Handle response
                if response is True:
                    if logger:
                        logger(f"{operation.capitalize()} operation successful")
                    return True, {"message": f"{operation} successful"}
                elif isinstance(response, dict) and 'error' not in response:
                    if logger:
                        logger(f"{operation.capitalize()} operation successful")
                    return True, response
                elif isinstance(response, Exception):
                    error_msg = str(response)
                    if logger:
                        logger(f"Agent {operation} error: {error_msg}")
                    # Continue to next method
                elif isinstance(response, dict) and 'error' in response:
                    error_msg = response.get('error', str(response))
                    if logger:
                        logger(f"Agent {operation} error: {error_msg}")
                    # Continue to next method
                else:
                    # For delete operations, many kinds of responses could indicate success
                    if operation == 'delete':
                        if logger:
                            logger(
                                f"Agent {operation} returned non-standard response, assuming success: {response}")
                        return True, {"message": "Delete operation completed", "response": response}
                    else:
                        if logger:
                            logger(f"Agent {operation} returned: {response}")
                        # If we got a non-error response, consider it successful
                        return True, response
            except Exception as e:
                import traceback
                if logger:
                    logger(f"Agent {operation} error: {str(e)}")
                    logger(f"Traceback: {traceback.format_exc()}")
                # Continue to next method

        # Try auth_service next
        if auth_service and hasattr(auth_service, 'make_authenticated_request'):
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

                # Handle async/sync methods
                if operation == 'read':
                    endpoint = "pii"
                    req_data = None
                else:
                    endpoint = "pii"
                    req_data = data

                # Check if method is async or sync
                import inspect
                if inspect.iscoroutinefunction(auth_service.make_authenticated_request):
                    # Need to run in async context
                    import asyncio
                    loop = asyncio.new_event_loop()
                    try:
                        success, response_data = loop.run_until_complete(
                            auth_service.make_authenticated_request(
                                method=method_map[operation],
                                endpoint=endpoint,
                                data=req_data
                            )
                        )
                    finally:
                        loop.close()
                else:
                    # Synchronous method
                    success, response_data = auth_service.make_authenticated_request(
                        method=method_map[operation],
                        endpoint=endpoint,
                        data=req_data
                    )

                if success:
                    if logger:
                        logger(f"Auth service {operation} successful")
                    return True, response_data
                else:
                    import json
                    error_data = response_data
                    try:
                        if isinstance(response_data, str):
                            error_data = json.loads(response_data)
                    except json.JSONDecodeError:
                        pass

                    error_msg = error_data.get('error', str(error_data)) if isinstance(
                        error_data, dict) else str(error_data)
                    if logger:
                        logger(f"Auth service {operation} failed: {error_msg}")

                    # Only continue if we have auth_manager
                    if auth_manager:
                        # Continue to next method
                        pass
                    else:
                        return False, error_msg
            except Exception as e:
                import traceback
                if logger:
                    logger(f"Auth service {operation} error: {str(e)}")
                    logger(f"Traceback: {traceback.format_exc()}")
                # Continue to next method if we have auth_manager
                if not auth_manager:
                    return False, str(e)

        # Try auth_manager as last authenticated option
        if auth_manager and hasattr(auth_manager, 'token') and auth_manager.token:
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
                    import json
                    error_data = response_data
                    try:
                        if isinstance(response_data, str):
                            error_data = json.loads(response_data)
                    except json.JSONDecodeError:
                        pass

                    error_msg = error_data.get('error', str(error_data)) if isinstance(
                        error_data, dict) else str(error_data)
                    if logger:
                        logger(f"Auth manager {operation} failed: {error_msg}")
                    return False, error_msg
            except Exception as e:
                import traceback
                if logger:
                    logger(f"Auth manager {operation} error: {str(e)}")
                    logger(f"Traceback: {traceback.format_exc()}")
                return False, str(e)

        # If we get here, all methods failed or weren't available
        error_msg = "No suitable authentication method available"
        if not agent and not auth_service and not auth_manager:
            error_msg = "No authentication providers available. Please connect to the server first."

        if logger:
            logger(f"Operation {operation} failed: {error_msg}")

        return False, error_msg
