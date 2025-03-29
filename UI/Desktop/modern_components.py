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

"""
Enhanced ModernDataDialog for improved PII data display.

This implementation provides a more user-friendly interface for displaying PII data
with improved card layouts, responsive text handling, and better visual hierarchy.
"""

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QScrollArea, 
    QFrame, QMessageBox, QComboBox, QApplication, QGraphicsDropShadowEffect,
    QWidget, QSizePolicy, QSpacerItem, QToolButton, QMenu, QAction, QLineEdit,
    QToolTip, QGridLayout, QSplitter
)
from PyQt5.QtGui import QColor, QFont, QIcon, QPalette, QCursor
from PyQt5.QtCore import Qt, QSize, QTimer, QDateTime, QPoint, QRect, pyqtSignal
import ast
import datetime
import logging
import re
import json

# Import components if available in your project
try:
    from UI.Desktop.standard_theme import StandardTheme
    from UI.Desktop.enhanced_dialogs import EnhancedDataItemDialog
except ImportError:
    # Fallback if not available
    from modern_components import DataItemEditDialog
    
# Import delete handler if available
try:
    from UI.Desktop.delete_handler import DeleteHandler
    delete_handler_available = True
except ImportError:
    delete_handler_available = False

logger = logging.getLogger("modern_ui")

class EnhancedPIIDataCard(QFrame):
    """
    Enhanced card component for displaying PII data with improved readability and layout.
    """
    # Signals for actions
    edit_clicked = pyqtSignal(dict)
    delete_clicked = pyqtSignal(dict)
    view_details_clicked = pyqtSignal(dict)
    
    def __init__(self, item_data, parent=None):
        """
        Initialize the enhanced PII data card.
        
        Args:
            item_data (dict): The data item to display
            parent: Parent widget
        """
        super().__init__(parent)
        self.item_data = item_data.copy()
        self.is_expanded = False
        
        # Apply styling
        self.setObjectName("piiDataCard")
        self.setFrameShape(QFrame.StyledPanel)
        try:
            self.setStyleSheet(StandardTheme.get_card_style('default', 1))
        except:
            # Fallback styling if StandardTheme is not available
            self.setStyleSheet("""
                QFrame#piiDataCard {
                    background-color: #FFFFFF;
                    border: 1px solid #E0E0E0;
                    border-radius: 8px;
                }
                QFrame#piiDataCard:hover {
                    border-color: #1976D2;
                }
            """)
        
        # Add shadow effect
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(10)
        shadow.setColor(QColor(0, 0, 0, 30))
        shadow.setOffset(0, 3)
        self.setGraphicsEffect(shadow)
        
        # Set up layout
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the card user interface with improved layout."""
        # Main layout with better spacing
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(12)
        
        # Header section with improved layout
        header_layout = self.create_header_section()
        main_layout.addLayout(header_layout)
        
        # Add separator line
        separator = QFrame(self)
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)
        separator.setStyleSheet("background-color: #E0E0E0;")
        main_layout.addWidget(separator)
        
        # Content section
        self.content_widget = QWidget(self)
        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_layout.setContentsMargins(5, 10, 5, 5)
        self.content_layout.setSpacing(8)
        
        # Parse and display PII data with improved formatting
        self.populate_pii_data()
        
        main_layout.addWidget(self.content_widget)
        
        # Footer section with "View more" option for long content
        self.footer_widget = QWidget(self)
        footer_layout = QHBoxLayout(self.footer_widget)
        footer_layout.setContentsMargins(0, 0, 0, 0)
        
        # Only show the "View more" button if we have multiple PII fields
        pii_count = self.get_pii_field_count()
        if pii_count > 3:
            self.view_more_btn = QPushButton("View all details", self.footer_widget)
            self.view_more_btn.setObjectName("viewMoreButton")
            self.view_more_btn.setCursor(Qt.PointingHandCursor)
            self.view_more_btn.setStyleSheet("""
                QPushButton#viewMoreButton {
                    background-color: transparent;
                    color: #1976D2;
                    border: none;
                    text-align: left;
                    padding: 0;
                    font-weight: bold;
                }
                QPushButton#viewMoreButton:hover {
                    color: #0D47A1;
                    text-decoration: underline;
                }
            """)
            self.view_more_btn.clicked.connect(self.toggle_expanded_view)
            footer_layout.addWidget(self.view_more_btn)
            
            # Add the footer to main layout
            main_layout.addWidget(self.footer_widget)
        
    def create_header_section(self):
        """Create the header section with type, ID and action buttons."""
        header_layout = QHBoxLayout()
        header_layout.setSpacing(8)
        
        # Left section with type icon and name
        left_layout = QHBoxLayout()
        left_layout.setSpacing(8)
        
        # Add a custom icon based on the category
        category = self.item_data.get('Category', 'Unknown')
        type_value = self.item_data.get('Type', 'Unknown')
        
        # Create type label with icon
        icon_label = QLabel(self)
        icon_label.setPixmap(self.parent().style().standardIcon(
            self.get_type_icon(category, type_value)).pixmap(16, 16))
        left_layout.addWidget(icon_label)
        
        # Type and category labels with improved styles
        info_layout = QVBoxLayout()
        info_layout.setSpacing(2)
        
        type_label = QLabel(type_value, self)
        type_label.setObjectName("typeLabel")
        type_label.setStyleSheet("""
            QLabel#typeLabel {
                font-weight: bold;
                font-size: 14px;
                color: #212121;
            }
        """)
        
        category_label = QLabel(category, self)
        category_label.setObjectName("categoryLabel")
        category_label.setStyleSheet("""
            QLabel#categoryLabel {
                font-size: 12px;
                color: #757575;
            }
        """)
        
        info_layout.addWidget(type_label)
        info_layout.addWidget(category_label)
        left_layout.addLayout(info_layout)
        
        header_layout.addLayout(left_layout)
        header_layout.addStretch()
        
        # Right section with action buttons
        id_value = self.item_data.get('_id', 'Unknown')
        id_label = QLabel(f"ID: {id_value[:8]}...", self)
        id_label.setObjectName("idLabel")
        id_label.setStyleSheet("""
            QLabel#idLabel {
                font-size: 11px;
                color: #9E9E9E;
            }
        """)
        id_label.setToolTip(id_value)
        header_layout.addWidget(id_label)
        
        # Action buttons with improved styling
        button_layout = QHBoxLayout()
        button_layout.setSpacing(4)
        
        # Edit button
        self.edit_button = self.create_action_button(
            "Edit", "SP_FileDialogDetailedView", "#E3F2FD", "#1976D2")
        self.edit_button.setToolTip("Edit item")
        self.edit_button.clicked.connect(lambda: self.edit_clicked.emit(self.item_data))
        button_layout.addWidget(self.edit_button)
        
        # Delete button
        self.delete_button = self.create_action_button(
            "Delete", "SP_TrashIcon", "#FFEBEE", "#F44336")
        self.delete_button.setToolTip("Delete item")
        self.delete_button.clicked.connect(lambda: self.delete_clicked.emit(self.item_data))
        button_layout.addWidget(self.delete_button)
        
        header_layout.addLayout(button_layout)
        
        return header_layout
    
    def create_action_button(self, text, icon_name, bg_color, hover_color):
        """Create a styled action button."""
        button = QPushButton(text, self)
        button.setIcon(self.parent().style().standardIcon(
            getattr(self.parent().style(), icon_name)))
        button.setCursor(Qt.PointingHandCursor)
        button.setStyleSheet(f"""
            QPushButton {{
                background-color: {bg_color};
                border: none;
                border-radius: 4px;
                padding: 4px 8px;
                font-size: 12px;
            }}
            QPushButton:hover {{
                background-color: {hover_color};
                color: white;
            }}
        """)
        return button
    
    def get_type_icon(self, category, type_value):
        """Get an appropriate icon based on category and type."""
        # Customize icons based on data categories
        if category.lower() in ['financial', 'finance', 'payment']:
            return "SP_FileDialogInfoView"
        elif category.lower() in ['personal', 'contact', 'address']:
            return "SP_DialogApplyButton"
        elif category.lower() in ['account', 'security', 'auth']:
            return "SP_DialogSaveButton"
        elif category.lower() in ['health', 'medical']:
            return "SP_TitleBarMenuButton"
        else:
            return "SP_FileIcon"
    
    def populate_pii_data(self):
        """Parse and display PII data with improved formatting."""
        try:
            pii_data = self.item_data.get('PII', '')
            
            # Parse PII data based on format
            pii_items = self.parse_pii_data(pii_data)
            
            # Display PII fields with improved layout
            self.display_pii_fields(pii_items)
            
        except Exception as e:
            # Show error message with better formatting
            error_label = QLabel(f"Error displaying data: {str(e)}", self)
            error_label.setStyleSheet("""
                color: #D32F2F; 
                background-color: #FFEBEE;
                padding: 8px;
                border-radius: 4px;
            """)
            self.content_layout.addWidget(error_label)
    
    def parse_pii_data(self, pii_data):
        """Parse PII data from various formats into a unified structure."""
        pii_items = []
        
        if isinstance(pii_data, str):
            try:
                # Try to parse as list of dictionaries
                parsed_data = ast.literal_eval(pii_data)
                
                if isinstance(parsed_data, list):
                    for item in parsed_data:
                        if isinstance(item, dict):
                            # Handle common field name variations
                            name = item.get("Item Name", item.get("item_name", item.get("name", "")))
                            value = item.get("Data", item.get("data", item.get("value", "")))
                            pii_items.append({"name": name, "value": value})
                elif isinstance(parsed_data, dict):
                    # Convert dict to list of items
                    for name, value in parsed_data.items():
                        pii_items.append({"name": name, "value": value})
                else:
                    # Handle non-standard formats
                    pii_items.append({"name": "Data", "value": str(parsed_data)})
            except (ValueError, SyntaxError):
                # If parsing fails, treat as raw text
                pii_items.append({"name": "Data", "value": pii_data})
        elif isinstance(pii_data, list):
            # Already a list, ensure consistent format
            for item in pii_data:
                if isinstance(item, dict):
                    name = item.get("Item Name", item.get("item_name", item.get("name", "")))
                    value = item.get("Data", item.get("data", item.get("value", "")))
                    pii_items.append({"name": name, "value": value})
                else:
                    pii_items.append({"name": "Item", "value": str(item)})
        elif isinstance(pii_data, dict):
            # Convert dict to list of items
            for name, value in pii_data.items():
                pii_items.append({"name": name, "value": value})
        else:
            # Handle any other type as a single item
            pii_items.append({"name": "Data", "value": str(pii_data)})
        
        return pii_items
    
    def display_pii_fields(self, pii_items):
        """Display PII fields with improved layout and formatting."""
        # Clear existing content
        self.clear_layout(self.content_layout)
        
        # Store the full list
        self.all_pii_items = pii_items
        
        # Determine how many to show initially
        display_count = len(pii_items) if self.is_expanded else min(3, len(pii_items))
        
        # Display fields
        for i, item in enumerate(pii_items[:display_count]):
            name = item.get("name", "")
            value = item.get("value", "")
            
            if name or value:  # Only display if we have data
                # Create field container
                field_container = QFrame(self)
                field_container.setObjectName("piiFieldContainer")
                field_container.setStyleSheet("""
                    QFrame#piiFieldContainer {
                        background-color: #F5F5F5;
                        border-radius: 6px;
                        padding: 2px;
                    }
                """)
                
                field_layout = QGridLayout(field_container)
                field_layout.setContentsMargins(8, 8, 8, 8)
                field_layout.setSpacing(6)
                
                # Field name with improved styling
                name_label = QLabel(f"{name}:", field_container)
                name_label.setObjectName("fieldNameLabel")
                name_label.setStyleSheet("""
                    QLabel#fieldNameLabel {
                        font-weight: bold;
                        color: #424242;
                        font-size: 13px;
                    }
                """)
                name_label.setAlignment(Qt.AlignLeft | Qt.AlignTop)
                
                # Field value with improved text handling
                value_label = QLabel(self.format_value(value), field_container)
                value_label.setObjectName("fieldValueLabel")
                value_label.setStyleSheet("""
                    QLabel#fieldValueLabel {
                        color: #212121;
                        font-size: 13px;
                        background-color: white;
                        border-radius: 4px;
                        padding: 4px;
                        border: 1px solid #E0E0E0;
                    }
                """)
                value_label.setAlignment(Qt.AlignLeft | Qt.AlignTop)
                value_label.setWordWrap(True)
                value_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
                
                # Set tooltips for both labels
                name_label.setToolTip(name)
                value_label.setToolTip(value)
                
                # Add copy action to value label
                value_label.setContextMenuPolicy(Qt.CustomContextMenu)
                value_label.customContextMenuRequested.connect(
                    lambda pos, val=value: self.show_value_context_menu(pos, val))
                
                # Add to layout - name in first column, value in second column
                field_layout.addWidget(name_label, 0, 0)
                field_layout.addWidget(value_label, 0, 1)
                
                # Make the value column expandable
                field_layout.setColumnStretch(0, 0)  # Name column fixed
                field_layout.setColumnStretch(1, 1)  # Value column expandable
                
                self.content_layout.addWidget(field_container)
        
        # Add a message if there are more items to show
        if not self.is_expanded and len(pii_items) > display_count:
            more_label = QLabel(f"{len(pii_items) - display_count} more fields...", self)
            more_label.setStyleSheet("""
                color: #757575;
                font-size: 12px;
                font-style: italic;
                padding-left: 8px;
            """)
            self.content_layout.addWidget(more_label)
    
    def format_value(self, value):
        """Format values for better display, especially for complex types."""
        if not value:
            return "<empty>"
            
        # Convert to string if needed
        if not isinstance(value, str):
            # For dict and list, make it look nicer
            if isinstance(value, (dict, list)):
                try:
                    return json.dumps(value, indent=2)
                except:
                    return str(value)
            return str(value)
            
        # Check if it's a JSON/dict/list string and try to format it nicely
        try:
            if (value.strip().startswith('{') and value.strip().endswith('}')) or \
               (value.strip().startswith('[') and value.strip().endswith(']')):
                parsed = ast.literal_eval(value)
                if isinstance(parsed, (dict, list)):
                    return json.dumps(parsed, indent=2)
        except:
            pass
            
        # Format email addresses with special styling
        if re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', value):
            return f'<a href="mailto:{value}">{value}</a>'
            
        # Format URLs with special styling
        if value.startswith(('http://', 'https://')):
            return f'<a href="{value}">{value}</a>'
            
        # Handle very long values
        if len(value) > 100:
            return value[:100] + "..."
            
        return value
    
    def show_value_context_menu(self, pos, value):
        """Show context menu for value field with copy option."""
        menu = QMenu(self)
        
        copy_action = QAction("Copy value", self)
        copy_action.triggered.connect(lambda: QApplication.clipboard().setText(value))
        menu.addAction(copy_action)
        
        # Special actions for certain types of data
        if re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', value):
            email_action = QAction("Email address...", self)
            email_action.triggered.connect(lambda: self.open_url(f"mailto:{value}"))
            menu.addAction(email_action)
            
        if value.startswith(('http://', 'https://')):
            url_action = QAction("Open URL", self)
            url_action.triggered.connect(lambda: self.open_url(value))
            menu.addAction(url_action)
            
        menu.exec_(QCursor.pos())
    
    def open_url(self, url):
        """Open a URL (handled by application)."""
        import webbrowser
        try:
            webbrowser.open(url)
        except Exception as e:
            logger.error(f"Error opening URL: {e}")
    
    def clear_layout(self, layout):
        """Safely clear all widgets from a layout."""
        if layout is None:
            return
            
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
            else:
                child_layout = item.layout()
                if child_layout is not None:
                    self.clear_layout(child_layout)
    
    def toggle_expanded_view(self):
        """Toggle between expanded and collapsed view."""
        self.is_expanded = not self.is_expanded
        
        # Update the button text
        if hasattr(self, 'view_more_btn'):
            self.view_more_btn.setText("Show fewer details" if self.is_expanded else "View all details")
        
        # Update the displayed fields
        self.display_pii_fields(self.all_pii_items)
    
    def get_pii_field_count(self):
        """Get the number of PII fields in the data."""
        pii_data = self.item_data.get('PII', '')
        items = self.parse_pii_data(pii_data)
        return len(items)


class EnhancedModernDataDialog(QDialog):
    """
    Enhanced dialog for displaying PII data with improved user experience.
    
    This dialog provides a more user-friendly interface with better card layout,
    improved filtering, and more intuitive interaction patterns.
    """
    
    def __init__(self, parent=None, title="Your GUARD Data", on_refresh=None):
        """
        Initialize the enhanced data dialog.
        
        Args:
            parent: Parent widget
            title: Dialog title
            on_refresh: Callback when data is modified and needs refresh
        """
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(1000, 700)  # Larger default size for better readability
        self.data_items = []
        self.filtered_items = []
        self.on_refresh_callback = on_refresh
        self.crud_helper = None
        self.auth_service = None
        self.agent = None
        self.current_search_text = ""
        
        # Apply styling if StandardTheme is available
        try:
            self.setStyleSheet(StandardTheme.get_dialog_style())
        except:
            # Fallback styling
            pass
        
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the enhanced user interface."""
        # Main layout with zero margins for maximum space utilization
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Header section with search, filters and actions
        self.setup_header_section(main_layout)
        
        # Create content area with improved layout
        content_container = QWidget(self)
        content_layout = QVBoxLayout(content_container)
        content_layout.setContentsMargins(15, 15, 15, 15)
        content_layout.setSpacing(15)
        
        # Create split view for categories and content
        splitter = QSplitter(Qt.Horizontal, content_container)
        splitter.setChildrenCollapsible(False)
        
        # Category panel on the left (filters)
        self.category_panel = self.create_category_panel(splitter)
        
        # Content area on the right
        self.setup_content_area(splitter)
        
        # Set initial split ratio (30/70)
        splitter.setSizes([300, 700])
        
        content_layout.addWidget(splitter)
        main_layout.addWidget(content_container, 1)  # Give it stretch priority
        
        # Footer section with actions
        self.setup_footer_section(main_layout)
    
    def setup_header_section(self, parent_layout):
        """Create the header section with search and filters."""
        header = QWidget(self)
        header.setObjectName("dialogHeader")
        try:
            header.setStyleSheet("""
                QWidget#dialogHeader {
                    background-color: #F5F5F5;
                    border-bottom: 1px solid #E0E0E0;
                }
            """)
        except:
            pass
            
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(15, 10, 15, 10)
        header_layout.setSpacing(10)
        
        # Search bar with clear button
        search_container = QWidget(header)
        search_layout = QHBoxLayout(search_container)
        search_layout.setContentsMargins(0, 0, 0, 0)
        search_layout.setSpacing(0)
        
        self.search_input = QLineEdit(search_container)
        self.search_input.setPlaceholderText("Search in all fields...")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.setMinimumWidth(250)
        try:
            self.search_input.setStyleSheet(StandardTheme.get_input_style())
        except:
            self.search_input.setStyleSheet("""
                QLineEdit {
                    border: 1px solid #BDBDBD;
                    border-radius: 4px;
                    padding: 6px 10px;
                    background-color: white;
                }
                QLineEdit:focus {
                    border-color: #1976D2;
                }
            """)
        self.search_input.textChanged.connect(self.on_search_text_changed)
        search_layout.addWidget(self.search_input)
        
        # Search button (optional)
        search_button = QPushButton(header)
        search_button.setIcon(self.style().standardIcon(self.style().SP_FileDialogContentsView))
        search_button.setToolTip("Search")
        search_button.setStyleSheet("""
            QPushButton {
                background-color: #1976D2;
                border: none;
                border-radius: 4px;
                padding: 6px 10px;
            }
            QPushButton:hover {
                background-color: #1565C0;
            }
        """)
        search_button.clicked.connect(lambda: self.apply_filters())
        search_layout.addWidget(search_button)
        
        header_layout.addWidget(search_container)
        
        # Filter section
        filter_layout = QHBoxLayout()
        filter_layout.setSpacing(10)
        
        # Category filter
        category_label = QLabel("Category:", header)
        category_label.setStyleSheet("font-weight: bold;")
        filter_layout.addWidget(category_label)
        
        self.category_filter = QComboBox(header)
        self.category_filter.addItem("All Categories")
        self.category_filter.setMinimumWidth(150)
        self.category_filter.currentTextChanged.connect(self.apply_filters)
        filter_layout.addWidget(self.category_filter)
        
        # Type filter
        type_label = QLabel("Type:", header)
        type_label.setStyleSheet("font-weight: bold;")
        filter_layout.addWidget(type_label)
        
        self.type_filter = QComboBox(header)
        self.type_filter.addItem("All Types")
        self.type_filter.setMinimumWidth(150)
        self.type_filter.currentTextChanged.connect(self.apply_filters)
        filter_layout.addWidget(self.type_filter)
        
        header_layout.addLayout(filter_layout)
        header_layout.addStretch()
        
        # Add buttons on the right
        action_layout = QHBoxLayout()
        action_layout.setSpacing(8)
        
        # Add new item button
        self.add_item_button = QPushButton("Add New Item", header)
        self.add_item_button.setIcon(self.style().standardIcon(self.style().SP_FileDialogNewFolder))
        try:
            self.add_item_button.setStyleSheet(StandardTheme.get_button_style('primary', 'medium'))
        except:
            self.add_item_button.setStyleSheet("""
                QPushButton {
                    background-color: #1976D2;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    padding: 6px 12px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #1565C0;
                }
            """)
        self.add_item_button.clicked.connect(self.show_add_item_dialog)
        action_layout.addWidget(self.add_item_button)
        
        # Refresh button
        refresh_button = QPushButton("", header)
        refresh_button.setIcon(self.style().standardIcon(self.style().SP_BrowserReload))
        refresh_button.setToolTip("Refresh data")
        refresh_button.setFixedSize(36, 36)
        refresh_button.setStyleSheet("""
            QPushButton {
                background-color: #F5F5F5;
                border: 1px solid #E0E0E0;
                border-radius: 18px;
                padding: 4px;
            }
            QPushButton:hover {
                background-color: #E0E0E0;
            }
        """)
        refresh_button.clicked.connect(self.refresh_data)
        action_layout.addWidget(refresh_button)
        
        header_layout.addLayout(action_layout)
        
        parent_layout.addWidget(header)
    
    def create_category_panel(self, parent):
        """Create the category panel for easy navigation."""
        category_widget = QWidget(parent)
        category_widget.setObjectName("categoryPanel")
        category_widget.setStyleSheet("""
            QWidget#categoryPanel {
                background-color: #F5F5F5;
                border-right: 1px solid #E0E0E0;
            }
        """)
        category_widget.setMinimumWidth(200)
        category_widget.setMaximumWidth(300)
        
        category_layout = QVBoxLayout(category_widget)
        category_layout.setContentsMargins(10, 10, 10, 10)
        category_layout.setSpacing(5)
        
        # Category heading
        category_heading = QLabel("Categories", category_widget)
        category_heading.setStyleSheet("""
            font-weight: bold;
            font-size: 14px;
            color: #212121;
            padding-bottom: 5px;
            border-bottom: 1px solid #E0E0E0;
        """)
        category_layout.addWidget(category_heading)
        
        # Category list container
        self.category_list_widget = QWidget(category_widget)
        self.category_list_layout = QVBoxLayout(self.category_list_widget)
        self.category_list_layout.setContentsMargins(0, 5, 0, 0)
        self.category_list_layout.setSpacing(2)
        self.category_list_layout.addStretch()
        
        # Wrap in scroll area
        category_scroll = QScrollArea(category_widget)
        category_scroll.setWidgetResizable(True)
        category_scroll.setFrameShape(QFrame.NoFrame)
        category_scroll.setWidget(self.category_list_widget)
        category_layout.addWidget(category_scroll)
        
        return category_widget
    
    def setup_content_area(self, parent):
        """Set up the main content area for data items."""
        self.content_widget = QWidget(parent)
        self.content_widget.setObjectName("contentArea")
        
        content_layout = QVBoxLayout(self.content_widget)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)
        
        # Create a scrollable area for data cards
        scroll_area = QScrollArea(self.content_widget)
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.NoFrame)
        
        # Container for data cards
        self.cards_container = QWidget(scroll_area)
        self.cards_layout = QVBoxLayout(self.cards_container)
        self.cards_layout.setContentsMargins(5, 5, 5, 5)
        self.cards_layout.setSpacing(15)
        
        # Add empty state message (hidden initially)
        self.empty_message = QLabel("No data items found", self.cards_container)
        self.empty_message.setAlignment(Qt.AlignCenter)
        self.empty_message.setStyleSheet("""
            color: #757575;
            font-size: 16px;
            padding: 40px;
            background-color: #F5F5F5;
            border: 1px dashed #BDBDBD;
            border-radius: 8px;
        """)
        self.empty_message.setVisible(False)
        self.cards_layout.addWidget(self.empty_message)
        
        # Add stretch to push cards to the top
        self.cards_layout.addStretch()
        
        scroll_area.setWidget(self.cards_container)
        content_layout.addWidget(scroll_area)
    
    def setup_footer_section(self, parent_layout):
        """Create the footer section with action buttons."""
        footer = QWidget(self)
        footer.setObjectName("dialogFooter")
        try:
            footer.setStyleSheet("""
                QWidget#dialogFooter {
                    background-color: #F5F5F5;
                    border-top: 1px solid #E0E0E0;
                }
            """)
        except:
            pass
            
        footer_layout = QHBoxLayout(footer)
        footer_layout.setContentsMargins(15, 10, 15, 10)
        
        # Status label on the left
        self.status_label = QLabel(footer)
        self.status_label.setStyleSheet("color: #757575;")
        footer_layout.addWidget(self.status_label)
        
        footer_layout.addStretch()
        
        # Close button
        self.close_btn = QPushButton("Close", footer)
        try:
            self.close_btn.setStyleSheet(StandardTheme.get_button_style('secondary', 'medium'))
        except:
            self.close_btn.setStyleSheet("""
                QPushButton {
                    background-color: #757575;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    padding: 6px 12px;
                }
                QPushButton:hover {
                    background-color: #616161;
                }
            """)
        self.close_btn.clicked.connect(self.accept)
        footer_layout.addWidget(self.close_btn)
        
        parent_layout.addWidget(footer)
    
    def set_crud_helper(self, crud_helper, auth_service=None, agent=None):
        """
        Set the CRUD helper for data operations.
        
        Args:
            crud_helper: Helper class for CRUD operations
            auth_service: Authentication service
            agent: Backend agent for direct operations
        """
        self.crud_helper = crud_helper
        self.auth_service = auth_service
        self.agent = agent
    
    def set_data(self, data_items):
        """
        Set the data items to display with improved processing.
        
        Args:
            data_items: List of data items to display
        """
        # Store the original data
        self.data_items = data_items
        
        # Extract unique categories and types
        categories = set()
        types = set()
        
        for item in data_items:
            category = item.get('Category', 'Uncategorized')
            item_type = item.get('Type', 'Unknown')
            
            categories.add(category)
            types.add(item_type)
        
        # Remember current selections
        current_cat = self.category_filter.currentText()
        current_type = self.type_filter.currentText()
        
        # Update filter combos
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
        
        # Update the category panel
        self.update_category_panel(categories, data_items)
        
        # Apply filters to display items
        self.apply_filters()
        
        # Update status display
        self.status_label.setText(f"{len(data_items)} total items • {len(categories)} categories")
    
    def update_category_panel(self, categories, data_items):
        """Update the category panel with category counts."""
        # Clear existing categories
        self.clear_layout(self.category_list_layout)
        
        # Get count of items per category
        category_counts = {}
        for item in data_items:
            category = item.get('Category', 'Uncategorized')
            category_counts[category] = category_counts.get(category, 0) + 1
        
        # Add "All" option at the top
        all_button = QPushButton(f"All Categories ({len(data_items)})", self.category_list_widget)
        all_button.setStyleSheet("""
            QPushButton {
                background-color: #1976D2;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 6px 10px;
                text-align: left;
            }
            QPushButton:hover {
                background-color: #1565C0;
            }
        """)
        all_button.clicked.connect(lambda: self.filter_by_category_click("All Categories"))
        self.category_list_layout.insertWidget(0, all_button)
        
        # Add each category with count
        for category in sorted(categories):
            count = category_counts.get(category, 0)
            category_button = QPushButton(f"{category} ({count})", self.category_list_widget)
            category_button.setStyleSheet("""
                QPushButton {
                    background-color: transparent;
                    border: none;
                    border-radius: 4px;
                    padding: 6px 10px;
                    text-align: left;
                }
                QPushButton:hover {
                    background-color: #E3F2FD;
                }
            """)
            category_button.clicked.connect(lambda c=category: self.filter_by_category_click(c))
            self.category_list_layout.insertWidget(self.category_list_layout.count() - 1, category_button)
    
    def filter_by_category_click(self, category):
        """Handle category selection from the category panel."""
        # Set the category filter dropdown
        index = self.category_filter.findText(category)
        if index >= 0:
            self.category_filter.setCurrentIndex(index)
        else:
            self.category_filter.setCurrentIndex(0)  # All Categories
        
        # Apply filters
        self.apply_filters()
    
    def on_search_text_changed(self, text):
        """Handle search text changes with debouncing."""
        self.current_search_text = text
        
        # Use a simple timer to debounce the search
        if hasattr(self, 'search_timer'):
            self.search_timer.stop()
        else:
            self.search_timer = QTimer(self)
            self.search_timer.setSingleShot(True)
            self.search_timer.timeout.connect(self.apply_filters)
        
        self.search_timer.start(300)  # 300ms debounce
    
    def apply_filters(self):
        """
        Apply filters to the data with improved search capabilities.
        
        This method filters data based on category, type and search text,
        then displays the filtered items.
        """
        # Get filter values
        category = self.category_filter.currentText()
        type_value = self.type_filter.currentText()
        search_text = self.current_search_text.lower()
        
        # Filter the data
        self.filtered_items = []
        for item in self.data_items:
            item_category = item.get('Category', 'Uncategorized')
            item_type = item.get('Type', 'Unknown')
            
            # Check if matches category filter
            if category != "All Categories" and item_category != category:
                continue
                
            # Check if matches type filter
            if type_value != "All Types" and item_type != type_value:
                continue
                
            # Check if matches search text
            if search_text:
                # Search in multiple fields
                searchable_text = (
                    f"{item_category} {item_type} "
                    f"{item.get('_id', '')} {item.get('PII', '')}"
                ).lower()
                
                if search_text not in searchable_text:
                    continue
            
            # Item passed all filters
            self.filtered_items.append(item)
        
        # Update UI
        self.display_filtered_items()
        
        # Update status with filter info
        if category != "All Categories" or type_value != "All Types" or search_text:
            filter_parts = []
            if category != "All Categories":
                filter_parts.append(f"Category: {category}")
            if type_value != "All Types":
                filter_parts.append(f"Type: {type_value}")
            if search_text:
                filter_parts.append(f"Search: \"{search_text}\"")
                
            self.status_label.setText(
                f"{len(self.filtered_items)} items found • Filters: {' • '.join(filter_parts)}"
            )
        else:
            # No filters active
            self.status_label.setText(f"{len(self.data_items)} total items")
    
    def display_filtered_items(self):
        """Display the filtered items with improved card layout."""
        # Clear existing cards
        self.clear_layout(self.cards_layout)
        
        # Show empty message if no items
        if not self.filtered_items:
            self.empty_message.setVisible(True)
            self.cards_layout.addWidget(self.empty_message)
            self.cards_layout.addStretch()
            return
        else:
            self.empty_message.setVisible(False)
        
        # Add cards for each item
        for item in self.filtered_items:
            card = EnhancedPIIDataCard(item, self)
            
            # Connect signals
            card.edit_clicked.connect(self.edit_item)
            card.delete_clicked.connect(self.delete_item)
            card.view_details_clicked.connect(self.view_item_details)
            
            self.cards_layout.insertWidget(self.cards_layout.count() - 1, card)
    
    def clear_layout(self, layout):
        """Safely clear all widgets from a layout."""
        if layout is None:
            return
            
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
            else:
                # Might be a layout
                self.clear_layout(item.layout())
    
    def edit_item(self, item_data):
        """
        Show dialog to edit an item with improved error handling.
        
        Args:
            item_data: Data of the item to edit
        """
        try:
            # Determine which edit dialog class to use
            try:
                # Try to use enhanced dialog if available
                from UI.Desktop.enhanced_dialogs import EnhancedDataItemDialog
                dialog = EnhancedDataItemDialog(item_data, self)
            except ImportError:
                # Fall back to the basic dialog
                dialog = DataItemEditDialog(item_data, self)
            
            # Execute the dialog
            if dialog.exec_() == QDialog.Accepted:
                updated_data = dialog.get_updated_data()
                
                if updated_data:
                    # Show progress indicator
                    self.status_label.setText("Updating item...")
                    QApplication.processEvents()
                    
                    # Use CRUD helper to update
                    self.update_item_data(updated_data)
        except Exception as e:
            logger.error(f"Error editing item: {e}")
            QMessageBox.critical(self, "Error", f"An error occurred while editing: {str(e)}")
    
    def update_item_data(self, item_data):
        """
        Update an item in the database with improved feedback.
        
        Args:
            item_data: Updated item data
        """
        if not self.crud_helper:
            QMessageBox.warning(self, "Error", "CRUD helper not set")
            return
        
        # Show progress dialog with better styling
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
                    self, "Success", "Item updated successfully"
                )
                
                # Refresh the data
                self.refresh_data()
            else:
                QMessageBox.warning(
                    self, "Error", f"Failed to update item: {response}"
                )
        except Exception as e:
            progress_dialog.close()
            QMessageBox.critical(
                self, "Error", f"Error updating item: {str(e)}"
            )
    
    def delete_item(self, item_data):
        """
        Delete an item with enhanced confirmation and feedback.
        
        Args:
            item_data: Data of the item to delete
        """
        # Determine whether to use enhanced delete handler
        if delete_handler_available:
            # Use the enhanced delete handler
            from UI.Desktop.delete_handler import DeleteHandler
            
            # Define callbacks
            def on_success():
                self.refresh_data()
            
            def log_callback(message):
                logger.info(message)
                self.status_label.setText(message)
                QApplication.processEvents()
            
            # Use the delete handler
            DeleteHandler.delete_item(
                parent=self,
                item_data=item_data,
                agent=self.agent,
                auth_service=self.auth_service,
                auth_manager=None,
                api_client=None,
                on_success=on_success,
                log_callback=log_callback
            )
        else:
            # Use standard confirmation dialog
            confirmation = QMessageBox.question(
                self,
                "Confirm Delete",
                f"Are you sure you want to delete this {item_data.get('Type', 'item')}?\n\n"
                f"Category: {item_data.get('Category', 'Unknown')}\n"
                f"ID: {item_data.get('_id', 'Unknown')}\n\n"
                "This action cannot be undone.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if confirmation == QMessageBox.Yes:
                # Show progress dialog
                progress_dialog = QMessageBox(self)
                progress_dialog.setWindowTitle("Deleting Data")
                progress_dialog.setText("Deleting data item...")
                progress_dialog.setStandardButtons(QMessageBox.NoButton)
                progress_dialog.show()
                QApplication.processEvents()
                
                try:
                    # Use CRUD helper to delete
                    success, response = self.crud_helper.perform_operation(
                        'delete',
                        item_data,
                        agent=self.agent,
                        auth_service=self.auth_service,
                        logger=logger.info
                    )
                    
                    # Close progress dialog
                    progress_dialog.close()
                    
                    if success:
                        QMessageBox.information(
                            self, "Success", "Item deleted successfully"
                        )
                        
                        # Refresh the data
                        self.refresh_data()
                    else:
                        QMessageBox.warning(
                            self, "Error", f"Failed to delete item: {response}"
                        )
                except Exception as e:
                    progress_dialog.close()
                    QMessageBox.critical(
                        self, "Error", f"Error deleting item: {str(e)}"
                    )
    
    def view_item_details(self, item_data):
        """
        Show a detailed view of a single item.
        
        Args:
            item_data: Data to display
        """
        # Create a simplified dialog to show all details
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Item Details: {item_data.get('Type', 'Unknown')}")
        dialog.resize(600, 400)
        
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Header with item info
        header_layout = QHBoxLayout()
        
        category_type_layout = QVBoxLayout()
        
        # Category and type
        category = item_data.get('Category', 'Uncategorized')
        type_value = item_data.get('Type', 'Unknown')
        
        type_label = QLabel(f"<b>{type_value}</b>", dialog)
        type_label.setStyleSheet("font-size: 16px; color: #212121;")
        category_type_layout.addWidget(type_label)
        
        category_label = QLabel(f"Category: {category}", dialog)
        category_label.setStyleSheet("font-size: 14px; color: #757575;")
        category_type_layout.addWidget(category_label)
        
        header_layout.addLayout(category_type_layout)
        header_layout.addStretch()
        
        # ID display
        id_value = item_data.get('_id', 'Unknown')
        id_label = QLabel(f"ID: {id_value}", dialog)
        id_label.setStyleSheet("font-size: 12px; color: #9E9E9E;")
        header_layout.addWidget(id_label)
        
        layout.addLayout(header_layout)
        
        # Separator
        separator = QFrame(dialog)
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)
        separator.setStyleSheet("background-color: #E0E0E0;")
        layout.addWidget(separator)
        
        # Content area
        content_scroll = QScrollArea(dialog)
        content_scroll.setWidgetResizable(True)
        content_scroll.setFrameShape(QFrame.NoFrame)
        
        content_widget = QWidget(content_scroll)
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(10)
        
        # Parse and display all PII fields
        try:
            pii_data = item_data.get('PII', '')
            pii_items = []
            
            # Parse PII data with robust error handling
            if isinstance(pii_data, str):
                try:
                    parsed_data = ast.literal_eval(pii_data)
                    if isinstance(parsed_data, list):
                        pii_items = parsed_data
                    elif isinstance(parsed_data, dict):
                        pii_items = [{"Item Name": k, "Data": v} for k, v in parsed_data.items()]
                    else:
                        pii_items = [{"Item Name": "Data", "Data": pii_data}]
                except:
                    pii_items = [{"Item Name": "Data", "Data": pii_data}]
            elif isinstance(pii_data, list):
                pii_items = pii_data
            elif isinstance(pii_data, dict):
                pii_items = [{"Item Name": k, "Data": v} for k, v in pii_data.items()]
            else:
                pii_items = [{"Item Name": "Data", "Data": str(pii_data)}]
            
            # Display each PII field in a card
            for item in pii_items:
                name = item.get("Item Name", "")
                value = item.get("Data", "")
                
                if name or value:
                    # Create a card for this field
                    field_frame = QFrame(content_widget)
                    field_frame.setFrameShape(QFrame.StyledPanel)
                    field_frame.setStyleSheet("""
                        QFrame {
                            background-color: #F5F5F5;
                            border-radius: 6px;
                            border: 1px solid #E0E0E0;
                        }
                    """)
                    
                    field_layout = QVBoxLayout(field_frame)
                    field_layout.setContentsMargins(10, 10, 10, 10)
                    field_layout.setSpacing(8)
                    
                    # Field name
                    name_label = QLabel(f"<b>{name}</b>", field_frame)
                    name_label.setStyleSheet("color: #424242;")
                    field_layout.addWidget(name_label)
                    
                    # Field value with better formatting
                    formatted_value = self.format_value_for_display(value)
                    value_label = QLabel(formatted_value, field_frame)
                    value_label.setStyleSheet("""
                        background-color: white;
                        padding: 8px;
                        border-radius: 4px;
                        border: 1px solid #E0E0E0;
                    """)
                    value_label.setTextInteractionFlags(
                        Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard
                    )
                    value_label.setWordWrap(True)
                    field_layout.addWidget(value_label)
                    
                    content_layout.addWidget(field_frame)
            
        except Exception as e:
            # Show error message
            error_label = QLabel(f"Error displaying data: {str(e)}", content_widget)
            error_label.setStyleSheet("color: #D32F2F; padding: 10px;")
            content_layout.addWidget(error_label)
        
        # Add some metadata fields
        metadata_frame = QFrame(content_widget)
        metadata_frame.setFrameShape(QFrame.StyledPanel)
        metadata_frame.setStyleSheet("""
            QFrame {
                background-color: #E8F5E9;
                border-radius: 6px;
                border: 1px solid #C8E6C9;
            }
        """)
        
        metadata_layout = QVBoxLayout(metadata_frame)
        metadata_layout.setContentsMargins(10, 10, 10, 10)
        
        # Add creation/update timestamps if available
        if 'created_at' in item_data:
            created_label = QLabel(f"Created: {item_data['created_at']}", metadata_frame)
            created_label.setStyleSheet("color: #2E7D32;")
            metadata_layout.addWidget(created_label)
            
        if 'updated_at' in item_data:
            updated_label = QLabel(f"Updated: {item_data['updated_at']}", metadata_frame)
            updated_label.setStyleSheet("color: #2E7D32;")
            metadata_layout.addWidget(updated_label)
            
        # Add user information if available
        if 'created_by' in item_data:
            created_by_label = QLabel(f"Created by: {item_data['created_by']}", metadata_frame)
            created_by_label.setStyleSheet("color: #2E7D32;")
            metadata_layout.addWidget(created_by_label)
            
        if 'updated_by' in item_data:
            updated_by_label = QLabel(f"Updated by: {item_data['updated_by']}", metadata_frame)
            updated_by_label.setStyleSheet("color: #2E7D32;")
            metadata_layout.addWidget(updated_by_label)
        
        # Only add the metadata frame if it has content
        if metadata_layout.count() > 0:
            content_layout.addWidget(metadata_frame)
        
        # Add stretch to push content to the top
        content_layout.addStretch()
        
        content_scroll.setWidget(content_widget)
        layout.addWidget(content_scroll, 1)  # Give stretch priority
        
        # Close button
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        close_button = QPushButton("Close", dialog)
        close_button.setStyleSheet("""
            QPushButton {
                background-color: #1976D2;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #1565C0;
            }
        """)
        close_button.clicked.connect(dialog.accept)
        button_layout.addWidget(close_button)
        
        layout.addLayout(button_layout)
        
        # Show the dialog
        dialog.exec_()
    
    def format_value_for_display(self, value):
        """Format a value for better display in the details view."""
        if not value:
            return "<em>empty</em>"
            
        # Convert to string if needed
        if not isinstance(value, str):
            # For dict and list, make it look nicer
            if isinstance(value, (dict, list)):
                try:
                    return f"<pre>{json.dumps(value, indent=2)}</pre>"
                except:
                    return f"<pre>{str(value)}</pre>"
            return str(value)
            
        # Check if it's JSON and try to pretty-print it
        try:
            if (value.strip().startswith('{') and value.strip().endswith('}')) or \
               (value.strip().startswith('[') and value.strip().endswith(']')):
                parsed = json.loads(value)
                return f"<pre>{json.dumps(parsed, indent=2)}</pre>"
        except:
            # Not valid JSON, try literal_eval
            try:
                if (value.strip().startswith('{') and value.strip().endswith('}')) or \
                   (value.strip().startswith('[') and value.strip().endswith(']')):
                    parsed = ast.literal_eval(value)
                    if isinstance(parsed, (dict, list)):
                        return f"<pre>{json.dumps(parsed, indent=2)}</pre>"
            except:
                pass
        
        # Format email addresses with mailto links
        if re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', value):
            return f'<a href="mailto:{value}">{value}</a>'
            
        # Format URLs with hyperlinks
        if value.startswith(('http://', 'https://')):
            return f'<a href="{value}">{value}</a>'
            
        # Escape HTML special characters for normal strings
        value = value.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        
        return value
    
    def show_add_item_dialog(self):
        """Show dialog to add a new item with improved template."""
        # Create empty item with better default structure
        new_item = {
            "Category": "",
            "Type": "",
            "PII": str([{"Item Name": "Name", "Data": ""}, {"Item Name": "Value", "Data": ""}])
        }
        
        # Try to pre-populate category and type if available from filters
        category = self.category_filter.currentText()
        type_value = self.type_filter.currentText()
        
        if category and category != "All Categories":
            new_item["Category"] = category
            
        if type_value and type_value != "All Types":
            new_item["Type"] = type_value
        
        try:
            # Try to use enhanced dialog if available
            from UI.Desktop.enhanced_dialogs import EnhancedDataItemDialog
            dialog = EnhancedDataItemDialog(new_item, self)
        except ImportError:
            # Fall back to the basic dialog
            dialog = DataItemEditDialog(new_item, self)
        
        dialog.setWindowTitle("Add New Data Item")
        
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
        Add a new item to the database with improved progress feedback.
        
        Args:
            item_data: New item data
        """
        if not self.crud_helper:
            QMessageBox.warning(self, "Error", "CRUD helper not set")
            return
            
        # Update status
        self.status_label.setText("Adding new item...")
        QApplication.processEvents()
        
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
                    self, "Success", "Item added successfully"
                )
                
                # Update status
                self.status_label.setText("Item added successfully. Refreshing data...")
                QApplication.processEvents()
                
                # Refresh the data
                self.refresh_data()
            else:
                QMessageBox.warning(
                    self, "Error", f"Failed to add item: {response}"
                )
                self.status_label.setText("Failed to add item")
        except Exception as e:
            progress_dialog.close()
            QMessageBox.critical(
                self, "Error", f"Error adding item: {str(e)}"
            )
            self.status_label.setText("Error adding item")
    
    def refresh_data(self):
        """Refresh the data display with improved feedback."""
        # Update status
        self.status_label.setText("Refreshing data...")
        QApplication.processEvents()
        
        # Trigger callback if provided
        if self.on_refresh_callback:
            try:
                result = self.on_refresh_callback()
                
                # If callback returns data directly, update our display
                if isinstance(result, list) or isinstance(result, dict):
                    self.set_data(result)
                    self.status_label.setText("Data refreshed successfully")
                    
                # Otherwise, assume the callback handled the refresh
                else:
                    self.status_label.setText("Refresh completed")
            except Exception as e:
                logger.error(f"Error during refresh callback: {e}")
                self.status_label.setText(f"Error refreshing data: {str(e)}")
                QMessageBox.warning(
                    self, "Refresh Error", f"Error refreshing data: {str(e)}"
                )