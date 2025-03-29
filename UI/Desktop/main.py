"""
Enhanced GUARD Desktop Application for secure PII data management with authentication.

This module provides a robust graphical user interface for managing PII
(Personally Identifiable Information) data with enterprise-grade security,
improved user experience, and standardized design patterns.
"""

# Standard library imports
import sys
import os
import logging
import traceback
from logging.handlers import RotatingFileHandler
from datetime import datetime

# Third-party imports
import pandas as pd
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QLabel, QTableWidget, QHeaderView, QTableWidgetItem,
    QMessageBox, QDialog, QMenu, QTabWidget, 
    QStatusBar, QProgressDialog, QFrame, QGraphicsDropShadowEffect, 
    QToolTip, QApplication, QSplitter, QGroupBox,
    QProgressBar, QStyle, QLineEdit, QComboBox
)
from PyQt5.QtGui import QColor
from PyQt5.QtCore import Qt, QTimer, QDateTime, QPoint, QRect

# Application imports
import api.CONSTANTS as CONSTANTS
from UI.Desktop.session_manager import SessionManager
from UI.Desktop.auth_service import AuthenticationService
from UI.Desktop.api_client import APIClient
from UI.Desktop.modern_components import CRUDHelper

from UI.Desktop.modern_components import EnhancedModernDataDialog as ModernDataDialog
from UI.Desktop.standard_theme import StandardTheme


# Setup logging with rotation
os.makedirs('logs', exist_ok=True)
handler = RotatingFileHandler('logs/application.log', maxBytes=5000000, backupCount=5)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logging.basicConfig(handlers=[handler], level=logging.INFO)
logger = logging.getLogger('GUARD_App')


class EnhancedSessionWidget(QWidget):
    """
    Enhanced session status widget with visual indicators.

    This widget shows the current authentication state, session type,
    and remaining session time with appropriate visual cues.
    """

    def __init__(self, parent=None, session_manager=None, auth_service=None):
        """
        Initialize the session status widget.

        Args:
            parent: Parent widget
            session_manager: Session manager to monitor
            auth_service: Authentication service
        """
        super().__init__(parent)
        self.session_manager = session_manager
        self.auth_service = auth_service
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_status)
        self.timer.start(1000)  # Update every second
        self.logger = logging.getLogger('SessionWidget')
        
        self.setup_ui()

    def setup_ui(self):
        """Set up the user interface."""
        # Main layout
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(10, 5, 10, 5)
        main_layout.setSpacing(10)

        # Create background frame
        self.status_card = QFrame(self)
        self.status_card.setObjectName("statusCard")
        self.status_card.setFrameShape(QFrame.StyledPanel)
        self.status_card.setStyleSheet(StandardTheme.get_frame_style('paper'))
        
        # Add shadow effect
        shadow = QGraphicsDropShadowEffect(self.status_card)
        shadow.setBlurRadius(8)
        shadow.setColor(QColor(0, 0, 0, 30))
        shadow.setOffset(0, 2)
        self.status_card.setGraphicsEffect(shadow)
        
        # Card layout
        card_layout = QHBoxLayout(self.status_card)
        card_layout.setContentsMargins(15, 10, 15, 10)
        card_layout.setSpacing(15)

        # Status indicator
        self.status_indicator = QFrame(self)
        self.status_indicator.setFixedSize(12, 12)
        self.status_indicator.setStyleSheet("""
            background-color: #9E9E9E;
            border-radius: 6px;
        """)
        card_layout.addWidget(self.status_indicator)

        # User info section
        user_info_layout = QVBoxLayout()
        user_info_layout.setSpacing(2)
        
        self.user_label = QLabel("Not authenticated", self)
        self.user_label.setStyleSheet(StandardTheme.get_label_style('default', 'medium', True))
        
        self.auth_type_label = QLabel("", self)
        self.auth_type_label.setStyleSheet(StandardTheme.get_label_style('muted', 'small'))
        
        user_info_layout.addWidget(self.user_label)
        user_info_layout.addWidget(self.auth_type_label)
        card_layout.addLayout(user_info_layout)
        
        # Add spacer
        card_layout.addStretch()
        
        # Session time section
        session_time_layout = QVBoxLayout()
        session_time_layout.setSpacing(5)
        
        self.time_label = QLabel("Session: --:--", self)
        self.time_label.setStyleSheet(StandardTheme.get_label_style())
        self.time_label.setAlignment(Qt.AlignRight)
        
        # Progress bar for time remaining
        self.time_progress = QProgressBar(self)
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
        self.refresh_button = QPushButton(self)
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
        self.info_button = QPushButton(self)
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
        
        # Initial update
        self.update_status()

    def update_status(self):
        """Update the session status display."""
        if not self.session_manager or not hasattr(self.session_manager, 'is_authenticated') or not self.session_manager.is_authenticated:
            # Not authenticated
            self.status_indicator.setStyleSheet("""
                background-color: #9E9E9E;
                border-radius: 6px;
            """)
            self.user_label.setText("Not authenticated")
            self.auth_type_label.setText("")
            self.time_label.setText("Session: --:--")
            self.time_progress.setValue(0)
            self.refresh_button.setEnabled(False)
            self.info_button.setEnabled(False)
            return

        # Get session info
        session_info = self.session_manager.get_session_info() if hasattr(
            self.session_manager, 'get_session_info') else {}
        remaining_seconds = session_info.get("remaining_seconds", 0)

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

        # Update remaining time
        if remaining_seconds is not None:
            minutes, seconds = divmod(remaining_seconds, 60)
            hours, minutes = divmod(minutes, 60)

            if hours > 0:
                time_text = f"{int(hours)}h {int(minutes)}m"
            else:
                time_text = f"{int(minutes)}m {int(seconds)}s"

            self.time_label.setText(f"Session: {time_text}")

            # Calculate percentage for progress bar
            max_duration = 3600  # 1 hour is standard
            if auth_type == "aws_sso":
                max_duration = 8 * 3600  # 8 hours for AWS SSO

            percentage = min(100, (remaining_seconds / max_duration) * 100)
            self.time_progress.setValue(int(percentage))

            # Set color based on remaining time
            if remaining_seconds < 300:  # Less than 5 minutes
                self.time_progress.setStyleSheet("""
                    QProgressBar { background-color: #FFEBEE; border-radius: 2px; }
                    QProgressBar::chunk { background-color: #F44336; border-radius: 2px; }
                """)
                self.time_label.setStyleSheet("color: #D32F2F; font-weight: bold;")
            elif remaining_seconds < 600:  # Less than 10 minutes
                self.time_progress.setStyleSheet("""
                    QProgressBar { background-color: #FFF8E1; border-radius: 2px; }
                    QProgressBar::chunk { background-color: #FFC107; border-radius: 2px; }
                """)
                self.time_label.setStyleSheet("color: #FFA000; font-weight: bold;")
            else:
                self.time_progress.setStyleSheet("""
                    QProgressBar { background-color: #E0E0E0; border-radius: 2px; }
                    QProgressBar::chunk { background-color: #1976D2; border-radius: 2px; }
                """)
                self.time_label.setStyleSheet("color: #424242;")

        # Update status indicator
        if self.session_manager.is_authenticated:
            self.refresh_button.setEnabled(True)
            self.info_button.setEnabled(True)
        else:
            self.refresh_button.setEnabled(False)
            self.info_button.setEnabled(False)

    def refresh_session(self):
        """Attempt to refresh the session token."""
        if not self.session_manager:
            return
            
        try:
            # Visual feedback that refresh is being attempted
            self.refresh_button.setEnabled(False)
            self.refresh_button.setToolTip("Refreshing...")
            QApplication.processEvents()
            
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
                    dt = datetime.fromisoformat(expiration_time.replace('Z', '+00:00'))
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


class GuardMainWindow(QMainWindow):
    """
    Enhanced main window for the GUARD data management application.
    
    This class handles the user interface with standardized styling,
    improved authentication flow, and robust data operations.
    """

    def __init__(self):
        """Initialize the main window and UI components."""
        super().__init__()
        self.setWindowTitle('GUARD: Secure PII Data Management')
        self.setGeometry(100, 100, 1200, 800)
        
        # Initialize variables
        self.modified = False
        self.auth_service = None
        self.api_client = None
        
        # Initialize logger
        self.logger = logging.getLogger('GuardMainWindow')
        self.logger.setLevel(logging.INFO)

        # Apply application styling
        self.setStyleSheet(StandardTheme.get_application_style())
        
        # Initialize session manager and auth service
        self.setup_session_manager()
        self.setup_auth_service()
        
        # Set up status bar
        self.setup_status_bar()
        
        # Set up UI
        self.setup_ui()
        
        # Show the window
        self.show()
        
        # Log application start
        self.logger.info("GUARD application started")
        
        # Connect the close event
        self.closeEvent = self.handle_close_event

    def setup_ui(self):
        """Initialize and set up the UI components."""
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # Create top section with logo and welcome message
        self.setup_header_section(main_layout)
        
        # Create tab widget for multiple functional areas
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabPosition(QTabWidget.North)
        self.tab_widget.setDocumentMode(True)  # More modern look
        main_layout.addWidget(self.tab_widget, 1)  # Give it stretch priority
        
        # Set up tabs
        self.setup_data_management_tab()
        
        # Create a container for the login panel that we can show/hide
        self.login_container = QFrame(self)
        self.login_container.setObjectName("loginContainer")
        self.login_container.setFrameShape(QFrame.NoFrame)
        self.login_container.setFixedSize(400, 300)  # Set appropriate size
        self.login_container.setStyleSheet("background: transparent;")
        login_container_layout = QVBoxLayout(self.login_container)
        login_container_layout.setContentsMargins(0, 0, 0, 0)
        
        # Initially hide the login container
        self.login_container.setVisible(False)
        
        # Add session status widget to main layout (fixed at bottom)
        self.session_status = EnhancedSessionWidget(self, self.session_manager, self.auth_service)
        main_layout.addWidget(self.session_status)
        
        # Log initialization
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        self.update_log(timestamp, "Application initialized")
    
    
   
    def setup_session_manager(self):
        """Set up the session manager and connect signals."""
        # Create session manager with 1-hour session timeout
        self.session_manager = SessionManager(self, token_ttl=3600)
        
        # Connect signals
        self.session_manager.session_expired.connect(self.handle_session_expired)
        self.session_manager.token_refreshed.connect(self.handle_token_refreshed)
        self.session_manager.session_expiring_soon.connect(self.handle_session_expiring_soon)
        self.session_manager.auth_success.connect(self.handle_auth_success)
        self.session_manager.auth_failure.connect(self.handle_auth_failure)
        
        # Log initialization
        self.logger.info("Session manager initialized")

    def setup_auth_service(self):
        """Set up the authentication service."""
        # Create authentication service
        self.auth_service = AuthenticationService(self)
        
        # Connect it to the session manager
        if hasattr(self, 'session_manager'):
            self.auth_service.set_session_manager(self.session_manager)
        
        # Log initialization
        self.logger.info("Authentication service initialized")

    def setup_status_bar(self):
        """Set up status bar with session information."""
        # Create status bar
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        
        # Add app version indicator
        version_label = QLabel(f"GUARD v1.0.0")
        version_label.setStyleSheet("color: white; padding-right: 10px;")
        self.statusBar.addPermanentWidget(version_label)
        
        # Add session timer display
        self.session_timer_label = QLabel("Not logged in")
        self.session_timer_label.setStyleSheet("color: white; padding-right: 10px;")
        self.statusBar.addPermanentWidget(self.session_timer_label)
        
        # Add session type indicator
        self.session_type_label = QLabel("")
        self.session_type_label.setStyleSheet("color: white; font-weight: bold; padding-right: 10px;")
        self.statusBar.addPermanentWidget(self.session_type_label)
        
        # Set up timer to update status bar
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_session_status)
        self.status_timer.start(5000)  # Update every 5 seconds

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
                self.session_timer_label.setStyleSheet("color: #FFC107; font-weight: bold;")
            elif session_info["remaining_seconds"] < 600:  # Less than 10 minutes
                self.session_timer_label.setStyleSheet("color: #FF9800; font-weight: bold;")
            else:
                self.session_timer_label.setStyleSheet("color: white;")
        
        # Update auth type indicator
        auth_type = session_info["auth_type"]
        if auth_type == "aws_sso":
            self.session_type_label.setText("AWS SSO")
            self.session_type_label.setStyleSheet("color: #FF9800; font-weight: bold;")
        elif auth_type == "password":
            self.session_type_label.setText("Password")
            self.session_type_label.setStyleSheet("color: white; font-weight: bold;")
        else:
            self.session_type_label.setText(auth_type)
            self.session_type_label.setStyleSheet("color: white; font-weight: bold;")

    def show_auth_options(self):
        """Show authentication options with AWS SSO login."""
        self.btn_connect_server.setText('Authenticating...')
        self.btn_connect_server.setDisabled(True)
        
        # Remove any existing login panels from previous attempts
        for i in reversed(range(self.data_tab.layout().count())):
            widget = self.data_tab.layout().itemAt(i).widget()
            if isinstance(widget, QFrame) and widget.objectName() == "loginPanel":
                widget.deleteLater()
        
        # Create a dedicated container that will float above other widgets
        login_panel = QFrame(self)
        login_panel.setObjectName("loginPanel")
        login_panel.setFrameShape(QFrame.StyledPanel)
        login_panel.setStyleSheet(StandardTheme.get_card_style('default', 2))
        login_panel.setFixedSize(400, 280)  # Fixed size for better positioning
        
        # Center the panel on the window
        login_panel.move(
            (self.width() - login_panel.width()) // 2,
            (self.height() - login_panel.height()) // 2
        )
        
        # Set up panel layout
        login_layout = QVBoxLayout(login_panel)
        login_layout.setContentsMargins(35, 35, 35, 35)
        login_layout.setSpacing(25)
        
        # Add header
        header_label = QLabel("Authentication", login_panel)
        header_label.setStyleSheet(StandardTheme.get_label_style('primary', 'large', True))
        login_layout.addWidget(header_label, 0, Qt.AlignHCenter)
        
        # Add message
        info_label = QLabel("Please select your authentication method:", login_panel)
        info_label.setStyleSheet(StandardTheme.get_label_style())
        login_layout.addWidget(info_label)
        
        # Add AWS SSO button
        sso_button = QPushButton("AWS Single Sign-On", login_panel)
        sso_button.setIcon(self.style().standardIcon(QStyle.SP_DialogApplyButton))
        sso_button.setStyleSheet(StandardTheme.get_button_style('aws', 'large'))
        sso_button.setCursor(Qt.PointingHandCursor)
        sso_button.setMinimumHeight(50)
        sso_button.clicked.connect(self.authenticate_with_sso)
        login_layout.addWidget(sso_button)
        
        # Add security message
        security_label = QLabel("Your credentials are securely managed and never stored locally.", login_panel)
        security_label.setStyleSheet(StandardTheme.get_label_style('muted', 'small'))
        login_layout.addWidget(security_label)
        
        # Add a close icon
        close_button = QPushButton("×", login_panel)
        close_button.setToolTip("Cancel")
        close_button.setFixedSize(24, 24)
        close_button.setStyleSheet("""
            QPushButton {
                background-color: #E0E0E0;
                border-radius: 12px;
                font-weight: bold;
                font-size: 16px;
            }
            QPushButton:hover {
                background-color: #F44336;
                color: white;
            }
        """)
        close_button.clicked.connect(login_panel.deleteLater)
        # Position in top-right corner
        close_button.move(login_panel.width() - 30, 10)
        
        # Show the login panel
        login_panel.show()
        login_panel.raise_()
        
        # Log attempt
        self.update_log(
            QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
            "Authentication panel displayed"
        )
        
        # Re-enable connect button
        self.btn_connect_server.setText('Connect to Server')
        self.btn_connect_server.setEnabled(True)
        
    def authenticate_with_sso(self):
        """Authenticate using AWS SSO with proper credential handling."""
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        self.update_log(timestamp, "Starting AWS SSO authentication...")
        
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
                self.update_log(timestamp, "AWS SSO authentication failed")
                return
            
            # Verify we have credentials
            if not self.session_manager.credentials:
                progress.close()
                QMessageBox.warning(
                    self, 
                    "Authentication Error", 
                    "AWS SSO authentication succeeded but no credentials were obtained."
                )
                self.update_log(timestamp, "AWS SSO authentication succeeded but no credentials were obtained")
                return
                
            # Log credential info (safely)
            credentials = self.session_manager.credentials
            access_key = credentials.get('AccessKeyId', '')
            has_secret = 'SecretAccessKey' in credentials
            has_token = 'SessionToken' in credentials
            
            self.update_log(
                timestamp,
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
                self.update_log(timestamp, f"API authentication failed: {message}")
                return
            
            # Setup API client
            progress.setValue(70)
            progress.setLabelText("Initializing API client...")
            QApplication.processEvents()
            
            self.setup_api_client()
            
            progress.setValue(80)
            progress.setLabelText("Loading data...")
            QApplication.processEvents()
            
            # Complete connection process
            self.connect_after_authentication()
            
            progress.setValue(100)
            progress.close()
            
            # Show success message
            self.update_log(
                timestamp,
                "AWS SSO authentication successful"
            )
            
            # Show welcome message with user ID
            user_id = self.session_manager.user_id or "User"
            QMessageBox.information(
                self,
                "Authentication Successful",
                f"Welcome, {user_id}!\n\nYou have successfully authenticated with AWS SSO."
            )
            
        except Exception as e:
            progress.close()
            self.logger.error(f"AWS SSO authentication error: {str(e)}")
            QMessageBox.critical(self, "Authentication Error", f"AWS SSO authentication failed: {str(e)}")
            self.update_log(timestamp, f"AWS SSO authentication error: {str(e)}")

    def setup_api_client(self):
        """Set up the API client for data operations."""
        try:
            self.api_client = APIClient(
                base_url=CONSTANTS.API_BASE_URL,
                auth_service=self.auth_service
            )
            self.logger.info("API client initialized")
            self.update_log(
                QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
                f"API client initialized: {CONSTANTS.API_BASE_URL}"
            )
        except Exception as e:
            self.logger.error(f"Error initializing API client: {str(e)}")
            raise
    
    def resizeEvent(self, event):
        """Handle window resize events."""
        super().resizeEvent(event)
        
        # Keep any login panel centered
        for child in self.children():
            if isinstance(child, QFrame) and child.objectName() == "loginPanel":
                child.move(
                    (self.width() - child.width()) // 2,
                    (self.height() - child.height()) // 2
                )

    def connect_after_authentication(self):
        """Complete the connection process after successful authentication."""
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        self.update_log(timestamp, "Authentication successful")
        
        # Remove login panel if present
        for child in self.children():
            if isinstance(child, QFrame) and child.objectName() == "loginPanel":
                child.deleteLater()
        
        # Update UI elements
        self.show_authenticated_ui()
        
        # Fetch initial data
        self.fetch_initial_data()
        
        # Update logs
        self.update_log(timestamp, "Connected to server")
        self.update_log(timestamp, "Application ready")


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
            progress.setLabelText("Retrieving data from server...")
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
                self.populate_category_table(df)
                
                progress.setValue(100)
                QApplication.processEvents()
                progress.close()
                
                # Log success
                self.update_log(
                    QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
                    f"Successfully loaded {len(df)} data items"
                )
            else:
                progress.close()
                error_msg = "Failed to fetch data"
                if isinstance(data, dict) and "error" in data:
                    error_msg = f"Failed to fetch data: {data['error']}"
                elif isinstance(data, str):
                    error_msg = f"Failed to fetch data: {data}"
                    
                QMessageBox.warning(self, "Data Fetch Error", error_msg)
                self.update_log(
                    QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
                    error_msg
                )
        except Exception as e:
            # Make sure the progress dialog is closed
            if 'progress' in locals():
                progress.close()
                
            self.logger.error(f"Error fetching initial data: {str(e)}")
            QMessageBox.warning(
                self,
                "Data Fetch Error",
                f"Error fetching data: {str(e)}"
            )
            self.update_log(
                QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
                f"Error fetching data: {str(e)}"
            )

    

    def fetch_latest_data(self):
        """Fetch the latest data and update displays with improved handling."""
        try:
            # Show a subtle progress indication in status bar
            self.statusBar.showMessage("Fetching data from server...", 2000)
            
            # Get fresh data
            if not hasattr(self, 'api_client') or self.api_client is None:
                self.logger.error("API client not available. Please connect to the server first.")
                self.statusBar.showMessage("API client not available. Please connect to the server.", 3000)
                return None
                
            success, data = self.api_client.sync_get_pii_data()
            
            if success:
                # Log the data received to help debug
                self.logger.info(f"Data received: {len(data) if isinstance(data, list) else 'non-list data'}")
                
                # Convert to DataFrame format if needed
                if isinstance(data, list):
                    if not data:  # Empty list
                        self.logger.warning("Received empty data list from server")
                        self.statusBar.showMessage("No data found on server", 3000)
                        return pd.DataFrame()  # Return empty DataFrame
                        
                    df = pd.DataFrame(data)
                elif isinstance(data, pd.DataFrame):
                    df = data
                else:
                    # Try to convert to list if it's not already one
                    try:
                        self.logger.warning(f"Unexpected data type: {type(data)}. Attempting conversion.")
                        data_list = list(data) if hasattr(data, '__iter__') else [data]
                        df = pd.DataFrame(data_list)
                    except Exception as e:
                        self.logger.error(f"Failed to convert data to DataFrame: {str(e)}")
                        df = pd.DataFrame([data] if data else [])
                
                # Check if DataFrame has expected columns
                if 'Category' not in df.columns or 'Type' not in df.columns:
                    self.logger.warning(f"Data missing required columns. Available columns: {df.columns.tolist()}")
                    # Try to fix column names if possible
                    if '_id' in df.columns:  # This indicates we have some data
                        # Look for alternate column names
                        for col in df.columns:
                            if col.lower() == 'category':
                                df['Category'] = df[col]
                            elif col.lower() == 'type':
                                df['Type'] = df[col]
                
                # Update category table
                self.populate_category_table(df)
                
                # Find any open ModernDataDialog instances and update them
                for dialog in QApplication.topLevelWidgets():
                    if hasattr(dialog, 'set_data') and callable(dialog.set_data):
                        try:
                            dialog.set_data(df.to_dict(orient='records'))
                        except Exception as dialog_err:
                            self.logger.error(f"Error updating dialog: {str(dialog_err)}")
                
                # Log the refresh
                timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
                self.update_log(timestamp, f"Data refreshed successfully: {len(df)} items")
                return df
            else:
                # Log the error and show message
                self.logger.error(f"Error fetching data: {data}")
                error_msg = str(data) if data else "Unknown error"
                self.statusBar.showMessage(f"Error fetching data: {error_msg}", 3000)
                
                # Show error dialog for better visibility
                QMessageBox.warning(
                    self,
                    "Data Fetch Error",
                    f"Failed to fetch data from server: {error_msg}"
                )
                return None
        except Exception as e:
            self.logger.error(f"Error refreshing data: {str(e)}")
            self.statusBar.showMessage(f"Error refreshing data: {str(e)}", 3000)
            
            # Show error dialog
            QMessageBox.warning(
                self,
                "Data Refresh Error",
                f"An error occurred while refreshing data: {str(e)}"
            )
            return None

    def populate_category_table(self, data):
        """
        Populate the category table with unique categories with improved handling.
        
        Args:
            data (DataFrame): Data to populate the table with
        """
        if data is None or data.empty:
            # Clear the table and show a message
            self.category_table.setRowCount(0)
            self.data_placeholder.setText("No data available. Please connect to the server.")
            self.data_placeholder.setVisible(True)
            return
            
        if 'Category' not in data.columns:
            self.logger.warning("Category column missing in data")
            # Clear the table and show a message
            self.category_table.setRowCount(0)
            self.data_placeholder.setText("Data format error: Category column missing")
            self.data_placeholder.setVisible(True)
            return
        
        # Get unique categories and count items in each
        category_counts = data['Category'].value_counts().to_dict()
        categories = list(category_counts.keys())
        
        # Clear table and set row count
        self.category_table.setRowCount(0)
        self.category_table.setRowCount(len(categories))
        
        # Add items to table
        for row, category in enumerate(sorted(categories)):
            # Category name
            category_item = QTableWidgetItem(category)
            # Add count in parentheses
            if category in category_counts:
                count = category_counts[category]
                category_item.setText(f"{category} ({count})")
                
            # Store raw category in item data for filtering
            category_item.setData(Qt.UserRole, category)
            
            self.category_table.setItem(row, 0, category_item)
        
        # Update data placeholder visibility
        self.data_placeholder.setVisible(False)
        
        # Log success
        self.logger.info(f"Populated category table with {len(categories)} categories")

    def show_data_window(self):
        """
        Show data in a modern dialog window with robust error handling and feedback.
        """
        # Check authentication first
        if not hasattr(self, 'auth_service') or not self.auth_service.is_authenticated():
            QMessageBox.warning(self, "Authentication Required", 
                            "You must be connected to the server to view data.")
            return
        
        try:
            # Log the operation
            timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
            self.update_log(timestamp, "Opening data display window")
            
            # Show a progress dialog while loading
            progress = QProgressDialog("Loading data, please wait...", None, 0, 100, self)
            progress.setWindowTitle("Data Display")
            progress.setWindowModality(Qt.WindowModal)
            progress.setValue(10)
            progress.show()
            QApplication.processEvents()
            
            # Create the data dialog
            data_dialog = ModernDataDialog(self, "Your GUARD Data", self.fetch_latest_data)
            
            # Set the CRUD helper and services
            data_dialog.set_crud_helper(
                CRUDHelper,
                auth_service=self.auth_service,
                agent=getattr(self, 'agent', None)  # Add agent if available
            )
            
            progress.setValue(40)
            QApplication.processEvents()
            
            # Get data with proper error handling
            try:
                # Make sure API client is available
                if not hasattr(self, 'api_client') or self.api_client is None:
                    progress.close()
                    QMessageBox.warning(
                        self, 
                        "Not Connected", 
                        "API client not available. Please connect to the server first."
                    )
                    return
                    
                success, data = self.api_client.sync_get_pii_data()
                progress.setValue(70)
                QApplication.processEvents()
                
                if success:
                    # Make sure we actually got data
                    if not data:
                        progress.close()
                        QMessageBox.information(
                            self,
                            "No Data",
                            "No data items found on the server."
                        )
                        return
                        
                    # Debug log the data structure
                    self.logger.info(f"Data type: {type(data)}, Content preview: {str(data)[:100]}...")
                    
                    # Ensure we have a list of items
                    if isinstance(data, pd.DataFrame):
                        data_list = data.to_dict(orient='records')
                    elif not isinstance(data, list):
                        try:
                            data_list = list(data) if hasattr(data, '__iter__') else [data]
                        except:
                            data_list = [data] if data else []
                    else:
                        data_list = data
                    
                    # Make sure we have data after conversion
                    if not data_list:
                        progress.close()
                        QMessageBox.information(
                            self,
                            "No Data",
                            "No data items found on the server."
                        )
                        return
                    
                    # Set the data in the dialog
                    data_dialog.set_data(data_list)
                    
                    # Close progress and show dialog
                    progress.setValue(100)
                    progress.close()
                    
                    # Show the dialog
                    data_dialog.exec_()
                    
                    # Log successful display
                    self.update_log(timestamp, f"Successfully displayed {len(data_list)} data items")
                else:
                    progress.close()
                    error_msg = str(data) if data else "Unknown error"
                    QMessageBox.warning(
                        self, 
                        "Data Retrieval Error", 
                        f"Failed to retrieve data from server: {error_msg}"
                    )
            except Exception as e:
                progress.close()
                self.logger.error(f"Error fetching data for display: {str(e)}")
                QMessageBox.critical(
                    self,
                    "Data Error",
                    f"Could not load data from server: {str(e)}"
                )
                
        except Exception as e:
            self.logger.error(f"Error displaying data: {str(e)}")
            QMessageBox.critical(
                self,
                "Application Error",
                f"An unexpected error occurred: {str(e)}"
            )
            
    def refresh_categories(self):
        """Refresh the category list from the server with improved feedback."""
        try:
            # Show progress dialog for better feedback
            progress = QProgressDialog("Refreshing data from server...", None, 0, 100, self)
            progress.setWindowTitle("Refreshing Data")
            progress.setWindowModality(Qt.WindowModal)
            progress.setValue(10)
            progress.show()
            QApplication.processEvents()
            
            # Check API client availability
            if not hasattr(self, 'api_client') or self.api_client is None:
                progress.close()
                QMessageBox.warning(
                    self,
                    "Connection Error",
                    "API client is not available. Please connect to the server first."
                )
                return
                
            progress.setValue(30)
            QApplication.processEvents()
            
            # Fetch the latest data
            df = self.fetch_latest_data()
            progress.setValue(80)
            QApplication.processEvents()
            
            # Update category table directly from the dataframe if available
            if df is not None and not df.empty:
                self.populate_category_table(df)
                progress.setValue(100)
                progress.close()
                
                # Show success message
                self.statusBar.showMessage("Data refreshed successfully", 3000)
            else:
                progress.close()
                self.statusBar.showMessage("Failed to refresh data", 3000)
                
        except Exception as e:
            if 'progress' in locals():
                progress.close()
                
            self.logger.error(f"Error refreshing categories: {str(e)}")
            self.statusBar.showMessage(f"Error refreshing data: {str(e)}", 3000)
            
            QMessageBox.warning(
                self,
                "Refresh Error",
                f"Error refreshing data: {str(e)}"
            )

    def add_new_entry(self):
        """
        Open dialog to add a new data entry with proper validation and feedback.
        """
        # Check authentication first
        if not hasattr(self, 'auth_service') or not self.auth_service.is_authenticated():
            QMessageBox.warning(self, "Authentication Required", 
                               "You must be connected to the server to add entries.")
            return
        
        try:
            # Log the operation
            timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
            self.update_log(timestamp, "Initializing add new entry dialog")
            
            # Create empty item data template with appropriate structure
            new_item_template = {
                "Category": "",
                "Type": "",
                "PII": str([{"Item Name": "Name", "Data": ""}, {"Item Name": "Value", "Data": ""}])
            }
            
            # Create and configure the edit dialog directly
            from UI.Desktop.modern_components import DataItemEditDialog
            edit_dialog = DataItemEditDialog(new_item_template, self)
            edit_dialog.setWindowTitle("Add New Data Entry")
            
            # Show the dialog and wait for user input
            if edit_dialog.exec_() == QDialog.Accepted:
                # Get the entered data
                item_data = edit_dialog.get_updated_data()
                
                if not item_data:
                    self.logger.warning("No data entered in add entry dialog")
                    return
                    
                # Remove ID field if present (will be generated by server)
                if "_id" in item_data:
                    del item_data["_id"]
                    
                # Show progress while adding
                progress = QProgressDialog("Adding new entry...", None, 0, 100, self)
                progress.setWindowTitle("Adding Data")
                progress.setWindowModality(Qt.WindowModal)
                progress.setValue(20)
                progress.show()
                QApplication.processEvents()
                
                # Use API client to add the item
                try:
                    progress.setValue(50)
                    QApplication.processEvents()
                    
                    # Use CRUD helper for the operation
                    success, result = CRUDHelper.perform_operation(
                        'create',
                        item_data,
                        agent=getattr(self, 'agent', None),
                        auth_service=self.auth_service,
                        logger=self.logger.info
                    )
                    
                    progress.setValue(90)
                    QApplication.processEvents()
                    
                    if success:
                        progress.close()
                        QMessageBox.information(
                            self,
                            "Success",
                            "New data entry added successfully."
                        )
                        
                        # Log the successful operation
                        self.update_log(timestamp, f"Added new {item_data.get('Category', 'Unknown')} entry")
                        
                        # Refresh data display 
                        self.refresh_categories()
                    else:
                        progress.close()
                        QMessageBox.warning(
                            self,
                            "Add Entry Error",
                            f"Failed to add entry: {result}"
                        )
                except Exception as e:
                    progress.close()
                    self.logger.error(f"Error adding new entry: {str(e)}")
                    QMessageBox.critical(
                        self,
                        "Server Communication Error",
                        f"Could not add entry to server: {str(e)}"
                    )
            else:
                # User cancelled the dialog
                self.logger.info("Add entry operation cancelled by user")
                
        except Exception as e:
            self.logger.error(f"Error in add entry dialog: {str(e)}")
            QMessageBox.critical(
                self,
                "Application Error",
                f"An unexpected error occurred: {str(e)}"
            )

    
    def on_category_selected(self):
        """Handle selection in the category table."""
        selected_items = self.category_table.selectedItems()
        if not selected_items:
            self.data_placeholder.setVisible(True)
            return
        
        # Get the raw category name from the user data (without count)
        selected_category = selected_items[0].data(Qt.UserRole)
        if not selected_category:
            selected_category = selected_items[0].text().split(' (')[0]  # Extract category name
        
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        self.update_log(timestamp, f"Selected category: {selected_category}")
        
        # Hide placeholder
        self.data_placeholder.setVisible(False)
        
        try:
            # Show loading message
            self.statusBar.showMessage(f"Loading items for {selected_category}...", 2000)
            
            # Get data for this category
            success, all_data = self.api_client.sync_get_pii_data()
            
            if not success:
                error_msg = f"Failed to fetch data for category: {selected_category}"
                if isinstance(all_data, dict) and "error" in all_data:
                    error_msg = f"Failed to fetch data: {all_data['error']}"
                elif isinstance(all_data, str):
                    error_msg = f"Failed to fetch data: {all_data}"
                    
                QMessageBox.warning(self, "Data Error", error_msg)
                return
            
            # Convert to list if needed
            if isinstance(all_data, pd.DataFrame):
                data_list = all_data.to_dict(orient='records')
            elif not isinstance(all_data, list):
                try:
                    data_list = list(all_data) if hasattr(all_data, '__iter__') else [all_data]
                except:
                    data_list = [all_data] if all_data else []
            else:
                data_list = all_data
            
            # Filter by selected category
            filtered_items = [item for item in data_list if item.get('Category') == selected_category]
            
            if not filtered_items:
                # Show message if no items
                self.data_placeholder.setText(f"No items found in category: {selected_category}")
                self.data_placeholder.setVisible(True)
                return
            
            # Show data using the modern data dialog
            data_dialog = ModernDataDialog(self, f"Items in {selected_category}", self.fetch_latest_data)
            data_dialog.set_crud_helper(
                CRUDHelper,
                auth_service=self.auth_service,
                agent=getattr(self, 'agent', None)
            )
            data_dialog.set_data(filtered_items)
            data_dialog.exec_()
            
        except Exception as e:
            self.logger.error(f"Error processing selection: {str(e)}")
            QMessageBox.warning(
                self,
                "Selection Error",
                f"Error processing selection: {str(e)}"
            )

    def show_category_menu(self, position):
        """
        Show context menu for the category table.
        
        Args:
            position: Position for the menu
        """
        selected_items = self.category_table.selectedItems()
        if not selected_items:
            return
        
        # Get the raw category name
        selected_category = selected_items[0].data(Qt.UserRole)
        if not selected_category:
            selected_category = selected_items[0].text().split(' (')[0]  # Extract category name
            
        # Create menu
        menu = QMenu(self)
        
        # Add actions
        view_action = menu.addAction("View Items")
        view_action.setIcon(self.style().standardIcon(QStyle.SP_FileDialogDetailedView))
        
        menu.addSeparator()
        
        add_action = menu.addAction("Add New Item")
        add_action.setIcon(self.style().standardIcon(QStyle.SP_FileDialogNewFolder))
        
        refresh_action = menu.addAction("Refresh Categories")
        refresh_action.setIcon(self.style().standardIcon(QStyle.SP_BrowserReload))
        
        # Show the menu
        action = menu.exec_(self.category_table.mapToGlobal(position))
        
        # Handle actions
        if action == view_action:
            self.on_category_selected()
        elif action == add_action:
            self.add_new_entry()
        elif action == refresh_action:
            self.refresh_categories()

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
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply != QMessageBox.Yes:
                return
            
            # Log logout
            timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
            self.update_log(timestamp, "Logging out...")
            
            # Show progress dialog
            progress = QProgressDialog("Logging out...", None, 0, 100, self)
            progress.setWindowTitle("Logout")
            progress.setWindowModality(Qt.WindowModal)
            progress.setValue(20)
            progress.show()
            QApplication.processEvents()
            
            # Perform logout operations
            try:
                if hasattr(self, 'auth_service'):
                    progress.setValue(40)
                    progress.setLabelText("Ending API session...")
                    QApplication.processEvents()
                    self.auth_service.logout()
                
                progress.setValue(70)
                progress.setLabelText("Ending SSO session...")
                QApplication.processEvents()
                if hasattr(self, 'session_manager'):
                    self.session_manager.logout()
                    
                progress.setValue(90)
                progress.setLabelText("Cleaning up resources...")
                QApplication.processEvents()
            except Exception as e:
                self.logger.error(f"Error during logout process: {str(e)}")
                # Continue with UI reset even if there's an error
            
            # Reset UI to initial state
            progress.close()
            self.reset_ui()
            
            # Log success
            self.update_log(timestamp, "Logged out successfully")
            
            # Show confirmation
            QMessageBox.information(self, "Logout", "You have been logged out successfully.")
            
        except Exception as e:
            self.logger.error(f"Error during logout: {str(e)}")
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
        self.category_table.setVisible(False)
        self.log_table.setVisible(False)
        self.btn_display_data.setVisible(False)
        self.btn_add_entry.setVisible(False)
        self.btn_refresh_categories.setVisible(False)
        self.data_placeholder.setVisible(False)
        
        # Clear category table
        self.category_table.setRowCount(0)
        
        # Clear auth button container
        while self.auth_button_container.layout().count():
            item = self.auth_button_container.layout().takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        
        # Re-add connect button
        self.btn_connect_server = QPushButton('Connect to Server', self)
        self.btn_connect_server.setStyleSheet(StandardTheme.get_button_style('primary', 'medium'))
        self.btn_connect_server.setToolTip('Click to authenticate and connect to the server')
        self.btn_connect_server.setCursor(Qt.PointingHandCursor)
        self.btn_connect_server.clicked.connect(self.show_auth_options)
        self.auth_button_container.layout().addWidget(self.btn_connect_server)
        
        # Reset session status
        self.update_session_status()
        
        # Reset authentication state
        self.auth_service = AuthenticationService(self)
        if hasattr(self, 'session_manager'):
            self.auth_service.set_session_manager(self.session_manager)
        
        # Clear API client
        self.api_client = None
        
        # Log reset
        self.update_log(
            QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
            "User interface reset to initial state"
        )

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
    # Add these methods to the GuardMainWindow class

    def setup_header_section(self, parent_layout):
        """Set up the header section with logo and welcome message."""
        header_widget = QWidget()
        header_layout = QHBoxLayout(header_widget)
        header_layout.setContentsMargins(5, 5, 5, 15)
        
        # App title with icon (placeholder)
        title_layout = QVBoxLayout()
        
        app_name_label = QLabel("GUARD", self)
        app_name_label.setStyleSheet("""
            font-family: 'Segoe UI', Arial, sans-serif;
            font-size: 24px;
            font-weight: bold;
            color: #1976D2;
        """)
        
        app_subtitle = QLabel("Secure PII Data Management", self)
        app_subtitle.setStyleSheet("""
            font-family: 'Segoe UI', Arial, sans-serif;
            font-size: 14px;
            color: #757575;
        """)
        
        title_layout.addWidget(app_name_label)
        title_layout.addWidget(app_subtitle)
        header_layout.addLayout(title_layout)
        
        # Add stretch to push remaining elements to the right
        header_layout.addStretch()
        
        # Add activity log button
        self.log_button = QPushButton("View Activity Log", self)
        try:
            self.log_button.setStyleSheet(StandardTheme.get_button_style('info', 'medium'))
        except:
            self.log_button.setStyleSheet("""
                QPushButton {
                    background-color: #2196F3;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    padding: 6px 12px;
                }
                QPushButton:hover {
                    background-color: #1976D2;
                }
            """)
        self.log_button.setIcon(self.style().standardIcon(QStyle.SP_FileDialogInfoView))
        self.log_button.setCursor(Qt.PointingHandCursor)
        self.log_button.clicked.connect(self.show_activity_log)
        self.log_button.setVisible(False)  # Initially hidden until authenticated
        header_layout.addWidget(self.log_button)
        
        # Welcome text that appears after login
        self.welcome_text = QLabel("", self)
        self.welcome_text.setStyleSheet("""
            font-family: 'Segoe UI', Arial, sans-serif;
            font-size: 14px;
            color: #424242;
        """)
        self.welcome_text.setVisible(False)
        header_layout.addWidget(self.welcome_text)
        
        # Add authentication button that will be replaced after login
        self.auth_button_container = QWidget()
        auth_button_layout = QHBoxLayout(self.auth_button_container)
        auth_button_layout.setContentsMargins(0, 0, 0, 0)
        
        self.btn_connect_server = QPushButton('Connect to Server', self)
        self.btn_connect_server.setStyleSheet(StandardTheme.get_button_style('primary', 'medium'))
        self.btn_connect_server.setToolTip('Click to authenticate and connect to the server')
        self.btn_connect_server.setCursor(Qt.PointingHandCursor)
        self.btn_connect_server.clicked.connect(self.show_auth_options)
        auth_button_layout.addWidget(self.btn_connect_server)
        
        header_layout.addWidget(self.auth_button_container)
        
        # Add header to main layout
        parent_layout.addWidget(header_widget)
        
        # Add a separator line
        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)
        separator.setStyleSheet("background-color: #E0E0E0;")
        parent_layout.addWidget(separator)

    def setup_log_tab(self):
        """Set up a dedicated tab for activity logs with enhanced features."""
        # Create the log tab
        self.log_tab = QWidget()
        log_layout = QVBoxLayout(self.log_tab)
        log_layout.setContentsMargins(15, 15, 15, 15)
        log_layout.setSpacing(15)
        
        # Create header with title and controls
        header_layout = QHBoxLayout()
        
        # Title
        log_title = QLabel("Activity Log", self.log_tab)
        log_title.setStyleSheet("""
            font-size: 18px;
            font-weight: bold;
            color: #1976D2;
        """)
        header_layout.addWidget(log_title)
        
        # Add filter and search controls
        search_layout = QHBoxLayout()
        search_label = QLabel("Search:", self.log_tab)
        self.log_search = QLineEdit(self.log_tab)
        self.log_search.setPlaceholderText("Search logs...")
        self.log_search.setClearButtonEnabled(True)
        self.log_search.textChanged.connect(self.filter_logs)
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.log_search, 1)  # Give stretch priority
        
        # Date filter
        date_label = QLabel("Date:", self.log_tab)
        self.log_date_filter = QComboBox(self.log_tab)
        self.log_date_filter.addItems(["All Dates", "Today", "Yesterday", "Last 7 Days"])
        self.log_date_filter.currentTextChanged.connect(self.filter_logs)
        search_layout.addWidget(date_label)
        search_layout.addWidget(self.log_date_filter)
        
        header_layout.addLayout(search_layout)
        header_layout.addStretch()
        
        # Add refresh and clear buttons
        buttons_layout = QHBoxLayout()
        
        # Refresh button
        refresh_log_button = QPushButton("Refresh", self.log_tab)
        refresh_log_button.setIcon(self.style().standardIcon(QStyle.SP_BrowserReload))
        refresh_log_button.clicked.connect(self.refresh_logs)
        try:
            refresh_log_button.setStyleSheet(StandardTheme.get_button_style('secondary', 'small'))
        except:
            pass
        buttons_layout.addWidget(refresh_log_button)
        
        # Export button
        export_log_button = QPushButton("Export", self.log_tab)
        export_log_button.setIcon(self.style().standardIcon(QStyle.SP_DialogSaveButton))
        export_log_button.clicked.connect(self.export_logs)
        try:
            export_log_button.setStyleSheet(StandardTheme.get_button_style('primary', 'small'))
        except:
            pass
        buttons_layout.addWidget(export_log_button)
        
        header_layout.addLayout(buttons_layout)
        
        log_layout.addLayout(header_layout)
        
        # Create enhanced log table
        self.enhanced_log_table = QTableWidget(0, 3, self.log_tab)
        self.enhanced_log_table.setHorizontalHeaderLabels(["Timestamp", "Action/Task", "Details"])
        self.enhanced_log_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.enhanced_log_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.enhanced_log_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.enhanced_log_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.enhanced_log_table.setAlternatingRowColors(True)
        self.enhanced_log_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.enhanced_log_table.setSortingEnabled(True)  # Enable sorting
        
        try:
            # Apply standardized styling if available
            self.enhanced_log_table.setStyleSheet(StandardTheme.get_table_style())
        except:
            # Fallback styling
            self.enhanced_log_table.setStyleSheet("""
                QTableWidget {
                    border: 1px solid #E0E0E0;
                    gridline-color: #E0E0E0;
                    background-color: white;
                    alternate-background-color: #F5F5F5;
                }
                QHeaderView::section {
                    background-color: #4361EE;
                    color: white;
                    font-weight: bold;
                    padding: 6px;
                    border: none;
                }
            """)
        
        log_layout.addWidget(self.enhanced_log_table, 1)  # Give stretch priority
        
        # Create status bar for log tab
        status_layout = QHBoxLayout()
        self.log_status_label = QLabel("Ready", self.log_tab)
        self.log_status_label.setStyleSheet("color: #757575;")
        status_layout.addWidget(self.log_status_label)
        status_layout.addStretch()
        
        # Add entry count
        self.log_count_label = QLabel("0 entries", self.log_tab)
        self.log_count_label.setStyleSheet("color: #757575;")
        status_layout.addWidget(self.log_count_label)
        
        log_layout.addLayout(status_layout)
        
        # Add the tab to the tab widget
        self.tab_widget.addTab(self.log_tab, "Activity Log")
        
        # Initially hide the tab - it will be shown when needed
        self.log_tab_index = self.tab_widget.count() - 1
        # No need to hide if we're showing it when the button is clicked
        # self.tab_widget.setTabVisible(self.log_tab_index, False)

    def show_activity_log(self):
        """Show the activity log tab and update its content."""
        # Make sure the tab exists
        if not hasattr(self, 'log_tab'):
            self.setup_log_tab()
            self.log_tab_index = self.tab_widget.indexOf(self.log_tab)
        
        # Switch to the log tab
        self.tab_widget.setCurrentIndex(self.log_tab_index)
        
        # Refresh the logs
        self.refresh_logs()

    def refresh_logs(self):
        """Refresh the log display with the latest entries."""
        # Update status
        self.log_status_label.setText("Refreshing logs...")
        QApplication.processEvents()
        
        try:
            # Read from the application log file if it exists
            file_logs = []
            try:
                with open('logs/application.log', 'r') as f:
                    file_logs = f.readlines()
            except:
                # If file reading fails, use memory logs
                pass
                
            # Get in-memory logs from the log table if it exists
            memory_logs = []
            if hasattr(self, 'log_table'):
                for row in range(self.log_table.rowCount()):
                    timestamp = self.log_table.item(row, 0).text()
                    message = self.log_table.item(row, 1).text()
                    memory_logs.append((timestamp, message, ""))
            
            # Clear the enhanced log table
            self.enhanced_log_table.setRowCount(0)
            
            # Process file logs
            parsed_logs = []
            for log_line in file_logs:
                # Try to parse log line with regex
                import re
                # Look for timestamp and message patterns
                match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})[^\]]*\] - ([^-]+) - ([^-]+) - (.*)', log_line)
                if match:
                    timestamp = match.group(1)
                    level = match.group(2)
                    module = match.group(3)
                    message = match.group(4)
                    
                    # Only add INFO, WARNING, and ERROR logs
                    if level in ["INFO", "WARNING", "ERROR"]:
                        details = f"Module: {module}, Level: {level}"
                        parsed_logs.append((timestamp, message, details))
            
            # Add both memory and parsed logs
            all_logs = parsed_logs + memory_logs
            
            # Sort logs by timestamp (newest first)
            all_logs.sort(reverse=True)
            
            # Add logs to table
            for timestamp, message, details in all_logs:
                row = self.enhanced_log_table.rowCount()
                self.enhanced_log_table.insertRow(row)
                
                # Add timestamp
                timestamp_item = QTableWidgetItem(timestamp)
                self.enhanced_log_table.setItem(row, 0, timestamp_item)
                
                # Add message
                message_item = QTableWidgetItem(message)
                self.enhanced_log_table.setItem(row, 1, message_item)
                
                # Add details
                details_item = QTableWidgetItem(details)
                self.enhanced_log_table.setItem(row, 2, details_item)
                
                # Apply color based on message content (optional)
                if "error" in message.lower() or "failed" in message.lower():
                    for col in range(3):
                        item = self.enhanced_log_table.item(row, col)
                        if item:
                            item.setBackground(QColor("#FFEBEE"))  # Light red
                elif "warning" in message.lower():
                    for col in range(3):
                        item = self.enhanced_log_table.item(row, col)
                        if item:
                            item.setBackground(QColor("#FFF8E1"))  # Light amber
                elif "success" in message.lower() or "authenticated" in message.lower():
                    for col in range(3):
                        item = self.enhanced_log_table.item(row, col)
                        if item:
                            item.setBackground(QColor("#E8F5E9"))  # Light green
            
            # Update status
            self.log_count_label.setText(f"{self.enhanced_log_table.rowCount()} entries")
            self.log_status_label.setText("Logs refreshed successfully")
            
            # Apply any active filters
            self.filter_logs()
            
        except Exception as e:
            self.log_status_label.setText(f"Error refreshing logs: {str(e)}")
            # Log the error
            self.logger.error(f"Error refreshing activity log display: {str(e)}")

    def filter_logs(self):
        """Filter logs based on search text and date filter."""
        search_text = self.log_search.text().lower()
        date_filter = self.log_date_filter.currentText()
        
        # Get current date for filtering
        current_datetime = QDateTime.currentDateTime()
        today = current_datetime.toString("yyyy-MM-dd")
        yesterday = current_datetime.addDays(-1).toString("yyyy-MM-dd")
        week_ago = current_datetime.addDays(-7).toString("yyyy-MM-dd")
        
        # Update status
        self.log_status_label.setText("Filtering logs...")
        QApplication.processEvents()
        
        # Count visible rows
        visible_count = 0
        
        # Check each row
        for row in range(self.enhanced_log_table.rowCount()):
            show_row = True
            
            # Get timestamp and message
            timestamp_item = self.enhanced_log_table.item(row, 0)
            message_item = self.enhanced_log_table.item(row, 1)
            details_item = self.enhanced_log_table.item(row, 2)
            
            if timestamp_item and message_item:
                timestamp = timestamp_item.text()
                message = message_item.text()
                details = details_item.text() if details_item else ""
                
                # Apply search filter
                if search_text and search_text not in message.lower() and search_text not in timestamp.lower() and search_text not in details.lower():
                    show_row = False
                
                # Apply date filter
                if date_filter != "All Dates":
                    # Extract date part for comparison
                    log_date = timestamp.split()[0] if " " in timestamp else timestamp
                    
                    if date_filter == "Today" and today != log_date:
                        show_row = False
                    elif date_filter == "Yesterday" and yesterday != log_date:
                        show_row = False
                    elif date_filter == "Last 7 Days":
                        # Check if date is older than a week
                        if log_date < week_ago:
                            show_row = False
            
            # Show or hide row
            self.enhanced_log_table.setRowHidden(row, not show_row)
            
            # Count visible rows
            if show_row:
                visible_count += 1
        
        # Update status
        if search_text or date_filter != "All Dates":
            self.log_count_label.setText(f"{visible_count} of {self.enhanced_log_table.rowCount()} entries")
            filter_info = []
            if search_text:
                filter_info.append(f"Search: \"{search_text}\"")
            if date_filter != "All Dates":
                filter_info.append(f"Date: {date_filter}")
            self.log_status_label.setText(f"Filtered by: {', '.join(filter_info)}")
        else:
            self.log_count_label.setText(f"{self.enhanced_log_table.rowCount()} entries")
            self.log_status_label.setText("Ready")

    def export_logs(self):
        """Export logs to a CSV or text file."""
        from PyQt5.QtWidgets import QFileDialog
        
        # Ask for file location
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Activity Log",
            "guard_activity_log.csv",
            "CSV Files (*.csv);;Text Files (*.txt);;All Files (*)"
        )
        
        if not file_path:
            return  # User cancelled
        
        try:
            # Determine format based on extension
            is_csv = file_path.lower().endswith('.csv')
            
            with open(file_path, 'w') as f:
                # Write header
                if is_csv:
                    f.write("Timestamp,Action,Details\n")
                else:
                    f.write("Timestamp | Action | Details\n")
                    f.write("-" * 80 + "\n")
                
                # Write visible rows only
                for row in range(self.enhanced_log_table.rowCount()):
                    if not self.enhanced_log_table.isRowHidden(row):
                        timestamp = self.enhanced_log_table.item(row, 0).text()
                        message = self.enhanced_log_table.item(row, 1).text()
                        details = self.enhanced_log_table.item(row, 2).text()
                        
                        # Escape commas and quotes for CSV
                        if is_csv:
                            timestamp = f'"{timestamp}"'
                            # Escape quotes in message and details
                            message = f'"{message.replace('"', '""')}"'
                            details = f'"{details.replace('"', '""')}"'
                            f.write(f"{timestamp},{message},{details}\n")
                        else:
                            f.write(f"{timestamp} | {message} | {details}\n")
            
            # Show success message
            self.log_status_label.setText(f"Log exported successfully to {file_path}")
            QMessageBox.information(
                self,
                "Export Successful",
                f"Activity log exported successfully to:\n{file_path}"
            )
            
        except Exception as e:
            QMessageBox.critical(
                self,
                "Export Error",
                f"Error exporting log: {str(e)}"
            )
            self.log_status_label.setText(f"Export failed: {str(e)}")
    def setup_data_management_tab(self):
        """Set up the PII data management tab without the log table."""
        # Create tab widget and layout
        self.data_tab = QWidget()
        data_layout = QVBoxLayout(self.data_tab)
        data_layout.setContentsMargins(10, 15, 10, 10)
        data_layout.setSpacing(15)
        
        # Split view - Categories on left, Details on right
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        
        # Left panel - Categories
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        
        
        # Categories table
        self.category_table = QTableWidget(0, 1, left_panel)
        self.category_table.setHorizontalHeaderLabels(["Category"])
        self.category_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.category_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.category_table.setSelectionMode(QTableWidget.SingleSelection)
        self.category_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.category_table.setAlternatingRowColors(True)
        self.category_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.category_table.customContextMenuRequested.connect(self.show_category_menu)
        self.category_table.itemSelectionChanged.connect(self.on_category_selected)
        self.category_table.setVisible(False)
        self.category_table.setStyleSheet(StandardTheme.get_table_style())
        left_layout.addWidget(self.category_table, 1)  # Give stretch priority
        
        # Left panel buttons
        left_buttons = QHBoxLayout()
        
        self.btn_refresh_categories = QPushButton("Refresh", left_panel)
        self.btn_refresh_categories.setIcon(self.style().standardIcon(QStyle.SP_BrowserReload))
        self.btn_refresh_categories.setStyleSheet(StandardTheme.get_button_style('secondary', 'small'))
        self.btn_refresh_categories.setCursor(Qt.PointingHandCursor)
        self.btn_refresh_categories.clicked.connect(self.refresh_categories)
        self.btn_refresh_categories.setVisible(False)
        left_buttons.addWidget(self.btn_refresh_categories)
        
        left_buttons.addStretch()
        left_layout.addLayout(left_buttons)
        
        # Right panel - Data view
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        
        # Placeholder when no category is selected
        self.data_placeholder = QLabel("Select a category to view data items", right_panel)
        self.data_placeholder.setAlignment(Qt.AlignCenter)
        self.data_placeholder.setStyleSheet("""
            font-family: 'Segoe UI', Arial, sans-serif;
            font-size: 14px;
            color: #9E9E9E;
            padding: 40px;
            background-color: #F5F5F5;
            border: 1px dashed #BDBDBD;
            border-radius: 8px;
        """)
        self.data_placeholder.setVisible(False)
        right_layout.addWidget(self.data_placeholder)
        
        # Right panel action buttons
        right_buttons = QHBoxLayout()
        
        self.btn_display_data = QPushButton("Display All Data", right_panel)
        self.btn_display_data.setIcon(self.style().standardIcon(QStyle.SP_FileDialogDetailedView))
        self.btn_display_data.setStyleSheet(StandardTheme.get_button_style('primary', 'medium'))
        self.btn_display_data.setCursor(Qt.PointingHandCursor)
        self.btn_display_data.clicked.connect(self.show_data_window)
        self.btn_display_data.setVisible(False)
        right_buttons.addWidget(self.btn_display_data)
        
        self.btn_add_entry = QPushButton("Add New Entry", right_panel)
        self.btn_add_entry.setIcon(self.style().standardIcon(QStyle.SP_FileDialogNewFolder))
        self.btn_add_entry.setStyleSheet(StandardTheme.get_button_style('success', 'medium'))
        self.btn_add_entry.setCursor(Qt.PointingHandCursor)
        self.btn_add_entry.clicked.connect(self.add_new_entry)
        self.btn_add_entry.setVisible(False)
        right_buttons.addWidget(self.btn_add_entry)
        
        right_buttons.addStretch()
        right_layout.addLayout(right_buttons)
        
        # Add panels to splitter
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setStretchFactor(0, 1)  # Left panel gets 1/3
        splitter.setStretchFactor(1, 2)  # Right panel gets 2/3
        data_layout.addWidget(splitter, 1)  # Give stretch priority
        
        # Create a hidden log table to store logs (won't be displayed)
        # This is maintained for compatibility with existing code
        self.log_table = QTableWidget(0, 2)
        self.log_table.setHorizontalHeaderLabels(["Timestamp", "Action/Task Performed"])
        self.log_table.setVisible(False)  # Never shown in the UI
        
        # Add tab to tab widget
        self.tab_widget.addTab(self.data_tab, "Data Management")

    def show_authenticated_ui(self):
        """Update UI to show authenticated state."""
        # Hide connect button
        self.btn_connect_server.setVisible(False)
        
        # Update auth button container with logout button
        logout_button = QPushButton("Logout", self)
        logout_button.setIcon(self.style().standardIcon(QStyle.SP_DialogCloseButton))
        try:
            logout_button.setStyleSheet(StandardTheme.get_button_style('outline'))
        except:
            pass
        logout_button.setCursor(Qt.PointingHandCursor)
        logout_button.clicked.connect(self.logout_user)
        self.auth_button_container.layout().addWidget(logout_button)
        
        # Show welcome message
        user_id = self.session_manager.user_id or "User"
        self.welcome_text.setText(f"Welcome, {user_id}")
        self.welcome_text.setVisible(True)
        
        # Show data components
        self.category_table.setVisible(True)
        self.btn_display_data.setVisible(True)
        self.btn_add_entry.setVisible(True)
        self.btn_refresh_categories.setVisible(True)
        self.data_placeholder.setVisible(True)
        
        # Show the activity log button
        self.log_button.setVisible(True)
        
        # Initialize the log tab if it doesn't exist
        if not hasattr(self, 'log_tab'):
            self.setup_log_tab()
    def update_log(self, timestamp, message):
        """
        Update the log table with a new entry and enhanced details.
        
        Args:
            timestamp (str): Timestamp for the log entry
            message (str): Log message
        """
        # Log to file
        self.logger.info(f"{timestamp} - {message}")
        
        # Extract details if available (for enhanced logging)
        details = ""
        
        # Parse out details if the message has a specific format
        if ":" in message:
            parts = message.split(":", 1)
            if len(parts) == 2:
                action_type = parts[0].strip()
                details = parts[1].strip()
                
                # Don't modify the message as we need it for the original log table
        
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
            
            # Limit to most recent 100 entries to avoid performance issues
            max_rows = 100
            if self.log_table.rowCount() > max_rows:
                self.log_table.removeRow(0)  # Remove oldest entry
        
        # Update the enhanced log table if it exists
        if hasattr(self, 'enhanced_log_table'):
            row_position = self.enhanced_log_table.rowCount()
            self.enhanced_log_table.insertRow(row_position)
            
            timestamp_item = QTableWidgetItem(timestamp)
            message_item = QTableWidgetItem(message)
            details_item = QTableWidgetItem(details)
            
            self.enhanced_log_table.setItem(row_position, 0, timestamp_item)
            self.enhanced_log_table.setItem(row_position, 1, message_item)
            self.enhanced_log_table.setItem(row_position, 2, details_item)
            
            # Apply color based on message content (optional)
            if "error" in message.lower() or "failed" in message.lower():
                for col in range(3):
                    item = self.enhanced_log_table.item(row_position, col)
                    if item:
                        item.setBackground(QColor("#FFEBEE"))  # Light red
            elif "warning" in message.lower():
                for col in range(3):
                    item = self.enhanced_log_table.item(row_position, col)
                    if item:
                        item.setBackground(QColor("#FFF8E1"))  # Light amber
            elif "success" in message.lower() or "authenticated" in message.lower():
                for col in range(3):
                    item = self.enhanced_log_table.item(row_position, col)
                    if item:
                        item.setBackground(QColor("#E8F5E9"))  # Light green
            
            # Update log counts
            if hasattr(self, 'log_count_label'):
                self.log_count_label.setText(f"{self.enhanced_log_table.rowCount()} entries")
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
        # Log the warning
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        self.update_log(
            timestamp,
            f"Session expiring in {minutes_remaining} minute{'s' if minutes_remaining != 1 else ''}"
        )
        
        # Show warning notification
        QMessageBox.warning(
            self,
            "Session Expiring Soon",
            f"Your session will expire in {minutes_remaining} minute{'s' if minutes_remaining != 1 else ''}.\n\n"
            f"Please save your work. You will be logged out when the session expires.\n\n"
            f"Click the refresh button in the session status panel to extend your session."
        )

    def handle_auth_success(self, auth_type):
        """
        Handle successful authentication event.
        
        Args:
            auth_type (str): Type of authentication
        """
        # Log the success
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        self.update_log(
            timestamp,
            f"Authentication successful using {auth_type}"
        )
        
        # Update status display
        self.update_session_status()

    def handle_auth_failure(self, error_message):
        """
        Handle authentication failure event.
        
        Args:
            error_message (str): Error message
        """
        # Log the failure
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        self.update_log(
            timestamp,
            f"Authentication failed: {error_message}"
        )
        
        # Show error message
        QMessageBox.warning(
            self,
            "Authentication Failed",
            f"Authentication failed: {error_message}"
        )

    def handle_close_event(self, event):
        """
        Handle application close event.
        
        Args:
            event: Close event
        """
        try:
            # Log application exit
            self.logger.info("Application closing, performing cleanup")
            
            # Check if there are unsaved changes
            if hasattr(self, 'modified') and self.modified:
                reply = QMessageBox.question(
                    self,
                    "Confirm Exit",
                    "You have unsaved changes. Are you sure you want to exit?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No
                )
                
                if reply != QMessageBox.Yes:
                    event.ignore()
                    return
            
            # Perform logout if authenticated
            if hasattr(self, 'auth_service') and self.auth_service.is_authenticated():
                try:
                    self.auth_service.logout()
                except:
                    pass
                    
            if hasattr(self, 'session_manager') and self.session_manager.is_authenticated:
                try:
                    self.session_manager.logout()
                except:
                    pass
            
            # Stop timers
            if hasattr(self, 'status_timer') and self.status_timer:
                self.status_timer.stop()
                
            # Accept the event to close the application
            event.accept()
            
        except Exception as e:
            # Log any errors during cleanup
            self.logger.error(f"Error during application close: {str(e)}")
            
            # Still accept the event to ensure the application closes
            event.accept()


if __name__ == '__main__':
    # Enable high DPI scaling
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Use Fusion style for consistent cross-platform appearance
    
    # Apply global stylesheet
    app.setStyleSheet(StandardTheme.get_complete_application_style())
    
    # Create and show main window
    window = GuardMainWindow()
    window.show()
    
    sys.exit(app.exec_())