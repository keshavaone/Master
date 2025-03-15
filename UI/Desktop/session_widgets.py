# UI/Desktop/session_widgets.py

"""
Enhanced session status display widgets for the GUARD application.
Provides visual feedback about the current authentication session.
"""

import time
from datetime import datetime, timedelta
from PyQt5.QtWidgets import (
    QWidget, QLabel, QProgressBar, QPushButton, 
    QHBoxLayout, QVBoxLayout, QFrame, QSizePolicy
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QColor, QPalette

# Import color definitions if available, otherwise use fallbacks
try:
    from UI.Desktop.styling import GuardColors
except ImportError:
    # Fallback colors if styling module not available
    class GuardColors:
        SUCCESS = "#4CAF50"
        WARNING = "#FFC107"
        DANGER = "#F44336"
        INFO = "#2196F3"
        AWS_SSO = "#FF9900"
        PASSWORD = "#1976D2"
        
        @staticmethod
        def get_expiration_color(seconds_remaining):
            if seconds_remaining < 300:  # Less than 5 minutes
                return GuardColors.DANGER
            elif seconds_remaining < 900:  # Less than 15 minutes
                return GuardColors.WARNING
            else:
                return GuardColors.SUCCESS


class SessionStatusWidget(QWidget):
    """
    Enhanced widget for displaying session status information.
    Shows authentication type, user ID, and remaining session time.
    """
    
    # Signal emitted when refresh is requested
    refresh_requested = pyqtSignal()
    logout_requested = pyqtSignal()
    
    def __init__(self, session_manager, parent=None):
        """Initialize the session status widget."""
        super().__init__(parent)
        self.session_manager = session_manager
        
        # Create layout
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(10, 5, 10, 5)
        
        # Create main horizontal layout for status information
        self.status_layout = QHBoxLayout()
        
        # Status indicator
        self.indicator_layout = QVBoxLayout()
        self.indicator_layout.setAlignment(Qt.AlignCenter)
        
        self.status_indicator = QLabel()
        self.status_indicator.setFixedSize(16, 16)
        self.status_indicator.setStyleSheet(f"""
            border-radius: 8px; 
            background-color: {status_color};
        """)
        
        # Update user info
        self.user_label.setText(session_info.get("user_id", "Unknown"))
        
        # Update auth type display
        auth_type = session_info.get("auth_type")
        if auth_type == "aws_sso":
            auth_label_text = "AWS SSO Authentication"
            auth_label_color = GuardColors.AWS_SSO
        else:
            auth_label_text = "Password Authentication"
            auth_label_color = GuardColors.PASSWORD
            
        self.auth_type_label.setText(auth_label_text)
        self.auth_type_label.setStyleSheet(f"font-size: 12px; color: {auth_label_color};")
        
        # Update time display
        hours, remainder = divmod(remaining_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        time_str = f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"
        self.time_label.setText(time_str)
        self.time_label.setStyleSheet(f"font-weight: bold; font-size: 14px; color: {status_color};")
        
        # Calculate and format expiration time
        if session_info.get("expiration_time"):
            try:
                expiry_time = datetime.fromisoformat(session_info["expiration_time"])
                formatted_time = expiry_time.strftime("%H:%M:%S")
                self.expires_label.setText(f"Expires at {formatted_time}")
            except (ValueError, TypeError):
                self.expires_label.setText("Session Active")
        else:
            self.expires_label.setText("Session Active")
        
        # Update progress bar
        self.progress_bar.setValue(progress)
        self.progress_bar.setStyleSheet(f"""
            QProgressBar {{
                border: none;
                border-radius: 4px;
                background-color: #E0E0E0;
            }}
            QProgressBar::chunk {{
                border-radius: 4px;
                background-color: {status_color};
            }}
        """)
        
        # Enable buttons
        self.refresh_button.setEnabled(True)
        self.logout_button.setEnabled(True)
    
    def refresh_clicked(self):
        """Handle refresh button click."""
        if self.session_manager and self.session_manager.is_authenticated:
            self.refresh_requested.emit()
    
    def logout_clicked(self):
        """Handle logout button click."""
        if self.session_manager and self.session_manager.is_authenticated:
            self.logout_requested.emit()
            
    def get_remaining_time_formatted(self):
        """Get remaining session time as formatted string."""
        if not self.session_manager or not self.session_manager.is_authenticated:
            return "--:--:--"
            
        session_info = self.session_manager.get_session_info()
        remaining_seconds = session_info.get("remaining_seconds", 0)
        
        hours, remainder = divmod(remaining_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"


class CompactSessionIndicator(QWidget):
    """
    Compact session status indicator for displaying in the status bar.
    Shows a colored dot with the remaining session time.
    """
    
    def __init__(self, session_manager, parent=None):
        """Initialize the compact session indicator."""
        super().__init__(parent)
        self.session_manager = session_manager
        
        # Create layout
        layout = QHBoxLayout(self)
        layout.setContentsMargins(2, 2, 2, 2)
        layout.setSpacing(5)
        
        # Create status indicator
        self.status_indicator = QLabel()
        self.status_indicator.setFixedSize(8, 8)
        self.status_indicator.setStyleSheet("""
            border-radius: 4px; 
            background-color: #CCCCCC;
        """)
        
        # Create time label
        self.time_label = QLabel("--:--:--")
        self.time_label.setStyleSheet("font-size: 12px;")
        
        # Add to layout
        layout.addWidget(self.status_indicator)
        layout.addWidget(self.time_label)
        
        # Set up timer to update display
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update_status)
        self.update_timer.start(1000)  # Update every second
        
        # Initial update
        self.update_status()
    
    def update_status(self):
        """Update the status display based on current session state."""
        if not self.session_manager or not self.session_manager.is_authenticated:
            # Not authenticated
            self.status_indicator.setStyleSheet("""
                border-radius: 4px; 
                background-color: #CCCCCC;
            """)
            self.time_label.setText("Not logged in")
            return
        
        # Get session info
        session_info = self.session_manager.get_session_info()
        remaining_seconds = session_info.get("remaining_seconds", 0)
        
        # Get color based on remaining time
        status_color = GuardColors.get_expiration_color(remaining_seconds)
        
        # Update status indicator color
        self.status_indicator.setStyleSheet(f"""
            border-radius: 4px; 
            background-color: {status_color};
        """)
        
        # Update time display
        hours, remainder = divmod(remaining_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        if hours > 0:
            time_str = f"{int(hours)}h {int(minutes)}m"
        else:
            time_str = f"{int(minutes)}:{int(seconds):02d}"
            
        auth_type = "SSO" if session_info.get("auth_type") == "aws_sso" else "PWD"
        self.time_label.setText(f"{auth_type} • {time_str}")
        self.time_label.setStyleSheet(f"font-size: 12px; color: {status_color};")
        
        self.indicator_layout.addWidget(self.status_indicator, alignment=Qt.AlignCenter)
        self.status_layout.addLayout(self.indicator_layout)
        
        # Create session details layout
        self.details_layout = QVBoxLayout()
        
        # User info
        self.user_label = QLabel("Not logged in")
        self.user_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        
        # Auth type
        self.auth_type_label = QLabel("")
        self.auth_type_label.setStyleSheet("font-size: 12px;")
        
        self.details_layout.addWidget(self.user_label)
        self.details_layout.addWidget(self.auth_type_label)
        
        self.status_layout.addLayout(self.details_layout, stretch=1)
        
        # Time display
        self.time_layout = QVBoxLayout()
        self.time_layout.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        
        self.time_label = QLabel("--:--:--")
        self.time_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        
        self.expires_label = QLabel("Session Inactive")
        self.expires_label.setStyleSheet("font-size: 12px;")
        
        self.time_layout.addWidget(self.time_label, alignment=Qt.AlignRight)
        self.time_layout.addWidget(self.expires_label, alignment=Qt.AlignRight)
        
        self.status_layout.addLayout(self.time_layout)
        
        # Session progress bar
        self.progress_layout = QVBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(8)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: none;
                border-radius: 4px;
                background-color: #E0E0E0;
            }
            QProgressBar::chunk {
                border-radius: 4px;
                background-color: #4CAF50;
            }
        """)
        
        # Action buttons
        self.button_layout = QHBoxLayout()
        self.button_layout.setAlignment(Qt.AlignRight)
        
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.setProperty("flat", True)
        self.refresh_button.clicked.connect(self.refresh_clicked)
        self.refresh_button.setCursor(Qt.PointingHandCursor)
        self.refresh_button.setFixedHeight(24)
        self.refresh_button.setEnabled(False)
        
        self.logout_button = QPushButton("Logout")
        self.logout_button.setProperty("flat", True)
        self.logout_button.clicked.connect(self.logout_clicked)
        self.logout_button.setCursor(Qt.PointingHandCursor)
        self.logout_button.setFixedHeight(24)
        self.logout_button.setEnabled(False)
        
        self.button_layout.addWidget(self.refresh_button)
        self.button_layout.addWidget(self.logout_button)
        
        # Add layouts to main layout
        self.main_layout.addLayout(self.status_layout)
        self.main_layout.addWidget(self.progress_bar)
        self.main_layout.addLayout(self.button_layout)
        
        # Add separator line
        self.separator = QFrame()
        self.separator.setFrameShape(QFrame.HLine)
        self.separator.setFrameShadow(QFrame.Sunken)
        self.separator.setStyleSheet("background-color: #E0E0E0;")
        
        self.main_layout.addWidget(self.separator)
        
        # Set fixed height
        self.setFixedHeight(100)
        
        # Set up timer to update display
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update_status)
        self.update_timer.start(1000)  # Update every second
        
        # Initial update
        self.update_status()
    
    def update_status(self):
        """Update the status display based on current session state."""
        if not self.session_manager or not self.session_manager.is_authenticated:
            # Not authenticated
            self.status_indicator.setStyleSheet("""
                border-radius: 8px; 
                background-color: #CCCCCC;
            """)
            self.user_label.setText("Not logged in")
            self.auth_type_label.setText("")
            self.time_label.setText("--:--:--")
            self.expires_label.setText("Session Inactive")
            self.progress_bar.setValue(0)
            self.progress_bar.setStyleSheet("""
                QProgressBar {
                    border: none;
                    border-radius: 4px;
                    background-color: #E0E0E0;
                }
                QProgressBar::chunk {
                    border-radius: 4px;
                    background-color: #CCCCCC;
                }
            """)
            
            # Disable buttons
            self.refresh_button.setEnabled(False)
            self.logout_button.setEnabled(False)
            return
        
        # Get session info
        session_info = self.session_manager.get_session_info()
        remaining_seconds = session_info.get("remaining_seconds", 0)
        max_seconds = self.session_manager.token_ttl
        
        # Calculate progress percentage (reversed)
        progress = int((remaining_seconds / max_seconds) * 100) if max_seconds > 0 else 0
        
        # Get color based on remaining time
        status_color = GuardColors.get_expiration_color(remaining_seconds)
        
        # Update status indicator color
        self.status_indicator.setStyleSheet(f"""
            border-radius: 8px; 
            background-color