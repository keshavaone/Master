"""
Enhanced UI components for GUARD desktop application.
These components provide a more modern, user-friendly interface
while maintaining the robust security architecture.
"""

import os
import sys
import time
from datetime import datetime, timedelta
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, 
    QFrame, QProgressBar, QStyle, QStyleOption, QSizePolicy,
    QGridLayout, QToolButton, QStackedWidget, QDialog, QComboBox
)
from PyQt5.QtGui import QPainter, QColor, QFont, QIcon, QPixmap, QPalette, QLinearGradient, QGradient
from PyQt5.QtCore import Qt, QSize, QTimer, QPropertyAnimation, QRect, QEasingCurve, pyqtProperty, QPoint

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


class StyledFrame(QFrame):
    """Modern styled frame with optional gradient background."""
    
    def __init__(self, parent=None, gradient=False, radius=8, border=False):
        """
        Initialize the styled frame.
        
        Args:
            parent: Parent widget
            gradient (bool): Whether to use gradient background
            radius (int): Border radius in pixels
            border (bool): Whether to show a border
        """
        super().__init__(parent)
        self.gradient = gradient
        self.border_radius = radius
        self.show_border = border
        self.start_color = QColor(ModernColors.BG_LIGHT)
        self.end_color = QColor(ModernColors.BG_MEDIUM)
        self.border_color = QColor(ModernColors.BG_DARK)
        
        # Set up style
        self.setObjectName("styledFrame")
        self.setAutoFillBackground(False)
        
        # Set stylesheet for border radius
        self.setStyleSheet(f"""
            QFrame#styledFrame {{
                background-color: transparent;
                border-radius: {self.border_radius}px;
                border: {1 if self.show_border else 0}px solid {ModernColors.BG_DARK};
            }}
        """)
    
    def paintEvent(self, event):
        """Custom paint event to draw gradient or solid background."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        if self.gradient:
            # Create gradient
            gradient = QLinearGradient(0, 0, self.width(), self.height())
            gradient.setColorAt(0, self.start_color)
            gradient.setColorAt(1, self.end_color)
            painter.setBrush(gradient)
        else:
            # Solid background
            painter.setBrush(self.start_color)
        
        # Draw rounded rectangle
        painter.setPen(Qt.NoPen if not self.show_border else QColor(self.border_color))
        painter.drawRoundedRect(0, 0, self.width(), self.height(), self.border_radius, self.border_radius)
        
        # Draw any child widgets
        option = QStyleOption()
        option.initFrom(self)
        super().paintEvent(event)


class SessionStatusWidget(QWidget):
    """
    Enhanced session status widget with visual indicators.
    
    This widget shows the current authentication state, session type,
    and remaining session time with appropriate visual cues.
    """
    
    def __init__(self, parent=None, session_manager=None):
        """
        Initialize the session status widget.
        
        Args:
            parent: Parent widget
            session_manager: Session manager to monitor
        """
        super().__init__(parent)
        self.session_manager = session_manager
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_status)
        self.timer.start(1000)  # Update every second
        
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the user interface."""
        # Main layout
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(10, 5, 10, 5)
        main_layout.setSpacing(10)
        
        # Create background frame
        self.bg_frame = StyledFrame(self, gradient=True, radius=10, border=True)
        self.bg_frame.start_color = QColor("#f8fbff")
        self.bg_frame.end_color = QColor("#e6f2ff")
        frame_layout = QHBoxLayout(self.bg_frame)
        frame_layout.setContentsMargins(10, 8, 10, 8)
        frame_layout.setSpacing(15)
        
        # Status indicator
        self.status_indicator = QLabel(self)
        self.status_indicator.setFixedSize(12, 12)
        self.status_indicator.setStyleSheet("""
            background-color: #a0a0a0;
            border-radius: 6px;
        """)
        frame_layout.addWidget(self.status_indicator)
        
        # Auth info layout (vertical)
        auth_layout = QVBoxLayout()
        auth_layout.setContentsMargins(0, 0, 0, 0)
        auth_layout.setSpacing(2)
        
        # Auth type and user ID
        self.auth_type_label = QLabel("Not authenticated", self)
        self.auth_type_label.setStyleSheet(f"color: {ModernColors.TEXT_PRIMARY}; font-weight: bold;")
        
        self.user_id_label = QLabel("", self)
        self.user_id_label.setStyleSheet(f"color: {ModernColors.TEXT_MUTED}; font-size: 10px;")
        
        auth_layout.addWidget(self.auth_type_label)
        auth_layout.addWidget(self.user_id_label)
        frame_layout.addLayout(auth_layout)
        
        # Add spacer
        frame_layout.addStretch()
        
        # Time remaining section
        time_layout = QVBoxLayout()
        time_layout.setContentsMargins(0, 0, 0, 0)
        time_layout.setSpacing(2)
        
        self.remaining_label = QLabel("Session: --:--", self)
        self.remaining_label.setStyleSheet(f"color: {ModernColors.TEXT_PRIMARY};")
        self.remaining_label.setAlignment(Qt.AlignRight)
        
        # Progress bar for remaining time
        self.time_progress = QProgressBar(self)
        self.time_progress.setRange(0, 100)
        self.time_progress.setValue(0)
        self.time_progress.setTextVisible(False)
        self.time_progress.setFixedHeight(4)
        self.time_progress.setFixedWidth(120)
        self.time_progress.setStyleSheet("""
            QProgressBar {
                background-color: #e0e0e0;
                border-radius: 2px;
                border: none;
            }
            QProgressBar::chunk {
                background-color: #4361ee;
                border-radius: 2px;
            }
        """)
        
        time_layout.addWidget(self.remaining_label)
        time_layout.addWidget(self.time_progress)
        frame_layout.addLayout(time_layout)
        
        # Refresh button
        self.refresh_button = QToolButton(self)
        self.refresh_button.setIcon(self.style().standardIcon(QStyle.SP_BrowserReload))
        self.refresh_button.setToolTip("Refresh session")
        self.refresh_button.clicked.connect(self.refresh_session)
        self.refresh_button.setStyleSheet(f"""
            QToolButton {{
                border: 1px solid {ModernColors.PRIMARY};
                border-radius: 4px;
                background-color: {ModernColors.PRIMARY};
                padding: 4px;
            }}
            QToolButton:hover {{
                background-color: {ModernColors.SECONDARY};
                border-color: {ModernColors.SECONDARY};
            }}
        """)
        # Make icon white
        icon = self.refresh_button.icon()
        pixmap = icon.pixmap(16, 16)
        painter = QPainter(pixmap)
        painter.setCompositionMode(QPainter.CompositionMode_SourceIn)
        painter.fillRect(pixmap.rect(), QColor("#ffffff"))
        painter.end()
        self.refresh_button.setIcon(QIcon(pixmap))
        
        frame_layout.addWidget(self.refresh_button)
        
        # Add the frame to the main layout
        main_layout.addWidget(self.bg_frame)
        
        # Initial update
        self.update_status()
    
    def update_status(self):
        """Update the session status display."""
        if not self.session_manager or not self.session_manager.is_authenticated:
            # Not authenticated
            self.status_indicator.setStyleSheet("background-color: #a0a0a0; border-radius: 6px;")
            self.auth_type_label.setText("Not authenticated")
            self.user_id_label.setText("")
            self.remaining_label.setText("Session: --:--")
            self.time_progress.setValue(0)
            self.refresh_button.setEnabled(False)
            return
        
        # Get session info
        session_info = self.session_manager.get_session_info()
        remaining_seconds = session_info.get("remaining_seconds", 0)
        
        # Update auth type and user
        auth_type = session_info.get("auth_type", "unknown")
        auth_display = "AWS SSO" if auth_type == "aws_sso" else "Password"
        self.auth_type_label.setText(auth_display)
        self.user_id_label.setText(session_info.get("user_id", ""))
        
        # Update remaining time
        if remaining_seconds is not None:
            minutes, seconds = divmod(remaining_seconds, 60)
            hours, minutes = divmod(minutes, 60)
            
            if hours > 0:
                time_text = f"{hours}h {minutes}m"
            else:
                time_text = f"{minutes}m {seconds}s"
                
            self.remaining_label.setText(f"Session: {time_text}")
            
            # Calculate percentage for progress bar
            max_duration = 3600  # 1 hour is standard
            if auth_type == "aws_sso":
                max_duration = 8 * 3600  # 8 hours for AWS SSO
                
            percentage = min(100, (remaining_seconds / max_duration) * 100)
            self.time_progress.setValue(int(percentage))
            
            # Set color based on remaining time
            if remaining_seconds < 300:  # Less than 5 minutes
                self.time_progress.setStyleSheet("""
                    QProgressBar { background-color: #e0e0e0; border-radius: 2px; }
                    QProgressBar::chunk { background-color: #e63946; border-radius: 2px; }
                """)
                self.remaining_label.setStyleSheet("color: #e63946; font-weight: bold;")
            elif remaining_seconds < 600:  # Less than 10 minutes
                self.time_progress.setStyleSheet("""
                    QProgressBar { background-color: #e0e0e0; border-radius: 2px; }
                    QProgressBar::chunk { background-color: #f72585; border-radius: 2px; }
                """)
                self.remaining_label.setStyleSheet("color: #f72585;")
            else:
                self.time_progress.setStyleSheet("""
                    QProgressBar { background-color: #e0e0e0; border-radius: 2px; }
                    QProgressBar::chunk { background-color: #4361ee; border-radius: 2px; }
                """)
                self.remaining_label.setStyleSheet(f"color: {ModernColors.TEXT_PRIMARY};")
        
        # Update status indicator
        if session_info.get("is_authenticated", False):
            self.status_indicator.setStyleSheet("background-color: #4cc9f0; border-radius: 6px;")
            self.refresh_button.setEnabled(True)
        else:
            self.status_indicator.setStyleSheet("background-color: #e63946; border-radius: 6px;")
            self.refresh_button.setEnabled(False)
    
    def refresh_session(self):
        """Attempt to refresh the session."""
        if hasattr(self.session_manager, 'refresh_token'):
            try:
                success = self.session_manager.refresh_token()
                if success:
                    # Show success indicator briefly
                    current_style = self.status_indicator.styleSheet()
                    self.status_indicator.setStyleSheet("background-color: #4cc9f0; border-radius: 6px;")
                    QTimer.singleShot(1000, lambda: self.status_indicator.setStyleSheet(current_style))
            except Exception as e:
                print(f"Session refresh error: {str(e)}")


class ModernButton(QPushButton):
    """Enhanced button with modern styling and animations."""
    
    def __init__(self, text, parent=None, primary=True, icon=None):
        """
        Initialize the modern button.
        
        Args:
            text (str): Button text
            parent: Parent widget
            primary (bool): If True, use primary color, otherwise secondary
            icon: Optional icon for the button
        """
        super().__init__(text, parent)
        self.primary = primary
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
        if self.primary:
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


class PiiDataCard(QWidget):
    """
    Card-style widget for displaying PII data items.
    
    This provides a more visual, intuitive presentation of PII data items
    with proper categorization and actions.
    """
    
    def __init__(self, item_data, parent=None, on_edit=None, on_delete=None):
        """
        Initialize the PII data card.
        
        Args:
            item_data (dict): PII item data to display
            parent: Parent widget
            on_edit: Callback for edit action
            on_delete: Callback for delete action
        """
        super().__init__(parent)
        self.item_data = item_data
        self.on_edit = on_edit
        self.on_delete = on_delete
        
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the user interface."""
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Create card frame
        self.card_frame = StyledFrame(self, gradient=False, radius=8, border=True)
        card_layout = QVBoxLayout(self.card_frame)
        card_layout.setContentsMargins(15, 15, 15, 15)
        card_layout.setSpacing(10)
        
        # Header section
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(10)
        
        # Category and type
        category = self.item_data.get('Category', 'Unknown')
        type_value = self.item_data.get('Type', 'Unknown')
        
        category_label = QLabel(category, self)
        category_label.setStyleSheet(f"""
            color: {ModernColors.PRIMARY};
            font-weight: bold;
            font-size: 14px;
        """)
        
        type_label = QLabel(type_value, self)
        type_label.setStyleSheet(f"""
            color: {ModernColors.TEXT_SECONDARY};
            font-size: 12px;
        """)
        
        header_layout.addWidget(category_label)
        header_layout.addWidget(QLabel(" › ", self))
        header_layout.addWidget(type_label)
        header_layout.addStretch()
        
        # Add header to card
        card_layout.addLayout(header_layout)
        
        # Divider
        divider = QFrame(self)
        divider.setFrameShape(QFrame.HLine)
        divider.setFrameShadow(QFrame.Sunken)
        divider.setStyleSheet(f"background-color: {ModernColors.BG_MEDIUM};")
        card_layout.addWidget(divider)
        
        # Content section - PII data
        content_widget = QWidget(self)
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(8)
        
        # Parse and display PII data items
        pii_data = self.item_data.get('PII', '')
        try:
            # Try to parse as list of dictionaries
            import ast
            if isinstance(pii_data, str):
                try:
                    pii_items = ast.literal_eval(pii_data)
                    if isinstance(pii_items, list):
                        for item in pii_items:
                            if isinstance(item, dict):
                                item_name = item.get('Item Name', 'Unknown')
                                item_data = item.get('Data', '')
                                self.add_pii_item(content_layout, item_name, item_data)
                except (ValueError, SyntaxError):
                    # If parsing fails, show raw data
                    self.add_pii_item(content_layout, "Data", pii_data)
            else:
                # Non-string PII data
                self.add_pii_item(content_layout, "Data", str(pii_data))
                
        except Exception as e:
            # Fallback for any errors
            self.add_pii_item(content_layout, "Error", f"Could not parse PII data: {str(e)}")
        
        card_layout.addWidget(content_widget)
        
        # Actions section
        actions_layout = QHBoxLayout()
        actions_layout.setContentsMargins(0, 0, 0, 0)
        actions_layout.setSpacing(10)
        actions_layout.addStretch()
        
        # Edit and delete buttons
        edit_btn = ModernButton("Edit", self, primary=False)
        edit_btn.setFixedWidth(80)
        edit_btn.setIcon(self.style().standardIcon(QStyle.SP_FileDialogDetailedView))
        edit_btn.clicked.connect(self.handle_edit)
        
        delete_btn = ModernButton("Delete", self, primary=False)
        delete_btn.setFixedWidth(80)
        delete_btn.setIcon(self.style().standardIcon(QStyle.SP_TrashIcon))
        delete_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {ModernColors.BG_MEDIUM};
                color: {ModernColors.DANGER};
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
                text-align: center;
            }}
            QPushButton:hover {{
                background-color: {ModernColors.DANGER};
                color: white;
            }}
            QPushButton:pressed {{
                background-color: {ModernColors.DANGER};
            }}
        """)
        delete_btn.clicked.connect(self.handle_delete)
        
        actions_layout.addWidget(edit_btn)
        actions_layout.addWidget(delete_btn)
        
        card_layout.addLayout(actions_layout)
        
        # Add card to main layout
        main_layout.addWidget(self.card_frame)
    
    def add_pii_item(self, layout, name, value):
        """
        Add a PII data item to the layout.
        
        Args:
            layout: Layout to add the item to
            name (str): Item name
            value (str): Item value/data
        """
        item_layout = QHBoxLayout()
        item_layout.setContentsMargins(0, 0, 0, 0)
        item_layout.setSpacing(10)
        
        name_label = QLabel(name + ":", self)
        name_label.setStyleSheet(f"""
            color: {ModernColors.TEXT_SECONDARY};
            font-weight: bold;
        """)
        name_label.setFixedWidth(120)
        
        value_label = QLabel(str(value), self)
        value_label.setStyleSheet(f"""
            color: {ModernColors.TEXT_PRIMARY};
        """)
        value_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        value_label.setCursor(Qt.IBeamCursor)
        value_label.setWordWrap(True)
        
        item_layout.addWidget(name_label)
        item_layout.addWidget(value_label, 1)
        
        layout.addLayout(item_layout)
    
    def handle_edit(self):
        """Handle edit button click."""
        if self.on_edit:
            self.on_edit(self.item_data)
    
    def handle_delete(self):
        """Handle delete button click."""
        if self.on_delete:
            self.on_delete(self.item_data)


class DataCategoryPanel(QWidget):
    """
    Panel for displaying data items categorized by a specific category.
    
    This provides a more organized view of PII data items by category.
    """
    
    def __init__(self, category, parent=None, on_edit=None, on_delete=None):
        """
        Initialize the category panel.
        
        Args:
            category (str): Category name
            parent: Parent widget
            on_edit: Callback for edit action
            on_delete: Callback for delete action
        """
        super().__init__(parent)
        self.category = category
        self.items = []
        self.on_edit = on_edit
        self.on_delete = on_delete
        
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the user interface."""
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 10)
        main_layout.setSpacing(5)
        
        # Category header
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(10, 5, 10, 5)
        
        icon_label = QLabel(self)
        icon_label.setPixmap(self.style().standardIcon(QStyle.SP_DirIcon).pixmap(16, 16))
        header_layout.addWidget(icon_label)
        
        category_label = QLabel(self.category, self)
        category_label.setStyleSheet(f"""
            color: {ModernColors.TEXT_PRIMARY};
            font-weight: bold;
            font-size: 16px;
        """)
        header_layout.addWidget(category_label)
        
        self.item_count_label = QLabel("(0 items)", self)
        self.item_count_label.setStyleSheet(f"color: {ModernColors.TEXT_MUTED};")
        header_layout.addWidget(self.item_count_label)
        
        header_layout.addStretch()
        
        # Add new item button
        add_btn = QPushButton("Add Item", self)
        add_btn.setIcon(self.style().standardIcon(QStyle.SP_FileDialogNewFolder))
        add_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {ModernColors.PRIMARY};
                color: white;
                border: none;
                border-radius: 4px;
                padding: 4px 8px;
            }}
            QPushButton:hover {{
                background-color: {ModernColors.SECONDARY};
            }}
        """)
        header_layout.addWidget(add_btn)
        
        main_layout.addLayout(header_layout)
        
        # Content area for cards
        self.content_widget = QWidget(self)
        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_layout.setContentsMargins(10, 0, 10, 0)
        self.content_layout.setSpacing(10)
        self.content_layout.addStretch()
        
        main_layout.addWidget(self.content_widget)
    
    def add_item(self, item_data):
        """
        Add a PII data item to the panel.
        
        Args:
            item_data (dict): PII item data to display
        """
        card = PiiDataCard(item_data, self, self.on_edit, self.on_delete)
        self.content_layout.insertWidget(self.content_layout.count() - 1, card)
        self.items.append(card)
        self.update_count()
    
    def clear_items(self):
        """Clear all items from the panel."""
        for i in reversed(range(self.content_layout.count())):
            item = self.content_layout.itemAt(i)
            if item.widget() and isinstance(item.widget(), PiiDataCard):
                item.widget().deleteLater()
                
        self.items = []
        self.update_count()
    
    def update_count(self):
        """Update the item count display."""
        count = len(self.items)
        self.item_count_label.setText(f"({count} item{'s' if count != 1 else ''})")


class ModernDataBrowser(QWidget):
    """
    Modern data browser with category panels.
    
    This provides a more intuitive, visually appealing interface for
    browsing and managing PII data with proper categorization.
    """
    
    def __init__(self, parent=None):
        """
        Initialize the data browser.
        
        Args:
            parent: Parent widget
        """
        super().__init__(parent)
        self.category_panels = {}
        
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the user interface."""
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Header with search and filters
        header_widget = QWidget(self)
        header_widget.setStyleSheet(f"background-color: {ModernColors.BG_MEDIUM};")
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
        
        # Sort options
        sort_label = QLabel("Sort by:", self)
        sort_label.setStyleSheet(f"color: {ModernColors.TEXT_SECONDARY};")
        header_layout.addWidget(sort_label)
        
        self.sort_combo = QComboBox(self)
        self.sort_combo.addItems(["Category", "Type", "Recently Modified"])
        self.sort_combo.setMinimumWidth(150)
        header_layout.addWidget(self.sort_combo)
        
        # Add header to main layout
        main_layout.addWidget(header_widget)
        
        # Scroll area for content
        from PyQt5.QtWidgets import QScrollArea
        scroll_area = QScrollArea(self)
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.NoFrame)
        
        # Content widget
        self.content_widget = QWidget(scroll_area)
        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_layout.setContentsMargins(0, 15, 0, 15)
        self.content_layout.setSpacing(20)
        
        scroll_area.setWidget(self.content_widget)
        main_layout.addWidget(scroll_area)
    
    def set_data(self, data_items):
        """
        Set the data items to display.
        
        Args:
            data_items (list): List of data items to display
        """
        # Clear existing panels
        self.clear_panels()
        
        # Collect unique categories and types
        categories = set()
        types = set()
        
        # Group items by category
        category_items = {}
        
        for item in data_items:
            category = item.get('Category', 'Uncategorized')
            item_type = item.get('Type', 'Unknown')
            
            categories.add(category)
            types.add(item_type)
            
            if category not in category_items:
                category_items[category] = []
                
            category_items[category].append(item)
        
        # Update filters
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
        
        # Create panels for each category
        for category, items in sorted(category_items.items()):
            panel = self.get_category_panel(category)
            
            # Add items to panel
            for item in items:
                panel.add_item(item)
    
    def get_category_panel(self, category):
        """
        Get or create a category panel.
        
        Args:
            category (str): Category name
            
        Returns:
            DataCategoryPanel: The category panel
        """
        if category not in self.category_panels:
            panel = DataCategoryPanel(
                category, self, 
                on_edit=self.handle_edit_item, 
                on_delete=self.handle_delete_item
            )
            self.category_panels[category] = panel
            self.content_layout.addWidget(panel)
            
        return self.category_panels[category]
    
    def clear_panels(self):
        """Clear all category panels."""
        for panel in self.category_panels.values():
            panel.clear_items()
    
    def apply_filters(self):
        """Apply category and type filters."""
        selected_category = self.category_filter.currentText()
        selected_type = self.type_filter.currentText()
        
        # Show/hide panels based on category filter
        for category, panel in self.category_panels.items():
            if selected_category == "All Categories" or category == selected_category:
                panel.setVisible(True)
            else:
                panel.setVisible(False)
    
    def handle_edit_item(self, item_data):
        """
        Handle edit action for an item.
        
        Args:
            item_data (dict): Item data to edit
        """
        # This would be connected to the application's edit dialog
        print(f"Edit item: {item_data.get('_id')}")
    
    def handle_delete_item(self, item_data):
        """
        Handle delete action for an item.
        
        Args:
            item_data (dict): Item data to delete
        """
        # This would be connected to the application's delete confirmation
        print(f"Delete item: {item_data.get('_id')}")


class ModernDataDialog(QDialog):
    """Modern dialog for displaying PII data."""
    
    def __init__(self, parent=None, title="Your Guard Data"):
        """
        Initialize the data dialog.
        
        Args:
            parent: Parent widget
            title (str): Dialog title
        """
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(900, 700)
        
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the user interface."""
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Create data browser
        self.data_browser = ModernDataBrowser(self)
        main_layout.addWidget(self.data_browser, 1)
        
        # Button area
        button_area = QWidget(self)
        button_area.setStyleSheet(f"background-color: {ModernColors.BG_MEDIUM};")
        button_layout = QHBoxLayout(button_area)
        button_layout.setContentsMargins(15, 10, 15, 10)
        
        # Add buttons
        button_layout.addStretch()
        
        self.download_btn = ModernButton("Download Data", self, primary=True)
        self.download_btn.setIcon(self.style().standardIcon(QStyle.SP_ArrowDown))
        self.download_btn.clicked.connect(self.handle_download)
        
        self.close_btn = ModernButton("Close", self, primary=False)
        self.close_btn.clicked.connect(self.accept)
        
        button_layout.addWidget(self.download_btn)
        button_layout.addWidget(self.close_btn)
        
        main_layout.addWidget(button_area)
    
    def set_data(self, data_items):
        """
        Set the data items to display.
        
        Args:
            data_items: Data items to display
        """
        self.data_browser.set_data(data_items)
    
    def handle_download(self):
        """Handle download button click."""
        # This would be connected to the application's download function
        print("Download data")