# modern_ui.py
"""
GUARD Modern UI - Comprehensive UI modernization for the GUARD application.

This module implements a modern, visually appealing, and intuitive user interface
for the GUARD application while maintaining all security features and functionality.
It uses PyQt5 with custom styling and enhanced user experience elements.
"""

import os
import sys
import time
import json
import logging
import datetime
from typing import Dict, Any, List, Optional
from functools import partial

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QPushButton, QLabel, QLineEdit, QComboBox, QScrollArea, QFrame, QSplitter,
    QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView, QProgressBar,
    QStackedWidget, QDialog, QMessageBox, QToolButton, QMenu, QAction,
    QGraphicsDropShadowEffect, QSizePolicy, QSpacerItem, QCheckBox, QFormLayout,
    QFileDialog, QToolTip, QProgressDialog, QStyle, QGraphicsOpacityEffect
)
from PyQt5.QtCore import (
    Qt, QSize, QTimer, QPropertyAnimation, QEasingCurve, QRect, QPoint,
    QParallelAnimationGroup, QSequentialAnimationGroup, QThread, pyqtSignal,
    QEvent, QObject
)
from PyQt5.QtGui import (
    QIcon, QColor, QFont, QPalette, QPixmap, QLinearGradient, QBrush, QPainter,
    QFontDatabase, QCursor, QMovie, QKeySequence
)

# Import existing components to enhance/integrate
from UI.Desktop.session_manager import SessionManager
from UI.Desktop.auth_service import AuthenticationService
from UI.Desktop.api_client import APIClient
from UI.Desktop.modern_components import CRUDHelper
from UI.Desktop.delete_handler import DeleteHandler

# Configure logging
logger = logging.getLogger("GUARD.ModernUI")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


class GuardTheme:
    """Modern theme and styling for the GUARD application."""
    
    # Color palette - Dark theme by default
    PRIMARY = "#4361ee"  # Main blue
    PRIMARY_LIGHT = "#6c8fff"
    PRIMARY_DARK = "#2234c9"
    
    SECONDARY = "#3a0ca3"  # Deep purple for accents
    
    SUCCESS = "#4cc9f0"  # Light blue for success/info
    SUCCESS_DARK = "#29a3d9"
    
    WARNING = "#f72585"  # Pink for warnings
    WARNING_DARK = "#d21a79"
    
    DANGER = "#e63946"  # Red for errors/danger
    DANGER_DARK = "#c82333"
    
    # Background colors
    BG_DARK = "#121826"  # Main dark background
    BG_MEDIUM = "#1E293B"  # Card/widget backgrounds
    BG_LIGHT = "#2C3E50"  # Lighter elements
    
    # Text colors
    TEXT_BRIGHT = "#E2E8F0"  # Bright text
    TEXT_NORMAL = "#B2BDCD"  # Normal text
    TEXT_MUTED = "#64748B"  # Muted/secondary text
    
    # Border colors
    BORDER_DARK = "#334155"
    BORDER_LIGHT = "#475569"
    
    # Additional colors
    CARD_BG = "#1E293B"
    HOVER_BG = "#2A3A51"
    INPUT_BG = "#1A2234"
    
    # Font settings
    FONT_FAMILY = "Segoe UI"
    FONT_SIZE_SMALL = 11
    FONT_SIZE_NORMAL = 13
    FONT_SIZE_LARGE = 16
    FONT_SIZE_XLARGE = 20
    
    @classmethod
    def load_fonts(cls):
        """Load and register custom fonts for the application."""
        # Here you would load additional fonts if needed
        pass
    
    @classmethod
    def get_stylesheet(cls):
        """Get the main application stylesheet."""
        return f"""
        /* Main Window */
        QMainWindow, QDialog {{
            background-color: {cls.BG_DARK};
            color: {cls.TEXT_BRIGHT};
            font-family: "{cls.FONT_FAMILY}";
            font-size: {cls.FONT_SIZE_NORMAL}px;
        }}
        
        /* Labels */
        QLabel {{
            color: {cls.TEXT_BRIGHT};
        }}
        
        QLabel[cssClass="heading"] {{
            font-size: {cls.FONT_SIZE_LARGE}px;
            font-weight: bold;
            color: {cls.TEXT_BRIGHT};
        }}
        
        QLabel[cssClass="subheading"] {{
            font-size: {cls.FONT_SIZE_NORMAL}px;
            color: {cls.TEXT_NORMAL};
        }}
        
        QLabel[cssClass="title"] {{
            font-size: {cls.FONT_SIZE_XLARGE}px;
            font-weight: bold;
            color: {cls.TEXT_BRIGHT};
        }}
        
        /* Buttons */
        QPushButton {{
            background-color: {cls.BG_LIGHT};
            color: {cls.TEXT_BRIGHT};
            border: none;
            border-radius: 6px;
            padding: 8px 16px;
            font-weight: bold;
        }}
        
        QPushButton:hover {{
            background-color: {cls.HOVER_BG};
        }}
        
        QPushButton:pressed {{
            background-color: {cls.BG_MEDIUM};
        }}
        
        QPushButton:disabled {{
            background-color: {cls.BG_MEDIUM};
            color: {cls.TEXT_MUTED};
        }}
        
        QPushButton[cssClass="primary"] {{
            background-color: {cls.PRIMARY};
            color: white;
        }}
        
        QPushButton[cssClass="primary"]:hover {{
            background-color: {cls.PRIMARY_DARK};
        }}
        
        QPushButton[cssClass="danger"] {{
            background-color: {cls.DANGER};
            color: white;
        }}
        
        QPushButton[cssClass="danger"]:hover {{
            background-color: {cls.DANGER_DARK};
        }}
        
        QPushButton[cssClass="success"] {{
            background-color: {cls.SUCCESS};
            color: white;
        }}
        
        QPushButton[cssClass="success"]:hover {{
            background-color: {cls.SUCCESS_DARK};
        }}
        
        /* Text inputs */
        QLineEdit {{
            background-color: {cls.INPUT_BG};
            color: {cls.TEXT_BRIGHT};
            border: 1px solid {cls.BORDER_DARK};
            border-radius: 6px;
            padding: 8px 12px;
        }}
        
        QLineEdit:focus {{
            border: 1px solid {cls.PRIMARY};
        }}
        
        /* Combo boxes */
        QComboBox {{
            background-color: {cls.INPUT_BG};
            color: {cls.TEXT_BRIGHT};
            border: 1px solid {cls.BORDER_DARK};
            border-radius: 6px;
            padding: 8px 12px;
            min-width: 6em;
        }}
        
        QComboBox:hover {{
            border: 1px solid {cls.PRIMARY};
        }}
        
        QComboBox::drop-down {{
            subcontrol-origin: padding;
            subcontrol-position: center right;
            width: 20px;
            border-left: none;
            border-top-right-radius: 6px;
            border-bottom-right-radius: 6px;
        }}
        
        QComboBox::down-arrow {{
            image: url(:/images/arrow-down.png);
            width: 12px;
            height: 12px;
        }}
        
        QComboBox QAbstractItemView {{
            background-color: {cls.BG_MEDIUM};
            color: {cls.TEXT_BRIGHT};
            border: 1px solid {cls.BORDER_DARK};
            selection-background-color: {cls.PRIMARY};
            selection-color: white;
            outline: 0;
        }}
        
        /* Scrollbars */
        QScrollBar:vertical {{
            background-color: {cls.BG_DARK};
            width: 12px;
            margin: 0;
            border-radius: 6px;
        }}
        
        QScrollBar::handle:vertical {{
            background-color: {cls.BG_LIGHT};
            min-height: 30px;
            border-radius: 6px;
        }}
        
        QScrollBar::handle:vertical:hover {{
            background-color: {cls.PRIMARY};
        }}
        
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
            height: 0px;
        }}
        
        QScrollBar:horizontal {{
            background-color: {cls.BG_DARK};
            height: 12px;
            margin: 0;
            border-radius: 6px;
        }}
        
        QScrollBar::handle:horizontal {{
            background-color: {cls.BG_LIGHT};
            min-width: 30px;
            border-radius: 6px;
        }}
        
        QScrollBar::handle:horizontal:hover {{
            background-color: {cls.PRIMARY};
        }}
        
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
            width: 0px;
        }}
        
        /* Frames */
        QFrame[cssClass="card"] {{
            background-color: {cls.CARD_BG};
            border-radius: 10px;
            border: 1px solid {cls.BORDER_DARK};
        }}
        
        /* Table Widget */
        QTableWidget {{
            background-color: {cls.CARD_BG};
            color: {cls.TEXT_BRIGHT};
            gridline-color: {cls.BORDER_DARK};
            border: 1px solid {cls.BORDER_DARK};
            border-radius: 10px;
            selection-background-color: {cls.PRIMARY};
            selection-color: white;
        }}
        
        QTableWidget::item {{
            padding: 6px;
            border-bottom: 1px solid {cls.BORDER_DARK};
        }}
        
        QTableWidget::item:selected {{
            background-color: {cls.PRIMARY};
            color: white;
        }}
        
        QHeaderView::section {{
            background-color: {cls.BG_MEDIUM};
            color: {cls.TEXT_NORMAL};
            padding: 8px;
            border: none;
            font-weight: bold;
        }}
        
        /* Tab Widget */
        QTabWidget::pane {{
            border: 1px solid {cls.BORDER_DARK};
            border-radius: 10px;
            background-color: {cls.CARD_BG};
        }}
        
        QTabBar::tab {{
            background-color: {cls.BG_MEDIUM};
            color: {cls.TEXT_NORMAL};
            padding: 10px 15px;
            margin-right: 2px;
            border-top-left-radius: 5px;
            border-top-right-radius: 5px;
            border: 1px solid {cls.BORDER_DARK};
            border-bottom: none;
        }}
        
        QTabBar::tab:selected {{
            background-color: {cls.PRIMARY};
            color: white;
        }}
        
        QTabBar::tab:!selected {{
            margin-top: 2px;
        }}
        
        /* Progress Bar */
        QProgressBar {{
            border: 1px solid {cls.BORDER_DARK};
            border-radius: 5px;
            background-color: {cls.BG_MEDIUM};
            text-align: center;
            color: {cls.TEXT_BRIGHT};
        }}
        
        QProgressBar::chunk {{
            background-color: {cls.PRIMARY};
            border-radius: 5px;
        }}
        
        /* Menu */
        QMenu {{
            background-color: {cls.CARD_BG};
            border: 1px solid {cls.BORDER_DARK};
            border-radius: 8px;
            padding: 5px 0;
        }}
        
        QMenu::item {{
            padding: 8px 25px 8px 20px;
            color: {cls.TEXT_BRIGHT};
        }}
        
        QMenu::item:selected {{
            background-color: {cls.PRIMARY};
            color: white;
        }}
        
        QMenu::separator {{
            height: 1px;
            background-color: {cls.BORDER_DARK};
            margin: 5px 10px;
        }}
        
        /* Status Bar */
        QStatusBar {{
            background-color: {cls.BG_MEDIUM};
            color: {cls.TEXT_NORMAL};
        }}
        
        QStatusBar QLabel {{
            color: {cls.TEXT_NORMAL};
            padding: 3px 5px;
        }}
        
        /* Tool Tips */
        QToolTip {{
            background-color: {cls.CARD_BG};
            color: {cls.TEXT_BRIGHT};
            border: 1px solid {cls.BORDER_LIGHT};
            border-radius: 4px;
            padding: 5px;
        }}
        """
    
    @classmethod
    def apply_to_app(cls, app):
        """Apply the theme to the entire application."""
        cls.load_fonts()
        app.setStyleSheet(cls.get_stylesheet())


class AnimatedStackedWidget(QStackedWidget):
    """
    Enhanced stacked widget with animated transitions between pages.
    """
    
    def __init__(self, parent=None):
        """Initialize the animated stacked widget."""
        super().__init__(parent)
        
        # Animation settings
        self.animation_duration = 400
        self.animation_type = QEasingCurve.OutCubic
        self.animation_direction = "horizontal"  # or "vertical"
        
        self._old_index = 0
        self._current_index = 0
        self._animation_in_progress = False
    
    def set_animation_direction(self, direction):
        """Set the animation direction (horizontal or vertical)."""
        if direction in ["horizontal", "vertical"]:
            self.animation_direction = direction
    
    def set_animation_duration(self, duration):
        """Set the animation duration in milliseconds."""
        self.animation_duration = max(0, duration)
    
    def set_animation_type(self, animation_type):
        """Set the animation easing curve type."""
        self.animation_type = animation_type
    
    def slide_in_index(self, index):
        """
        Slide to the widget at the given index with animation.
        
        Args:
            index: Index of the widget to slide to
        """
        if self._animation_in_progress or index == self.currentIndex():
            return
        
        self._animation_in_progress = True
        self._old_index = self.currentIndex()
        self._current_index = index
        
        # Get widget dimensions
        widget_width = self.widget(index).width()
        widget_height = self.widget(index).height()
        
        # Position the next widget
        self.widget(index).setGeometry(
            widget_width if self.animation_direction == "horizontal" else 0,
            widget_height if self.animation_direction == "vertical" else 0,
            widget_width,
            widget_height
        )
        
        # Show the widget
        self.widget(index).show()
        self.widget(index).raise_()
        
        # Create animations
        current_animation = QPropertyAnimation(self.widget(self._old_index), b"geometry")
        current_animation.setDuration(self.animation_duration)
        current_animation.setEasingCurve(self.animation_type)
        current_animation.setStartValue(QRect(0, 0, widget_width, widget_height))
        
        if self.animation_direction == "horizontal":
            current_animation.setEndValue(QRect(-widget_width, 0, widget_width, widget_height))
        else:  # vertical
            current_animation.setEndValue(QRect(0, -widget_height, widget_width, widget_height))
        
        next_animation = QPropertyAnimation(self.widget(index), b"geometry")
        next_animation.setDuration(self.animation_duration)
        next_animation.setEasingCurve(self.animation_type)
        
        if self.animation_direction == "horizontal":
            next_animation.setStartValue(QRect(widget_width, 0, widget_width, widget_height))
        else:  # vertical
            next_animation.setStartValue(QRect(0, widget_height, widget_width, widget_height))
            
        next_animation.setEndValue(QRect(0, 0, widget_width, widget_height))
        
        # Animation group
        self.animation_group = QParallelAnimationGroup()
        self.animation_group.addAnimation(current_animation)
        self.animation_group.addAnimation(next_animation)
        self.animation_group.finished.connect(self._on_animation_finished)
        
        # Start animation
        self.animation_group.start()
    
    def _on_animation_finished(self):
        """Handle animation finished event."""
        self.setCurrentIndex(self._current_index)
        self.widget(self._old_index).hide()
        self._animation_in_progress = False


class FadeLabel(QLabel):
    """Label with fade-in/fade-out animation capabilities."""
    
    def __init__(self, text="", parent=None):
        """Initialize the fade label."""
        super().__init__(text, parent)
        self.opacity_effect = QGraphicsOpacityEffect(self)
        self.opacity_effect.setOpacity(0)
        self.setGraphicsEffect(self.opacity_effect)
        
        self.animation = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.animation.setDuration(500)
        self.animation.setEasingCurve(QEasingCurve.InOutQuad)
    
    def fade_in(self, duration=None):
        """Fade in the label."""
        if duration is not None:
            self.animation.setDuration(duration)
        
        self.animation.setStartValue(0)
        self.animation.setEndValue(1)
        self.animation.start()
    
    def fade_out(self, duration=None):
        """Fade out the label."""
        if duration is not None:
            self.animation.setDuration(duration)
        
        self.animation.setStartValue(1)
        self.animation.setEndValue(0)
        self.animation.start()


class CardWidget(QFrame):
    """
    Modern card widget with shadow effects and hover states.
    """
    
    def __init__(self, parent=None, title=None, icon=None):
        """Initialize the card widget."""
        super().__init__(parent)
        
        # Set frame properties
        self.setProperty("cssClass", "card")
        
        # Add shadow effect
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(15)
        shadow.setColor(QColor(0, 0, 0, 80))
        shadow.setOffset(0, 4)
        self.setGraphicsEffect(shadow)
        
        # Set up layout
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(15, 15, 15, 15)
        
        # Add title if provided
        if title:
            title_layout = QHBoxLayout()
            title_layout.setContentsMargins(0, 0, 0, 10)
            
            if icon:
                icon_label = QLabel(self)
                icon_label.setPixmap(icon.pixmap(24, 24))
                title_layout.addWidget(icon_label)
            
            title_label = QLabel(title, self)
            title_label.setProperty("cssClass", "heading")
            title_label.setStyleSheet(f"color: {GuardTheme.TEXT_BRIGHT}; font-weight: bold;")
            title_layout.addWidget(title_label)
            title_layout.addStretch()
            
            self.layout.addLayout(title_layout)
            
            # Add separator
            separator = QFrame(self)
            separator.setFrameShape(QFrame.HLine)
            separator.setFrameShadow(QFrame.Sunken)
            separator.setStyleSheet(f"background-color: {GuardTheme.BORDER_DARK};")
            self.layout.addWidget(separator)
    
    def set_content_layout(self, layout):
        """Set the content layout of the card."""
        self.layout.addLayout(layout)
    
    def set_content_widget(self, widget):
        """Set the content widget of the card."""
        self.layout.addWidget(widget)


class PillButton(QPushButton):
    """
    Modern pill-shaped button with icon support and hover animations.
    """
    
    def __init__(self, text="", parent=None, icon=None, color=None):
        """Initialize the pill button."""
        super().__init__(text, parent)
        
        if icon:
            self.setIcon(icon)
            self.setIconSize(QSize(16, 16))
        
        # Default color if not specified
        if color is None:
            color = GuardTheme.PRIMARY
        
        # Set styling
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: {color};
                color: white;
                border: none;
                border-radius: 15px;
                padding: 5px 15px;
                font-weight: bold;
            }}
            
            QPushButton:hover {{
                background-color: {self._darken_color(color, 15)};
            }}
            
            QPushButton:pressed {{
                background-color: {self._darken_color(color, 30)};
            }}
        """)
        
        # Set size policy
        self.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Fixed)
        self.setMinimumHeight(30)
    
    def _darken_color(self, hex_color, percent):
        """Darken a hex color by the given percentage."""
        # Remove '#' if present
        hex_color = hex_color.lstrip('#')
        
        # Convert hex to RGB
        r = int(hex_color[0:2], 16)
        g = int(hex_color[2:4], 16)
        b = int(hex_color[4:6], 16)
        
        # Darken
        factor = 1 - percent/100
        r = max(0, min(255, int(r * factor)))
        g = max(0, min(255, int(g * factor)))
        b = max(0, min(255, int(b * factor)))
        
        # Convert back to hex
        return f"#{r:02x}{g:02x}{b:02x}"


class ModernLoginDialog(QDialog):
    """
    Modern, visually appealing login dialog with animation and AWS SSO support.
    """
    
    def __init__(self, parent=None, session_manager=None, auth_service=None):
        """Initialize the modern login dialog."""
        super().__init__(parent)
        
        self.session_manager = session_manager
        self.auth_service = auth_service
        
        self.setWindowTitle("GUARD Secure Authentication")
        self.setMinimumSize(800, 500)
        self.setWindowFlags(Qt.Dialog | Qt.WindowCloseButtonHint)
        
        # Apply modern styling
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {GuardTheme.BG_DARK};
                color: {GuardTheme.TEXT_BRIGHT};
            }}
        """)
        
        # Main layout
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Create left panel (branding)
        self.setup_branding_panel(main_layout)
        
        # Create right panel (authentication)
        self.setup_auth_panel(main_layout)
        
        # Animation elements
        self.animations = []
        
        # Security tips
        self.security_tips = [
            "Use AWS SSO for seamless enterprise authentication.",
            "Your credentials are never stored locally for enhanced security.",
            "All data is encrypted with AES-256 at rest and in transit.",
            "Regular security audits ensure the highest level of protection.",
            "Multi-factor authentication adds an additional layer of security."
        ]
        
        # Start animations after a short delay
        QTimer.singleShot(100, self.start_animations)
        
        # Start rotating security tips
        self.tip_timer = QTimer(self)
        self.tip_timer.timeout.connect(self.rotate_security_tip)
        self.tip_timer.start(8000)  # Every 8 seconds
        
        # Set random initial tip
        self.rotate_security_tip()
    
    def setup_branding_panel(self, parent_layout):
        """Set up the branding panel (left side)."""
        # Create panel with gradient background
        branding_panel = QWidget(self)
        branding_panel.setMinimumWidth(350)
        branding_panel.setStyleSheet(f"""
            background: qlineargradient(
                x1:0, y1:0, x2:1, y2:1,
                stop:0 #121F3D, stop:1 #0B1222
            );
        """)
        
        panel_layout = QVBoxLayout(branding_panel)
        panel_layout.setContentsMargins(30, 40, 30, 30)
        panel_layout.setSpacing(20)
        
        # Application branding container
        branding_container = QWidget(branding_panel)
        branding_layout = QVBoxLayout(branding_container)
        branding_layout.setContentsMargins(0, 0, 0, 0)
        branding_layout.setSpacing(20)
        
        # Logo and app name
        logo_layout = QHBoxLayout()
        logo_layout.setSpacing(15)
        
        logo_label = QLabel(branding_container)
        # Here you would normally set a logo image
        # For now, we'll use a placeholder colored box
        logo_placeholder = QFrame(branding_container)
        logo_placeholder.setFixedSize(50, 50)
        logo_placeholder.setStyleSheet(f"""
            background-color: {GuardTheme.PRIMARY};
            border-radius: 10px;
        """)
        logo_layout.addWidget(logo_placeholder)
        
        app_name_container = QWidget(branding_container)
        app_name_layout = QVBoxLayout(app_name_container)
        app_name_layout.setContentsMargins(0, 0, 0, 0)
        app_name_layout.setSpacing(5)
        
        app_name = QLabel("GUARD", app_name_container)
        app_name.setStyleSheet(f"""
            font-size: 28px;
            font-weight: bold;
            color: white;
        """)
        app_name_layout.addWidget(app_name)
        
        app_tagline = QLabel("Secure PII Data Management", app_name_container)
        app_tagline.setStyleSheet(f"""
            font-size: 14px;
            color: {GuardTheme.PRIMARY_LIGHT};
        """)
        app_name_layout.addWidget(app_tagline)
        
        logo_layout.addWidget(app_name_container)
        branding_layout.addLayout(logo_layout)
        
        # App description
        description = QLabel(
            "Enterprise-grade security for your most sensitive personal information "
            "with end-to-end encryption and comprehensive access controls.",
            branding_container
        )
        description.setWordWrap(True)
        description.setStyleSheet(f"""
            font-size: 15px;
            color: {GuardTheme.TEXT_NORMAL};
            line-height: 150%;
        """)
        branding_layout.addWidget(description)
        
        # Add to main panel layout with stretch to push security tip down
        panel_layout.addWidget(branding_container)
        panel_layout.addStretch(1)
        
        # Security tip card
        security_card = QFrame(branding_panel)
        security_card.setStyleSheet(f"""
            background-color: rgba(59, 130, 246, 0.1);
            border: 1px solid rgba(59, 130, 246, 0.3);
            border-radius: 10px;
            padding: 15px;
        """)
        
        security_layout = QVBoxLayout(security_card)
        security_layout.setContentsMargins(15, 15, 15, 15)
        
        security_header = QLabel("Security Tip", security_card)
        security_header.setStyleSheet(f"""
            color: {GuardTheme.PRIMARY_LIGHT};
            font-size: 16px;
            font-weight: bold;
        """)
        security_layout.addWidget(security_header)
        
        self.security_tip_label = QLabel(security_card)
        self.security_tip_label.setWordWrap(True)
        self.security_tip_label.setStyleSheet(f"""
            color: {GuardTheme.TEXT_NORMAL};
            font-size: 14px;
            line-height: 150%;
        """)
        security_layout.addWidget(self.security_tip_label)
        
        panel_layout.addWidget(security_card)
        
        # Copyright footer
        footer = QLabel("© 2025 GUARD Security. All rights reserved.\nIndustry standard compliance: GDPR, HIPAA, PCI DSS", branding_panel)
        footer.setStyleSheet(f"""
            color: {GuardTheme.TEXT_MUTED};
            font-size: 12px;
            margin-top: 20px;
        """)
        panel_layout.addWidget(footer)
        
        # Add panel to main layout
        parent_layout.addWidget(branding_panel)
    
    def setup_auth_panel(self, parent_layout):
        """Set up the authentication panel (right side)."""
        auth_panel = QWidget(self)
        
        panel_layout = QVBoxLayout(auth_panel)
        panel_layout.setContentsMargins(0, 0, 0, 0)
        
        # Create a scrollable content area
        scroll_area = QScrollArea(auth_panel)
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.NoFrame)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        
        scroll_content = QWidget(scroll_area)
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setContentsMargins(40, 40, 40, 40)
        scroll_layout.setAlignment(Qt.AlignCenter)
        
        # Authentication card
        auth_card = QFrame(scroll_content)
        auth_card.setProperty("cssClass", "card")
        auth_card.setStyleSheet(f"""
            background-color: {GuardTheme.CARD_BG};
            border: 1px solid {GuardTheme.BORDER_DARK};
            border-radius: 15px;
        """)
        
        # Add shadow to the card
        shadow = QGraphicsDropShadowEffect(auth_card)
        shadow.setBlurRadius(20)
        shadow.setColor(QColor(0, 0, 0, 80))
        shadow.setOffset(0, 4)
        auth_card.setGraphicsEffect(shadow)
        
        # Card layout
        card_layout = QVBoxLayout(auth_card)
        card_layout.setContentsMargins(30, 30, 30, 30)
        card_layout.setSpacing(20)
        
        # Welcome text
        welcome_label = QLabel("Welcome Back", auth_card)
        welcome_label.setStyleSheet(f"""
            font-size: 24px;
            font-weight: bold;
            color: {GuardTheme.TEXT_BRIGHT};
        """)
        card_layout.addWidget(welcome_label)
        
        subtitle_label = QLabel("Please authenticate to continue", auth_card)
        subtitle_label.setStyleSheet(f"""
            font-size: 14px;
            color: {GuardTheme.TEXT_NORMAL};
            margin-bottom: 10px;
        """)
        card_layout.addWidget(subtitle_label)
        
        # Error message (initially hidden)
        self.error_container = QFrame(auth_card)
        self.error_container.setStyleSheet(f"""
            background-color: rgba(220, 38, 38, 0.1);
            border: 1px solid rgba(220, 38, 38, 0.3);
            border-radius: 8px;
            padding: 10px;
        """)
        error_layout = QHBoxLayout(self.error_container)
        error_layout.setContentsMargins(10, 10, 10, 10)
        
        error_icon = QLabel(self.error_container)
        # Here we'd normally set an error icon
        # For now, we'll use a red text placeholder
        error_icon.setText("⚠️")
        error_icon.setStyleSheet("color: #F87171; font-size: 16px;")
        error_layout.addWidget(error_icon, 0)
        
        self.error_message = QLabel(self.error_container)
        self.error_message.setWordWrap(True)
        self.error_message.setStyleSheet(f"""
            color: #F87171;
            font-size: 13px;
        """)
        error_layout.addWidget(self.error_message, 1)
        
        card_layout.addWidget(self.error_container)
        self.error_container.setVisible(False)
        
        # Create stacked widget for authentication methods
        self.auth_stack = QStackedWidget(auth_card)
        
        # Auth method selection page
        auth_select_page = QWidget(self.auth_stack)
        auth_select_layout = QVBoxLayout(auth_select_page)
        auth_select_layout.setContentsMargins(0, 0, 0, 0)
        auth_select_layout.setSpacing(15)
        
        # AWS SSO button
        aws_sso_button = QPushButton("Sign in with AWS SSO", auth_select_page)
        aws_sso_button.setProperty("cssClass", "primary")
        aws_sso_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {GuardTheme.PRIMARY};
                color: white;
                border: none;
                border-radius: 8px;
                padding: 12px;
                font-size: 15px;
                font-weight: bold;
                text-align: center;
            }}
            QPushButton:hover {{
                background-color: {GuardTheme.PRIMARY_DARK};
            }}
        """)
        # Here we would set an AWS icon if available
        aws_sso_button.clicked.connect(self.start_aws_sso_auth)
        auth_select_layout.addWidget(aws_sso_button)
        
        # Divider
        divider_layout = QHBoxLayout()
        divider_layout.setContentsMargins(0, 10, 0, 10)
        
        divider_left = QFrame(auth_select_page)
        divider_left.setFrameShape(QFrame.HLine)
        divider_left.setFrameShadow(QFrame.Sunken)
        divider_left.setStyleSheet(f"background-color: {GuardTheme.BORDER_DARK};")
        divider_layout.addWidget(divider_left)
        
        divider_text = QLabel("or", auth_select_page)
        divider_text.setStyleSheet(f"color: {GuardTheme.TEXT_MUTED}; margin: 0 10px;")
        divider_layout.addWidget(divider_text)
        
        divider_right = QFrame(auth_select_page)
        divider_right.setFrameShape(QFrame.HLine)
        divider_right.setFrameShadow(QFrame.Sunken)
        divider_right.setStyleSheet(f"background-color: {GuardTheme.BORDER_DARK};")
        divider_layout.addWidget(divider_right)
        
        auth_select_layout.addLayout(divider_layout)
        
        # Password button
        password_button = QPushButton("Sign in with Password", auth_select_page)
        password_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {GuardTheme.BG_LIGHT};
                color: {GuardTheme.TEXT_BRIGHT};
                border: none;
                border-radius: 8px;
                padding: 12px;
                font-size: 15px;
                font-weight: bold;
                text-align: center;
            }}
            QPushButton:hover {{
                background-color: {GuardTheme.HOVER_BG};
            }}
        """)
        # Here we would set a password icon if available
        password_button.clicked.connect(self.show_password_auth)
        auth_select_layout.addWidget(password_button)
        
        # Add the selection page to the stack
        self.auth_stack.addWidget(auth_select_page)
        
        # AWS SSO auth page
        aws_sso_page = QWidget(self.auth_stack)
        aws_sso_layout = QVBoxLayout(aws_sso_page)
        aws_sso_layout.setContentsMargins(0, 0, 0, 0)
        aws_sso_layout.setSpacing(20)
        
        # AWS SSO info box
        aws_info_box = QFrame(aws_sso_page)
        aws_info_box.setStyleSheet(f"""
            background-color: rgba(59, 130, 246, 0.1);
            border: 1px solid rgba(59, 130, 246, 0.3);
            border-radius: 8px;
            padding: 15px;
        """)
        
        aws_info_layout = QVBoxLayout(aws_info_box)
        aws_info_layout.setSpacing(10)
        
        aws_info_title = QLabel("AWS SSO Authentication", aws_info_box)
        aws_info_title.setStyleSheet(f"""
            color: {GuardTheme.PRIMARY_LIGHT};
            font-size: 16px;
            font-weight: bold;
        """)
        aws_info_layout.addWidget(aws_info_title)
        
        aws_info_text = QLabel(
            "We're redirecting you to AWS Single Sign-On. "
            "You'll return here after authentication.",
            aws_info_box
        )
        aws_info_text.setWordWrap(True)
        aws_info_text.setStyleSheet(f"""
            color: {GuardTheme.TEXT_NORMAL};
            font-size: 14px;
        """)
        aws_info_layout.addWidget(aws_info_text)
        
        aws_company_id = QLabel("Company ID: guardian-corp", aws_info_box)
        aws_company_id.setStyleSheet(f"""
            color: {GuardTheme.TEXT_MUTED};
            font-size: 12px;
        """)
        aws_info_layout.addWidget(aws_company_id)
        
        aws_sso_layout.addWidget(aws_info_box)
        
        # AWS SSO loading state
        self.aws_loading_widget = QWidget(aws_sso_page)
        aws_loading_layout = QVBoxLayout(self.aws_loading_widget)
        aws_loading_layout.setAlignment(Qt.AlignCenter)
        aws_loading_layout.setSpacing(15)
        
        # Loading spinner would be added here
        # For now, we'll use a loading progress bar
        self.aws_progress = QProgressBar(self.aws_loading_widget)
        self.aws_progress.setRange(0, 0)  # Indeterminate
        self.aws_progress.setTextVisible(False)
        self.aws_progress.setFixedHeight(8)
        self.aws_progress.setStyleSheet(f"""
            QProgressBar {{
                border: none;
                border-radius: 4px;
                background-color: {GuardTheme.BG_LIGHT};
            }}
            QProgressBar::chunk {{
                background-color: {GuardTheme.PRIMARY};
                border-radius: 4px;
            }}
        """)
        aws_loading_layout.addWidget(self.aws_progress)
        
        aws_loading_text = QLabel("Connecting to AWS SSO...", self.aws_loading_widget)
        aws_loading_text.setAlignment(Qt.AlignCenter)
        aws_loading_text.setStyleSheet(f"color: {GuardTheme.TEXT_NORMAL};")
        aws_loading_layout.addWidget(aws_loading_text)
        
        aws_sso_layout.addWidget(self.aws_loading_widget)
        
        # AWS SSO buttons
        self.aws_buttons_widget = QWidget(aws_sso_page)
        aws_buttons_layout = QVBoxLayout(self.aws_buttons_widget)
        aws_buttons_layout.setAlignment(Qt.AlignCenter)
        aws_buttons_layout.setSpacing(15)
        
        self.aws_continue_button = QPushButton("Continue to AWS SSO", self.aws_buttons_widget)
        self.aws_continue_button.setProperty("cssClass", "primary")
        self.aws_continue_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {GuardTheme.PRIMARY};
                color: white;
                border: none;
                border-radius: 8px;
                padding: 10px 20px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {GuardTheme.PRIMARY_DARK};
            }}
        """)
        self.aws_continue_button.clicked.connect(self.authenticate_with_aws_sso)
        aws_buttons_layout.addWidget(self.aws_continue_button, 0, Qt.AlignCenter)
        
        aws_back_button = QPushButton("Back to authentication options", self.aws_buttons_widget)
        aws_back_button.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: {GuardTheme.TEXT_MUTED};
                border: none;
                font-size: 13px;
            }}
            QPushButton:hover {{
                color: {GuardTheme.TEXT_NORMAL};
            }}
        """)
        aws_back_button.clicked.connect(self.show_auth_selection)
        aws_buttons_layout.addWidget(aws_back_button, 0, Qt.AlignCenter)
        
        aws_sso_layout.addWidget(self.aws_buttons_widget)
        
        # Set initial visibility
        self.aws_loading_widget.setVisible(False)
        
        # Add the AWS SSO page to the stack
        self.auth_stack.addWidget(aws_sso_page)
        
        # Password auth page
        password_page = QWidget(self.auth_stack)
        password_layout = QVBoxLayout(password_page)
        password_layout.setContentsMargins(0, 0, 0, 0)
        password_layout.setSpacing(15)
        
        # Username field
        username_label = QLabel("Username", password_page)
        username_label.setStyleSheet(f"color: {GuardTheme.TEXT_NORMAL}; font-size: 14px;")
        password_layout.addWidget(username_label)
        
        self.username_input = QLineEdit(password_page)
        self.username_input.setPlaceholderText("Enter your username")
        self.username_input.setStyleSheet(f"""
            QLineEdit {{
                background-color: {GuardTheme.INPUT_BG};
                color: {GuardTheme.TEXT_BRIGHT};
                border: 1px solid {GuardTheme.BORDER_DARK};
                border-radius: 8px;
                padding: 12px;
                font-size: 14px;
            }}
            QLineEdit:focus {{
                border: 1px solid {GuardTheme.PRIMARY};
            }}
        """)
        password_layout.addWidget(self.username_input)
        
        # Password field with forgot password link
        password_header = QHBoxLayout()
        
        password_label = QLabel("Password", password_page)
        password_label.setStyleSheet(f"color: {GuardTheme.TEXT_NORMAL}; font-size: 14px;")
        password_header.addWidget(password_label)
        
        password_header.addStretch()
        
        forgot_password = QPushButton("Forgot password?", password_page)
        forgot_password.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: {GuardTheme.PRIMARY_LIGHT};
                border: none;
                font-size: 13px;
                text-decoration: none;
            }}
            QPushButton:hover {{
                color: {GuardTheme.PRIMARY};
                text-decoration: underline;
            }}
        """)
        password_header.addWidget(forgot_password)
        
        password_layout.addLayout(password_header)
        
        self.password_input = QLineEdit(password_page)
        self.password_input.setPlaceholderText("Enter your password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setStyleSheet(f"""
            QLineEdit {{
                background-color: {GuardTheme.INPUT_BG};
                color: {GuardTheme.TEXT_BRIGHT};
                border: 1px solid {GuardTheme.BORDER_DARK};
                border-radius: 8px;
                padding: 12px;
                font-size: 14px;
            }}
            QLineEdit:focus {{
                border: 1px solid {GuardTheme.PRIMARY};
            }}
        """)
        password_layout.addWidget(self.password_input)
        
        # Sign in button
        password_button_layout = QVBoxLayout()
        password_button_layout.setSpacing(15)
        
        self.signin_button = QPushButton("Sign in", password_page)
        self.signin_button.setProperty("cssClass", "primary")
        self.signin_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {GuardTheme.PRIMARY};
                color: white;
                border: none;
                border-radius: 8px;
                padding: 12px;
                font-size: 15px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {GuardTheme.PRIMARY_DARK};
            }}
        """)
        self.signin_button.clicked.connect(self.authenticate_with_password)
        password_button_layout.addWidget(self.signin_button)
        
        # Back button
        password_back_button = QPushButton("Back to authentication options", password_page)
        password_back_button.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: {GuardTheme.TEXT_MUTED};
                border: none;
                font-size: 13px;
                text-align: center;
            }}
            QPushButton:hover {{
                color: {GuardTheme.TEXT_NORMAL};
            }}
        """)
        password_back_button.clicked.connect(self.show_auth_selection)
        password_button_layout.addWidget(password_back_button, 0, Qt.AlignCenter)
        
        password_layout.addLayout(password_button_layout)
        password_layout.addStretch()
        
        # Add the password page to the stack
        self.auth_stack.addWidget(password_page)
        
        # Add auth stack to card layout
        card_layout.addWidget(self.auth_stack)
        
        # Add the auth card to the scroll layout
        scroll_layout.addWidget(auth_card)
        
        # Security note
        security_note = QLabel(
            "Protected by GUARD's advanced encryption. Your credentials never leave your device.",
            scroll_content
        )
        security_note.setAlignment(Qt.AlignCenter)
        security_note.setStyleSheet(f"""
            color: {GuardTheme.TEXT_MUTED};
            font-size: 12px;
            margin-top: 20px;
        """)
        scroll_layout.addWidget(security_note)
        
        # Set scroll content
        scroll_area.setWidget(scroll_content)
        
        # Add scroll area to panel layout
        panel_layout.addWidget(scroll_area)
        
        # Add panel to main layout
        parent_layout.addWidget(auth_panel)
    
    def show_auth_selection(self):
        """Show the authentication method selection page."""
        self.auth_stack.setCurrentIndex(0)
        self.error_container.setVisible(False)
    
    def show_password_auth(self):
        """Show the password authentication page."""
        self.auth_stack.setCurrentIndex(2)
        self.error_container.setVisible(False)
        self.username_input.setFocus()
    
    def start_aws_sso_auth(self):
        """Show the AWS SSO authentication page."""
        self.auth_stack.setCurrentIndex(1)
        self.error_container.setVisible(False)
        self.aws_loading_widget.setVisible(False)
        self.aws_buttons_widget.setVisible(True)
    
    def authenticate_with_aws_sso(self):
        """Authenticate using AWS SSO."""
        if not self.session_manager:
            self.show_error("Session manager not initialized. Please restart the application.")
            return
        
        # Show loading state
        self.aws_loading_widget.setVisible(True)
        self.aws_buttons_widget.setVisible(False)
        self.error_container.setVisible(False)
        
        try:
            # Start the AWS SSO authentication process
            # This is a long-running operation, so we need to use a worker thread
            # For now, we'll simulate the process with QTimer
            
            # In a real implementation, we would spawn a worker thread:
            # auth_thread = AuthThread(self.session_manager)
            # auth_thread.finished.connect(self.on_aws_auth_finished)
            # auth_thread.error.connect(self.on_aws_auth_error)
            # auth_thread.start()
            
            # Simulate the process for demonstration
            QTimer.singleShot(2500, self.simulate_aws_auth_success)
        except Exception as e:
            self.aws_loading_widget.setVisible(False)
            self.aws_buttons_widget.setVisible(True)
            self.show_error(f"Failed to start authentication: {str(e)}")
    
    def simulate_aws_auth_success(self):
        """Simulate successful AWS SSO authentication (for demo purposes)."""
        try:
            # In a real implementation, this would be called by the auth thread
            if self.session_manager:
                # Authenticate with AWS SSO
                sso_success = self.session_manager.authenticate_aws_sso(self)
                
                if sso_success:
                    # Get an API token using the AWS credentials
                    if self.auth_service:
                        api_success, message = self.auth_service.authenticate_with_aws_sso()
                        
                        if api_success:
                            self.accept()  # Close dialog and return success
                        else:
                            self.show_error(f"API authentication failed: {message}")
                    else:
                        self.show_error("Authentication service not initialized")
                else:
                    self.show_error("AWS SSO authentication failed")
            else:
                self.show_error("Session manager not initialized")
        except Exception as e:
            self.show_error(f"Authentication error: {str(e)}")
        finally:
            # Restore button state
            self.aws_loading_widget.setVisible(False)
            self.aws_buttons_widget.setVisible(True)
    
    def authenticate_with_password(self):
        """Authenticate using password."""
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        
        if not username:
            self.show_error("Please enter your username")
            self.username_input.setFocus()
            return
        
        if not password:
            self.show_error("Please enter your password")
            self.password_input.setFocus()
            return
        
        # Show loading state
        self.signin_button.setText("Signing in...")
        self.signin_button.setEnabled(False)
        self.error_container.setVisible(False)
        
        # Here we would normally authenticate with the backend
        # For now, we'll just show an error since we're focusing on AWS SSO
        QTimer.singleShot(1500, lambda: self.show_error("Password authentication is currently disabled. Please use AWS SSO."))
        QTimer.singleShot(1500, lambda: self.signin_button.setText("Sign in"))
        QTimer.singleShot(1500, lambda: self.signin_button.setEnabled(True))
    
    def show_error(self, message):
        """Show an error message."""
        self.error_message.setText(message)
        self.error_container.setVisible(True)
    
    def start_animations(self):
        """Start entrance animations for UI elements."""
        # Here we would normally create and start animations for various elements
        # For simplicity, we'll just focus on the security tip rotation
        pass
    
    def rotate_security_tip(self):
        """Rotate to a new security tip."""
        import random
        tip = random.choice(self.security_tips)
        
        # Create a fade out animation for the current tip
        fade_out = QPropertyAnimation(self.security_tip_label, b"opacity")
        if not hasattr(self.security_tip_label, "setGraphicsEffect"):
            # For PyQt5, we need to add the opacity effect first
            opacity_effect = QGraphicsOpacityEffect(self.security_tip_label)
            opacity_effect.setOpacity(1.0)
            self.security_tip_label.setGraphicsEffect(opacity_effect)
            fade_out = QPropertyAnimation(opacity_effect, b"opacity")
        
        fade_out.setDuration(500)
        fade_out.setStartValue(1.0)
        fade_out.setEndValue(0.0)
        fade_out.finished.connect(lambda: self.update_tip_text(tip))
        
        # Start the animation
        fade_out.start(QPropertyAnimation.DeleteWhenStopped)
    
    def update_tip_text(self, tip):
        """Update the security tip text and fade it in."""
        # Update the tip text
        self.security_tip_label.setText(tip)
        
        # Create a fade in animation
        fade_in = QPropertyAnimation(self.security_tip_label.graphicsEffect(), b"opacity")
        fade_in.setDuration(500)
        fade_in.setStartValue(0.0)
        fade_in.setEndValue(1.0)
        
        # Start the animation
        fade_in.start(QPropertyAnimation.DeleteWhenStopped)
    
    def closeEvent(self, event):
        """Handle dialog close event."""
        # Stop the tip timer
        if hasattr(self, 'tip_timer') and self.tip_timer.isActive():
            self.tip_timer.stop()
        
        # Accept the event to close the dialog
        event.accept()


class ModernDataViewDialog(QDialog):
    """
    Modern data viewing dialog with enhanced visualization and interaction.
    
    This dialog provides a modern, visually appealing interface for viewing
    and managing PII data items with filtering, searching, and comprehensive
    data visualization.
    """
    
    def __init__(self, parent=None, api_client=None, session_manager=None, auth_service=None):
        """Initialize the modern data view dialog."""
        super().__init__(parent)
        
        self.api_client = api_client
        self.session_manager = session_manager
        self.auth_service = auth_service
        
        self.setWindowTitle("GUARD PII Data Management")
        self.setMinimumSize(1000, 700)
        self.setWindowFlags(Qt.Dialog | Qt.WindowMaximizeButtonHint | Qt.WindowCloseButtonHint)
        
        # Data state
        self.categories = []
        self.data_items = []
        self.filtered_items = []
        self.selected_category = None
        self.current_view_mode = "grid"  # "grid" or "table"
        self.is_loading = True
        
        # Set up UI
        self.setup_ui()
        
        # Load data
        self.load_data()
    
    def setup_ui(self):
        """Set up the user interface."""
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Set up header section
        self.setup_header_section()
        main_layout.addWidget(self.header_widget)
        
        # Set up main content
        self.content_widget = QWidget(self)
        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_layout.setContentsMargins(20, 20, 20, 20)
        self.content_layout.setSpacing(20)
        
        # Status bar
        self.setup_status_bar()
        self.content_layout.addLayout(self.status_layout)
        
        # Create stacked widget for different views
        self.view_stack = QStackedWidget(self.content_widget)
        
        # Loading view
        self.loading_widget = QWidget(self.view_stack)
        loading_layout = QVBoxLayout(self.loading_widget)
        loading_layout.setAlignment(Qt.AlignCenter)
        loading_layout.setSpacing(20)
        
        loading_icon = QLabel(self.loading_widget)
        # Here we'd normally use a loading spinner or animation
        loading_icon.setText("⌛")
        loading_icon.setAlignment(Qt.AlignCenter)
        loading_icon.setStyleSheet("font-size: 48px; color: #4361ee;")
        loading_layout.addWidget(loading_icon)
        
        loading_text = QLabel("Loading data items...", self.loading_widget)
        loading_text.setAlignment(Qt.AlignCenter)
        loading_text.setStyleSheet(f"""
            font-size: 18px;
            color: {GuardTheme.TEXT_NORMAL};
        """)
        loading_layout.addWidget(loading_text)
        
        loading_progress = QProgressBar(self.loading_widget)
        loading_progress.setRange(0, 0)  # Indeterminate
        loading_progress.setFixedWidth(300)
        loading_progress.setFixedHeight(8)
        loading_progress.setTextVisible(False)
        loading_progress.setStyleSheet(f"""
            QProgressBar {{
                border: none;
                border-radius: 4px;
                background-color: {GuardTheme.BG_LIGHT};
            }}
            QProgressBar::chunk {{
                background-color: {GuardTheme.PRIMARY};
                border-radius: 4px;
            }}
        """)
        loading_layout.addWidget(loading_progress, 0, Qt.AlignCenter)
        
        # Add loading view to stack
        self.view_stack.addWidget(self.loading_widget)
        
        # Empty view
        self.empty_widget = QWidget(self.view_stack)
        empty_layout = QVBoxLayout(self.empty_widget)
        empty_layout.setAlignment(Qt.AlignCenter)
        empty_layout.setSpacing(20)
        
        empty_icon = QLabel(self.empty_widget)
        # Here we'd normally use a proper icon
        empty_icon.setText("🔍")
        empty_icon.setAlignment(Qt.AlignCenter)
        empty_icon.setStyleSheet("font-size: 48px; color: #9ca3af;")
        empty_layout.addWidget(empty_icon)
        
        self.empty_message = QLabel("No data items found", self.empty_widget)
        self.empty_message.setAlignment(Qt.AlignCenter)
        self.empty_message.setWordWrap(True)
        self.empty_message.setStyleSheet(f"""
            font-size: 18px;
            color: {GuardTheme.TEXT_NORMAL};
            max-width: 500px;
        """)
        empty_layout.addWidget(self.empty_message, 0, Qt.AlignCenter)
        
        empty_add_button = QPushButton("Add New Item", self.empty_widget)
        empty_add_button.setProperty("cssClass", "primary")
        empty_add_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {GuardTheme.PRIMARY};
                color: white;
                border: none;
                border-radius: 8px;
                padding: 10px 20px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {GuardTheme.PRIMARY_DARK};
            }}
        """)
        empty_add_button.clicked.connect(self.add_new_item)
        empty_layout.addWidget(empty_add_button, 0, Qt.AlignCenter)
        
        # Add empty view to stack
        self.view_stack.addWidget(self.empty_widget)
        
        # Grid view
        self.grid_widget = QScrollArea(self.view_stack)
        self.grid_widget.setWidgetResizable(True)
        self.grid_widget.setFrameShape(QFrame.NoFrame)
        self.grid_widget.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        
        self.grid_content = QWidget(self.grid_widget)
        self.grid_layout = QGridLayout(self.grid_content)
        self.grid_layout.setContentsMargins(0, 0, 0, 0)
        self.grid_layout.setSpacing(20)
        
        self.grid_widget.setWidget(self.grid_content)
        
        # Add grid view to stack
        self.view_stack.addWidget(self.grid_widget)
        
        # Table view
        self.table_widget = QWidget(self.view_stack)
        table_layout = QVBoxLayout(self.table_widget)
        table_layout.setContentsMargins(0, 0, 0, 0)
        table_layout.setSpacing(0)
        
        self.data_table = QTableWidget(0, 6, self.table_widget)
        self.data_table.setHorizontalHeaderLabels(["ID", "Category", "Type", "Last Updated", "Security", "Actions"])
        self.data_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.data_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.data_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.data_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.data_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.data_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.data_table.verticalHeader().setVisible(False)
        self.data_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.data_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.data_table.setAlternatingRowColors(True)
        self.data_table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {GuardTheme.CARD_BG};
                color: {GuardTheme.TEXT_BRIGHT};
                gridline-color: {GuardTheme.BORDER_DARK};
                border-radius: 10px;
                border: 1px solid {GuardTheme.BORDER_DARK};
            }}
            
            QTableWidget::item {{
                padding: 8px;
                border-bottom: 1px solid {GuardTheme.BORDER_DARK};
            }}
            
            QTableWidget::item:selected {{
                background-color: {GuardTheme.PRIMARY};
                color: white;
            }}
            
            QHeaderView::section {{
                background-color: {GuardTheme.BG_MEDIUM};
                color: {GuardTheme.TEXT_NORMAL};
                padding: 8px;
                border: none;
                font-weight: bold;
            }}
        """)
        
        table_layout.addWidget(self.data_table)
        
        # Table pagination
        pagination_layout = QHBoxLayout()
        pagination_layout.setContentsMargins(10, 10, 10, 10)
        
        self.table_info_label = QLabel(self.table_widget)
        self.table_info_label.setStyleSheet(f"color: {GuardTheme.TEXT_MUTED}; font-size: 13px;")
        pagination_layout.addWidget(self.table_info_label)
        
        pagination_layout.addStretch()
        
        self.prev_page_button = QPushButton("Previous", self.table_widget)
        self.prev_page_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {GuardTheme.BG_LIGHT};
                color: {GuardTheme.TEXT_NORMAL};
                border: 1px solid {GuardTheme.BORDER_DARK};
                border-radius: 4px;
                padding: 5px 10px;
            }}
            QPushButton:hover {{
                background-color: {GuardTheme.HOVER_BG};
            }}
            QPushButton:disabled {{
                background-color: {GuardTheme.BG_MEDIUM};
                color: {GuardTheme.TEXT_MUTED};
            }}
        """)
        pagination_layout.addWidget(self.prev_page_button)
        
        self.page_number_label = QLabel("1", self.table_widget)
        self.page_number_label.setStyleSheet(f"""
            background-color: {GuardTheme.PRIMARY};
            color: white;
            border-radius: 4px;
            padding: 5px 10px;
            font-weight: bold;
        """)
        pagination_layout.addWidget(self.page_number_label)
        
        self.next_page_button = QPushButton("Next", self.table_widget)
        self.next_page_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {GuardTheme.BG_LIGHT};
                color: {GuardTheme.TEXT_NORMAL};
                border: 1px solid {GuardTheme.BORDER_DARK};
                border-radius: 4px;
                padding: 5px 10px;
            }}
            QPushButton:hover {{
                background-color: {GuardTheme.HOVER_BG};
            }}
            QPushButton:disabled {{
                background-color: {GuardTheme.BG_MEDIUM};
                color: {GuardTheme.TEXT_MUTED};
            }}
        """)
        pagination_layout.addWidget(self.next_page_button)
        
        table_layout.addLayout(pagination_layout)
        
        # Add table view to stack
        self.view_stack.addWidget(self.table_widget)
        
        # Add view stack to content layout
        self.content_layout.addWidget(self.view_stack, 1)  # Give stretch priority
        
        # Add content widget to main layout
        main_layout.addWidget(self.content_widget, 1)  # Give stretch priority
        
        # Set initial view
        self.view_stack.setCurrentWidget(self.loading_widget)
    
    def setup_header_section(self):
        """Set up the header section with search, title, and filters."""
        self.header_widget = QWidget(self)
        self.header_widget.setStyleSheet(f"""
            background-color: {GuardTheme.BG_MEDIUM};
            border-bottom: 1px solid {GuardTheme.BORDER_DARK};
        """)
        
        header_layout = QVBoxLayout(self.header_widget)
        header_layout.setContentsMargins(20, 20, 20, 20)
        header_layout.setSpacing(15)
        
        # Title and search bar
        top_layout = QHBoxLayout()
        
        # Title section
        title_layout = QVBoxLayout()
        
        title_label = QLabel("PII Data Management", self.header_widget)
        title_label.setStyleSheet(f"""
            font-size: 24px;
            font-weight: bold;
            color: {GuardTheme.TEXT_BRIGHT};
        """)
        title_layout.addWidget(title_label)
        
        subtitle_label = QLabel("Securely manage and view your encrypted personal information", self.header_widget)
        subtitle_label.setStyleSheet(f"""
            font-size: 14px;
            color: {GuardTheme.TEXT_NORMAL};
        """)
        title_layout.addWidget(subtitle_label)
        
        top_layout.addLayout(title_layout)
        
        top_layout.addStretch()
        
        # Search section
        search_layout = QHBoxLayout()
        
        self.search_input = QLineEdit(self.header_widget)
        self.search_input.setPlaceholderText("Search data items...")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.setStyleSheet(f"""
            QLineEdit {{
                background-color: {GuardTheme.INPUT_BG};
                color: {GuardTheme.TEXT_BRIGHT};
                border: 1px solid {GuardTheme.BORDER_DARK};
                border-radius: 8px;
                padding: 10px 15px;
                min-width: 250px;
            }}
            QLineEdit:focus {{
                border: 1px solid {GuardTheme.PRIMARY};
            }}
        """)
        self.search_input.textChanged.connect(self.filter_data)
        search_layout.addWidget(self.search_input)
        
        add_button = QPushButton("Add New", self.header_widget)
        add_button.setProperty("cssClass", "primary")
        add_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {GuardTheme.PRIMARY};
                color: white;
                border: none;
                border-radius: 8px;
                padding: 10px 15px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {GuardTheme.PRIMARY_DARK};
            }}
        """)
        add_button.clicked.connect(self.add_new_item)
        search_layout.addWidget(add_button)
        
        top_layout.addLayout(search_layout)
        
        header_layout.addLayout(top_layout)
        
        # Filter section
        filter_layout = QHBoxLayout()
        
        # Category filters
        self.category_buttons = {}
        self.category_button_layout = QHBoxLayout()
        self.category_button_layout.setSpacing(10)
        
        # All categories button
        all_categories_button = QPushButton("All Categories", self.header_widget)
        all_categories_button.setCheckable(True)
        all_categories_button.setChecked(True)
        all_categories_button.setProperty("category", None)
        self.category_buttons[None] = all_categories_button
        all_categories_button.clicked.connect(lambda: self.set_category_filter(None))
        self.category_button_layout.addWidget(all_categories_button)
        
        self.update_category_button_style(all_categories_button, True)
        
        filter_layout.addLayout(self.category_button_layout)
        
        filter_layout.addStretch()
        
        # View mode toggle
        view_toggle_layout = QHBoxLayout()
        view_toggle_layout.setSpacing(5)
        
        self.grid_view_button = QPushButton(self.header_widget)
        self.grid_view_button.setIcon(self.style().standardIcon(QStyle.SP_FileDialogDetailedView))
        self.grid_view_button.setToolTip("Grid View")
        self.grid_view_button.setFixedSize(36, 36)
        self.grid_view_button.clicked.connect(lambda: self.set_view_mode("grid"))
        view_toggle_layout.addWidget(self.grid_view_button)
        
        self.table_view_button = QPushButton(self.header_widget)
        self.table_view_button.setIcon(self.style().standardIcon(QStyle.SP_FileDialogListView))
        self.table_view_button.setToolTip("Table View")
        self.table_view_button.setFixedSize(36, 36)
        self.table_view_button.clicked.connect(lambda: self.set_view_mode("table"))
        view_toggle_layout.addWidget(self.table_view_button)
        
        # Update button styles based on current view mode
        self.update_view_toggle_styles()
        
        filter_layout.addLayout(view_toggle_layout)
        
        header_layout.addLayout(filter_layout)
    
    def setup_status_bar(self):
        """Set up the status bar with item count and export button."""
        self.status_layout = QHBoxLayout()
        self.status_layout.setContentsMargins(0, 0, 0, 10)
        
        self.status_label = QLabel(self.content_widget)
        self.status_label.setStyleSheet(f"""
            color: {GuardTheme.TEXT_MUTED};
            font-size: 13px;
        """)
        self.status_layout.addWidget(self.status_label)
        
        self.status_layout.addStretch()
        
        export_button = QPushButton("Export Data", self.content_widget)
        export_button.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                color: {GuardTheme.TEXT_NORMAL};
                border: none;
                font-size: 13px;
            }}
            QPushButton:hover {{
                color: {GuardTheme.TEXT_BRIGHT};
                text-decoration: underline;
            }}
        """)
        export_button.clicked.connect(self.export_data)
        self.status_layout.addWidget(export_button)
    
    def create_data_card(self, item, row, col):
        """Create a data card for grid view."""
        card = CardWidget(self.grid_content)
        card.setFixedSize(300, 200)
        card.setProperty("item_data", item)
        
        # Main layout
        card_layout = QVBoxLayout()
        card_layout.setContentsMargins(0, 0, 0, 0)
        card_layout.setSpacing(10)
        
        # Category color indicator
        category_color = self.get_category_color(item.get("Category", ""))
        color_bar = QFrame(card)
        color_bar.setFixedHeight(5)
        color_bar.setStyleSheet(f"background-color: {category_color};")
        card_layout.addWidget(color_bar)
        
        # Card content layout
        content_layout = QVBoxLayout()
        content_layout.setContentsMargins(15, 10, 15, 15)
        content_layout.setSpacing(15)
        
        # Header with type and security level
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)
        
        type_layout = QVBoxLayout()
        type_layout.setSpacing(5)
        
        type_name = QLabel(item.get("Type", "Unknown"), card)
        type_name.setStyleSheet(f"""
            font-size: 16px;
            font-weight: bold;
            color: {GuardTheme.TEXT_BRIGHT};
        """)
        type_layout.addWidget(type_name)
        
        category_name = QLabel(item.get("Category", "Unknown"), card)
        category_name.setStyleSheet(f"""
            font-size: 12px;
            color: {GuardTheme.TEXT_NORMAL};
        """)
        type_layout.addWidget(category_name)
        
        header_layout.addLayout(type_layout)
        
        security_level = self.get_security_level(item)
        security_label = QLabel(security_level, card)
        security_label.setStyleSheet(self.get_security_label_style(security_level))
        header_layout.addWidget(security_label, 0, Qt.AlignRight | Qt.AlignTop)
        
        content_layout.addLayout(header_layout)
        
        # Separator
        separator = QFrame(card)
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)
        separator.setStyleSheet(f"background-color: {GuardTheme.BORDER_DARK};")
        content_layout.addWidget(separator)
        
        # Card info
        info_layout = QHBoxLayout()
        info_layout.setContentsMargins(0, 0, 0, 0)
        
        details_layout = QVBoxLayout()
        details_layout.setSpacing(5)
        
        id_label = QLabel(f"ID: {item.get('_id', 'Unknown')}", card)
        id_label.setStyleSheet(f"""
            font-size: 12px;
            color: {GuardTheme.TEXT_MUTED};
        """)
        details_layout.addWidget(id_label)
        
        updated_label = QLabel(f"Updated: {item.get('lastUpdated', 'Unknown')}", card)
        updated_label.setStyleSheet(f"""
            font-size: 12px;
            color: {GuardTheme.TEXT_MUTED};
        """)
        details_layout.addWidget(updated_label)
        
        info_layout.addLayout(details_layout)
        
        # Action buttons
        actions_layout = QHBoxLayout()
        actions_layout.setSpacing(5)
        
        view_button = QPushButton(card)
        view_button.setIcon(self.style().standardIcon(QStyle.SP_FileDialogContentsView))
        view_button.setFixedSize(30, 30)
        view_button.setToolTip("View")
        view_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {GuardTheme.BG_LIGHT};
                border: none;
                border-radius: 4px;
                padding: 5px;
            }}
            QPushButton:hover {{
                background-color: {GuardTheme.PRIMARY};
            }}
        """)
        view_button.clicked.connect(lambda: self.view_item(item))
        actions_layout.addWidget(view_button)
        
        edit_button = QPushButton(card)
        edit_button.setIcon(self.style().standardIcon(QStyle.SP_FileDialogDetailedView))
        edit_button.setFixedSize(30, 30)
        edit_button.setToolTip("Edit")
        edit_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {GuardTheme.BG_LIGHT};
                border: none;
                border-radius: 4px;
                padding: 5px;
            }}
            QPushButton:hover {{
                background-color: {GuardTheme.WARNING};
            }}
        """)
        edit_button.clicked.connect(lambda: self.edit_item(item))
        actions_layout.addWidget(edit_button)
        
        info_layout.addLayout(actions_layout)
        
        content_layout.addLayout(info_layout)
        
        card_layout.addLayout(content_layout)
        
        # Finalize card
        card.setLayout(card_layout)
        
        # Add to grid
        self.grid_layout.addWidget(card, row, col)
        
        return card
    
    def update_category_button_style(self, button, is_selected):
        """Update the style of a category filter button."""
        if is_selected:
            button.setStyleSheet(f"""
                QPushButton {{
                    background-color: {GuardTheme.PRIMARY};
                    color: white;
                    border: none;
                    border-radius: 15px;
                    padding: 5px 15px;
                    font-weight: bold;
                }}
                QPushButton:hover {{
                    background-color: {GuardTheme.PRIMARY_DARK};
                }}
            """)
        else:
            button.setStyleSheet(f"""
                QPushButton {{
                    background-color: {GuardTheme.BG_LIGHT};
                    color: {GuardTheme.TEXT_NORMAL};
                    border: none;
                    border-radius: 15px;
                    padding: 5px 15px;
                }}
                QPushButton:hover {{
                    background-color: {GuardTheme.HOVER_BG};
                    color: {GuardTheme.TEXT_BRIGHT};
                }}
            """)

if __name__ == '__main__':
    # Enable high DPI scaling
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Use Fusion style for consistent cross-platform appearance
    
    # Apply global stylesheet
    # app.setStyleSheet(StandardTheme.get_complete_application_style())
    
    # Create and show main window
    window = ModernDataViewDialog()
    window.show()
    
    sys.exit(app.exec_())