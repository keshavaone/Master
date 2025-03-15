# UI/Desktop/styling.py

"""
Modern styling framework for the GUARD application.
This module provides consistent colors, themes, and styling utilities.
"""

from PyQt5.QtGui import QColor, QFont, QPalette, QIcon
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QApplication, QStyleFactory

class GuardColors:
    """Color palette for the GUARD application."""
    # Primary colors
    PRIMARY = "#1976D2"  # Modern blue 
    PRIMARY_LIGHT = "#64B5F6"
    PRIMARY_DARK = "#0D47A1"
    
    # Secondary colors
    SECONDARY = "#26A69A"  # Teal
    SECONDARY_LIGHT = "#80CBC4"
    SECONDARY_DARK = "#00796B"
    
    # Accent colors
    ACCENT = "#E91E63"  # Pink
    ACCENT_LIGHT = "#F48FB1"
    ACCENT_DARK = "#AD1457"
    
    # Status colors
    SUCCESS = "#4CAF50"  # Green
    WARNING = "#FFC107"  # Amber
    DANGER = "#F44336"  # Red
    INFO = "#2196F3"  # Blue
    
    # Neutral colors
    NEUTRAL_100 = "#FAFAFA"  # Lightest
    NEUTRAL_200 = "#F5F5F5"
    NEUTRAL_300 = "#EEEEEE"
    NEUTRAL_400 = "#E0E0E0"
    NEUTRAL_500 = "#9E9E9E"  # Medium
    NEUTRAL_600 = "#757575"
    NEUTRAL_700 = "#616161"
    NEUTRAL_800 = "#424242"
    NEUTRAL_900 = "#212121"  # Darkest
    
    # Pure colors
    WHITE = "#FFFFFF"
    BLACK = "#000000"
    TRANSPARENT = "transparent"
    
    # Authentication type colors
    AWS_SSO = "#FF9900"  # AWS Orange
    PASSWORD = "#1976D2"  # Blue
    
    # Security status colors
    SECURE = "#4CAF50"  # Green
    CAUTION = "#FFC107"  # Amber
    INSECURE = "#F44336"  # Red
    
    @staticmethod
    def get_expiration_color(seconds_remaining):
        """Get the appropriate color based on expiration time."""
        if seconds_remaining < 300:  # Less than 5 minutes
            return GuardColors.DANGER
        elif seconds_remaining < 900:  # Less than 15 minutes
            return GuardColors.WARNING
        else:
            return GuardColors.SUCCESS


class GuardTheme:
    """Theme management for the GUARD application."""
    
    LIGHT = "light"
    DARK = "dark"
    
    @staticmethod
    def apply_theme(app, theme_name=LIGHT):
        """
        Apply the specified theme to the application.
        
        Args:
            app: QApplication instance
            theme_name: Theme name (light or dark)
        """
        # Set application style
        app.setStyle(QStyleFactory.create("Fusion"))
        
        # Create palette
        palette = QPalette()
        
        if theme_name == GuardTheme.DARK:
            # Dark theme
            palette.setColor(QPalette.Window, QColor(GuardColors.NEUTRAL_900))
            palette.setColor(QPalette.WindowText, QColor(GuardColors.WHITE))
            palette.setColor(QPalette.Base, QColor(GuardColors.NEUTRAL_800))
            palette.setColor(QPalette.AlternateBase, QColor(GuardColors.NEUTRAL_700))
            palette.setColor(QPalette.ToolTipBase, QColor(GuardColors.WHITE))
            palette.setColor(QPalette.ToolTipText, QColor(GuardColors.WHITE))
            palette.setColor(QPalette.Text, QColor(GuardColors.WHITE))
            palette.setColor(QPalette.Button, QColor(GuardColors.NEUTRAL_700))
            palette.setColor(QPalette.ButtonText, QColor(GuardColors.WHITE))
            palette.setColor(QPalette.BrightText, QColor(GuardColors.RED))
            palette.setColor(QPalette.Link, QColor(GuardColors.PRIMARY_LIGHT))
            palette.setColor(QPalette.Highlight, QColor(GuardColors.PRIMARY))
            palette.setColor(QPalette.HighlightedText, QColor(GuardColors.WHITE))
        else:
            # Light theme
            palette.setColor(QPalette.Window, QColor(GuardColors.NEUTRAL_200))
            palette.setColor(QPalette.WindowText, QColor(GuardColors.NEUTRAL_900))
            palette.setColor(QPalette.Base, QColor(GuardColors.WHITE))
            palette.setColor(QPalette.AlternateBase, QColor(GuardColors.NEUTRAL_100))
            palette.setColor(QPalette.ToolTipBase, QColor(GuardColors.WHITE))
            palette.setColor(QPalette.ToolTipText, QColor(GuardColors.NEUTRAL_900))
            palette.setColor(QPalette.Text, QColor(GuardColors.NEUTRAL_900))
            palette.setColor(QPalette.Button, QColor(GuardColors.NEUTRAL_300))
            palette.setColor(QPalette.ButtonText, QColor(GuardColors.NEUTRAL_900))
            palette.setColor(QPalette.Link, QColor(GuardColors.PRIMARY))
            palette.setColor(QPalette.Highlight, QColor(GuardColors.PRIMARY))
            palette.setColor(QPalette.HighlightedText, QColor(GuardColors.WHITE))
        
        app.setPalette(palette)
        
        # Apply stylesheet
        if theme_name == GuardTheme.DARK:
            app.setStyleSheet(DARK_STYLESHEET)
        else:
            app.setStyleSheet(LIGHT_STYLESHEET)


# Base stylesheet for light theme
LIGHT_STYLESHEET = """
    QMainWindow {
        background-color: #F5F5F5;
    }
    
    QWidget {
        font-family: 'Segoe UI', Arial, sans-serif;
    }
    
    QLabel {
        color: #212121;
        font-size: 14px;
    }
    
    QLabel[heading="true"] {
        font-size: 18px;
        font-weight: bold;
        color: #1976D2;
    }
    
    QPushButton {
        background-color: #1976D2;
        color: white;
        border: none;
        border-radius: 4px;
        padding: 8px 16px;
        font-size: 14px;
        min-height: 20px;
    }
    
    QPushButton:hover {
        background-color: #1565C0;
    }
    
    QPushButton:pressed {
        background-color: #0D47A1;
    }
    
    QPushButton:disabled {
        background-color: #BDBDBD;
        color: #757575;
    }
    
    QPushButton[success="true"] {
        background-color: #4CAF50;
    }
    
    QPushButton[success="true"]:hover {
        background-color: #388E3C;
    }
    
    QPushButton[danger="true"] {
        background-color: #F44336;
    }
    
    QPushButton[danger="true"]:hover {
        background-color: #D32F2F;
    }
    
    QPushButton[warning="true"] {
        background-color: #FFC107;
        color: #212121;
    }
    
    QPushButton[warning="true"]:hover {
        background-color: #FFA000;
    }
    
    QPushButton[flat="true"] {
        background-color: transparent;
        color: #1976D2;
    }
    
    QPushButton[flat="true"]:hover {
        background-color: rgba(25, 118, 210, 0.1);
    }
    
    QLineEdit {
        padding: 8px;
        border: 1px solid #BDBDBD;
        border-radius: 4px;
        background-color: white;
    }
    
    QLineEdit:focus {
        border: 2px solid #1976D2;
    }
    
    QLineEdit:disabled {
        background-color: #F5F5F5;
        color: #9E9E9E;
    }
    
    QTableWidget {
        border: 1px solid #E0E0E0;
        background-color: white;
        gridline-color: #EEEEEE;
        selection-background-color: #E3F2FD;
        selection-color: #212121;
        alternate-background-color: #FAFAFA;
    }
    
    QTableWidget::item {
        padding: 8px;
        border-bottom: 1px solid #F5F5F5;
    }
    
    QTableWidget::item:selected {
        background-color: #E3F2FD;
        color: #212121;
    }
    
    QHeaderView::section {
        background-color: #1976D2;
        color: white;
        padding: 8px;
        font-weight: bold;
        border: none;
        border-right: 1px solid #1565C0;
    }
    
    QComboBox {
        padding: 8px;
        border: 1px solid #BDBDBD;
        border-radius: 4px;
        background-color: white;
    }
    
    QComboBox::drop-down {
        subcontrol-origin: padding;
        subcontrol-position: center right;
        width: 24px;
        border-left: none;
    }
    
    QComboBox QAbstractItemView {
        border: 1px solid #BDBDBD;
        selection-background-color: #E3F2FD;
    }
    
    QTabWidget::pane {
        border: 1px solid #BDBDBD;
        border-radius: 4px;
    }
    
    QTabBar::tab {
        background-color: #E0E0E0;
        color: #757575;
        padding: 10px 20px;
        margin-right: 2px;
        border-top-left-radius: 4px;
        border-top-right-radius: 4px;
    }
    
    QTabBar::tab:selected {
        background-color: #1976D2;
        color: white;
    }
    
    QTabBar::tab:hover:!selected {
        background-color: #BDBDBD;
    }
    
    QProgressBar {
        border: none;
        border-radius: 4px;
        background-color: #E0E0E0;
        text-align: center;
        color: #212121;
        font-weight: bold;
    }
    
    QProgressBar::chunk {
        background-color: #1976D2;
        border-radius: 4px;
    }
    
    QScrollBar:vertical {
        border: none;
        background-color: #F5F5F5;
        width: 10px;
        margin: 0px;
    }
    
    QScrollBar::handle:vertical {
        background-color: #BDBDBD;
        border-radius: 5px;
        min-height: 20px;
    }
    
    QScrollBar::handle:vertical:hover {
        background-color: #9E9E9E;
    }
    
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
        height: 0px;
    }
    
    QScrollBar:horizontal {
        border: none;
        background-color: #F5F5F5;
        height: 10px;
        margin: 0px;
    }
    
    QScrollBar::handle:horizontal {
        background-color: #BDBDBD;
        border-radius: 5px;
        min-width: 20px;
    }
    
    QScrollBar::handle:horizontal:hover {
        background-color: #9E9E9E;
    }
    
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
        width: 0px;
    }
    
    QMenuBar {
        background-color: #1976D2;
        color: white;
    }
    
    QMenuBar::item {
        background-color: transparent;
        padding: 8px 16px;
    }
    
    QMenuBar::item:selected {
        background-color: #1565C0;
    }
    
    QMenu {
        background-color: white;
        border: 1px solid #E0E0E0;
    }
    
    QMenu::item {
        padding: 8px 16px;
    }
    
    QMenu::item:selected {
        background-color: #E3F2FD;
        color: #212121;
    }
    
    QGroupBox {
        border: 1px solid #BDBDBD;
        border-radius: 4px;
        margin-top: 16px;
        padding-top: 16px;
    }
    
    QGroupBox::title {
        subcontrol-origin: margin;
        subcontrol-position: top left;
        left: 8px;
        padding: 0 5px;
        color: #1976D2;
        font-weight: bold;
    }
    
    QStatusBar {
        background-color: #F5F5F5;
        color: #757575;
    }
    
    QToolTip {
        background-color: #212121;
        color: white;
        border: none;
        padding: 8px;
        opacity: 225;
    }
    
    QDialog {
        background-color: #FAFAFA;
    }
"""

# Dark stylesheet
DARK_STYLESHEET = """
    QMainWindow {
        background-color: #212121;
    }
    
    QWidget {
        font-family: 'Segoe UI', Arial, sans-serif;
    }
    
    QLabel {
        color: #FAFAFA;
        font-size: 14px;
    }
    
    QLabel[heading="true"] {
        font-size: 18px;
        font-weight: bold;
        color: #64B5F6;
    }
    
    QPushButton {
        background-color: #1976D2;
        color: white;
        border: none;
        border-radius: 4px;
        padding: 8px 16px;
        font-size: 14px;
        min-height: 20px;
    }
    
    QPushButton:hover {
        background-color: #1565C0;
    }
    
    QPushButton:pressed {
        background-color: #0D47A1;
    }
    
    QPushButton:disabled {
        background-color: #424242;
        color: #757575;
    }
    
    QPushButton[success="true"] {
        background-color: #4CAF50;
    }
    
    QPushButton[success="true"]:hover {
        background-color: #388E3C;
    }
    
    QPushButton[danger="true"] {
        background-color: #F44336;
    }
    
    QPushButton[danger="true"]:hover {
        background-color: #D32F2F;
    }
    
    QPushButton[warning="true"] {
        background-color: #FFC107;
        color: #212121;
    }
    
    QPushButton[warning="true"]:hover {
        background-color: #FFA000;
    }
    
    QPushButton[flat="true"] {
        background-color: transparent;
        color: #64B5F6;
    }
    
    QPushButton[flat="true"]:hover {
        background-color: rgba(100, 181, 246, 0.1);
    }
    
    QLineEdit {
        padding: 8px;
        border: 1px solid #424242;
        border-radius: 4px;
        background-color: #424242;
        color: #FAFAFA;
    }
    
    QLineEdit:focus {
        border: 2px solid #1976D2;
    }
    
    QLineEdit:disabled {
        background-color: #212121;
        color: #757575;
    }
    
    QTableWidget {
        border: 1px solid #424242;
        background-color: #212121;
        gridline-color: #424242;
        selection-background-color: #1E88E5;
        selection-color: #FAFAFA;
        alternate-background-color: #262626;
    }
    
    QTableWidget::item {
        padding: 8px;
        border-bottom: 1px solid #333333;
    }
    
    QTableWidget::item:selected {
        background-color: #0D47A1;
        color: #FAFAFA;
    }
    
    QHeaderView::section {
        background-color: #0D47A1;
        color: white;
        padding: 8px;
        font-weight: bold;
        border: none;
        border-right: 1px solid #0A3880;
    }
    
    QComboBox {
        padding: 8px;
        border: 1px solid #424242;
        border-radius: 4px;
        background-color: #424242;
        color: #FAFAFA;
    }
    
    QComboBox::drop-down {
        subcontrol-origin: padding;
        subcontrol-position: center right;
        width: 24px;
        border-left: none;
    }
    
    QComboBox QAbstractItemView {
        border: 1px solid #424242;
        background-color: #424242;
        selection-background-color: #0D47A1;
    }
    
    QTabWidget::pane {
        border: 1px solid #424242;
        border-radius: 4px;
    }
    
    QTabBar::tab {
        background-color: #424242;
        color: #BDBDBD;
        padding: 10px 20px;
        margin-right: 2px;
        border-top-left-radius: 4px;
        border-top-right-radius: 4px;
    }
    
    QTabBar::tab:selected {
        background-color: #1976D2;
        color: white;
    }
    
    QTabBar::tab:hover:!selected {
        background-color: #616161;
    }
    
    QProgressBar {
        border: none;
        border-radius: 4px;
        background-color: #424242;
        text-align: center;
        color: #FAFAFA;
        font-weight: bold;
    }
    
    QProgressBar::chunk {
        background-color: #1976D2;
        border-radius: 4px;
    }
    
    QScrollBar:vertical {
        border: none;
        background-color: #333333;
        width: 10px;
        margin: 0px;
    }
    
    QScrollBar::handle:vertical {
        background-color: #616161;
        border-radius: 5px;
        min-height: 20px;
    }
    
    QScrollBar::handle:vertical:hover {
        background-color: #757575;
    }
    
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
        height: 0px;
    }
    
    QScrollBar:horizontal {
        border: none;
        background-color: #333333;
        height: 10px;
        margin: 0px;
    }
    
    QScrollBar::handle:horizontal {
        background-color: #616161;
        border-radius: 5px;
        min-width: 20px;
    }
    
    QScrollBar::handle:horizontal:hover {
        background-color: #757575;
    }
    
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
        width: 0px;
    }
    
    QMenuBar {
        background-color: #1565C0;
        color: white;
    }
    
    QMenuBar::item {
        background-color: transparent;
        padding: 8px 16px;
    }
    
    QMenuBar::item:selected {
        background-color: #0D47A1;
    }
    
    QMenu {
        background-color: #424242;
        border: 1px solid #616161;
    }
    
    QMenu::item {
        padding: 8px 16px;
        color: #FAFAFA;
    }
    
    QMenu::item:selected {
        background-color: #1976D2;
        color: #FAFAFA;
    }
    
    QGroupBox {
        border: 1px solid #424242;
        border-radius: 4px;
        margin-top: 16px;
        padding-top: 16px;
    }
    
    QGroupBox::title {
        subcontrol-origin: margin;
        subcontrol-position: top left;
        left: 8px;
        padding: 0 5px;
        color: #64B5F6;
        font-weight: bold;
    }
    
    QStatusBar {
        background-color: #212121;
        color: #BDBDBD;
    }
    
    QToolTip {
        background-color: #FAFAFA;
        color: #212121;
        border: none;
        padding: 8px;
        opacity: 225;
    }
    
    QDialog {
        background-color: #212121;
    }
"""