"""
GUARD application theme module for consistent styling across the application.

This module provides a unified approach to UI styling with a consistent color
scheme, component styles, and design patterns that follow modern UI principles
while maintaining a secure and professional appearance.
"""

from PyQt5.QtWidgets import QGraphicsDropShadowEffect
from PyQt5.QtGui import QColor
from PyQt5.QtCore import Qt, QSize


class StandardTheme:
    """
    GUARD application theme with consistent styling and design patterns.
    
    This class provides standardized colors, font styles, component styles,
    and design patterns to be used across the application for a consistent
    and professional appearance.
    """
    
    # Core brand colors
    PRIMARY = "#1976D2"         # Primary blue
    PRIMARY_LIGHT = "#BBDEFB"
    PRIMARY_DARK = "#0D47A1" 
    
    SECONDARY = "#455A64"       # Dark blue-gray
    SECONDARY_LIGHT = "#CFD8DC"
    SECONDARY_DARK = "#263238"
    
    # AWS specific colors (for SSO integration)
    AWS_ORANGE = "#FF9900"
    AWS_LIGHT = "#FFECB3"
    AWS_DARK = "#E65100"
    
    # Status/State colors
    SUCCESS = "#4CAF50"         # Green
    SUCCESS_LIGHT = "#C8E6C9"
    SUCCESS_DARK = "#2E7D32"
    
    WARNING = "#FFC107"         # Amber
    WARNING_LIGHT = "#FFECB3"
    WARNING_DARK = "#FF8F00"
    
    DANGER = "#F44336"          # Red
    DANGER_LIGHT = "#FFCDD2"
    DANGER_DARK = "#B71C1C"
    
    INFO = "#2196F3"            # Light Blue
    INFO_LIGHT = "#B3E5FC"
    INFO_DARK = "#0277BD"
    
    # Gray scale
    GRAY_50 = "#FAFAFA"
    GRAY_100 = "#F5F5F5"
    GRAY_200 = "#EEEEEE"
    GRAY_300 = "#E0E0E0"
    GRAY_400 = "#BDBDBD"
    GRAY_500 = "#9E9E9E"
    GRAY_600 = "#757575"
    GRAY_700 = "#616161"
    GRAY_800 = "#424242"
    GRAY_900 = "#212121"
    
    # Text colors
    TEXT_PRIMARY = "#212121"
    TEXT_SECONDARY = "#757575"
    TEXT_DISABLED = "#9E9E9E"
    TEXT_LIGHT = "#FFFFFF"
    
    # Background colors
    BG_DEFAULT = "#FFFFFF"
    BG_PAPER = "#F5F5F5"
    BG_DARK = "#EEEEEE"
    
    # Font families
    FONT_FAMILY_PRIMARY = "'Segoe UI', 'Helvetica Neue', Arial, sans-serif"
    FONT_FAMILY_MONOSPACE = "'Consolas', 'Courier New', monospace"
    
    # Font sizes
    FONT_SIZE_SMALL = "11px"
    FONT_SIZE_NORMAL = "13px"
    FONT_SIZE_MEDIUM = "15px"
    FONT_SIZE_LARGE = "18px"
    FONT_SIZE_XLARGE = "24px"
    
    # Border radius
    BORDER_RADIUS_SMALL = "4px"
    BORDER_RADIUS_MEDIUM = "6px"
    BORDER_RADIUS_LARGE = "8px"
    
    # Transition duration
    TRANSITION_DURATION = "0.15s"
    
    # Spacing
    SPACING_UNIT = 8
    
    @classmethod
    def add_shadow(cls, widget, radius=10, offset=3, color_alpha=30):
        """
        Add a drop shadow effect to a widget.
        
        Args:
            widget: The widget to add shadow to
            radius (int): Shadow blur radius
            offset (int): Shadow offset
            color_alpha (int): Shadow opacity (0-255)
            
        Returns:
            QGraphicsDropShadowEffect: The created shadow effect
        """
        shadow = QGraphicsDropShadowEffect(widget)
        shadow.setBlurRadius(radius)
        shadow.setColor(QColor(0, 0, 0, color_alpha))
        shadow.setOffset(0, offset)
        widget.setGraphicsEffect(shadow)
        return shadow
    
    @classmethod
    def get_button_style(cls, button_type='primary', size='medium', disabled=False):
        """
        Get a standardized button style based on type and size.
        
        Args:
            button_type (str): 'primary', 'secondary', 'success', 'danger', 
                              'warning', 'info', 'text', 'outline', or 'aws'
            size (str): 'small', 'medium', 'large'
            disabled (bool): Whether the button is disabled
            
        Returns:
            str: CSS style string for the button
        """
        # Base style for all buttons
        style = """
            QPushButton {
                border: none;
                border-radius: """ + cls.BORDER_RADIUS_MEDIUM + """;
                font-family: """ + cls.FONT_FAMILY_PRIMARY + """;
                font-weight: 600;
                color: """ + cls.TEXT_LIGHT + """;
                transition: background-color """ + cls.TRANSITION_DURATION + """;
            }
            QPushButton:hover {
                transition: background-color """ + cls.TRANSITION_DURATION + """;
            }
            QPushButton:disabled {
                background-color: """ + cls.GRAY_300 + """;
                color: """ + cls.GRAY_500 + """;
            }
        """
        
        # Size variations
        if size == 'small':
            style += """
                QPushButton {
                    padding: 4px 10px;
                    font-size: """ + cls.FONT_SIZE_SMALL + """;
                }
            """
        elif size == 'medium':
            style += """
                QPushButton {
                    padding: 6px 16px;
                    font-size: """ + cls.FONT_SIZE_NORMAL + """;
                }
            """
        else:  # large
            style += """
                QPushButton {
                    padding: 8px 22px;
                    font-size: """ + cls.FONT_SIZE_MEDIUM + """;
                }
            """
        
        # Type variations
        if button_type == 'primary':
            style += """
                QPushButton {
                    background-color: """ + cls.PRIMARY + """;
                }
                QPushButton:hover {
                    background-color: """ + cls.PRIMARY_DARK + """;
                }
                QPushButton:pressed {
                    background-color: """ + cls.PRIMARY_DARK + """;
                }
            """
        elif button_type == 'secondary':
            style += """
                QPushButton {
                    background-color: """ + cls.SECONDARY + """;
                }
                QPushButton:hover {
                    background-color: """ + cls.SECONDARY_DARK + """;
                }
                QPushButton:pressed {
                    background-color: """ + cls.SECONDARY_DARK + """;
                }
            """
        elif button_type == 'success':
            style += """
                QPushButton {
                    background-color: """ + cls.SUCCESS + """;
                }
                QPushButton:hover {
                    background-color: """ + cls.SUCCESS_DARK + """;
                }
                QPushButton:pressed {
                    background-color: """ + cls.SUCCESS_DARK + """;
                }
            """
        elif button_type == 'danger':
            style += """
                QPushButton {
                    background-color: """ + cls.DANGER + """;
                }
                QPushButton:hover {
                    background-color: """ + cls.DANGER_DARK + """;
                }
                QPushButton:pressed {
                    background-color: """ + cls.DANGER_DARK + """;
                }
            """
        elif button_type == 'warning':
            style += """
                QPushButton {
                    background-color: """ + cls.WARNING + """;
                    color: """ + cls.TEXT_PRIMARY + """;
                }
                QPushButton:hover {
                    background-color: """ + cls.WARNING_DARK + """;
                    color: """ + cls.TEXT_LIGHT + """;
                }
                QPushButton:pressed {
                    background-color: """ + cls.WARNING_DARK + """;
                    color: """ + cls.TEXT_LIGHT + """;
                }
            """
        elif button_type == 'info':
            style += """
                QPushButton {
                    background-color: """ + cls.INFO + """;
                }
                QPushButton:hover {
                    background-color: """ + cls.INFO_DARK + """;
                }
                QPushButton:pressed {
                    background-color: """ + cls.INFO_DARK + """;
                }
            """
        elif button_type == 'aws':
            style += """
                QPushButton {
                    background-color: """ + cls.AWS_ORANGE + """;
                }
                QPushButton:hover {
                    background-color: """ + cls.AWS_DARK + """;
                }
                QPushButton:pressed {
                    background-color: """ + cls.AWS_DARK + """;
                }
            """
        elif button_type == 'text':
            style += """
                QPushButton {
                    background-color: transparent;
                    color: """ + cls.PRIMARY + """;
                }
                QPushButton:hover {
                    background-color: """ + cls.PRIMARY_LIGHT + """;
                    color: """ + cls.PRIMARY_DARK + """;
                }
                QPushButton:pressed {
                    background-color: """ + cls.PRIMARY_LIGHT + """;
                    color: """ + cls.PRIMARY_DARK + """;
                }
                QPushButton:disabled {
                    background-color: transparent;
                    color: """ + cls.GRAY_400 + """;
                }
            """
        elif button_type == 'outline':
            style += """
                QPushButton {
                    background-color: transparent;
                    color: """ + cls.PRIMARY + """;
                    border: 1px solid """ + cls.PRIMARY + """;
                }
                QPushButton:hover {
                    background-color: """ + cls.PRIMARY_LIGHT + """;
                    color: """ + cls.PRIMARY_DARK + """;
                    border: 1px solid """ + cls.PRIMARY_DARK + """;
                }
                QPushButton:pressed {
                    background-color: """ + cls.PRIMARY_LIGHT + """;
                    color: """ + cls.PRIMARY_DARK + """;
                    border: 1px solid """ + cls.PRIMARY_DARK + """;
                }
                QPushButton:disabled {
                    background-color: transparent;
                    color: """ + cls.GRAY_400 + """;
                    border: 1px solid """ + cls.GRAY_400 + """;
                }
            """
        
        return style
    
    @classmethod
    def get_label_style(cls, type='default', size='medium', bold=False):
        """
        Get standardized label styling.
        
        Args:
            type (str): 'default', 'primary', 'secondary', 'success', 'danger', 
                       'warning', 'info', 'muted'
            size (str): 'small', 'medium', 'large', 'xlarge'
            bold (bool): Whether to use bold font weight
            
        Returns:
            str: CSS style string for the label
        """
        # Base style for all labels
        style = """
            font-family: """ + cls.FONT_FAMILY_PRIMARY + """;
        """
        
        # Add font weight if bold
        if bold:
            style += """
                font-weight: bold;
            """
        
        # Size variations
        if size == 'small':
            style += """
                font-size: """ + cls.FONT_SIZE_SMALL + """;
            """
        elif size == 'medium':
            style += """
                font-size: """ + cls.FONT_SIZE_NORMAL + """;
            """
        elif size == 'large':
            style += """
                font-size: """ + cls.FONT_SIZE_LARGE + """;
            """
        elif size == 'xlarge':
            style += """
                font-size: """ + cls.FONT_SIZE_XLARGE + """;
            """
        
        # Type variations
        if type == 'primary':
            style += """
                color: """ + cls.PRIMARY + """;
            """
        elif type == 'secondary':
            style += """
                color: """ + cls.SECONDARY + """;
            """
        elif type == 'success':
            style += """
                color: """ + cls.SUCCESS + """;
            """
        elif type == 'danger':
            style += """
                color: """ + cls.DANGER + """;
            """
        elif type == 'warning':
            style += """
                color: """ + cls.WARNING + """;
            """
        elif type == 'info':
            style += """
                color: """ + cls.INFO + """;
            """
        elif type == 'muted':
            style += """
                color: """ + cls.TEXT_SECONDARY + """;
            """
        else:  # default
            style += """
                color: """ + cls.TEXT_PRIMARY + """;
            """
        
        return style
    
    @classmethod
    def get_frame_style(cls, type='default', elevation=0):
        """
        Get standardized frame styling.
        
        Args:
            type (str): 'default', 'card', 'panel', 'paper', 'raised'
            elevation (int): Shadow elevation level (0-3)
            
        Returns:
            str: CSS style string for the frame
        """
        # Base style for all frames
        style = """
            background-color: """ + cls.BG_DEFAULT + """;
            border-radius: """ + cls.BORDER_RADIUS_MEDIUM + """;
        """
        
        # Type variations
        if type == 'card':
            style += """
                border: 1px solid """ + cls.GRAY_200 + """;
                padding: 16px;
            """
        elif type == 'panel':
            style += """
                border: 1px solid """ + cls.GRAY_300 + """;
                padding: 12px;
            """
        elif type == 'paper':
            style += """
                background-color: """ + cls.BG_PAPER + """;
                border: 1px solid """ + cls.GRAY_200 + """;
                padding: 8px;
            """
        elif type == 'raised':
            style += """
                border: none;
                padding: 16px;
                margin: """ + str(elevation * 2) + """px;
            """
        else:  # default
            style += """
                border: 1px solid """ + cls.GRAY_300 + """;
            """
        
        return style
    
    @classmethod
    def get_card_style(cls, card_type='default', elevation=1):
        """
        Get a standardized card style with optional elevation.
        
        Args:
            card_type (str): 'default', 'primary', 'secondary', 'success', 'warning', 'danger', 'info'
            elevation (int): Shadow elevation (0-3)
            
        Returns:
            str: CSS style string for the card
        """
        # Base card style
        style = """
            QFrame {
                background-color: """ + cls.BG_DEFAULT + """;
                border-radius: """ + cls.BORDER_RADIUS_LARGE + """;
                padding: """ + str(cls.SPACING_UNIT * 2) + """px;
            }
        """
        
        # Add border based on type
        if card_type == 'default':
            style += """
                QFrame {
                    border: 1px solid """ + cls.GRAY_200 + """;
                }
            """
        elif card_type == 'primary':
            style += """
                QFrame {
                    border: 1px solid """ + cls.PRIMARY_LIGHT + """;
                }
            """
        elif card_type == 'secondary':
            style += """
                QFrame {
                    border: 1px solid """ + cls.SECONDARY_LIGHT + """;
                }
            """
        elif card_type == 'success':
            style += """
                QFrame {
                    border: 1px solid """ + cls.SUCCESS_LIGHT + """;
                }
            """
        elif card_type == 'warning':
            style += """
                QFrame {
                    border: 1px solid """ + cls.WARNING_LIGHT + """;
                }
            """
        elif card_type == 'danger':
            style += """
                QFrame {
                    border: 1px solid """ + cls.DANGER_LIGHT + """;
                }
            """
        elif card_type == 'info':
            style += """
                QFrame {
                    border: 1px solid """ + cls.INFO_LIGHT + """;
                }
            """
        
        # Add elevation (for shadow effect via code)
        # The shadow will need to be added with cls.add_shadow()
        # This style just to ensure consistent padding with elevation
        if elevation > 0:
            style += """
                QFrame {
                    margin: """ + str(elevation * 2) + """px;
                }
            """
        
        return style
    
    @classmethod
    def get_input_style(cls, state='default'):
        """
        Get standardized input field styles with states.
        
        Args:
            state (str): 'default', 'focus', 'error', 'success', 'disabled'
            
        Returns:
            str: CSS style string for input fields
        """
        # Base input styles
        style = """
            QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox, QDoubleSpinBox {
                background-color: """ + cls.BG_DEFAULT + """;
                color: """ + cls.TEXT_PRIMARY + """;
                font-family: """ + cls.FONT_FAMILY_PRIMARY + """;
                font-size: """ + cls.FONT_SIZE_NORMAL + """;
                border: 1px solid """ + cls.GRAY_300 + """;
                border-radius: """ + cls.BORDER_RADIUS_SMALL + """;
                padding: 6px 10px;
                selection-background-color: """ + cls.PRIMARY_LIGHT + """;
            }
            
            QLineEdit:hover, QTextEdit:hover, QPlainTextEdit:hover, 
            QComboBox:hover, QSpinBox:hover, QDoubleSpinBox:hover {
                border: 1px solid """ + cls.GRAY_400 + """;
            }
            
            QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus,
            QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus {
                border: 1px solid """ + cls.PRIMARY + """;
                background-color: """ + cls.BG_DEFAULT + """;
            }
            
            QLineEdit:disabled, QTextEdit:disabled, QPlainTextEdit:disabled,
            QComboBox:disabled, QSpinBox:disabled, QDoubleSpinBox:disabled {
                background-color: """ + cls.GRAY_100 + """;
                color: """ + cls.TEXT_DISABLED + """;
                border: 1px solid """ + cls.GRAY_200 + """;
            }
            
            /* ComboBox dropdown button */
            QComboBox::drop-down {
                border: none;
                width: 20px;
            }
            
            QComboBox::down-arrow {
                image: none;
                width: 10px;
                height: 10px;
                background: """ + cls.SECONDARY + """;
                border-radius: 5px;
            }
            
            /* SpinBox buttons */
            QSpinBox::up-button, QDoubleSpinBox::up-button,
            QSpinBox::down-button, QDoubleSpinBox::down-button {
                background-color: """ + cls.GRAY_200 + """;
                border: none;
                border-radius: 2px;
                margin: 1px;
            }
            
            QSpinBox::up-button:hover, QDoubleSpinBox::up-button:hover,
            QSpinBox::down-button:hover, QDoubleSpinBox::down-button:hover {
                background-color: """ + cls.GRAY_300 + """;
            }
        """
        
        # Add state-specific styles
        if state == 'error':
            style += """
                QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox, QDoubleSpinBox {
                    border: 1px solid """ + cls.DANGER + """;
                    background-color: """ + cls.DANGER_LIGHT + """;
                }
                
                QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus,
                QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus {
                    border: 1px solid """ + cls.DANGER_DARK + """;
                    background-color: """ + cls.BG_DEFAULT + """;
                }
            """
        elif state == 'success':
            style += """
                QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox, QDoubleSpinBox {
                    border: 1px solid """ + cls.SUCCESS + """;
                    background-color: """ + cls.SUCCESS_LIGHT + """;
                }
                
                QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus,
                QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus {
                    border: 1px solid """ + cls.SUCCESS_DARK + """;
                    background-color: """ + cls.BG_DEFAULT + """;
                }
            """
        
        return style
    
    @classmethod
    def get_table_style(cls, alternating_rows=True, hover_effect=True):
        """
        Get standardized table styles.
        
        Args:
            alternating_rows (bool): Whether to use alternating row colors
            hover_effect (bool): Whether to include row hover effect
            
        Returns:
            str: CSS style string for tables
        """
        style = """
            QTableWidget, QTableView {
                background-color: """ + cls.BG_DEFAULT + """;
                gridline-color: """ + cls.GRAY_200 + """;
                color: """ + cls.TEXT_PRIMARY + """;
                selection-background-color: """ + cls.PRIMARY_LIGHT + """;
                selection-color: """ + cls.PRIMARY_DARK + """;
                border: 1px solid """ + cls.GRAY_300 + """;
                border-radius: """ + cls.BORDER_RADIUS_SMALL + """;
            }
            
            QHeaderView::section {
                background-color: """ + cls.PRIMARY + """;
                color: """ + cls.TEXT_LIGHT + """;
                padding: 6px;
                border: none;
                font-weight: bold;
            }
            
            QTableWidget::item, QTableView::item {
                padding: 4px;
                border-bottom: 1px solid """ + cls.GRAY_200 + """;
            }
        """
        
        # Add alternating row colors if requested
        if alternating_rows:
            style += """
                QTableWidget, QTableView {
                    alternate-background-color: """ + cls.GRAY_50 + """;
                }
            """
        
        # Add hover effect if requested
        if hover_effect:
            style += """
                QTableWidget::item:hover, QTableView::item:hover {
                    background-color: """ + cls.PRIMARY_LIGHT + """;
                }
            """
        
        return style
    
    @classmethod
    def get_scrollbar_style(cls):
        """
        Get standardized scrollbar styles for a modern look.
        
        Returns:
            str: CSS style string for scrollbars
        """
        return """
            QScrollBar:vertical {
                border: none;
                background: """ + cls.GRAY_200 + """;
                width: 8px;
                margin: 0px;
                border-radius: 4px;
            }
            
            QScrollBar::handle:vertical {
                background: """ + cls.GRAY_500 + """;
                min-height: 30px;
                border-radius: 4px;
            }
            
            QScrollBar::handle:vertical:hover {
                background: """ + cls.PRIMARY + """;
            }
            
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                border: none;
                background: none;
                height: 0px;
            }
            
            QScrollBar:horizontal {
                border: none;
                background: """ + cls.GRAY_200 + """;
                height: 8px;
                margin: 0px;
                border-radius: 4px;
            }
            
            QScrollBar::handle:horizontal {
                background: """ + cls.GRAY_500 + """;
                min-width: 30px;
                border-radius: 4px;
            }
            
            QScrollBar::handle:horizontal:hover {
                background: """ + cls.PRIMARY + """;
            }
            
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                border: none;
                background: none;
                width: 0px;
            }
        """
    
    @classmethod
    def get_main_window_style(cls):
        """
        Get styling for the main application window.
        
        Returns:
            str: CSS style string for main window
        """
        return """
            QMainWindow {
                background-color: """ + cls.BG_DEFAULT + """;
                font-family: """ + cls.FONT_FAMILY_PRIMARY + """;
                font-size: """ + cls.FONT_SIZE_NORMAL + """;
                color: """ + cls.TEXT_PRIMARY + """;
            }
            
            QLabel {
                font-family: """ + cls.FONT_FAMILY_PRIMARY + """;
                color: """ + cls.TEXT_PRIMARY + """;
            }
            
            QStatusBar {
                background-color: """ + cls.PRIMARY_DARK + """;
                color: """ + cls.TEXT_LIGHT + """;
                font-family: """ + cls.FONT_FAMILY_PRIMARY + """;
                padding: 3px;
                font-size: """ + cls.FONT_SIZE_SMALL + """;
            }
            
            QStatusBar QLabel {
                color: """ + cls.TEXT_LIGHT + """;
            }
            
            QToolTip {
                background-color: """ + cls.SECONDARY_DARK + """;
                color: """ + cls.TEXT_LIGHT + """;
                border: none;
                font-size: """ + cls.FONT_SIZE_SMALL + """;
                padding: 5px;
            }
        """
    
    @classmethod
    def get_application_style(cls):
        """
        Get main application styling (combines main window and common elements).
        
        Returns:
            str: CSS style string for application
        """
        return cls.get_main_window_style() + """
            /* Common elements styling */
            QWidget {
                font-family: """ + cls.FONT_FAMILY_PRIMARY + """;
            }
            
            QToolBar {
                background-color: """ + cls.BG_PAPER + """;
                border: 1px solid """ + cls.GRAY_300 + """;
                spacing: 4px;
            }
            
            QToolBar QToolButton {
                background-color: transparent;
                border: 1px solid transparent;
                border-radius: 4px;
                padding: 3px;
            }
            
            QToolBar QToolButton:hover {
                background-color: """ + cls.PRIMARY_LIGHT + """;
                border: 1px solid """ + cls.PRIMARY + """;
            }
            
            QToolBar QToolButton:pressed {
                background-color: """ + cls.PRIMARY + """;
            }
            
            QMenu {
                background-color: """ + cls.BG_DEFAULT + """;
                border: 1px solid """ + cls.GRAY_300 + """;
                border-radius: 4px;
            }
            
            QMenu::item {
                padding: 6px 24px 6px 12px;
            }
            
            QMenu::item:selected {
                background-color: """ + cls.PRIMARY_LIGHT + """;
                color: """ + cls.PRIMARY_DARK + """;
            }
            
            QMenu::separator {
                height: 1px;
                background-color: """ + cls.GRAY_300 + """;
                margin: 4px 12px;
            }
        """
    
    @classmethod
    def get_tab_style(cls):
        """
        Get standardized tab widget styling.
        
        Returns:
            str: CSS style string for tab widgets
        """
        return """
            QTabWidget::pane {
                border: 1px solid """ + cls.GRAY_300 + """;
                border-radius: """ + cls.BORDER_RADIUS_SMALL + """;
                top: -1px;
                background-color: """ + cls.BG_DEFAULT + """;
            }
            
            QTabBar::tab {
                background-color: """ + cls.GRAY_200 + """;
                color: """ + cls.TEXT_PRIMARY + """;
                border: 1px solid """ + cls.GRAY_300 + """;
                border-bottom-color: transparent;
                border-top-left-radius: """ + cls.BORDER_RADIUS_SMALL + """;
                border-top-right-radius: """ + cls.BORDER_RADIUS_SMALL + """;
                padding: 8px 16px;
                min-width: 100px;
                font-family: """ + cls.FONT_FAMILY_PRIMARY + """;
                font-weight: 500;
            }
            
            QTabBar::tab:selected {
                background-color: """ + cls.BG_DEFAULT + """;
                border-bottom-color: """ + cls.BG_DEFAULT + """;
                color: """ + cls.PRIMARY + """;
                font-weight: bold;
            }
            
            QTabBar::tab:!selected {
                margin-top: 2px;
            }
            
            QTabBar::tab:hover:!selected {
                background-color: """ + cls.GRAY_300 + """;
            }
        """
    
    @classmethod
    def get_dialog_style(cls):
        """
        Get standardized dialog styling.
        
        Returns:
            str: CSS style string for dialogs
        """
        return """
            QDialog {
                background-color: """ + cls.BG_DEFAULT + """;
                font-family: """ + cls.FONT_FAMILY_PRIMARY + """;
                font-size: """ + cls.FONT_SIZE_NORMAL + """;
                color: """ + cls.TEXT_PRIMARY + """;
            }
            
            QDialog QLabel {
                color: """ + cls.TEXT_PRIMARY + """;
            }
            
            QDialog QLabel#dialogTitle {
                font-size: """ + cls.FONT_SIZE_LARGE + """;
                font-weight: bold;
                color: """ + cls.PRIMARY + """;
                margin-bottom: 10px;
            }
            
            QDialog QPushButton {
                min-width: 80px;
            }
        """
    
    @classmethod
    def get_message_box_style(cls):
        """
        Get standardized message box styling.
        
        Returns:
            str: CSS style string for message boxes
        """
        return """
            QMessageBox {
                background-color: """ + cls.BG_DEFAULT + """;
                font-family: """ + cls.FONT_FAMILY_PRIMARY + """;
                font-size: """ + cls.FONT_SIZE_NORMAL + """;
            }
            
            QMessageBox QLabel {
                color: """ + cls.TEXT_PRIMARY + """;
                min-width: 300px;
            }
            
            QMessageBox QPushButton {
                min-width: 80px;
                min-height: 24px;
            }
        """
    
    @classmethod
    def get_progress_style(cls):
        """
        Get standardized progress bar styling.
        
        Returns:
            str: CSS style string for progress bars
        """
        return """
            QProgressBar {
                border: 1px solid """ + cls.GRAY_300 + """;
                border-radius: """ + cls.BORDER_RADIUS_SMALL + """;
                background-color: """ + cls.GRAY_200 + """;
                text-align: center;
                color: """ + cls.TEXT_PRIMARY + """;
                font-weight: bold;
            }
            
            QProgressBar::chunk {
                background-color: """ + cls.PRIMARY + """;
                border-radius: """ + cls.BORDER_RADIUS_SMALL + """;
            }
            
            QProgressDialog {
                background-color: """ + cls.BG_DEFAULT + """;
                font-family: """ + cls.FONT_FAMILY_PRIMARY + """;
            }
            
            QProgressDialog QLabel {
                font-size: """ + cls.FONT_SIZE_NORMAL + """;
                color: """ + cls.TEXT_PRIMARY + """;
                margin: 10px;
                min-width: 300px;
            }
        """
    
    @classmethod
    def get_complete_application_style(cls):
        """
        Get comprehensive styling for the entire application.
        
        Returns:
            str: Complete CSS style string for the application
        """
        return (
            cls.get_main_window_style() + 
            cls.get_input_style() + 
            cls.get_table_style() +
            cls.get_scrollbar_style() +
            cls.get_tab_style() +
            cls.get_dialog_style() +
            cls.get_message_box_style() +
            cls.get_progress_style()
        )
    
    @classmethod
    def create_icon_button(cls, widget, icon_name, tooltip, size=QSize(24, 24), button_type='primary'):
        """
        Create a standardized icon button.
        
        Args:
            widget: Parent widget
            icon_name: QStyle.StandardPixmap or QIcon
            tooltip: Tooltip text
            size: Button size
            button_type: Button style type
            
        Returns:
            QPushButton: Configured icon button
        """
        from PyQt5.QtWidgets import QPushButton
        
        button = QPushButton(widget)
        
        # Set icon
        if isinstance(icon_name, int):  # StandardPixmap
            button.setIcon(widget.style().standardIcon(icon_name))
        else:  # QIcon
            button.setIcon(icon_name)
            
        button.setIconSize(size)
        button.setFixedSize(size.width() + 8, size.height() + 8)
        button.setToolTip(tooltip)
        button.setCursor(Qt.PointingHandCursor)
        button.setStyleSheet(cls.get_button_style(button_type))
        
        return button