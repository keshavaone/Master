"""
Standard theme for the GUARD application with consistent color schemes and styling.

This module provides a unified approach to UI styling with semantic color naming
for different UI states and components, ensuring consistency across the application.
"""

class StandardTheme:
    """
    Standard theme for the GUARD application.
    
    This class provides a consistent color palette and styling rules for the entire
    application with semantic color naming for different UI states and components.
    """
    # Primary colors
    PRIMARY = "#1976D2"  # Blue
    PRIMARY_LIGHT = "#BBDEFB"
    PRIMARY_DARK = "#0D47A1"
    
    # Secondary/accent colors
    SECONDARY = "#673AB7"  # Purple
    SECONDARY_LIGHT = "#D1C4E9"
    SECONDARY_DARK = "#4527A0"
    
    # State colors
    SUCCESS = "#4CAF50"  # Green
    SUCCESS_LIGHT = "#A5D6A7"
    SUCCESS_DARK = "#2E7D32"
    
    WARNING = "#FF9800"  # Orange
    WARNING_LIGHT = "#FFE0B2"
    WARNING_DARK = "#E65100"
    
    DANGER = "#F44336"  # Red
    DANGER_LIGHT = "#FFCDD2"
    DANGER_DARK = "#B71C1C"
    
    INFO = "#2196F3"  # Light Blue
    INFO_LIGHT = "#B3E5FC"
    INFO_DARK = "#0277BD"
    
    # Neutral colors
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
    
    @classmethod
    def get_button_style(cls, button_type='primary', size='medium', disabled=False):
        """
        Get standardized button styles based on type and state.
        
        Args:
            button_type (str): 'primary', 'secondary', 'success', 'danger', 'warning', 'info'
            size (str): 'small', 'medium', 'large'
            disabled (bool): Whether the button is disabled
            
        Returns:
            str: CSS style string for QPushButton
        """
        # Base style
        style = """
            QPushButton {
                border: none;
                border-radius: 4px;
                font-weight: bold;
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
                    padding: 4px 8px;
                    font-size: 12px;
                }
            """
        elif size == 'medium':
            style += """
                QPushButton {
                    padding: 6px 12px;
                    font-size: 14px;
                }
            """
        else:  # large
            style += """
                QPushButton {
                    padding: 8px 16px;
                    font-size: 16px;
                }
            """
        
        # Type variations
        if button_type == 'primary':
            style += """
                QPushButton {
                    background-color: """ + cls.PRIMARY + """;
                    color: """ + cls.TEXT_LIGHT + """;
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
                    color: """ + cls.TEXT_LIGHT + """;
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
                    color: """ + cls.TEXT_LIGHT + """;
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
                    color: """ + cls.TEXT_LIGHT + """;
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
                    color: """ + cls.TEXT_LIGHT + """;
                }
                QPushButton:hover {
                    background-color: """ + cls.WARNING_DARK + """;
                }
                QPushButton:pressed {
                    background-color: """ + cls.WARNING_DARK + """;
                }
            """
        elif button_type == 'info':
            style += """
                QPushButton {
                    background-color: """ + cls.INFO + """;
                    color: """ + cls.TEXT_LIGHT + """;
                }
                QPushButton:hover {
                    background-color: """ + cls.INFO_DARK + """;
                }
                QPushButton:pressed {
                    background-color: """ + cls.INFO_DARK + """;
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
            """
        
        return style
        
    @classmethod
    def get_table_style(cls):
        """
        Get standardized table styles.
        
        Returns:
            str: CSS style string for QTableWidget
        """
        return """
            QTableWidget {
                gridline-color: """ + cls.GRAY_300 + """;
                border: 1px solid """ + cls.GRAY_300 + """;
                border-radius: 4px;
                selection-background-color: """ + cls.PRIMARY_LIGHT + """;
                selection-color: """ + cls.TEXT_PRIMARY + """;
                alternate-background-color: """ + cls.GRAY_100 + """;
            }
            QHeaderView::section {
                background-color: """ + cls.PRIMARY_LIGHT + """;
                padding: 6px;
                border: 1px solid """ + cls.GRAY_300 + """;
                font-weight: bold;
                color: """ + cls.PRIMARY_DARK + """;
            }
            QTableWidget::item {
                padding: 6px;
            }
            QTableWidget::item:selected {
                color: """ + cls.PRIMARY_DARK + """;
            }
        """
    
    @classmethod
    def get_frame_style(cls, frame_type='default', border=True):
        """
        Get standardized frame styles.
        
        Args:
            frame_type (str): 'default', 'primary', 'secondary', 'success', 'warning', 'danger', 'info'
            border (bool): Whether to include a border
            
        Returns:
            str: CSS style string for QFrame
        """
        # Base style
        style = """
            QFrame {
                border-radius: 4px;
                padding: 8px;
            }
        """
        
        # Add border if requested
        if border:
            style += """
                QFrame {
                    border: 1px solid """ + cls.GRAY_300 + """;
                }
            """
        
        # Type variations
        if frame_type == 'default':
            style += """
                QFrame {
                    background-color: """ + cls.BG_DEFAULT + """;
                }
            """
        elif frame_type == 'primary':
            style += """
                QFrame {
                    background-color: """ + cls.PRIMARY_LIGHT + """;
                    border-color: """ + cls.PRIMARY + """;
                }
            """
        elif frame_type == 'secondary':
            style += """
                QFrame {
                    background-color: """ + cls.SECONDARY_LIGHT + """;
                    border-color: """ + cls.SECONDARY + """;
                }
            """
        elif frame_type == 'success':
            style += """
                QFrame {
                    background-color: """ + cls.SUCCESS_LIGHT + """;
                    border-color: """ + cls.SUCCESS + """;
                }
            """
        elif frame_type == 'warning':
            style += """
                QFrame {
                    background-color: """ + cls.WARNING_LIGHT + """;
                    border-color: """ + cls.WARNING + """;
                }
            """
        elif frame_type == 'danger':
            style += """
                QFrame {
                    background-color: """ + cls.DANGER_LIGHT + """;
                    border-color: """ + cls.DANGER + """;
                }
            """
        elif frame_type == 'info':
            style += """
                QFrame {
                    background-color: """ + cls.INFO_LIGHT + """;
                    border-color: """ + cls.INFO + """;
                }
            """
        elif frame_type == 'paper':
            style += """
                QFrame {
                    background-color: """ + cls.BG_PAPER + """;
                }
            """
        
        return style
    
    @classmethod
    def get_input_style(cls):
        """
        Get standardized input field styles.
        
        Returns:
            str: CSS style string for QLineEdit, QTextEdit, etc.
        """
        return """
            QLineEdit, QTextEdit, QComboBox {
                border: 1px solid """ + cls.GRAY_400 + """;
                border-radius: 4px;
                padding: 6px;
                background-color: """ + cls.BG_DEFAULT + """;
                color: """ + cls.TEXT_PRIMARY + """;
            }
            QLineEdit:focus, QTextEdit:focus, QComboBox:focus {
                border: 1px solid """ + cls.PRIMARY + """;
                outline: none;
            }
            QLineEdit:disabled, QTextEdit:disabled, QComboBox:disabled {
                background-color: """ + cls.GRAY_200 + """;
                border: 1px solid """ + cls.GRAY_300 + """;
                color: """ + cls.TEXT_DISABLED + """;
            }
        """
    
    @classmethod
    def get_label_style(cls, label_type='default', size='medium', bold=False):
        """
        Get standardized label styles.
        
        Args:
            label_type (str): 'default', 'primary', 'secondary', 'success', 'warning', 'danger', 'info'
            size (str): 'small', 'medium', 'large', 'header'
            bold (bool): Whether to make the text bold
            
        Returns:
            str: CSS style string for QLabel
        """
        # Base style
        style = "QLabel { "
        
        # Size variations
        if size == 'small':
            style += "font-size: 11px; "
        elif size == 'medium':
            style += "font-size: 13px; "
        elif size == 'large':
            style += "font-size: 16px; "
        elif size == 'header':
            style += "font-size: 18px; "
        
        # Bold option
        if bold:
            style += "font-weight: bold; "
        
        # Type variations
        if label_type == 'default':
            style += "color: " + cls.TEXT_PRIMARY + "; "
        elif label_type == 'primary':
            style += "color: " + cls.PRIMARY + "; "
        elif label_type == 'secondary':
            style += "color: " + cls.SECONDARY + "; "
        elif label_type == 'success':
            style += "color: " + cls.SUCCESS + "; "
        elif label_type == 'warning':
            style += "color: " + cls.WARNING + "; "
        elif label_type == 'danger':
            style += "color: " + cls.DANGER + "; "
        elif label_type == 'info':
            style += "color: " + cls.INFO + "; "
        elif label_type == 'muted':
            style += "color: " + cls.TEXT_SECONDARY + "; "
        
        style += "}"
        return style
    
    @classmethod
    def get_application_style(cls):
        """
        Get a comprehensive style for the entire application.
        
        Returns:
            str: CSS style string for the main application
        """
        return """
            QMainWindow {
                background-color: """ + cls.BG_DEFAULT + """;
            }
            
            QTabWidget::pane {
                border: 1px solid """ + cls.GRAY_300 + """;
                border-radius: 4px;
                top: -1px;
            }
            
            QTabBar::tab {
                background-color: """ + cls.GRAY_200 + """;
                border: 1px solid """ + cls.GRAY_300 + """;
                border-bottom-color: transparent;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                padding: 8px 12px;
                margin-right: 2px;
            }
            
            QTabBar::tab:selected {
                background-color: """ + cls.BG_DEFAULT + """;
                border-bottom-color: """ + cls.BG_DEFAULT + """;
            }
            
            QTabBar::tab:!selected {
                margin-top: 2px;
            }
            
            QGroupBox {
                border: 1px solid """ + cls.GRAY_300 + """;
                border-radius: 4px;
                margin-top: 12px;
                padding-top: 12px;
                font-weight: bold;
            }
            
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 5px;
                color: """ + cls.PRIMARY + """;
            }
            
            QStatusBar {
                background-color: """ + cls.PRIMARY + """;
                color: """ + cls.TEXT_LIGHT + """;
            }
            
            QScrollBar:vertical {
                border: none;
                background: """ + cls.GRAY_200 + """;
                width: 10px;
                margin: 0px;
            }
            
            QScrollBar::handle:vertical {
                background: """ + cls.PRIMARY + """;
                min-height: 20px;
                border-radius: 5px;
            }
            
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                border: none;
                background: none;
                height: 0px;
            }
            
            QScrollBar:horizontal {
                border: none;
                background: """ + cls.GRAY_200 + """;
                height: 10px;
                margin: 0px;
            }
            
            QScrollBar::handle:horizontal {
                background: """ + cls.PRIMARY + """;
                min-width: 20px;
                border-radius: 5px;
            }
            
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                border: none;
                background: none;
                width: 0px;
            }
            
            QToolTip {
                background-color: """ + cls.BG_DARK + """;
                color: """ + cls.TEXT_PRIMARY + """;
                border: 1px solid """ + cls.GRAY_400 + """;
                padding: 4px;
                border-radius: 2px;
            }
        """