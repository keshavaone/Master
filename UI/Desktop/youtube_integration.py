# UI/Desktop/youtube_integration.py
"""
YouTube downloader integration for the GUARD application.

This module provides a wrapper for the YouTube downloader that doesn't
require authentication to use.
"""

import logging
from typing import Callable, Optional
from PyQt5.QtWidgets import QTabWidget, QMessageBox
from PyQt5.QtCore import QDateTime

# Try to import the YouTube downloader
try:
    from UI.Desktop.youtube_ui import YouTubeDownloaderWidget
    YOUTUBE_DOWNLOADER_AVAILABLE = True
except ImportError:
    YOUTUBE_DOWNLOADER_AVAILABLE = False
    logging.warning("YouTube downloader component not available")

def setup_youtube_downloader(main_window, tab_widget: QTabWidget, log_callback: Optional[Callable] = None):
    """
    Set up and integrate the YouTube downloader with the main application.
    
    Args:
        main_window: The main application window
        tab_widget: Tab widget to add the YouTube downloader tab to
        log_callback: Optional callback for logging
        
    Returns:
        The YouTube downloader widget or None if not available
    """
    if not YOUTUBE_DOWNLOADER_AVAILABLE:
        if log_callback:
            timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
            log_callback(timestamp, "YouTube downloader component not available")
        return None
    
    try:
        # Create a default log callback if none provided
        if not log_callback:
            def default_log(timestamp, message):
                logging.info(f"{timestamp} - {message}")
            log_callback = default_log
        
        # Log start of setup
        timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
        log_callback(timestamp, "Setting up YouTube downloader component")
        
        # Create the YouTube downloader widget
        yt_downloader = YouTubeDownloaderWidget(
            parent=main_window,
            log_callback=lambda msg: log_callback(
                QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
                f"YouTube Downloader: {msg}"
            )
        )
        
        # Add the downloader as a tab
        downloader_tab_index = tab_widget.addTab(yt_downloader, "YouTube Downloader")
        
        # Store reference to the downloader widget
        main_window.downloader_widget = yt_downloader
        
        # Set initial tab to YouTube downloader
        tab_widget.setCurrentIndex(downloader_tab_index)
        
        # Log completion
        log_callback(timestamp, "YouTube downloader component initialized successfully")
        
        return yt_downloader
        
    except Exception as e:
        logging.error(f"Error setting up YouTube downloader: {str(e)}")
        if log_callback:
            timestamp = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")
            log_callback(timestamp, f"Error setting up YouTube downloader: {str(e)}")
        
        # Show error dialog
        QMessageBox.warning(
            main_window,
            "Component Error",
            f"Could not initialize YouTube downloader component: {str(e)}"
        )
        
        return None