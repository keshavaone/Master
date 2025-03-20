"""
YouTube downloader integration module for the GUARD application.

This module adds YouTube downloading capabilities to the GUARD desktop application,
making it accessible without authentication requirements.
"""

import os
import sys
import subprocess
import threading
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, 
    QLineEdit, QProgressBar, QFileDialog, QGroupBox,
    QRadioButton, QButtonGroup, QMessageBox, QApplication
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject
from PyQt5.QtGui import QIcon, QCursor

class DownloadWorker(QObject):
    """Worker thread for handling YouTube downloads without freezing the UI."""
    progress = pyqtSignal(str)
    completed = pyqtSignal(bool, str)
    
    def __init__(self, url, output_path, format_option):
        """
        Initialize the download worker.
        
        Args:
            url (str): YouTube URL to download
            output_path (str): Path to save the downloaded file
            format_option (str): Selected format option (quicktime, mp4, etc.)
        """
        super().__init__()
        self.url = url
        self.output_path = output_path
        self.format_option = format_option
        self.process = None
        self.is_cancelled = False
        
    def run(self):
        """Run the download process in the background."""
        try:
            # Ensure output directory exists
            if self.output_path and not os.path.exists(self.output_path):
                os.makedirs(self.output_path)
            
            # Prepare output template
            if self.output_path:
                output_template = os.path.join(self.output_path, "%(title)s.%(ext)s")
            else:
                output_template = "%(title)s.%(ext)s"
            
            # Configure format based on selected option
            if self.format_option == "quicktime":
                format_arg = "22/18/best"
                post_args = ["-c:v", "h264", "-c:a", "aac", "-strict", "experimental", "-movflags", "+faststart"]
            elif self.format_option == "mp4_hd":
                format_arg = "bestvideo[ext=mp4][height<=1080]+bestaudio[ext=m4a]/best[ext=mp4]/best"
                post_args = []
            elif self.format_option == "mp4_sd":
                format_arg = "18/best[height<=480]"
                post_args = []
            elif self.format_option == "audio":
                format_arg = "bestaudio[ext=m4a]/bestaudio"
                post_args = []
            else:  # Default
                format_arg = "best"
                post_args = []
            
            # Prepare download command
            cmd = [
                "yt-dlp",
                self.url,
                "-f", format_arg,
                "--output", output_template,
                "--no-playlist",
                "--restrict-filenames",
                "--no-part",
                "--newline",
                "--progress"
            ]
            
            if post_args and self.format_option == "quicktime":
                cmd.extend(["--postprocessor-args", f"ffmpeg:{' '.join(post_args)}"])
                cmd.extend(["--merge-output-format", "mp4"])
            
            self.progress.emit("Starting download...")
            
            # Execute the download process
            self.process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            
            # Read and emit progress updates
            for line in iter(self.process.stdout.readline, ''):
                if self.is_cancelled:
                    self.process.terminate()
                    self.completed.emit(False, "Download cancelled")
                    return
                
                self.progress.emit(line.strip())
                
            # Wait for process to complete
            self.process.wait()
            
            if self.process.returncode == 0:
                self.completed.emit(True, "Download completed successfully")
            else:
                self.completed.emit(False, f"Download failed with error code {self.process.returncode}")
                
        except Exception as e:
            self.progress.emit(f"Error: {str(e)}")
            self.completed.emit(False, f"Download failed: {str(e)}")
    
    def cancel(self):
        """Cancel the download process."""
        self.is_cancelled = True
        if self.process:
            self.process.terminate()


class YouTubeDownloaderWidget(QWidget):
    """Widget for YouTube download functionality."""
    
    def __init__(self, parent=None, log_callback=None):
        """
        Initialize the YouTube downloader widget.
        
        Args:
            parent: Parent widget
            log_callback: Callback function for logging
        """
        super().__init__(parent)
        self.parent = parent
        self.log_callback = log_callback
        self.download_thread = None
        self.download_worker = None
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the user interface components."""
        # Main layout
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Create title and description
        title_label = QLabel("YouTube Video Downloader")
        title_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        desc_label = QLabel("Download videos from YouTube in various formats")
        desc_label.setStyleSheet("font-size: 14px; color: #666;")
        
        layout.addWidget(title_label, alignment=Qt.AlignCenter)
        layout.addWidget(desc_label, alignment=Qt.AlignCenter)
        layout.addSpacing(20)
        
        # URL input section
        url_layout = QHBoxLayout()
        url_label = QLabel("YouTube URL:")
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter YouTube video URL...")
        url_layout.addWidget(url_label)
        url_layout.addWidget(self.url_input)
        layout.addLayout(url_layout)
        
        # Output path section
        path_layout = QHBoxLayout()
        path_label = QLabel("Save to:")
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Select download location...")
        self.path_input.setText(os.path.expanduser("~/Downloads"))
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_output_path)
        path_layout.addWidget(path_label)
        path_layout.addWidget(self.path_input)
        path_layout.addWidget(browse_btn)
        layout.addLayout(path_layout)
        
        # Format options
        format_group = QGroupBox("Download Format")
        format_layout = QVBoxLayout()
        
        self.format_buttons = QButtonGroup(self)
        
        qt_option = QRadioButton("QuickTime Compatible (MP4)")
        qt_option.setToolTip("Optimized for playback in QuickTime Player")
        
        mp4_hd_option = QRadioButton("MP4 HD Quality (up to 1080p)")
        mp4_hd_option.setToolTip("High quality MP4 format")
        
        mp4_sd_option = QRadioButton("MP4 Standard Quality (480p)")
        mp4_sd_option.setToolTip("Smaller file size, standard definition")
        
        audio_option = QRadioButton("Audio Only (M4A)")
        audio_option.setToolTip("Extract audio only, ideal for music")
        
        self.format_buttons.addButton(qt_option, 1)
        self.format_buttons.addButton(mp4_hd_option, 2)
        self.format_buttons.addButton(mp4_sd_option, 3)
        self.format_buttons.addButton(audio_option, 4)
        
        # Set default option
        qt_option.setChecked(True)
        
        format_layout.addWidget(qt_option)
        format_layout.addWidget(mp4_hd_option)
        format_layout.addWidget(mp4_sd_option)
        format_layout.addWidget(audio_option)
        format_group.setLayout(format_layout)
        layout.addWidget(format_group)
        
        # Progress section
        progress_layout = QVBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setAlignment(Qt.AlignCenter)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Ready")
        
        self.status_label = QLabel("Enter a YouTube URL and click Download")
        self.status_label.setWordWrap(True)
        
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.status_label)
        layout.addLayout(progress_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.download_btn = QPushButton("Download")
        self.download_btn.setCursor(QCursor(Qt.PointingHandCursor))
        self.download_btn.setIcon(QIcon("download.png"))
        self.download_btn.clicked.connect(self.start_download)
        self.download_btn.setStyleSheet("""
            background-color: #4CAF50; 
            color: white; 
            font-size: 16px; 
            padding: 10px;
            border-radius: 5px;
        """)
        
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setCursor(QCursor(Qt.PointingHandCursor))
        self.cancel_btn.clicked.connect(self.cancel_download)
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.setStyleSheet("""
            background-color: #f44336; 
            color: white; 
            font-size: 16px; 
            padding: 10px;
            border-radius: 5px;
        """)
        
        button_layout.addWidget(self.download_btn)
        button_layout.addWidget(self.cancel_btn)
        layout.addLayout(button_layout)
        
        # First time check for yt-dlp
        self.check_ytdlp_installed()
    
    def check_ytdlp_installed(self):
        """Check if yt-dlp is installed and offer to install if not."""
        try:
            subprocess.run(["yt-dlp", "--version"], capture_output=True, check=True)
            self.log("yt-dlp is installed")
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.log("yt-dlp not found")
            reply = QMessageBox.question(
                self, 
                "Install Required Component",
                "The YouTube downloader requires yt-dlp to be installed. Would you like to install it now?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes
            )
            if reply == QMessageBox.Yes:
                self.install_ytdlp()
            else:
                self.status_label.setText("yt-dlp is required for downloading. Please install it to use this feature.")
                self.download_btn.setEnabled(False)
    
    def install_ytdlp(self):
        """Install the yt-dlp package."""
        self.status_label.setText("Installing yt-dlp...")
        self.progress_bar.setFormat("Installing components...")
        
        def install_thread():
            try:
                process = subprocess.run(
                    [sys.executable, "-m", "pip", "install", "--upgrade", "yt-dlp"],
                    capture_output=True,
                    text=True,
                    check=True
                )
                if process.returncode == 0:
                    self.log("yt-dlp installed successfully")
                    # Update UI in main thread
                    self.status_label.setText("yt-dlp installed successfully")
                    self.download_btn.setEnabled(True)
                    self.progress_bar.setFormat("Ready")
                else:
                    self.log(f"Failed to install yt-dlp: {process.stderr}")
                    # Update UI in main thread
                    self.status_label.setText("Failed to install yt-dlp. Please install it manually.")
                    self.download_btn.setEnabled(False)
            except Exception as e:
                self.log(f"Error installing yt-dlp: {str(e)}")
                # Update UI in main thread
                self.status_label.setText(f"Error installing yt-dlp: {str(e)}")
                self.download_btn.setEnabled(False)
        
        install_thread = threading.Thread(target=install_thread)
        install_thread.daemon = True
        install_thread.start()
    
    def browse_output_path(self):
        """Open file dialog to select output directory."""
        directory = QFileDialog.getExistingDirectory(
            self, 
            "Select Download Location",
            self.path_input.text() or os.path.expanduser("~/Downloads"),
            QFileDialog.ShowDirsOnly
        )
        if directory:
            self.path_input.setText(directory)
    
    def get_selected_format(self):
        """Get the selected format option."""
        button_id = self.format_buttons.checkedId()
        if button_id == 1:
            return "quicktime"
        elif button_id == 2:
            return "mp4_hd"
        elif button_id == 3:
            return "mp4_sd"
        elif button_id == 4:
            return "audio"
        else:
            return "quicktime"  # Default
    
    def start_download(self):
        """Start the download process."""
        url = self.url_input.text().strip()
        output_path = self.path_input.text().strip()
        
        if not url:
            QMessageBox.warning(self, "Missing URL", "Please enter a YouTube URL.")
            return
        
        if not output_path:
            QMessageBox.warning(self, "Missing Path", "Please select a download location.")
            return
        
        # Check if yt-dlp is installed
        try:
            subprocess.run(["yt-dlp", "--version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.check_ytdlp_installed()
            return
        
        # Disable download button, enable cancel button
        self.download_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Preparing...")
        self.status_label.setText("Starting download...")
        
        # Log the download attempt
        format_selected = self.get_selected_format()
        self.log(f"Download started: {url} in {format_selected} format to {output_path}")
        
        # Create worker and thread
        self.download_worker = DownloadWorker(url, output_path, format_selected)
        self.download_thread = QThread()
        self.download_worker.moveToThread(self.download_thread)
        
        # Connect signals
        self.download_thread.started.connect(self.download_worker.run)
        self.download_worker.progress.connect(self.update_progress)
        self.download_worker.completed.connect(self.download_finished)
        
        # Start the thread
        self.download_thread.start()
    
    def cancel_download(self):
        """Cancel the ongoing download."""
        if self.download_worker:
            self.download_worker.cancel()
            self.status_label.setText("Cancelling download...")
            self.log("Download cancelled by user")
    
    def update_progress(self, message):
        """Update the progress display with the latest message."""
        self.status_label.setText(message)
        
        # Extract download percentage if available
        if "%" in message:
            try:
                # Try to find percentage in the message
                percent_parts = [p for p in message.split() if "%" in p]
                if percent_parts:
                    percent_str = percent_parts[0].replace("%", "")
                    percent = float(percent_str)
                    self.progress_bar.setValue(int(percent))
                    self.progress_bar.setFormat(f"{percent:.1f}%")
            except (ValueError, IndexError):
                pass
        
        # Keep UI responsive
        QApplication.processEvents()
    
    def download_finished(self, success, message):
        """Handle download completion."""
        # Clean up the thread
        if self.download_thread:
            self.download_thread.quit()
            self.download_thread.wait()
        
        # Reset UI
        self.download_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        
        if success:
            self.progress_bar.setValue(100)
            self.progress_bar.setFormat("Completed")
            QMessageBox.information(self, "Download Complete", message)
            self.log(message)
        else:
            self.progress_bar.setFormat("Failed")
            QMessageBox.warning(self, "Download Failed", message)
            self.log(f"Download failed: {message}")
        
        self.status_label.setText(message)
    
    def log(self, message):
        """Log a message using the provided callback if available."""
        if self.log_callback:
            self.log_callback(message)
        print(f"YouTube Downloader: {message}")


# Function to integrate with the main application
def integrate_youtube_downloader(main_window):
    """
    Integrate the YouTube downloader into the main window.
    
    Args:
        main_window: The main application window (PIIWindow instance)
    
    Returns:
        The YouTube downloader widget instance
    """
    # Create YouTube downloader widget with logging callback
    yt_downloader = YouTubeDownloaderWidget(
        parent=main_window,
        log_callback=lambda msg: main_window.update_log(
            main_window.assistant.get_current_time() if hasattr(main_window, 'assistant') else "N/A",
            f"YouTube Downloader: {msg}"
        ) if hasattr(main_window, 'update_log') else None
    )
    
    return yt_downloader