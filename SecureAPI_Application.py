from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
import sys, os, time, ast, logging, hashlib, subprocess,json
import pandas as pd
import requests
from Backend import Agent
from Assistant import Assistant
import CONSTANTS
from PyQt5 import QtCore
from PyQt5.QtWidgets import QInputDialog
import hashlib
from PyQt5.QtWidgets import QMessageBox



# Setup logging with rotation
from logging.handlers import RotatingFileHandler
from PyQt5.QtWidgets import QLineEdit
handler = RotatingFileHandler('application.log', maxBytes=1000000, backupCount=3)
logging.basicConfig(handlers=[handler], level=logging.INFO)

class PIIWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Guard Data')
        self.setGeometry(100, 100, 1000, 600)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f8fbd9;
            }
            QPushButton {
                background-color: #4CAF50; 
                color: white; 
                font-size: 16px; 
                padding: 10px;
                border-radius: 5px;
            }
        """)
        self.UIComponents()
        self.show()
        self.showMaximized()
        self.modified = False
        # Connect the close event to the cleanup function
        self.closeEvent = self.cleanup_on_exit

    def UIComponents(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        self.welcome_text = QLabel(f"Welcome to GUARD: {os.environ.get('USER').upper()}", central_widget)
        self.welcome_text.setStyleSheet("font-size: 15px; font-weight: bold;")
        self.welcome_text.setVisible(False)
        layout.addWidget(self.welcome_text, alignment=Qt.AlignCenter)


        self.btnConnectServer = self.setButton('Connect to Server', 'Click to connect to server', 'Ctrl+Q', self.show_password_input, visibleTrue=True)
        layout.addWidget(self.btnConnectServer, alignment=Qt.AlignCenter)

        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.returnPressed.connect(self.authenticate_and_connect)
        self.password_input.setHidden(True)
        layout.addWidget(self.password_input)


        self.data_table = self.setTable(columncount=1, hlabels=['Item Name'])
        self.data_table.itemSelectionChanged.connect(self.on_data_table_selection)
        layout.addWidget(self.data_table)

        self.log_table = self.setTable(columncount=2,hlabels=['Timestamp', 'Action/Task Performed'])
        layout.addWidget(self.log_table)
        
        button_layout = QHBoxLayout()
        self.btnDisplayData = self.setButton('Display Data', 'Click to display data', 'Ctrl+D', self.show_data_window,style="background-color: gray; color: black;")
        button_layout.addWidget(self.btnDisplayData)

        # Add a button for adding a new entry
        self.btnAddEntry = self.setButton('Add New Entry', 'Click to add a new entry', 'Ctrl+N', self.add_new_entry)
        button_layout.addWidget(self.btnAddEntry)
        button_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addLayout(button_layout)
    
    def setButton(self,btnName,tooltip,shortcut,connect,visibleTrue=False,style="background-color: green; color: white;"):
        btn = QPushButton(btnName, self)
        btn.setVisible(visibleTrue)
        btn.setToolTip(tooltip)
        btn.setCursor(QCursor(Qt.PointingHandCursor))
        btn.setIcon(QIcon(f'{btnName.lower()}.png'))
        btn.setStyleSheet(style)
        btn.setShortcut(shortcut)
        btn.clicked.connect(connect)
        return btn
    
    def setTable(self, columncount,hlabels):
        table = QTableWidget(self)
        table.setColumnCount(columncount)
        table.setVisible(False)
        table.setHorizontalHeaderLabels(hlabels)
        table.horizontalHeader().setStretchLastSection(True)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.setAlternatingRowColors(True)
        return table
    
    def logout_user(self):
        self.update_log(self.assistant.get_current_time(),'Logging Out...')
        self.UIComponents()
        self.update_log(self.assistant.get_current_time(),'Logged Out Successfully.')
        self.cleanup_on_exit()
        self.modified = False
        self.btnLogOut.setVisible(False)
        self.assistant.logout()
        self.agent = None
    def add_new_entry(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Add New Entry")
        main_layout = QVBoxLayout(dialog)
    
        # Category input
        category_label = QLabel("Category:", dialog)
        category_input = QLineEdit(dialog)
        main_layout.addWidget(category_label)
        main_layout.addWidget(category_input)
    
        # Type input
        type_label = QLabel("Type:", dialog)
        type_input = QLineEdit(dialog)
        main_layout.addWidget(type_label)
        main_layout.addWidget(type_input)
    
        # Your Guard section
        pii_label = QLabel("Your Guard:", dialog)
        main_layout.addWidget(pii_label)
    
        pii_layout = QVBoxLayout()
        pii_items = []
    
        def add_pii_item(default_name='', default_data=''):
            item_layout = QHBoxLayout()
    
            item_name_input = QLineEdit(dialog)
            if default_name:
                item_name_input.setText(default_name)
            item_data_input = QLineEdit(dialog)
            if default_data:
                item_data_input.setText(default_data)
    
            item_layout.addWidget(QLabel("Item Name:", dialog))
            item_layout.addWidget(item_name_input)
            item_layout.addWidget(QLabel("Data:", dialog))
            item_layout.addWidget(item_data_input)
    
            remove_button = QPushButton("-", dialog)
            remove_button.setFixedSize(35, 25)
            remove_button.clicked.connect(lambda: remove_pii_item(item_layout, item_name_input, item_data_input))
            item_layout.addWidget(remove_button)

            # Increase the font size for better visibility
            font = remove_button.font()
            font.setPointSize(5)  # Adjust the font size as needed
            remove_button.setFont(font)

            pii_layout.addLayout(item_layout)
            pii_items.append((item_name_input, item_data_input))
    
        def remove_pii_item(item_layout, item_name_input, item_data_input):
            for i in reversed(range(item_layout.count())):
                widget = item_layout.itemAt(i).widget()
                if widget is not None:
                    widget.deleteLater()
            pii_layout.removeItem(item_layout)
            pii_items.remove((item_name_input, item_data_input))
    
        # Add default Guard Data item
        add_pii_item()
    
        # Button to add new Guard Data items
        add_button = QPushButton("+", dialog)
        add_button.setFixedSize(35, 30)
        
        # Increase the font size for better visibility
        font = add_button.font()
        font.setPointSize(5)  # Adjust the font size as needed
        add_button.setFont(font)
        
        add_button.clicked.connect(add_pii_item)
        main_layout.addWidget(add_button)  # Corrected to use main_layout
        main_layout.addLayout(pii_layout)
        
    
        # OK and Cancel buttons
        button_layout = QHBoxLayout()
        ok_button = QPushButton("OK", dialog)
        cancel_button = QPushButton("Cancel", dialog)
        button_layout.addWidget(ok_button)
        button_layout.addWidget(cancel_button)
        main_layout.addLayout(button_layout)
    
        def get_pii_data():
            pii_list = []
            for name_input, data_input in pii_items:
                name = name_input.text()
                data = data_input.text()
                if name and data:
                    pii_list.append({"Item Name": name, "Data": data})
            return pii_list
    
        def handle_ok():
            category = category_input.text().strip()
            type_ = type_input.text().strip()
            pii_data = get_pii_data()
    
            error_messages = []
            
            if not category:
                error_messages.append("Category is required.")
            if not type_:
                error_messages.append("Type is required.")
            for i, (name_input, data_input) in enumerate(pii_items):
                name = name_input.text().strip()
                data = data_input.text().strip()
                if not name or not data:
                    error_messages.append(f"Guard's Item {i+1} requires both 'Item Name' and 'Data'.")
    
            if error_messages:
                QMessageBox.warning(dialog, "Validation Errors", "\n".join(error_messages))
            else:
                
                self.insert_to_db(
                    dialog,
                    category,
                    type_,
                    pii_data
                )
                dialog.accept()  # Ensure the dialog is closed after OK clicked
                
                
    
        ok_button.clicked.connect(handle_ok)
        cancel_button.clicked.connect(dialog.reject)

        dialog.exec_()
    
    
        def remove_pii_item(item_layout, item_name_input, item_data_input):
            for i in reversed(range(item_layout.count())):
                widget = item_layout.itemAt(i).widget()
                if widget is not None:
                    widget.deleteLater()
            pii_layout.removeItem(item_layout)
            pii_items.remove((item_name_input, item_data_input))
    
    
    def process_request(self):
        response = requests.get(CONSTANTS.URL)
        if response.status_code != 200:
            QMessageBox.warning(self, "Error", "Failed to fetch data from server.")
            return
        data = pd.DataFrame.from_records(response.json())
        return data
    
    def insert_to_db(self, dialog, category, type_, pii):
        try:
            new_entry = {
                "Category": category,
                "Type": type_,
                "PII": str(pii)
            }
            response = requests.post(CONSTANTS.URL,json=new_entry)
            if response.status_code == 200:
                response = response.json()
                QMessageBox.information(self, "Insertion Successful", "New entry has been inserted successfully!")
                new_entry.update({'PII':'Hidden'})
                self.update_log(self.assistant.get_current_time(), f"Inserted new entry: {new_entry}")
                dialog.accept()
                data = self.process_request()
                self.populate_data_table(data)
            else:
                QMessageBox.warning(self, "Insertion Failed", f"Failed to insert new entry.\n{response}")
        except (ValueError, SyntaxError) as e:
            QMessageBox.warning(self, "Invalid Input", "Please check the Error Below.\n\n"+str(e))

    def download_pii(self):
        self.update_log(self.assistant.get_current_time(), "Guard Data Download Attempted")
        pre_download_time_stamp = time.time()
        response = self.agent.download_excel()
        self.update_log(self.assistant.get_current_time(), f"Guard Data Download Time: {time.time() - pre_download_time_stamp:.2f} Seconds")
        self.update_log(self.assistant.get_current_time(), "Guard Data Download Function Response: " + str(response))
        if response:
            QMessageBox.information(self, "Download Complete", "Data downloaded and decrypted successfully!")
        else:
            QMessageBox.warning(self, "Download Failed", "Failed to download data!")

    def show_password_input(self):
        self.btnConnectServer.setText('Authenticating...')
        self.btnConnectServer.setDisabled(True)
        self.btnConnectServer.setStyleSheet("background-color: gray; color: white;")
        self.password_input.setHidden(False)  # Make the password input visible
        self.password_input.setFocus()
        self.btnConnectServer.clicked.disconnect(self.show_password_input)
        self.btnConnectServer.clicked.connect(self.authenticate_and_connect)

    def show_data_window(self):
        try:
            # Secure the window by disabling certain features
            data_window = QMainWindow(self)
            data_window.setWindowTitle("Your Guard Data")
            data_window.setWindowFlags(Qt.Window | Qt.CustomizeWindowHint | Qt.WindowTitleHint | Qt.WindowCloseButtonHint | Qt.WindowMinimizeButtonHint)
    
            central_widget = QWidget(data_window)
            data_window.setCentralWidget(central_widget)
            layout = QVBoxLayout(central_widget)
    
            self.table_widget = QTableWidget()
            layout.addWidget(self.table_widget)
    
            try:
                response = requests.get(CONSTANTS.URL)
                if response.status_code != 200:
                    raise ValueError("Empty response received from the server.")
                  # Ensure response is a valid JSON string
                response = response.json()
                data_frame = pd.DataFrame(response)
                self.update_log(self.assistant.get_current_time(), 'Guard Data Displaying...')
            
            except (subprocess.CalledProcessError, ValueError) as e:
                self.update_log(self.assistant.get_current_time(), f'Error: {str(e)}')
                QMessageBox.warning(self, "Connection Error", "Invalid server response or connection issue. Please check the server.")
                return
            except json.JSONDecodeError as jde:
                self.update_log(self.assistant.get_current_time(), f'JSON Error: {str(jde)}')
                QMessageBox.warning(self, "Data Error", "Received data is not in JSON format.")
                return
    
            # Set DataFrame data to QTableWidget
            if isinstance(data_frame, pd.DataFrame):
                num_rows, num_columns = data_frame.shape
                self.table_widget.setRowCount(num_rows)
                self.table_widget.setColumnCount(num_columns)
                self.table_widget.setHorizontalHeaderLabels(data_frame.columns.tolist())
                self.table_widget.setEditTriggers(QAbstractItemView.NoEditTriggers)
    
                for row in range(num_rows):
                    for col in range(num_columns):
                        value = data_frame.iat[row, col]
    
                        # Check if the column is 'PII' and contains a list of dictionaries
                        if data_frame.columns[col] == 'PII' and isinstance(value, str):
                            try:
                                pii_list = ast.literal_eval(value)
                                if isinstance(pii_list, list) and all(isinstance(d, dict) for d in pii_list):
                                    formatted_value = '\n'.join(
                                        f"{d['Item Name']} - {str(d['Data'])}"
                                        for d in pii_list if 'Item Name' in d and 'Data' in d
                                    )
                                    item = QTableWidgetItem(formatted_value)
                                else:
                                    item = QTableWidgetItem(str(value))
                            except (ValueError, SyntaxError):
                                item = QTableWidgetItem(str(value))
                        else:
                            item = QTableWidgetItem(str(value))
    
                        self.table_widget.setItem(row, col, item)
    
                self.table_widget.setContextMenuPolicy(Qt.CustomContextMenu)
                self.table_widget.customContextMenuRequested.connect(self.open_context_menu)
    
            btnDownload = QPushButton('Download Data', data_window)
            btnDownload.setCursor(QCursor(Qt.PointingHandCursor))
            btnDownload.setIcon(QIcon('download.png'))
            btnDownload.clicked.connect(self.download_pii)
            layout.addWidget(btnDownload)
    
            self.table_widget.resizeColumnsToContents()
            self.table_widget.resizeRowsToContents()
            self.table_widget.setSortingEnabled(True)
            self.table_widget.sortByColumn(0, Qt.AscendingOrder)
            self.table_widget.setSelectionBehavior(QAbstractItemView.SelectRows)
            self.table_widget.setSelectionMode(QAbstractItemView.SingleSelection)
            self.table_widget.horizontalHeader().setStretchLastSection(True)
            self.table_widget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
            self.table_widget.verticalHeader().setVisible(False)
            self.table_widget.setAlternatingRowColors(True)
            self.table_widget.setStyleSheet("QTableWidget::item { padding: 5px; }")
    
            self.pii_table_strt_time = time.time()
            data_window.showMaximized()
            data_window.show()
    
            def on_close_event(event):
                event.accept()
                close_event_strt_time = time.time()
                self.update_log(self.assistant.get_current_time(), f'Guard Window Closed')
                if self.modified:
                    self.update_log(self.assistant.get_current_time(), f'Data Backup Initiated...')
                    self.agent.upload_securely()
                    self.update_log(self.assistant.get_current_time(), f'Refreshing Data...')
                    refresh_time = time.time()
                    data = self.process_request()
                    self.update_log(self.assistant.get_current_time(), f'Data Refreshed in {time.time() - refresh_time:.2f} Seconds')
                    self.populate_data_table(data)
                    self.update_log(self.assistant.get_current_time(), f'Data Backed Up in {time.time() - close_event_strt_time:.2f} Seconds')
                close_event_time = close_event_strt_time - self.pii_table_strt_time
                self.update_log(self.assistant.get_current_time(), f'Guard Window Closed after {close_event_time:.2f} Seconds')
    
            data_window.closeEvent = on_close_event
    
        except subprocess.CalledProcessError as e:
            if 'ConnectionError' in str(e.output.decode('utf-8')):
                self.update_log(self.assistant.get_current_time(), 'Connection Error: Unable to reach server.')
                QMessageBox.warning(self, "Connection Error", "Please run the Server. Application unable to detect SERVER")
                return
            else:
                QMessageBox.warning(self, "Connection Error", "Please run the Server. Application unable to detect SERVER")
    
    
    def open_context_menu(self, position):
        menu = QMenu()
    
        copy_action = QAction('Copy', self)
        copy_action.triggered.connect(self.copy_selected_row)
        menu.addAction(copy_action)

        edit_action = QAction('Edit', self)
        edit_action.triggered.connect(self.edit_selected_row)
        menu.addAction(edit_action)

        delete_action = QAction('Delete', self)
        delete_action.triggered.connect(self.delete_item)
        menu.addAction(delete_action)

        menu.exec_(self.table_widget.viewport().mapToGlobal(position))
    
    def edit_selected_row(self):
        selected_items = self.table_widget.selectedItems()
        if not selected_items:
            return
        
        row = selected_items[2].row()
        column = selected_items[2].column()
        item = self.table_widget.item(row, column)
        
        if item is None:
            return
    
        old_value = item.text()
    
        # Create and set up the dialog
        dialog = QDialog(self)
        dialog.setWindowTitle("Edit Guard Data")
        layout = QVBoxLayout()
    
        # Add + button to add new Item Name and Data at the top right
        def add_new_item_data():
            hbox = QHBoxLayout()
            
            item_name_label = QLabel("Item Name:")
            item_name_edit = QLineEdit("")
            hbox.addWidget(item_name_label)
            hbox.addWidget(item_name_edit)
    
            data_label = QLabel("Data:")
            data_edit = QLineEdit("")
            hbox.addWidget(data_label)
            hbox.addWidget(data_edit)
    
            layout.insertLayout(layout.count() - 1, hbox)
            edits.append((item_name_edit, data_edit))
    
        # top_layout = QHBoxLayout()
        # top_layout.addStretch()  # Pushes the button to the right
        # add_button = QPushButton("+")
        # add_button.setFixedSize(20,20)
        # add_button.clicked.connect(add_new_item_data)
        # top_layout.addWidget(add_button)
        # layout.addLayout(top_layout)
        
    
        # Process old_value into multiple item name-data pairs
        list_of_pairs = []
        for pair in old_value.split('\n'):
            parts = pair.split(' - ', 1)
            if len(parts) == 2:
                list_of_pairs.append(parts)
            elif len(parts) == 1:
                list_of_pairs.append([parts[0], ""])  # Handle case where there's no ' - '
    
        # Create input fields for each pair with side-by-side layout
        edits = []
        for item_name, data in list_of_pairs:
            hbox = QHBoxLayout()
            
            item_name_label = QLabel("Item Name:")
            item_name_edit = QLineEdit(item_name)
            hbox.addWidget(item_name_label)
            hbox.addWidget(item_name_edit)
    
            data_label = QLabel("Data:")
            data_edit = QLineEdit(data)
            hbox.addWidget(data_label)
            hbox.addWidget(data_edit)
    
            layout.addLayout(hbox)
            edits.append((item_name_edit, data_edit))
    
        # Add OK and Cancel buttons
        button_layout = QHBoxLayout()
        ok_button = QPushButton("Update")
        add_button = QPushButton("Add New Item")
        # add_button.setFixedSize(20,20)
        add_button.clicked.connect(add_new_item_data)
        button_layout.addWidget(ok_button)
        button_layout.addWidget(add_button)
        layout.addLayout(button_layout)
        dialog.setLayout(layout)
    
        # Connect buttons to appropriate slots
        ok_button.clicked.connect(dialog.accept)
        
        # Show the dialog and handle the result
        if dialog.exec_() == QDialog.Accepted:
            new_values = []
            for item_name_edit, data_edit in edits:
                new_item_name = item_name_edit.text()
                new_data = data_edit.text()
                new_values.append(f"{new_item_name} - {new_data}")
            
            new_value = '\n'.join(new_values)
            item.setText(new_value)
    
            # Convert edited entries into JSON format
            final_value_list = [{"Item Name": item_name_edit.text(), "Data": data_edit.text()} for item_name_edit, data_edit in edits]
            final_value = json.dumps(final_value_list)
    
            final_item = {}
    
            row = selected_items[0].row()
            column = selected_items[0].column()
            final_item["Category"] = self.table_widget.item(row, column).text()
    
            row = selected_items[1].row()
            column = selected_items[1].column()
            final_item["Type"] = self.table_widget.item(row, column).text()
            
            final_item["PII"] = final_value
            update_data = {
                'Category':final_item['Category'],
                'PII':final_item['PII'].replace('"', "\'"),
                'Type':final_item['Type']
            }
            self.time_updt_strt_time = time.time()
            try:
                response = requests.patch(CONSTANTS.URL,json=update_data)
                if response.status_code == 200:
                    response = response.json()
                    self.update_log(self.assistant.get_current_time(), f"Update Time: {time.time() - self.time_updt_strt_time:.2f} Seconds")
                    self.update_log(self.assistant.get_current_time(), f"Update Function Response: {response}")
                    self.update_log(self.assistant.get_current_time(), f"Modified: {final_item['Category']}'s {final_item['Type']} - Guard Data")
                    self.modified = True
                    QMessageBox.information(self, "Update Successful", "Data updated successfully!")
                else:
                    QMessageBox.warning(self, "Update Failed", f"Failed to update data!\n{response}")
            except subprocess.CalledProcessError as e:
                QMessageBox.critical(self, "Error", f"An error occurred while updating: {e}")
    
    
    
    
    def copy_selected_row(self):
        selected_items = self.table_widget.selectedItems()
        if selected_items:
            clipboard = QApplication.clipboard()
            clipboard.setText('\t'.join([item.text() for item in selected_items]))

    def authenticate_and_connect(self):
        password = self.password_input.text()
        env_password = CONSTANTS.APP_PASSWORD
        self.btnConnectServer.setText('Logging in...')
        if not env_password:
            QMessageBox.warning(self, "Security Warning", "Please Activate your Secure Environment before performing operations")
            return 

        hashed_input_password = hashlib.sha256(password.encode()).hexdigest()
        hashed_env_password = hashlib.sha256(env_password.encode()).hexdigest()

        if hashed_input_password == hashed_env_password:
            self.btnConnectServer.setStyleSheet("background-color: orange; color: white;")
            self.password_input.clear()
            self.password_input.setHidden(True)
            self.connect_to_server()
            self.update_log(self.assistant.get_current_time(), 'Authentication Successful')
        else:
            QMessageBox.warning(self, "Authentication Failed", "Incorrect Password!")
            self.password_input.clear()

    
    
    def connect_to_server(self):
        self.btnConnectServer.setDisabled(True)
        self.agent = Agent(s3=CONSTANTS.AWS_S3, file_name=CONSTANTS.AWS_FILE)
        self.assistant = Assistant(CONSTANTS.AWS_S3)
        self.btnConnectServer.setText('Connected')
        self.btnConnectServer.setDisabled(True)
        self.btnConnectServer.setStyleSheet("background-color: green; color: white;")
        self.btnDisplayData.setStyleSheet("background-color: green; color: white;")
        self.btnDisplayData.setVisible(True)
        self.btnAddEntry.setVisible(True)
        self.log_table.setVisible(True)
        self.welcome_text.setVisible(True)
        self.data_table.setVisible(True)
        self.btnAddEntry.setStyleSheet("background-color: green; color: white;")
        self.btnDisplayData.setToolTip('Click to download data')
        self.btnConnectServer.setToolTip('You are Connected Successfully. Button Disabled')
        self.btnLogOut = QPushButton('LogOut', self)
        self.btnLogOut.setCursor(QCursor(Qt.PointingHandCursor))
        self.btnLogOut.clicked.connect(self.logout_user)
        self.btnLogOut.setShortcut("Ctrl+W")
        self.btnLogOut.resize(100, 40)
        self.btnLogOut.show()
        self.btnLogOut.setStyleSheet("background-color: orange; color: white;")
        self.btnLogOut.setDisabled(False)
        self.btnLogOut.setToolTip('Click to Logout')
        # position the logout to right side corner in the Top Right Corner
        self.btnLogOut.move(self.width() - self.btnLogOut.width() - 10, 10)
        self.btnConnectServer.move(self.width() - self.btnConnectServer.width() - 10, 10)
        self.btnDisplayData.move(self.width() - self.btnDisplayData.width() - 10, 10)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.fetch_status)
        self.timer.start(1000)
        data = self.process_request()
        self.populate_data_table(data)
        self.update_log(self.assistant.get_current_time(), "Connected to Server.")
        self.update_log(self.assistant.get_current_time(), 'Display Data Button: Activated')
        self.update_log(self.assistant.get_current_time(), 'Add New Entry Button: Activated')

    def on_data_table_selection(self):
        selected_items = self.data_table.selectedItems()
        if not selected_items:
            return
        selected_item_text = selected_items[0].text()
        sub_options = self.agent.get_sub_options_to_choose(selected_item_text)
        self.update_log(self.assistant.get_current_time(), f"Selected item: {selected_item_text}")

        sub_option, ok_pressed = QInputDialog.getItem(
            self,
            "Choose Sub Option",
            f"Sub options for {selected_item_text}:"+"  "*45,
            sub_options,
            0,
            False,  # Editable flag set to False
            QtCore.Qt.WindowFlags(QtCore.Qt.WindowTitleHint | QtCore.Qt.WindowSystemMenuHint | QtCore.Qt.WindowCloseButtonHint)

)
            
        
        if ok_pressed and sub_option:
            output = self.agent.get_final_output(sub_option)
            self.update_log(self.assistant.get_current_time(), f"Selected {selected_item_text}'s sub option: {sub_option}")
            self.show_output_dialog(sub_option, output)

 
    def show_output_dialog(self, sub_option, output):
        self.start_time = time.time()
    
        def on_close_event(event):
            event.accept()
            end_time = time.time() - self.start_time
            self.update_log(
                self.assistant.get_current_time(),
                f"{self.option}'s dialog closed after {end_time:.2f} seconds"
            )
        
        # Create dialog
        dialog = QDialog(self)
        dialog.setWindowTitle(sub_option)
        self.option = sub_option
        dialog.closeEvent = on_close_event
    
        # Calculate the size of the dialog based on content
        num_items = len(output)
        item_height = 50  # Approximate height for each item (can be adjusted)
        base_height = 100  # Base height for dialog components (buttons, etc.)
        width = 700  # Fixed or calculated width
        height = min(400, item_height * num_items + base_height)  # Calculate height
        
        # Set dialog geometry and move to center
        screen_geometry = QGuiApplication.primaryScreen().availableGeometry()
        x = (screen_geometry.width() - width) // 2
        y = (screen_geometry.height() - height) // 2
        dialog.setGeometry(x, y, width, height)
    
        # Layout setup
        dialog_layout = QVBoxLayout(dialog)
        scroll_area = QScrollArea(dialog)
        scroll_area.setWidgetResizable(True)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
    
        for item in output:
            h_layout = QHBoxLayout()
            copy_button = QPushButton('Copy', dialog)
            copy_button.setToolTip('Click to copy the data')
            copy_button.setCursor(QCursor(Qt.PointingHandCursor))
            if isinstance(item, dict):
                label = QLabel(f"{item['Item Name']} : {str(item['Data'])}", dialog)
                item["Button"] = copy_button
                copy_button.clicked.connect(lambda checked, data=item: self.copy_to_clipboard(data))
                label.setWordWrap(True)
                copy_button.setStyleSheet("background-color: White; color: Black;")
                label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
                h_layout.addWidget(label)
                h_layout.addWidget(copy_button)
                scroll_layout.addLayout(h_layout)
                scroll_layout.addSpacing(10)
            else:
                QMessageBox.warning(self, "Error Code: 404 and 503 WARNING MESSAGE", "You are Not Allowed to view this here.")
                return
        self.update_log(self.assistant.get_current_time(), f"Displaying... {self.option}")
    
        scroll_content.setLayout(scroll_layout)
        scroll_area.setWidget(scroll_content)
    
        dialog_layout.addWidget(scroll_area)
        close_button = QPushButton('Close', dialog)
        close_button.clicked.connect(dialog.close)  # Close button functionality
        dialog_layout.addWidget(close_button)
        dialog_layout.setAlignment(close_button, Qt.AlignRight)
    
        # dialog.exec_()
    

        def on_accept():
            end_time = time.time()
            duration = end_time - self.start_time
            self.update_log(self.assistant.get_current_time(), f"{self.option}'s dialog was visible for {duration:.2f} seconds")
            dialog.accept()

        close_button.clicked.connect(on_accept)

        dialog.exec_()

    def fetch_status(self):
        try:
            if hasattr(self, 'agent') and hasattr(self.agent, 'status'):
                for task_name, task_time in self.agent.status.items():
                    self.update_log(task_time, task_name)
                self.agent.status = {}
        except AttributeError:
            pass
    def copy_to_clipboard(self, data):
        clipboard = QApplication.clipboard()
        clipboard.setText(str(data['Data']))
        data["Button"].setText("Copied")
        data["Button"].setStyleSheet("background-color: green; color: white; font-weight: bold;")
        self.update_log(self.assistant.get_current_time(), f"Copied {self.option}'s {data['Item Name']} to Clipboard.")
        # QMessageBox.information(self, "Copied", f"{data['Item Name']} Copied to Clipboard.")

    def update_log(self, task_time, task_name):
        row_position = self.log_table.rowCount()
        self.log_table.insertRow(row_position)

        timestamp_item = QTableWidgetItem(task_time)
        message_item = QTableWidgetItem(task_name)

        self.log_table.setItem(row_position, 0, timestamp_item)
        self.log_table.setItem(row_position, 1, message_item)

        logging.info(f"{task_time} - {task_name}")

    def populate_data_table(self, data):
        data = data['Category'].unique()
        self.data_table.setRowCount(len(data))
        for row, item in enumerate(data):
            self.data_table.setItem(row, 0, QTableWidgetItem(item))

    def cleanup_on_exit(self, event=None):
       log_files = ['application.log']
       for log_file in log_files:
        if os.path.exists(log_file):
            try:
                self.update_log(self.assistant.get_current_time(), f"Processing Logging Data...")
                pre_log_time = time.time()
                self.assistant.collect_logs()
                self.update_log(self.assistant.get_current_time(), f"Log Data Backedup in {time.time() - pre_log_time:.2f} Seconds")
            except AttributeError:
                logging.info("EVNT_FLRE: Closed the Application without Login.")
    
    def update_item(self, item):
        self.data_table.setCurrentItem(item, QAbstractItemView.Select)
        self.on_data_table_selection()
        self.data_table.setCurrentItem(None)
        self.data_table.clearSelection()
        self.data_table.update()
        self.data_table.repaint()
        self.data_table.viewport().update()
        self.data_table.viewport().repaint()
    
    def delete_item(self):
        selected_items = self.table_widget.selectedItems()
        
        if not selected_items:
            QMessageBox.warning(self, "Delete Error", "No item selected to delete.")
            return
        
        # Assuming the table has columns 'Category' and 'Type'
        item_info = {'Category': '', 'Type': ''}
        row = selected_items[0].row()
    
        for column in range(2):  # Assuming that Category is column 0 and Type is column 1
            item = self.table_widget.item(row, column)
            if item is None:
                QMessageBox.warning(self, "Delete Error", "Selected item has missing columns.")
                return
            if column == 0:
                item_info['Category'] = item.text()
            elif column == 1:
                item_info['Type'] = item.text()
    
        # Confirm deletion with the user
        reply = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to delete the item '{item_info['Category']}' with type '{item_info['Type']}'?\n\nNote: This Action is Irreversible!",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
    
        if reply == QMessageBox.Yes:
            self.modified = True
            delete_data = {
                'Category': item_info['Category'],
                'Type': item_info['Type']
            }
            response = requests.delete(CONSTANTS.URL,json=delete_data)
            if response.status_code == 200:
                QMessageBox.information(self, "Deletion Complete", "Item deleted successfully!")
                self.update_log(self.assistant.get_current_time(), f"Deleted Item: {item_info['Category']} - {item_info['Type']}")
                self.table_widget.removeRow(row)
            else:
                QMessageBox.warning(self, "Delete Error", "Failed to delete the item.")
                self.update_log(self.assistant.get_current_time(), "Failed to delete the item.")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = PIIWindow()
    sys.exit(app.exec_())