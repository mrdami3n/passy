import sys
import sqlite3
import base64
import hashlib
import random
import string
import pyotp
import qrcode
import bcrypt
import json
import csv
import datetime
import requests # ADDED for Have I Been Pwned API

from cryptography.fernet import Fernet, InvalidToken
from PyQt5.QtGui import QDesktopServices, QFont, QIcon, QClipboard
from PyQt5.QtCore import QUrl, Qt, QTimer, QEvent
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton,
    QLineEdit, QLabel, QMessageBox, QHBoxLayout, QTableWidget,
    QTableWidgetItem, QInputDialog, QMenuBar, QMenu, QAction, QProgressBar, QComboBox,
    QSpacerItem, QSizePolicy, QListWidget, QListWidgetItem, QTextEdit, QDialog,
    QTabWidget, QGridLayout, QFrame, QCheckBox, QRadioButton, QDialogButtonBox, QFileDialog,
    QSpinBox, QGroupBox
)

# --- Encryption and Utility Functions ---

# Derives a secure encryption key from the master password using SHA256 and base64 encoding
def derive_key(master_password):
    return base64.urlsafe_b64encode(
        hashlib.sha256(master_password.encode()).digest()
    )

# Calculates password strength based on length, presence of uppercase, lowercase, digits, special chars
def calculate_password_strength(password):
    length = len(password)
    upper = any(c.isupper() for c in password)
    lower = any(c.islower() for c in password)
    digits = any(c.isdigit() for c in password)
    special = any(c in string.punctuation for c in password)
    score = sum([upper, lower, digits, special])
    if length >= 16:
        score += 1
    elif length < 8:
        score -= 1
    return max(0, min(100, score * 20))  # Returns strength as a percentage 0-100

# --- NEW: Have I Been Pwned API Check ---
def check_pwned(password):
    """
    Checks a password against the 'Have I Been Pwned' database.
    Returns the pwnage count, or 0 if not found. Returns -1 on error.
    """
    try:
        sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_password[:5], sha1_password[5:]
        
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
        response.raise_for_status() # Raise an exception for bad status codes

        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return int(count)
        return 0
    except requests.RequestException:
        # This could be a network error, timeout, etc.
        return -1


# --- Dialog for Viewing/Editing Notes ---
class NoteViewer(QDialog):
    def __init__(self, parent=None, note_id=None, title="", content=""):
        super().__init__(parent)
        self.setWindowTitle("View/Edit Note")
        self.setGeometry(200, 200, 500, 400)
        self.parent_app = parent
        self.note_id = note_id

        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        self.title_input = QLineEdit(title)
        self.title_input.setPlaceholderText("Note Title")
        self.layout.addWidget(QLabel("Title:"))
        self.layout.addWidget(self.title_input)

        self.content_input = QTextEdit(content)
        self.content_input.setPlaceholderText("Note Content")
        self.layout.addWidget(QLabel("Content:"))
        self.layout.addWidget(self.content_input)

        self.save_button = QPushButton("Save Note")
        self.save_button.clicked.connect(self.save_note)
        self.layout.addWidget(self.save_button)

    def save_note(self):
        title = self.title_input.text()
        content = self.content_input.toPlainText()

        if not title:
            QMessageBox.warning(self, "Error", "Note title cannot be empty.")
            return

        encrypted_title = self.parent_app.encrypt(title)
        encrypted_content = self.parent_app.encrypt(content)

        if self.note_id:
            self.parent_app.c.execute(
                "UPDATE notes SET title=?, content=? WHERE id=? AND user_id=?",
                (encrypted_title, encrypted_content, self.note_id, self.parent_app.user_id)
            )
        else:
            self.parent_app.c.execute(
                "INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
                (self.parent_app.user_id, encrypted_title, encrypted_content)
            )
        self.parent_app.conn.commit()
        QMessageBox.information(self, "Success", "Note saved successfully!")
        self.accept()

# --- Dialog for Viewing/Editing Crypto Wallet Entries ---
class CryptoWalletViewer(QDialog):
    def __init__(self, parent=None, wallet_id=None, name="", wallet_id_str="", restore_key="", secret_phrase=""):
        super().__init__(parent)
        self.setWindowTitle("View/Edit Crypto Wallet")
        self.setGeometry(200, 200, 600, 500)
        self.parent_app = parent
        self.wallet_id = wallet_id

        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        self.name_input = QLineEdit(name)
        self.name_input.setPlaceholderText("Wallet Name (e.g., My Bitcoin Wallet)")
        self.layout.addWidget(QLabel("Wallet Name:"))
        self.layout.addWidget(self.name_input)

        self.wallet_id_input = QLineEdit(wallet_id_str)
        self.wallet_id_input.setPlaceholderText("Wallet ID or Public Address (Optional)")
        self.layout.addWidget(QLabel("Wallet ID/Address (Optional):"))
        self.layout.addWidget(self.wallet_id_input)

        self.restore_key_input = QTextEdit(restore_key)
        self.restore_key_input.setPlaceholderText("Restore Key / Private Key (Highly Sensitive!)")
        self.layout.addWidget(QLabel("Restore Key / Private Key:"))
        self.layout.addWidget(self.restore_key_input)
        
        self.secret_phrase_input = QTextEdit(secret_phrase)
        self.secret_phrase_input.setPlaceholderText("Secret Recovery Phrase / Seed Phrase (Extremely Sensitive!)")
        self.layout.addWidget(QLabel("Secret Recovery Phrase / Seed Phrase:"))
        self.layout.addWidget(self.secret_phrase_input)

        self.save_button = QPushButton("Save Wallet Info")
        self.save_button.clicked.connect(self.save_wallet)
        self.layout.addWidget(self.save_button)

    def save_wallet(self):
        name = self.name_input.text()
        wallet_id_str = self.wallet_id_input.text()
        restore_key = self.restore_key_input.toPlainText()
        secret_phrase = self.secret_phrase_input.toPlainText()

        if not name or not (restore_key or secret_phrase):
            QMessageBox.warning(self, "Error", "Wallet Name and at least one of Restore Key or Secret Phrase are required.")
            return
        
        # Only show this warning for new entries, not when editing
        if not self.wallet_id:
            warning_reply = QMessageBox.warning(self, "Security Warning!",
                                                "Storing sensitive crypto wallet information digitally carries significant risks.\n\n"
                                                "Ensure your master password is extremely strong and your 2FA is secure. "
                                                "It is generally recommended to store these physically offline.\n\n"
                                                "Do you wish to proceed?",
                                                QMessageBox.Yes | QMessageBox.No)
            if warning_reply == QMessageBox.No:
                return

        encrypted_name = self.parent_app.encrypt(name)
        encrypted_wallet_id_str = self.parent_app.encrypt(wallet_id_str)
        encrypted_restore_key = self.parent_app.encrypt(restore_key)
        encrypted_secret_phrase = self.parent_app.encrypt(secret_phrase)

        if self.wallet_id:
            # Update existing wallet
            self.parent_app.c.execute(
                "UPDATE crypto_wallets SET name=?, wallet_id_str=?, restore_key=?, secret_phrase=? WHERE id=? AND user_id=?",
                (encrypted_name, encrypted_wallet_id_str, encrypted_restore_key, encrypted_secret_phrase, self.wallet_id, self.parent_app.user_id)
            )
        else:
            # Add new wallet
            self.parent_app.c.execute(
                "INSERT INTO crypto_wallets (user_id, name, wallet_id_str, restore_key, secret_phrase) VALUES (?, ?, ?, ?, ?)",
                (self.parent_app.user_id, encrypted_name, encrypted_wallet_id_str, encrypted_restore_key, encrypted_secret_phrase)
            )
        self.parent_app.conn.commit()
        QMessageBox.information(self, "Success", "Crypto Wallet information saved successfully!")
        self.accept()

# --- Dialog for Export Options ---
class ExportDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Export Vault Options")
        self.layout = QVBoxLayout(self)

        # Data Type Selection
        self.data_groupbox = QFrame()
        self.data_groupbox.setLayout(QVBoxLayout())
        self.layout.addWidget(self.data_groupbox)
        self.data_groupbox.layout().addWidget(QLabel("<b>Select Data to Export:</b>"))
        self.chk_passwords = QCheckBox("Passwords")
        self.chk_passwords.setChecked(True)
        self.chk_notes = QCheckBox("Secure Notes")
        self.chk_notes.setChecked(True)
        self.chk_crypto = QCheckBox("Crypto Wallets")
        self.chk_crypto.setChecked(True)
        self.data_groupbox.layout().addWidget(self.chk_passwords)
        self.data_groupbox.layout().addWidget(self.chk_notes)
        self.data_groupbox.layout().addWidget(self.chk_crypto)

        # Format Selection
        self.format_groupbox = QFrame()
        self.format_groupbox.setLayout(QVBoxLayout())
        self.layout.addWidget(self.format_groupbox)
        self.format_groupbox.layout().addWidget(QLabel("<b>Select Export Format:</b>"))
        self.radio_json = QRadioButton("Encrypted JSON (.json) - Recommended & Secure")
        self.radio_csv = QRadioButton("Unencrypted CSV (.csv) - Passwords Only & Insecure")
        self.radio_json.setChecked(True)
        self.format_groupbox.layout().addWidget(self.radio_json)
        self.format_groupbox.layout().addWidget(self.radio_csv)

        # Note: CSV export will disable other data types
        self.radio_csv.toggled.connect(self.on_format_change)

        # Buttons
        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        self.layout.addWidget(self.button_box)

    def on_format_change(self, is_csv):
        # When CSV is selected, only passwords can be exported.
        if is_csv:
            self.chk_notes.setChecked(False)
            self.chk_notes.setEnabled(False)
            self.chk_crypto.setChecked(False)
            self.chk_crypto.setEnabled(False)
        else:
            self.chk_notes.setEnabled(True)
            self.chk_crypto.setEnabled(True)

    def get_options(self):
        return {
            "passwords": self.chk_passwords.isChecked(),
            "notes": self.chk_notes.isChecked(),
            "crypto": self.chk_crypto.isChecked(),
            "format": "json" if self.radio_json.isChecked() else "csv"
        }

# --- Dialog for Customizable Password Generation ---
class PasswordGeneratorDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Password Generator Options")
        self.setMinimumWidth(400)
        
        self.layout = QGridLayout(self)

        # Length
        self.layout.addWidget(QLabel("Password Length:"), 0, 0)
        self.length_spinbox = QSpinBox()
        self.length_spinbox.setRange(8, 128)
        self.length_spinbox.setValue(16)
        self.layout.addWidget(self.length_spinbox, 0, 1)

        # Character types
        self.chk_upper = QCheckBox("Include Uppercase (A-Z)")
        self.chk_upper.setChecked(True)
        self.layout.addWidget(self.chk_upper, 1, 0, 1, 2)

        self.chk_lower = QCheckBox("Include Lowercase (a-z)")
        self.chk_lower.setChecked(True)
        self.layout.addWidget(self.chk_lower, 2, 0, 1, 2)

        self.chk_digits = QCheckBox("Include Numbers (0-9)")
        self.chk_digits.setChecked(True)
        self.layout.addWidget(self.chk_digits, 3, 0, 1, 2)

        self.chk_symbols = QCheckBox("Include Symbols (!@#$%)")
        self.chk_symbols.setChecked(True)
        self.layout.addWidget(self.chk_symbols, 4, 0, 1, 2)

        # Buttons
        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        self.layout.addWidget(self.button_box, 5, 0, 1, 2)
        
        self.generated_password = ""

    def get_generated_password(self):
        charset = ""
        if self.chk_upper.isChecked():
            charset += string.ascii_uppercase
        if self.chk_lower.isChecked():
            charset += string.ascii_lowercase
        if self.chk_digits.isChecked():
            charset += string.digits
        if self.chk_symbols.isChecked():
            charset += string.punctuation
            
        if not charset:
            QMessageBox.warning(self, "Error", "You must select at least one character type.")
            return None

        length = self.length_spinbox.value()
        password = ''.join(random.choices(charset, k=length))
        return password

# --- Main Password Manager Application ---
class PasswordManager(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Passy - The Secure Password Manager")
        self.setMinimumSize(800, 700) # Increased height for new audit section
        
        self.main_layout = QVBoxLayout()
        self.setLayout(self.main_layout)

        self.master_key = None
        self.user_id = None
        self.current_theme = 'dark'

        # --- Idle Timeout ---
        self.inactivity_timer = QTimer(self)
        self.inactivity_timer.timeout.connect(self.auto_logout)
        self.inactivity_timeout_seconds = 300 # 5 minutes (300 seconds)
        # Install event filter to reset timer on user activity
        self.installEventFilter(self)

        # --- Clipboard Timer ---
        self.clipboard_timer = QTimer(self)
        self.clipboard_timer.setSingleShot(True)
        self.clipboard_timer.timeout.connect(self.clear_clipboard)
        self.clipboard_clear_delay_seconds = 30 # Clear clipboard after 30 seconds

        self._dark_stylesheet = """
            QWidget {
                background-color: #2C3E50; /* Dark blue-gray */
                color: #ECF0F1; /* Light text */
                font-size: 14px;
            }
            QLineEdit, QTextEdit, QComboBox, QSpinBox {
                background-color: #34495E; /* Slightly lighter input fields */
                border: 1px solid #5D6D7E;
                padding: 5px;
                border-radius: 3px;
                color: #ECF0F1;
            }
            QPushButton {
                background-color: #0000FF; /* blue for buttons */
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #16A085; /* Darker green on hover */
            }
            QProgressBar {
                text-align: center;
                border: 1px solid #5D6D7E;
                border-radius: 3px;
                background-color: #34495E;
            }
            QProgressBar::chunk {
                border-radius: 3px;
            }
            QTableWidget {
                background-color: #34495E;
                alternate-background-color: #2C3E50;
                border: 1px solid #5D6D7E;
                gridline-color: #5D6D7E;
                color: #ECF0F1;
            }
            QTableWidget QHeaderView::section {
                background-color: #2C3E50;
                color: white;
                padding: 5px;
                border: 1px solid #16A085;
            }
            QTableWidget::item:selected {
                background-color: #3498DB; /* Blue for selected item */
                color: white;
            }
            QListWidget {
                background-color: #34495E;
                border: 1px solid #5D6D7E;
                color: #ECF0F1;
            }
            QListWidget::item:selected {
                background-color: #3498DB;
                color: white;
            }
            QTabWidget::pane {
                border: 1px solid #5D6D7E;
                background-color: #2C3E50;
            }
            QTabBar::tab {
                background: #34495E;
                color: #ECF0F1;
                padding: 8px 15px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                border: 1px solid #5D6D7E;
                border-bottom: none;
            }
            QTabBar::tab:selected {
                background: #2C3E50;
                border-top: 2px solid #1ABC9C; /* Highlight selected tab */
            }
            QMenuBar {
                background-color: #34495E;
                color: #ECF0F1;
            }
            QMenuBar::item {
                padding: 5px 10px;
                background: transparent;
            }
            QMenuBar::item:selected {
                background-color: #1ABC9C;
            }
            QMenu {
                background-color: #34495E;
                border: 1px solid #5D6D7E;
                color: #ECF0F1;
            }
            QMenu::item {
                padding: 5px 20px;
            }
            QMenu::item:selected {
                background-color: #1ABC9C;
            }
            QLabel {
                color: #ECF0F1;
            }
            QGroupBox {
                border: 1px solid #5D6D7E;
                margin-top: 10px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 5px;
            }
        """

        self._light_stylesheet = """
            QWidget {
                background-color: #F0F0F0; /* Light gray */
                color: #333333; /* Dark text */
                font-size: 14px;
            }
            QLineEdit, QTextEdit, QComboBox, QSpinBox {
                background-color: #FFFFFF; /* White input fields */
                border: 1px solid #CCCCCC;
                padding: 5px;
                border-radius: 3px;
                color: #333333;
            }
            QPushButton {
                background-color: #4CAF50; /* Green for buttons */
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #45A049; /* Darker green on hover */
            }
            QProgressBar {
                text-align: center;
                border: 1px solid #CCCCCC;
                border-radius: 3px;
                background-color: #E0E0E0;
            }
            QProgressBar::chunk {
                border-radius: 3px;
            }
            QTableWidget {
                background-color: #FFFFFF;
                alternate-background-color: #F5F5F5;
                border: 1px solid #CCCCCC;
                gridline-color: #E0E0E0;
                color: #333333;
            }
            QTableWidget QHeaderView::section {
                background-color: #607D8B; /* Darker gray-blue */
                color: white;
                padding: 5px;
                border: 1px solid #546E7A;
            }
            QTableWidget::item:selected {
                background-color: #BBDEFB; /* Light blue for selected item */
                color: #333333;
            }
            QListWidget {
                background-color: #FFFFFF;
                border: 1px solid #CCCCCC;
                color: #333333;
            }
            QListWidget::item:selected {
                background-color: #BBDEFB;
                color: #333333;
            }
            QTabWidget::pane {
                border: 1px solid #CCCCCC;
                background-color: #F0F0F0;
            }
            QTabBar::tab {
                background: #E0E0E0;
                color: #333333;
                padding: 8px 15px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                border: 1px solid #CCCCCC;
                border-bottom: none;
            }
            QTabBar::tab:selected {
                background: #F0F0F0;
                border-top: 2px solid #4CAF50; /* Highlight selected tab */
            }
            QMenuBar {
                background-color: #E0E0E0;
                color: #333333;
            }
            QMenuBar::item {
                padding: 5px 10px;
                background: transparent;
            }
            QMenuBar::item:selected {
                background-color: #4CAF50;
            }
            QMenu {
                background-color: #E0E0E0;
                border: 1px solid #CCCCCC;
                color: #333333;
            }
            QMenu::item {
                padding: 5px 20px;
            }
            QMenu::item:selected {
                background-color: #4CAF50;
            }
            QLabel {
                color: #333333;
            }
            QGroupBox {
                border: 1px solid #CCCCCC;
                margin-top: 10px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 5px;
            }
        """

        self.setup_database()
        self.login_screen()
    
    def eventFilter(self, obj, event):
        # Reset the inactivity timer on mouse press, key press, or mouse move events
        if self.master_key is not None and (
            event.type() == QEvent.Type.MouseButtonPress or
            event.type() == QEvent.Type.KeyPress or
            event.type() == QEvent.Type.MouseMove
        ):
            self.inactivity_timer.start(self.inactivity_timeout_seconds * 1000)
        return super().eventFilter(obj, event)

    def auto_logout(self):
        if self.master_key is not None: # Only auto-logout if currently logged in
            QMessageBox.information(self, "Session Expired", "You have been logged out due to inactivity.")
            self.logout()
            
    def show_reused_password(self, password):
        """Displays a password from the audit screen in a message box."""
        try:
            QMessageBox.information(self, "Reused Password", f"The password is: \n\n{password}\n\n(Copied to clipboard automatically and will clear in {self.clipboard_clear_delay_seconds} seconds)")
            QApplication.clipboard().setText(password)
            self.clipboard_timer.start(self.clipboard_clear_delay_seconds * 1000)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An unexpected error occurred: {e}")

    def clear_layout(self, layout):
        if layout is not None:
            while layout.count():
                item = layout.takeAt(0)
                widget = item.widget()
                if widget is not None:
                    widget.setParent(None)
                    widget.deleteLater()
                else:
                    self.clear_layout(item.layout())

    def logout(self):
        self.clear_layout(self.main_layout)
        self.master_key = None
        self.user_id = None
        self.totp_secret = None # Clear 2FA secret on logout
        self.inactivity_timer.stop() # Stop the timer
        self.clipboard_timer.stop() # Stop clipboard timer
        self.clear_clipboard() # Ensure clipboard is cleared on logout
        self.login_screen()
        self.apply_theme('dark') # Re-apply default dark theme on logout

    def setup_database(self):
        self.conn = sqlite3.connect("vault.db")
        self.c = self.conn.cursor()
        self.c.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            master_password_hash TEXT,
            theme_mode TEXT DEFAULT 'dark'
        )""")
        # Add theme_mode column if it doesn't exist (for existing databases)
        try:
            self.c.execute("ALTER TABLE users ADD COLUMN theme_mode TEXT DEFAULT 'dark'")
            self.conn.commit()
        except sqlite3.OperationalError as e:
            if "duplicate column name: theme_mode" in str(e):
                pass # Column already exists
            else:
                raise # Re-raise other errors
        
        # MODIFIED: Added last_modified column
        self.c.execute("""CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            website TEXT,
            username TEXT,
            password TEXT,
            category TEXT DEFAULT 'Uncategorized',
            last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        # Add category column if it doesn't exist (for existing databases)
        try:
            self.c.execute("ALTER TABLE passwords ADD COLUMN category TEXT DEFAULT 'Uncategorized'")
            self.conn.commit()
        except sqlite3.OperationalError as e:
            if "duplicate column name: category" in str(e):
                pass # Column already exists
            else:
                raise # Re-raise other errors

        # MODIFIED: Added block to add last_modified column to existing dbs
        try:
            self.c.execute("ALTER TABLE passwords ADD COLUMN last_modified TIMESTAMP")
            # For existing rows, you might want to set a default value, 
            # but for this implementation, new entries will get it automatically
            # and old ones will be NULL, which our audit function handles.
            self.conn.commit()
        except sqlite3.OperationalError as e:
            if "duplicate column name: last_modified" in str(e):
                pass # Column already exists
            else:
                raise # Re-raise other errors

        self.c.execute("""CREATE TABLE IF NOT EXISTS vault_settings (
            user_id INTEGER,
            key TEXT,
            value TEXT
        )""")
        self.c.execute("""CREATE TABLE IF NOT EXISTS recovery_codes (
            user_id INTEGER,
            code TEXT,
            used INTEGER
        )""")
        self.c.execute("""CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            title TEXT,
            content TEXT
        )""")
        self.c.execute("""CREATE TABLE IF NOT EXISTS crypto_wallets (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            name TEXT,
            wallet_id_str TEXT,
            restore_key TEXT,
            secret_phrase TEXT
        )""")
        self.conn.commit()

    def login_screen(self):
        self.clear_layout(self.main_layout)

        login_widget = QWidget()
        login_layout = QVBoxLayout()
        login_widget.setLayout(login_layout)
        
        title_label = QLabel("Passy Password Manager")
        title_font = QFont()
        title_font.setPointSize(20)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter)
        login_layout.addWidget(title_label)
        
        login_layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

        username_label = QLabel("Username:")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter your username")
        username_layout = QHBoxLayout()
        username_layout.addWidget(username_label)
        username_layout.addWidget(self.username_input)
        login_layout.addLayout(username_layout)

        master_label = QLabel("Master Password:")
        self.master_input = QLineEdit()
        self.master_input.setEchoMode(QLineEdit.Password)
        self.master_input.setPlaceholderText("Enter your master password")
        master_layout = QHBoxLayout()
        master_layout.addWidget(master_label)
        master_layout.addWidget(self.master_input)
        login_layout.addLayout(master_layout)

        login_layout.addSpacerItem(QSpacerItem(20, 20, QSizePolicy.Minimum, QSizePolicy.Fixed))

        button_layout = QHBoxLayout()
        self.login_btn = QPushButton("Login")
        self.login_btn.clicked.connect(self.unlock_vault)
        self.login_btn.setMinimumHeight(35)
        
        self.register_btn = QPushButton("Create Account")
        self.register_btn.clicked.connect(self.create_account)
        self.register_btn.setMinimumHeight(35)

        button_layout.addWidget(self.login_btn)
        button_layout.addWidget(self.register_btn)
        login_layout.addLayout(button_layout)

        self.help_btn = QPushButton("How to Use")
        self.help_btn.clicked.connect(self.show_help_dialog)
        self.help_btn.setMinimumHeight(35)
        login_layout.addWidget(self.help_btn)

        login_layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

        self.main_layout.addWidget(login_widget, alignment=Qt.AlignCenter)

    def show_help_dialog(self):
        help_text = """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    margin: 15px; 
                    line-height: 1.5;
                    color: #E0E0E0; /* Light gray for text */
                    background-color: #34495E; /* Dark blue-gray background */
                }
                h1 { 
                    color: #1ABC9C; /* Greenish blue */
                    font-size: 24px; 
                    margin-top: 20px; 
                    margin-bottom: 10px; 
                    border-bottom: 2px solid #5D6D7E; /* Slightly lighter border */
                    padding-bottom: 5px;
                }
                h2 { 
                    color: #1ABC9C; /* Greenish blue */
                    font-size: 18px; 
                    margin-top: 15px; 
                    margin-bottom: 8px; 
                    border-bottom: 1px dashed #7F8C8D; /* Lighter dashed border */
                    padding-bottom: 3px;
                }
                p { 
                    margin-bottom: 8px; 
                }
                ul { 
                    margin-top: 0; 
                    padding-left: 25px; 
                    margin-bottom: 10px;
                }
                li { 
                    margin-bottom: 5px; 
                }
                strong { 
                    color: #ECF0F1; /* Lighter text for strong */
                    font-weight: bold;
                }
                .warning { 
                    color: #E74C3C; /* Red */
                    font-weight: bold; 
                    padding: 5px;
                    border-radius: 4px;
                    display: inline-block; /* Allows padding to apply */
                }
                .important { 
                    color: #E74C3C; /* Red */
                    font-weight: bold; 
                }
                code {
                    background-color: #2C3E50; /* Darker background for code */
                    color: #ECF0F1;
                    padding: 2px 4px;
                    border-radius: 3px;
                    font-family: monospace;
                }
            </style>
        </head>
        <body>
            <center><h1>Welcome to Passy</h1>
            <h1>Your Secure Password Manager!</h1></center>
            <p>This application helps you securely store your passwords, notes, and crypto wallet information.</p>

            <h2>1. Create Account</h2>
            <ul>
                <li>Enter a unique <b>Username</b> and a strong <b>Master Password</b>.</li>
                <li>Click "Create Account". This password will encrypt all your data.</li>
                <li>You will then be prompted to set up <b>Two-Factor Authentication (2FA)</b>.
                    <ul>
                        <li>A QR code will be generated. Scan it with an authenticator app (like Google Authenticator, Authy, Microsoft Authenticator) on your phone.</li>
                        <li>You will also be given <b>Recovery Codes</b>. Save these in a safe, offline place! They are crucial if you lose your 2FA device or forget your master password.</li>
                    </ul>
                </li>
            </ul>

            <h2>2. Login</h2>
            <ul>
                <li>Enter your <b>Username</b> and <b>Master Password</b>.</li>
                <li>Click "Login".</li>
                <li>You will then be prompted for your 2FA code from your authenticator app, or one of your recovery codes.</li>
            </ul>

            <h2>3. Managing Passwords (Passwords Tab)</h2>
            <ul>
                <li><b>Add Password:</b> Enter the website, username, and password. You can use the "Generate" button to create a secure password with custom options.</li>
                <li><b>Password Strength:</b> The bar will show how strong your entered password is.</li>
                <li>Click "Add Password" to save it.</li>
                <li>Your saved passwords will appear in the table below. You can view, copy, or edit them using the buttons in each row.</li>
            </ul>

            <h2>4. Managing Notes (Notes Tab)</h2>
            <ul>
                <li>Switch to the "Notes" tab.</li>
                <li><b>Add New Note:</b> Click this button to open a new window where you can enter a title and content for your note. Click "Save Note".</li>
                <li><b>View/Edit Note:</b> Double-click on any note in the list to open it in a new window for viewing or editing. Remember to save your changes.</li>
                <li><b>Delete Selected Note:</b> Select a note from the list and click this button to remove it.</li>
            </ul>

            <h2>5. Managing Crypto Wallets (Crypto Wallets Tab)</h2>
            <ul>
                <li>Switch to the "Crypto Wallets" tab.</li>
                <li><b>Add New Wallet:</b> Click this button to add details for a new crypto wallet.</li>
                <li><b>View/Edit Wallet:</b> Double-click on any wallet entry in the table to open its details for viewing or editing.</li>
                <li><b>Delete Selected Wallet:</b> Select a wallet entry from the table and click this button to remove it.</li>
                <li><p class="warning"><b>WARNING:</b> Storing crypto recovery phrases and private keys digitally carries extreme risk. Ensure your master password is uncompromisable and consider offline storage for these critical assets.</p></li>
            </ul>
            
            <h2>6. Password Audit (Password Audit Tab)</h2>
            <ul>
                <li>Switch to the "Password Audit" tab.</li>
                <li>Click the <b>"Run Password Health Audit"</b> button.</li>
                <li>The tables below will populate with information about:
                    <ul>
                        <li><b>Reused Passwords:</b> Shows which accounts are using the same password.</li>
                        <li><b>Weak Passwords:</b> Lists passwords that do not meet a strong criteria.</li>
                        <li><b>Old Passwords:</b> Shows passwords that haven't been updated in over 6 months.</li>
                        <li><b>Pwned Passwords:</b> Lists any passwords that have appeared in known data breaches.</li>
                    </ul>
                </li>
                <li>Use this information to update your weak or reused passwords for better security.</li>
            </ul>

            <h2>7. Options (Menu Bar)</h2>
            <ul>
                <li><b>Export/Import Vault:</b> Backup your data to a secure encrypted file or import from a backup.</li>
                <li><b>View Recovery Codes:</b> Check the status of your current recovery codes.</li>
                <li><b>Regenerate Recovery Codes:</b> If you've used some recovery codes or want new ones, you can generate a fresh set here. Remember to save them!</li>
                <li><b>Change Master Password:</b> You can change your master password. The app will securely re-encrypt all your stored passwords, notes, and 2FA secrets with the new master key.</li>
                <li><b>Change Theme:</b> Select between Dark and Light mode for the application's appearance. Your preference will be saved.</li>
            </ul>

            <h2>8. Account (Menu Bar)</h2>
            <ul>
                <li><b>Logout:</b> Safely log out of your account.</li>
            </ul>

            <h2>Important Security Reminders:</h2>
            <ul>
                <li><span class="important"><b>NEVER forget your Master Password.</b> Without it, your data is inaccessible.</span></li>
                <li><span class="important"><b>Keep your 2FA Recovery Codes SAFE and OFFLINE.</b> They are your backup.</span></li>
                <li>Regularly back up your <code>vault.db</code> file if you want to be extra cautious, though losing it means losing all your data.</li>
                <li>For crypto wallet information, physical offline storage (e.g., hardware wallet, paper backup) is always recommended over digital storage. Use this feature with extreme caution.</li>
            </ul>

            <p>For any issues, please refer to the application's website or contact support.</p>
        </body>
        </html>
        """
        
        help_dialog = QDialog(self)
        help_dialog.setWindowTitle("How to Use Passy")
        
        help_dialog.setFixedSize(700, 500) 

        dialog_layout = QVBoxLayout(help_dialog)

        text_edit = QTextEdit()
        text_edit.setHtml(help_text) 
        text_edit.setReadOnly(True) 
        
        dialog_layout.addWidget(text_edit)

        close_button = QPushButton("Close")
        close_button.clicked.connect(help_dialog.accept) 
        dialog_layout.addWidget(close_button, alignment=Qt.AlignCenter)

        help_dialog.exec_() 

    def create_account(self):
        username = self.username_input.text()
        password = self.master_input.text()
        if not username or not password:
            QMessageBox.warning(self, "Error", "Username and password required.")
            return
        
        if len(password) < 8:
            QMessageBox.warning(self, "Weak Password", "Master password should be at least 8 characters long for better security.")
            return

        try:
            # Hash the master password using bcrypt for storage
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            
            # Store the bcrypt hash in the database, with default dark theme
            self.c.execute("INSERT INTO users (username, master_password_hash, theme_mode) VALUES (?, ?, ?)", (username, hashed_password.decode('utf-8'), 'dark'))
            self.conn.commit()
            QMessageBox.information(self, "Success", "Account created. You can now log in.")
        except sqlite3.IntegrityError:
            QMessageBox.warning(self, "Error", "Username already exists.")

    def unlock_vault(self):
        username = self.username_input.text()
        password = self.master_input.text()
        if not username or not password:
            QMessageBox.warning(self, "Error", "Username and password required.")
            return

        self.c.execute("SELECT id, master_password_hash FROM users WHERE username=?", (username,))
        row = self.c.fetchone()
        if not row:
            QMessageBox.warning(self, "Error", "Invalid credentials.")
            return
        user_id, stored_hash = row

        try:
            # Verify the master password using bcrypt
            if not bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
                QMessageBox.critical(self, "Error", "Wrong master password.")
                return

            # Derive the Fernet key *only after* master password verification
            self.master_key = derive_key(password)
            self.user_id = user_id

            self.totp_secret = self.get_or_create_2fa_secret()

            code, ok = QInputDialog.getText(
                self, "Two-Factor Authentication",
                "Enter 6-digit code (or 8-digit recovery code):"
            )
            if not ok: # User cancelled 2FA
                self.master_key = None # Clear master key on 2FA cancel for security
                self.user_id = None
                return

            totp_valid = pyotp.TOTP(self.totp_secret).verify(code)

            self.c.execute("SELECT code, used FROM recovery_codes WHERE user_id=?", (self.user_id,))
            recovery_valid = False
            code_was_used = False 

            all_recovery_codes = self.c.fetchall()

            for enc_code, used_status in all_recovery_codes:
                try:
                    decrypted_recovery_code = self.decrypt(enc_code)
                    if decrypted_recovery_code == code:
                        if used_status == 0: # Check if recovery code is unused
                            recovery_valid = True
                            self.c.execute("UPDATE recovery_codes SET used=1 WHERE user_id=? AND code=?", (self.user_id, enc_code))
                            self.conn.commit()
                            
                            # Check remaining recovery codes
                            self.c.execute("SELECT COUNT(*) FROM recovery_codes WHERE user_id=? AND used=0", (self.user_id,))
                            unused_count = self.c.fetchone()[0]

                            if unused_count <= 2: # Warn user if running low
                                reply = QMessageBox.question(self, "Low Recovery Codes", f"You only have {unused_count} recovery code(s) left. Do you want to generate new recovery codes now?", QMessageBox.Yes | QMessageBox.No)
                                if reply == QMessageBox.Yes:
                                    self.generate_recovery_codes_prompt() # Call the one with prompt
                                else:
                                    QMessageBox.information(self, "Recovery Code Used", f"You have {unused_count} recovery code(s) left.")
                            break
                        else:
                            code_was_used = True # This code was valid but already used
                except InvalidToken:
                    continue # Skip if decryption fails for a recovery code

            if not totp_valid and not recovery_valid:
                if code_was_used:
                    QMessageBox.critical(self, "2FA Failed", "That recovery code has already been used.")
                else:
                    QMessageBox.critical(self, "2FA Failed", "Invalid authentication code or recovery code.")
                self.master_key = None # Clear master key on 2FA failure
                self.user_id = None
                return

            self.load_main_ui()
            self.apply_theme(self.load_theme_preference())
            # Start the inactivity timer after successful login
            self.inactivity_timer.start(self.inactivity_timeout_seconds * 1000)


        except InvalidToken:
            QMessageBox.critical(self, "Error", "An unexpected decryption error occurred. Master key might be corrupt.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An unexpected error occurred during login: {e}")


    def get_or_create_2fa_secret(self):
        self.c.execute("SELECT value FROM vault_settings WHERE user_id=? AND key='2fa_secret'", (self.user_id,))
        row = self.c.fetchone()
        if row:
            return self.decrypt(row[0])

        # If no 2FA secret exists, generate a new one
        secret = pyotp.random_base32()
        encrypted = self.encrypt(secret)
        self.c.execute("INSERT INTO vault_settings (user_id, key, value) VALUES (?, ?, ?)", (self.user_id, '2fa_secret', encrypted))
        self.conn.commit()

        # Generate QR code for 2FA setup
        uri = pyotp.TOTP(secret).provisioning_uri(name=f"{self.user_id}@PassyVault", issuer_name="Passy Password Manager")
        img = qrcode.make(uri)
        qr_code_path = "qrcode.png"
        img.save(qr_code_path)

        QMessageBox.information(self, "2FA Setup - Important!",
                                    f"A Two-Factor Authentication QR code has been saved as '{qr_code_path}'.\n\n"
                                    "Please scan this image with your authenticator app (e.g., Google Authenticator, Authy, Microsoft Authenticator) **immediately**.\n\n"
                                    "Once scanned, enter the 6-digit code from your app into the prompt to finish setting up 2FA."
                                    "\n\n**Keep this QR code image secure or delete it after successful setup!**",
                                    QMessageBox.Ok)
        
        self.generate_recovery_codes_initial(count=5) # Also generate recovery codes for new 2FA setup

        return secret

    def generate_recovery_codes_initial(self, count=5):
        # This version is for initial setup, without requiring master password re-entry
        self.c.execute("DELETE FROM recovery_codes WHERE user_id=?", (self.user_id,)) # Clear old codes
        codes = [''.join(random.choices(string.ascii_uppercase + string.digits, k=8)) for _ in range(count)]
        recovery_message = "Your new recovery codes are:\n\n" + '\n'.join(codes) + "\n\n" \
                                "**IMPORTANT:** Store these codes in a very safe, offline place (e.g., printed, written down). " \
                                "Each code can be used once to log in if you lose access to your 2FA authenticator app. " \
                                "Do NOT store them on this computer unless encrypted by other means."
        
        for code in codes:
            encrypted = self.encrypt(code)
            self.c.execute("INSERT INTO recovery_codes (user_id, code, used) VALUES (?, ?, 0)", (self.user_id, encrypted))
        self.conn.commit()
        QMessageBox.information(self, "Your New Recovery Codes", recovery_message, QMessageBox.Ok)

    def generate_recovery_codes_prompt(self, count=5):
        # This version is for regeneration from the menu, requiring master password re-entry
        old_pass, ok = QInputDialog.getText(self, "Confirm Master Password", "Enter your current master password to regenerate recovery codes:", QLineEdit.Password)
        if not ok or not old_pass:
            return

        self.c.execute("SELECT master_password_hash FROM users WHERE id=?", (self.user_id,))
        stored_hash = self.c.fetchone()[0]

        if not bcrypt.checkpw(old_pass.encode('utf-8'), stored_hash.encode('utf-8')):
            QMessageBox.critical(self, "Authentication Failed", "Incorrect master password.")
            return
        
        # Now regenerate codes
        self.generate_recovery_codes_initial(count) # Use the non-prompt version after auth
    
    def view_recovery_codes(self):
        # Step 1: Confirm master password for security
        password, ok = QInputDialog.getText(self, "Confirm Identity",
                                            "Enter your master password to view your recovery codes:",
                                            QLineEdit.Password)
        if not ok or not password:
            return

        self.c.execute("SELECT master_password_hash FROM users WHERE id=?", (self.user_id,))
        stored_hash = self.c.fetchone()[0]
        if not bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
            QMessageBox.critical(self, "Authentication Failed", "Incorrect master password.")
            return

        # Step 2: Fetch all recovery codes for the user from the database
        self.c.execute("SELECT code, used FROM recovery_codes WHERE user_id=?", (self.user_id,))
        codes_data = self.c.fetchall()

        if not codes_data:
            QMessageBox.information(self, "No Codes Found", "No recovery codes found for this account. You can generate them from the Options menu.")
            return

        # Step 3: Create and configure the dialog to display the codes
        dialog = QDialog(self)
        dialog.setWindowTitle("Your Recovery Codes")
        dialog.setMinimumWidth(400)
        
        layout = QVBoxLayout(dialog)

        info_label = QLabel("Green codes are available. Red codes have been used.\nStore these safely offline.")
        info_label.setWordWrap(True)
        layout.addWidget(info_label)

        codes_list_widget = QListWidget()
        # Use a monospaced font for better readability of codes
        monospace_font = QFont("Courier New", 12)
        codes_list_widget.setFont(monospace_font)
        
        any_decryption_failed = False
        for enc_code, used_status in codes_data:
            try:
                decrypted_code = self.decrypt(enc_code)
                if used_status == 0:  # Unused code
                    item = QListWidgetItem(f"{decrypted_code}   (Unused)")
                    item.setForeground(Qt.green)
                else:  # Used code
                    item = QListWidgetItem(f"{decrypted_code}   (Used)")
                    item.setForeground(Qt.red)
                    # Add a strike-through font for used codes
                    font = item.font()
                    font.setStrikeOut(True)
                    item.setFont(font)

                codes_list_widget.addItem(item)
            except InvalidToken:
                any_decryption_failed = True
                continue

        layout.addWidget(codes_list_widget)

        if any_decryption_failed:
            error_label = QLabel("Warning: Some codes could not be decrypted and are not shown.")
            error_label.setStyleSheet("color: orange;")
            layout.addWidget(error_label)

        close_button = QPushButton("Close")
        close_button.clicked.connect(dialog.accept)
        layout.addWidget(close_button, alignment=Qt.AlignCenter)

        dialog.exec_()

    def encrypt(self, plaintext):
        if self.master_key is None:
            raise ValueError("Master key not set for encryption.")
        f = Fernet(self.master_key)
        return f.encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext):
        if self.master_key is None:
            raise ValueError("Master key not set for decryption.")
        f = Fernet(self.master_key)
        return f.decrypt(ciphertext.encode()).decode()

    def safe_decrypt(self, data):
        """
        Attempts to decrypt data. If decryption fails (e.g., data is plaintext),
        it returns the original data.
        """
        if not data:  # Handles None or empty strings
            return ""
        try:
            # Try to decrypt assuming it's a valid Fernet token
            return self.decrypt(data)
        except InvalidToken:
            # If it fails, it's likely old plaintext data. Return it directly.
            return data

    # --- Theme Management Functions ---
    def apply_theme(self, theme_name):
        """Applies the specified theme to the application."""
        if theme_name == 'dark':
            QApplication.instance().setStyleSheet(self._dark_stylesheet)
        elif theme_name == 'light':
            QApplication.instance().setStyleSheet(self._light_stylesheet)
        self.current_theme = theme_name # Update current theme state

    def set_dark_mode(self):
        """Switches to dark mode and saves the preference."""
        self.apply_theme('dark')
        self.save_theme_preference('dark')
        QMessageBox.information(self, "Theme Changed", "Switched to Dark Mode.")

    def set_light_mode(self):
        """Switches to light mode and saves the preference."""
        self.apply_theme('light')
        self.save_theme_preference('light')
        QMessageBox.information(self, "Theme Changed", "Switched to Light Mode.")

    def load_theme_preference(self):
        """Loads the user's theme preference from the database."""
        self.c.execute("SELECT theme_mode FROM users WHERE id=?", (self.user_id,))
        result = self.c.fetchone()
        if result and result[0] in ['dark', 'light']:
            return result[0]
        return 'dark' # Default to dark if no preference is found or it's invalid

    def save_theme_preference(self, theme_name):
        """Saves the user's theme preference to the database."""
        self.c.execute("UPDATE users SET theme_mode=? WHERE id=?", (theme_name, self.user_id))
        self.conn.commit()

    def load_main_ui(self):
        self.clear_layout(self.main_layout)

        # --- Menu Bar Setup ---
        self.menu_bar = QMenuBar()
        
        self.options_menu = QMenu("Options", self)

        # --- Import/Export Actions ---
        export_action = QAction("Export Vault...", self)
        export_action.triggered.connect(self.export_vault)
        import_action = QAction("Import Vault...", self)
        import_action.triggered.connect(self.import_vault)
        self.options_menu.addAction(export_action)
        self.options_menu.addAction(import_action)
        self.options_menu.addSeparator() # Adds a nice visual line
        
        view_recovery_action = QAction("View Recovery Codes", self)
        view_recovery_action.triggered.connect(self.view_recovery_codes)
        self.options_menu.addAction(view_recovery_action)
        
        regen = QAction("Regenerate Recovery Codes", self)
        regen.triggered.connect(self.generate_recovery_codes_prompt) # Connect to the prompt version
        self.options_menu.addAction(regen)

        self.options_menu.addSeparator()

        change = QAction("Change Master Password", self)
        change.triggered.connect(self.change_master_password)
        self.options_menu.addAction(change)
        self.menu_bar.addMenu(self.options_menu)
        
        # --- New Theme Menu ---
        self.theme_menu = QMenu("Theme", self)
        dark_mode_action = QAction("Dark Mode", self)
        dark_mode_action.triggered.connect(self.set_dark_mode)
        light_mode_action = QAction("Light Mode", self)
        light_mode_action.triggered.connect(self.set_light_mode)
        self.theme_menu.addAction(dark_mode_action)
        self.theme_menu.addAction(light_mode_action)
        self.menu_bar.addMenu(self.theme_menu) # Add theme menu to menu bar

        self.info_menu = QMenu("Info", self)
        about_action = QAction("About This App", self)
        about_action.triggered.connect(lambda: QMessageBox.information(self, "About", "Passy The Password Manager\nVersion 1.0\nCreated by Thorn Industries\nDami3n Thorn"))
        website_action = QAction("Visit Website", self)
        website_action.triggered.connect(lambda: QDesktopServices.openUrl(QUrl("https://github.com/mrdami3n"))) # Placeholder URL
        help_action = QAction("How to Use", self)
        help_action.triggered.connect(self.show_help_dialog)
        self.info_menu.addAction(about_action)
        self.info_menu.addAction(website_action)
        self.info_menu.addAction(help_action)
        
        self.account_menu = QMenu("Account", self)
        logout_action = QAction("Logout", self)
        logout_action.triggered.connect(self.logout)
        self.account_menu.addAction(logout_action)
        self.menu_bar.addMenu(self.account_menu)     
        self.menu_bar.addMenu(self.info_menu)
        self.main_layout.addWidget(self.menu_bar)

        # --- Tab Widget Setup ---
        self.tab_widget = QTabWidget()
        self.main_layout.addWidget(self.tab_widget)

        # --- Passwords Tab ---
        self.password_tab = QWidget()
        self.password_layout = QVBoxLayout(self.password_tab)
        self.tab_widget.addTab(self.password_tab, "Passwords")

        # Password input form layout (using QGridLayout for better alignment)
        password_form_grid = QGridLayout()

        password_form_grid.addWidget(QLabel("Website:"), 0, 0, Qt.AlignRight)
        self.website_input = QLineEdit()
        self.website_input.setPlaceholderText("e.g., Google, Facebook")
        password_form_grid.addWidget(self.website_input, 0, 1, 1, 2) # Span 2 columns

        password_form_grid.addWidget(QLabel("Username:"), 1, 0, Qt.AlignRight)
        self.username_input_main = QLineEdit() # Renamed to avoid conflict
        self.username_input_main.setPlaceholderText("Your username or email for this site")
        password_form_grid.addWidget(self.username_input_main, 1, 1, 1, 2)

        password_form_grid.addWidget(QLabel("Password:"), 2, 0, Qt.AlignRight)
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter or generate password")
        self.password_input.textChanged.connect(self.update_strength_meter)
        password_form_grid.addWidget(self.password_input, 2, 1)

        self.gen_btn = QPushButton("Generate")
        self.gen_btn.clicked.connect(self.generate_password)
        password_form_grid.addWidget(self.gen_btn, 2, 2)

        password_form_grid.addWidget(QLabel("Category:"), 3, 0, Qt.AlignRight) # New Label
        self.category_combo = QComboBox() # New ComboBox
        self.category_combo.addItems(["Uncategorized", "Work", "Personal", "Social Media", "Banking", "Shopping", "Email", "Other"])
        password_form_grid.addWidget(self.category_combo, 3, 1, 1, 2) # Span 2 columns

        password_form_grid.addWidget(QLabel("Strength:"), 4, 0, Qt.AlignRight) # Adjusted row index
        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 100)
        self.strength_bar.setValue(0)
        self.strength_bar.setTextVisible(True)
        password_form_grid.addWidget(self.strength_bar, 4, 1, 1, 2) # Adjusted row index

        self.add_btn = QPushButton("Add Password")
        password_form_grid.addWidget(self.add_btn, 5, 0, 1, 3) # Adjusted row index, Span all columns
        self.add_btn.clicked.connect(self.add_password)

        self.password_layout.addLayout(password_form_grid)
        self.password_layout.addSpacing(20) # Add some space

        # Separator Line
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        self.password_layout.addWidget(line)
        self.password_layout.addSpacing(10)

        # --- Search and Filter for Passwords ---
        password_filter_layout = QHBoxLayout()
        password_filter_layout.addWidget(QLabel("Search:"))
        self.password_search_input = QLineEdit()
        self.password_search_input.setPlaceholderText("Search by website or username")
        self.password_search_input.textChanged.connect(self.filter_passwords)
        password_filter_layout.addWidget(self.password_search_input)

        password_filter_layout.addWidget(QLabel("Filter by Category:"))
        self.password_filter_category_combo = QComboBox()
        self.password_filter_category_combo.addItems(["All", "Uncategorized", "Work", "Personal", "Social Media", "Banking", "Shopping", "Email", "Other"])
        self.password_filter_category_combo.currentIndexChanged.connect(self.filter_passwords)
        password_filter_layout.addWidget(self.password_filter_category_combo)
        self.password_layout.addLayout(password_filter_layout)


        self.table = QTableWidget()
        self.table.setColumnCount(7) # MODIFIED: ID, Website, Username, Category, View, Copy, Edit
        self.table.setHorizontalHeaderLabels(["ID", "Website", "Username", "Category", "", "", ""]) # MODIFIED: Empty headers for buttons
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnHidden(0, True) # Hide the ID column
        # Adjust button column widths (now 3 columns over)
        self.table.setColumnWidth(4, 80)
        self.table.setColumnWidth(5, 80)
        self.table.setColumnWidth(6, 80)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers) # Make cells non-editable by default

        self.password_layout.addWidget(self.table)
        self.load_passwords() # Initial load of all passwords

        # Add a "Delete Selected" button for passwords
        self.delete_password_btn = QPushButton("Delete Selected Password")
        self.delete_password_btn.clicked.connect(self.delete_selected_password)
        self.password_layout.addWidget(self.delete_password_btn)


        # --- Notes Tab ---
        self.notes_tab = QWidget()
        self.notes_layout = QVBoxLayout(self.notes_tab)
        self.tab_widget.addTab(self.notes_tab, "Notes")

        # --- Search for Notes ---
        notes_filter_layout = QHBoxLayout()
        notes_filter_layout.addWidget(QLabel("Search Notes:"))
        self.notes_search_input = QLineEdit()
        self.notes_search_input.setPlaceholderText("Search by note title or content")
        self.notes_search_input.textChanged.connect(self.filter_notes) # Connect to filter_notes
        notes_filter_layout.addWidget(self.notes_search_input)
        self.notes_layout.addLayout(notes_filter_layout)

        self.notes_list_widget = QListWidget()
        self.notes_list_widget.itemDoubleClicked.connect(self.open_note_viewer)
        self.notes_layout.addWidget(self.notes_list_widget)

        notes_buttons_layout = QHBoxLayout()
        self.add_note_btn = QPushButton("Add New Note")
        self.add_note_btn.clicked.connect(self.add_new_note)
        self.delete_note_btn = QPushButton("Delete Selected Note")
        self.delete_note_btn.clicked.connect(self.delete_selected_note) # Updated to include confirmation
        
        notes_buttons_layout.addWidget(self.add_note_btn)
        notes_buttons_layout.addWidget(self.delete_note_btn)
        self.notes_layout.addLayout(notes_buttons_layout)
        self.load_notes() # Initial load of all notes

        # --- Crypto Wallets Tab ---
        self.crypto_tab = QWidget()
        self.crypto_layout = QVBoxLayout(self.crypto_tab)
        self.tab_widget.addTab(self.crypto_tab, "Crypto Wallets")

        # --- Search for Crypto Wallets ---
        crypto_filter_layout = QHBoxLayout()
        crypto_filter_layout.addWidget(QLabel("Search Wallets:"))
        self.crypto_search_input = QLineEdit()
        self.crypto_search_input.setPlaceholderText("Search by wallet name or ID/address")
        self.crypto_search_input.textChanged.connect(self.filter_crypto_wallets) # Connect to filter_crypto_wallets
        crypto_filter_layout.addWidget(self.crypto_search_input)
        self.crypto_layout.addLayout(crypto_filter_layout)

        self.crypto_table = QTableWidget()
        self.crypto_table.setColumnCount(3) # Name, ID/Address, Action buttons
        self.crypto_table.setHorizontalHeaderLabels(["Wallet Name", "Wallet ID/Address", ""]) # Empty header for buttons
        self.crypto_table.horizontalHeader().setStretchLastSection(True)
        self.crypto_table.setEditTriggers(QTableWidget.NoEditTriggers) # Make cells non-editable by default
        self.crypto_table.setColumnWidth(2, 100) # Width for buttons

        self.crypto_table.itemDoubleClicked.connect(self.open_crypto_wallet_viewer) 
        self.crypto_layout.addWidget(self.crypto_table)

        crypto_buttons_layout = QHBoxLayout()
        self.add_crypto_btn = QPushButton("Add New Wallet")
        self.add_crypto_btn.clicked.connect(self.add_new_crypto_wallet)
        self.delete_crypto_btn = QPushButton("Delete Selected Wallet")
        self.delete_crypto_btn.clicked.connect(self.delete_selected_crypto_wallet) # Updated to include confirmation

        crypto_buttons_layout.addWidget(self.add_crypto_btn)
        crypto_buttons_layout.addWidget(self.delete_crypto_btn)
        self.crypto_layout.addLayout(crypto_buttons_layout)

        self.load_crypto_wallets() # Initial load of all crypto wallets

        # --- Password Audit Tab ---
        self.audit_tab = QWidget()
        self.audit_layout = QVBoxLayout(self.audit_tab)
        self.tab_widget.addTab(self.audit_tab, "Password Audit")

        audit_run_btn = QPushButton("Run Password Health Audit")
        audit_run_btn.clicked.connect(self.run_password_audit)
        self.audit_layout.addWidget(audit_run_btn)
        
        # Reused Passwords Section
        reused_group = QGroupBox("Reused Passwords")
        reused_layout = QVBoxLayout()
        reused_group.setLayout(reused_layout)
        reused_layout.addWidget(QLabel("Passwords used for more than one account."))
        self.reused_passwords_table = QTableWidget()
        self.reused_passwords_table.setColumnCount(3)
        self.reused_passwords_table.setHorizontalHeaderLabels(["Password", "Used For", "Action"])
        reused_layout.addWidget(self.reused_passwords_table)
        self.audit_layout.addWidget(reused_group)

        # Weak Passwords Section
        weak_group = QGroupBox("Weak Passwords")
        weak_layout = QVBoxLayout()
        weak_group.setLayout(weak_layout)
        weak_layout.addWidget(QLabel("Passwords that are considered easy to guess."))
        self.weak_passwords_table = QTableWidget()
        self.weak_passwords_table.setColumnCount(3)
        self.weak_passwords_table.setHorizontalHeaderLabels(["Website", "Username", "Strength"])
        weak_layout.addWidget(self.weak_passwords_table)
        self.audit_layout.addWidget(weak_group)
        
        # Old Passwords Section
        old_group = QGroupBox("Old Passwords (Older than 6 months)")
        old_layout = QVBoxLayout()
        old_group.setLayout(old_layout)
        old_layout.addWidget(QLabel("Passwords that have not been changed in a long time."))
        self.old_passwords_table = QTableWidget()
        self.old_passwords_table.setColumnCount(3)
        self.old_passwords_table.setHorizontalHeaderLabels(["Website", "Username", "Last Updated"])
        old_layout.addWidget(self.old_passwords_table)
        self.audit_layout.addWidget(old_group)

        # --- NEW: Pwned Passwords Section ---
        pwned_group = QGroupBox("Pwned Passwords")
        pwned_layout = QVBoxLayout()
        pwned_group.setLayout(pwned_layout)
        pwned_layout.addWidget(QLabel("Passwords found in known data breaches."))
        self.pwned_passwords_table = QTableWidget()
        self.pwned_passwords_table.setColumnCount(4)
        self.pwned_passwords_table.setHorizontalHeaderLabels(["Website", "Username", "Found in Breaches", "Action"])
        pwned_layout.addWidget(self.pwned_passwords_table)
        self.audit_layout.addWidget(pwned_group)


    def update_strength_meter(self):
        strength = calculate_password_strength(self.password_input.text())
        self.strength_bar.setValue(strength)
        if strength < 40:
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: #f44336; }") # Red
        elif strength < 70:
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: #ffc107; }") # Orange
        else:
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: #4CAF50; }") # Green

    def add_password(self):
        website = self.website_input.text().strip()
        username = self.username_input_main.text().strip()
        password = self.password_input.text()
        category = self.category_combo.currentText() # Get selected category
        
        if not all([website, username, password]):
            QMessageBox.warning(self, "Error", "All fields are required.")
            return
        
        # --- NEW: Check if password is pwned ---
        pwn_count = check_pwned(password)
        if pwn_count > 0:
            reply = QMessageBox.warning(
                self, 
                "Security Warning", 
                f"This password has been found in {pwn_count:,} known data breaches. "
                "It is strongly recommended that you use a different password.\n\n"
                "Do you want to use this password anyway?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            if reply == QMessageBox.No:
                return
        elif pwn_count == -1:
             QMessageBox.warning(self, "API Error", "Could not check if the password was pwned. Please check your internet connection.")


        encrypted_password = self.encrypt(password)
        encrypted_category = self.encrypt(category) # Encrypt category too

        self.c.execute("INSERT INTO passwords (user_id, website, username, password, category, last_modified) VALUES (?, ?, ?, ?, ?, ?)",
                       (self.user_id, website, username, encrypted_password, encrypted_category, datetime.datetime.now()))
        self.conn.commit()
        QMessageBox.information(self, "Success", "Password added successfully!")
        
        self.website_input.clear()
        self.username_input_main.clear()
        self.password_input.clear()
        self.category_combo.setCurrentIndex(0) # Reset to "Uncategorized"
        self.strength_bar.setValue(0)
        self.load_passwords() # Refresh with the new entry

    def load_passwords(self, search_query="", category_filter="All"):
        self.table.setRowCount(0)  # Clear existing rows

        # Step 1: Fetch rows from DB, filtering only by the text search query in SQL.
        query = "SELECT id, website, username, password, category FROM passwords WHERE user_id=?"
        params = [self.user_id]

        if search_query:
            query += " AND (website LIKE ? OR username LIKE ?)"
            search_param = f"%{search_query}%"
            params.extend([search_param, search_param])
        
        self.c.execute(query, tuple(params))
        all_rows = self.c.fetchall()
        
        # Step 2: In Python, filter the fetched rows by the category dropdown selection.
        final_rows = []
        if category_filter == "All":
            final_rows = all_rows
        else:
            for row in all_rows:
                # The 'category' is at index 4 of the row tuple
                encrypted_category = row[4]
                decrypted_category = self.safe_decrypt(encrypted_category)
                if decrypted_category == category_filter:
                    final_rows.append(row)

        # Step 3: Populate the table with the correctly filtered rows.
        if self.table.columnCount() != 7:
            self.table.setColumnCount(7)
            self.table.setHorizontalHeaderLabels(["ID", "Website", "Username", "Category", "", "", ""])
            self.table.setColumnHidden(0, True)
            self.table.setColumnWidth(4, 80)  # View
            self.table.setColumnWidth(5, 80)  # Copy
            self.table.setColumnWidth(6, 80)  # Edit

        for row in final_rows:
            password_id, website, username, encrypted_password, encrypted_category = row
            i = self.table.rowCount()
            self.table.insertRow(i)
            
            id_item = QTableWidgetItem(str(password_id))
            id_item.setData(Qt.UserRole, password_id)
            self.table.setItem(i, 0, id_item) # Hidden ID

            website_button = QPushButton(website)
            website_button.setFlat(True)
            website_button.setStyleSheet("text-align: left; text-decoration: underline; color: #3498DB;")
            url_to_open = website
            if not (url_to_open.startswith("http://") or url_to_open.startswith("https://")):
                url_to_open = "http://" + url_to_open
            website_button.clicked.connect(lambda _, url=url_to_open: QDesktopServices.openUrl(QUrl(url)))
            self.table.setCellWidget(i, 1, website_button)
            
            self.table.setItem(i, 2, QTableWidgetItem(username))
            
            # Use safe_decrypt to handle both encrypted and old plaintext categories
            decrypted_category = self.safe_decrypt(encrypted_category)
            self.table.setItem(i, 3, QTableWidgetItem(decrypted_category))

            show_button = QPushButton("Show")
            show_button.clicked.connect(lambda _, r=i, c=encrypted_password: self.show_password_in_cell(r, c))
            self.table.setCellWidget(i, 4, show_button)

            copy_button = QPushButton("Copy")
            copy_button.clicked.connect(lambda _, c=encrypted_password: self.copy_to_clipboard(c))
            self.table.setCellWidget(i, 5, copy_button)
            
            edit_button = QPushButton("Edit")
            edit_button.clicked.connect(lambda _, pid=password_id: self.edit_password(pid))
            self.table.setCellWidget(i, 6, edit_button)
            
        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setStretchLastSection(True)

    def filter_passwords(self):
        search_query = self.password_search_input.text()
        category_filter = self.password_filter_category_combo.currentText()
        self.load_passwords(search_query, category_filter)

    def show_password_in_cell(self, row, encrypted_password):
        try:
            decrypted_password = self.decrypt(encrypted_password)
            QMessageBox.information(self, "Password", f"The password is: \n\n{decrypted_password}\n\n(Copied to clipboard automatically and will clear in {self.clipboard_clear_delay_seconds} seconds)")
            QApplication.clipboard().setText(decrypted_password)
            self.clipboard_timer.start(self.clipboard_clear_delay_seconds * 1000)
        except InvalidToken:
            QMessageBox.critical(self, "Decryption Error", "Could not decrypt this password. The master key might be incorrect or the data is corrupted.")

    def copy_to_clipboard(self, encrypted_data):
        try:
            decrypted_data = self.decrypt(encrypted_data)
            QApplication.clipboard().setText(decrypted_data)
            QMessageBox.information(self, "Copied!", f"Data copied to clipboard. It will clear in {self.clipboard_clear_delay_seconds} seconds.")
            self.clipboard_timer.start(self.clipboard_clear_delay_seconds * 1000)
        except InvalidToken:
            QMessageBox.critical(self, "Decryption Error", "Could not decrypt data for copying.")

    def clear_clipboard(self):
        clipboard = QApplication.clipboard()
        if clipboard.text() and clipboard.text() != "":
            clipboard.clear()

    def generate_password(self):
        dialog = PasswordGeneratorDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            generated_password = dialog.get_generated_password()
            if generated_password:
                self.password_input.setText(generated_password)
                QMessageBox.information(self, "Password Generated", "A new password has been generated and set in the password field.")

    def change_master_password(self):
        old_pass, ok = QInputDialog.getText(self, "Confirm Current Master Password", "Enter your CURRENT master password:", QLineEdit.Password)
        if not ok or not old_pass:
            return

        self.c.execute("SELECT master_password_hash FROM users WHERE id=?", (self.user_id,))
        stored_hash = self.c.fetchone()[0]

        if not bcrypt.checkpw(old_pass.encode('utf-8'), stored_hash.encode('utf-8')):
            QMessageBox.critical(self, "Authentication Failed", "Incorrect current master password.")
            return

        new_pass, ok = QInputDialog.getText(self, "Change Master Password", "Enter new master password:", QLineEdit.Password)
        if not ok or not new_pass:
            return
        
        if len(new_pass) < 8:
            QMessageBox.warning(self, "Weak Password", "New master password should be at least 8 characters long for better security.")
            return

        confirm_pass, ok = QInputDialog.getText(self, "Confirm Password", "Confirm new master password:", QLineEdit.Password)
        if not ok or new_pass != confirm_pass:
            QMessageBox.warning(self, "Error", "Passwords do not match.")
            return

        current_master_key_for_decryption = self.master_key
        new_key_for_encryption = derive_key(new_pass)
        new_hashed_master = bcrypt.hashpw(new_pass.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        try:
            self.c.execute("UPDATE users SET master_password_hash=? WHERE id=?", (new_hashed_master, self.user_id))

            self.c.execute("SELECT id, password, category FROM passwords WHERE user_id=?", (self.user_id,))
            for pid, enc_pass, enc_cat in self.c.fetchall():
                plain_pass = Fernet(current_master_key_for_decryption).decrypt(enc_pass.encode()).decode()
                new_enc_pass = Fernet(new_key_for_encryption).encrypt(plain_pass.encode()).decode()

                plain_cat = self.safe_decrypt(enc_cat) # Use safe_decrypt here too!
                new_enc_cat = Fernet(new_key_for_encryption).encrypt(plain_cat.encode()).decode()

                self.c.execute("UPDATE passwords SET password=?, category=? WHERE id=?", (new_enc_pass, new_enc_cat, pid))

            self.c.execute("SELECT key, value FROM vault_settings WHERE user_id=?", (self.user_id,))
            for key_name, val in self.c.fetchall():
                plain = Fernet(current_master_key_for_decryption).decrypt(val.encode()).decode()
                new_val = Fernet(new_key_for_encryption).encrypt(plain.encode()).decode()
                self.c.execute("UPDATE vault_settings SET value=? WHERE user_id=? AND key=?", (new_val, self.user_id, key_name))

            self.c.execute("SELECT code FROM recovery_codes WHERE user_id=?", (self.user_id,))
            for row in self.c.fetchall():
                plain = Fernet(current_master_key_for_decryption).decrypt(row[0].encode()).decode()
                new_enc = Fernet(new_key_for_encryption).encrypt(plain.encode()).decode()
                self.c.execute("UPDATE recovery_codes SET code=? WHERE user_id=? AND code=?", (new_enc, self.user_id, row[0]))

            self.c.execute("SELECT id, title, content FROM notes WHERE user_id=?", (self.user_id,))
            for note_id, enc_title, enc_content in self.c.fetchall():
                plain_title = Fernet(current_master_key_for_decryption).decrypt(enc_title.encode()).decode()
                plain_content = Fernet(current_master_key_for_decryption).decrypt(enc_content.encode()).decode()
                new_enc_title = Fernet(new_key_for_encryption).encrypt(plain_title.encode()).decode()
                new_enc_content = Fernet(new_key_for_encryption).encrypt(plain_content.encode()).decode()
                self.c.execute("UPDATE notes SET title=?, content=? WHERE id=?", (new_enc_title, new_enc_content, note_id))

            self.c.execute("SELECT id, name, wallet_id_str, restore_key, secret_phrase FROM crypto_wallets WHERE user_id=?", (self.user_id,))
            for wallet_id, enc_name, enc_wallet_id_str, enc_restore_key, enc_secret_phrase in self.c.fetchall():
                plain_name = Fernet(current_master_key_for_decryption).decrypt(enc_name.encode()).decode()
                plain_wallet_id_str = Fernet(current_master_key_for_decryption).decrypt(enc_wallet_id_str.encode()).decode()
                plain_restore_key = Fernet(current_master_key_for_decryption).decrypt(enc_restore_key.encode()).decode()
                plain_secret_phrase = Fernet(current_master_key_for_decryption).decrypt(enc_secret_phrase.encode()).decode()

                new_enc_name = Fernet(new_key_for_encryption).encrypt(plain_name.encode()).decode()
                new_enc_wallet_id_str = Fernet(new_key_for_encryption).encrypt(plain_wallet_id_str.encode()).decode()
                new_enc_restore_key = Fernet(new_key_for_encryption).encrypt(plain_restore_key.encode()).decode()
                new_enc_secret_phrase = Fernet(new_key_for_encryption).encrypt(plain_secret_phrase.encode()).decode()
                
                self.c.execute(
                    "UPDATE crypto_wallets SET name=?, wallet_id_str=?, restore_key=?, secret_phrase=? WHERE id=?",
                    (new_enc_name, new_enc_wallet_id_str, new_enc_restore_key, new_enc_secret_phrase, wallet_id)
                )
            
            self.conn.commit()
            self.master_key = new_key_for_encryption
            QMessageBox.information(self, "Success", "Master password changed successfully. All data has been re-encrypted.")

        except InvalidToken:
            self.conn.rollback()
            QMessageBox.critical(self, "Error", "An error occurred during re-encryption. Data might be in an inconsistent state. Please try again or restore from backup.")
        except Exception as e:
            self.conn.rollback()
            QMessageBox.critical(self, "Error", f"An unexpected error occurred: {e}. Data might be in an inconsistent state.")

    def delete_selected_password(self):
        selected_items = self.table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a password entry to delete.")
            return
        
        selected_row = selected_items[0].row()
        password_id = self.table.item(selected_row, 0).data(Qt.UserRole)
        website = self.table.cellWidget(selected_row, 1).text() 
        username = self.table.item(selected_row, 2).text()

        old_pass, ok = QInputDialog.getText(self, "Confirm Master Password", 
                                            f"Enter your master password to delete password for '{website}' (User: {username}):", 
                                            QLineEdit.Password)
        if not ok or not old_pass:
            return

        self.c.execute("SELECT master_password_hash FROM users WHERE id=?", (self.user_id,))
        stored_hash = self.c.fetchone()[0]

        if not bcrypt.checkpw(old_pass.encode('utf-8'), stored_hash.encode('utf-8')):
            QMessageBox.critical(self, "Authentication Failed", "Incorrect master password.")
            return

        reply = QMessageBox.question(
            self, "Confirm Delete",
            f"Are you sure you want to delete the password for '{website}' (User: {username})?",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            self.c.execute("DELETE FROM passwords WHERE id=? AND user_id=?", (password_id, self.user_id))
            self.conn.commit()
            QMessageBox.information(self, "Success", "Password entry deleted successfully.")
            self.load_passwords()

    def edit_password(self, password_id):
        """Allows editing a password entry."""
        self.c.execute("SELECT website, username, password, category FROM passwords WHERE id=?", (password_id,))
        row = self.c.fetchone()
        if not row:
            QMessageBox.warning(self, "Error", "Password entry not found.")
            return

        website, username, enc_password, enc_category = row
        
        # Prompt for the new password
        new_password, ok = QInputDialog.getText(self, "Edit Password", f"Enter new password for {website} ({username}):", QLineEdit.Password)
        if not ok or not new_password:
            return

        # --- NEW: Check if the new password is pwned ---
        pwn_count = check_pwned(new_password)
        if pwn_count > 0:
            reply = QMessageBox.warning(
                self, 
                "Security Warning", 
                f"This password has been found in {pwn_count:,} known data breaches. "
                "It is strongly recommended that you use a different password.\n\n"
                "Do you want to use this password anyway?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            if reply == QMessageBox.No:
                return
        elif pwn_count == -1:
             QMessageBox.warning(self, "API Error", "Could not check if the password was pwned. Please check your internet connection.")

        # Encrypt the new password and update the database including the timestamp
        encrypted_new_password = self.encrypt(new_password)
        
        current_timestamp = datetime.datetime.now()

        self.c.execute("UPDATE passwords SET password=?, last_modified=? WHERE id=?", (encrypted_new_password, current_timestamp, password_id))
        self.conn.commit()

        QMessageBox.information(self, "Success", "Password updated successfully.")
        self.load_passwords() # Refresh the table

    # --- Notes Functions ---
    def load_notes(self, search_query=""):
        self.notes_list_widget.clear()
        
        self.c.execute("SELECT id, title, content FROM notes WHERE user_id=?", (self.user_id,))
        all_notes_raw = self.c.fetchall()
        
        lower_search_query = search_query.lower().strip()

        for note_id, encrypted_title, encrypted_content in all_notes_raw:
            try:
                decrypted_title = self.decrypt(encrypted_title)
                decrypted_content = self.decrypt(encrypted_content)

                if lower_search_query and \
                   not (lower_search_query in decrypted_title.lower() or \
                        lower_search_query in decrypted_content.lower()):
                    continue

                item = QListWidgetItem(decrypted_title)
                item.setData(Qt.UserRole, note_id)
                self.notes_list_widget.addItem(item)
            except InvalidToken:
                item = QListWidgetItem("[Decryption Failed] Invalid Note")
                item.setData(Qt.UserRole, note_id)
                self.notes_list_widget.addItem(item)
                QMessageBox.warning(self, "Decryption Error", f"Could not decrypt note with ID: {note_id}. It might be corrupted.")

    def filter_notes(self):
        search_query = self.notes_search_input.text()
        self.load_notes(search_query)

    def add_new_note(self):
        viewer = NoteViewer(self)
        if viewer.exec_() == QDialog.Accepted:
            self.load_notes()

    def open_note_viewer(self, item):
        note_id = item.data(Qt.UserRole)
        self.c.execute("SELECT title, content FROM notes WHERE id=? AND user_id=?", (note_id, self.user_id))
        row = self.c.fetchone()
        if row:
            try:
                decrypted_title = self.decrypt(row[0])
                decrypted_content = self.decrypt(row[1])
                viewer = NoteViewer(self, note_id, decrypted_title, decrypted_content)
                if viewer.exec_() == QDialog.Accepted:
                    self.load_notes()
            except InvalidToken:
                QMessageBox.critical(self, "Decryption Error", "Could not decrypt this note. The master key might be incorrect or the note data is corrupted.")
        else:
            QMessageBox.warning(self, "Error", "Note not found.")

    def delete_selected_note(self):
        selected_item = self.notes_list_widget.currentItem()
        if not selected_item:
            QMessageBox.warning(self, "No Selection", "Please select a note to delete.")
            return

        note_id = selected_item.data(Qt.UserRole)
        note_title = selected_item.text()

        old_pass, ok = QInputDialog.getText(self, "Confirm Master Password", f"Enter your master password to delete '{note_title}':", QLineEdit.Password)
        if not ok or not old_pass:
            return

        self.c.execute("SELECT master_password_hash FROM users WHERE id=?", (self.user_id,))
        stored_hash = self.c.fetchone()[0]

        if not bcrypt.checkpw(old_pass.encode('utf-8'), stored_hash.encode('utf-8')):
            QMessageBox.critical(self, "Authentication Failed", "Incorrect master password.")
            return

        reply = QMessageBox.question(
            self, "Confirm Delete",
            f"Are you sure you want to delete the note '{note_title}'?",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            self.c.execute("DELETE FROM notes WHERE id=? AND user_id=?", (note_id, self.user_id))
            self.conn.commit()
            QMessageBox.information(self, "Success", "Note deleted successfully.")
            self.load_notes()

    # --- Crypto Wallet Functions ---
    def load_crypto_wallets(self, search_query=""):
        self.crypto_table.setRowCount(0)
        
        self.c.execute("SELECT id, name, wallet_id_str FROM crypto_wallets WHERE user_id=?", (self.user_id,))
        all_wallets_raw = self.c.fetchall()

        lower_search_query = search_query.lower().strip()

        for wallet_id, encrypted_name, encrypted_wallet_id_str in all_wallets_raw:
            try:
                decrypted_name = self.decrypt(encrypted_name)
                decrypted_wallet_id_str = self.decrypt(encrypted_wallet_id_str)

                if lower_search_query and \
                   not (lower_search_query in decrypted_name.lower() or \
                        lower_search_query in decrypted_wallet_id_str.lower()):
                    continue
                
                i = self.crypto_table.rowCount()
                self.crypto_table.insertRow(i)
                
                name_item = QTableWidgetItem(decrypted_name)
                name_item.setData(Qt.UserRole, wallet_id)
                self.crypto_table.setItem(i, 0, name_item)
                self.crypto_table.setItem(i, 1, QTableWidgetItem(decrypted_wallet_id_str))

                edit_button = QPushButton("View/Edit")
                edit_button.clicked.connect(lambda _, wid=wallet_id: self.open_crypto_wallet_viewer_by_id(wid))
                self.crypto_table.setCellWidget(i, 2, edit_button)

            except InvalidToken:
                i = self.crypto_table.rowCount()
                self.crypto_table.insertRow(i)
                name_item = QTableWidgetItem("[Decryption Failed] Invalid Wallet")
                name_item.setData(Qt.UserRole, wallet_id)
                self.crypto_table.setItem(i, 0, name_item)
                self.crypto_table.setItem(i, 1, QTableWidgetItem("[Error]"))
                self.crypto_table.setItem(i, 2, QTableWidgetItem(""))
                QMessageBox.warning(self, "Decryption Error", f"Could not decrypt crypto wallet entry with ID: {wallet_id}. It might be corrupted.")
        self.crypto_table.resizeColumnsToContents()
        self.crypto_table.horizontalHeader().setStretchLastSection(True)

    def filter_crypto_wallets(self):
        search_query = self.crypto_search_input.text()
        self.load_crypto_wallets(search_query)

    def add_new_crypto_wallet(self):
        viewer = CryptoWalletViewer(self)
        if viewer.exec_() == QDialog.Accepted:
            self.load_crypto_wallets()

    def open_crypto_wallet_viewer(self, item):
        wallet_id = self.crypto_table.item(item.row(), 0).data(Qt.UserRole)
        self.open_crypto_wallet_viewer_by_id(wallet_id)

    def open_crypto_wallet_viewer_by_id(self, wallet_id):
        self.c.execute("SELECT name, wallet_id_str, restore_key, secret_phrase FROM crypto_wallets WHERE id=? AND user_id=?", (wallet_id, self.user_id))
        row = self.c.fetchone()
        if row:
            try:
                decrypted_name = self.decrypt(row[0])
                decrypted_wallet_id_str = self.decrypt(row[1])
                decrypted_restore_key = self.decrypt(row[2])
                decrypted_secret_phrase = self.decrypt(row[3])
                
                viewer = CryptoWalletViewer(self, wallet_id, decrypted_name, decrypted_wallet_id_str, decrypted_restore_key, decrypted_secret_phrase)
                if viewer.exec_() == QDialog.Accepted:
                    self.load_crypto_wallets()
            except InvalidToken:
                QMessageBox.critical(self, "Decryption Error", "Could not decrypt this crypto wallet entry. The master key might be incorrect or the data is corrupted.")
        else:
            QMessageBox.warning(self, "Error", "Crypto wallet entry not found.")

    def delete_selected_crypto_wallet(self):
        selected_items = self.crypto_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a crypto wallet entry to delete.")
            return
        
        selected_row = selected_items[0].row()
        wallet_id = self.crypto_table.item(selected_row, 0).data(Qt.UserRole)
        wallet_name = self.crypto_table.item(selected_row, 0).text()

        old_pass, ok = QInputDialog.getText(self, "Confirm Master Password", 
                                            f"Enter your master password to delete '{wallet_name}':", 
                                            QLineEdit.Password)
        if not ok or not old_pass:
            return

        self.c.execute("SELECT master_password_hash FROM users WHERE id=?", (self.user_id,))
        stored_hash = self.c.fetchone()[0]

        if not bcrypt.checkpw(old_pass.encode('utf-8'), stored_hash.encode('utf-8')):
            QMessageBox.critical(self, "Authentication Failed", "Incorrect master password.")
            return

        reply = QMessageBox.question(
            self, "Confirm Delete",
            f"Are you sure you want to delete the crypto wallet entry for '{wallet_name}'?\n\n"
            "This action is irreversible and should only be done if you have backed up this information elsewhere.",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            self.c.execute("DELETE FROM crypto_wallets WHERE id=? AND user_id=?", (wallet_id, self.user_id))
            self.conn.commit()
            QMessageBox.information(self, "Success", "Crypto wallet entry deleted successfully.")
            self.load_crypto_wallets()

    # --- Import/Export Methods ---
    def export_vault(self):
        dialog = ExportDialog(self)
        if dialog.exec_() != QDialog.Accepted:
            return

        options = dialog.get_options()
        if not options["passwords"] and not options["notes"] and not options["crypto"]:
            QMessageBox.warning(self, "No Data Selected", "Please select at least one data type to export.")
            return

        password, ok = QInputDialog.getText(self, "Confirm Identity", "Enter your master password to proceed with the export:", QLineEdit.Password)
        if not ok or not password:
            return

        self.c.execute("SELECT master_password_hash FROM users WHERE id=?", (self.user_id,))
        stored_hash = self.c.fetchone()[0]
        if not bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
            QMessageBox.critical(self, "Authentication Failed", "Incorrect master password.")
            return

        if options["format"] == 'json':
            self._export_encrypted_json(options)
        else:
            self._export_csv(options)

    def _export_encrypted_json(self, options):
        export_password, ok = QInputDialog.getText(self, "Create Export Password", "Create a password to encrypt this backup file. You will need this to import it.", QLineEdit.Password)
        if not ok or not export_password:
            QMessageBox.warning(self, "Export Cancelled", "An encryption password is required.")
            return
        
        # Suggest a default filename and provide filters
        default_filename = "passy_vault_backup.json"
        filters = "Encrypted JSON (*.json);;All Files (*)"
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Encrypted Vault", default_filename, filters)

        if not file_path:
            return

        # Ensure the file has the correct .json extension
        if not file_path.lower().endswith('.json'):
            file_path += '.json'
            
        vault_data = {}
        try:
            if options["passwords"]:
                vault_data['passwords'] = []
                self.c.execute("SELECT website, username, password, category FROM passwords WHERE user_id=?", (self.user_id,))
                for row in self.c.fetchall():
                    vault_data['passwords'].append({
                        'website': row[0],
                        'username': row[1],
                        'password': self.decrypt(row[2]),
                        'category': self.safe_decrypt(row[3])
                    })
            
            if options["notes"]:
                vault_data['notes'] = []
                self.c.execute("SELECT title, content FROM notes WHERE user_id=?", (self.user_id,))
                for row in self.c.fetchall():
                    vault_data['notes'].append({
                        'title': self.decrypt(row[0]),
                        'content': self.decrypt(row[1])
                    })

            if options["crypto"]:
                vault_data['crypto_wallets'] = []
                self.c.execute("SELECT name, wallet_id_str, restore_key, secret_phrase FROM crypto_wallets WHERE user_id=?", (self.user_id,))
                for row in self.c.fetchall():
                    vault_data['crypto_wallets'].append({
                        'name': self.decrypt(row[0]),
                        'wallet_id_str': self.decrypt(row[1]),
                        'restore_key': self.decrypt(row[2]),
                        'secret_phrase': self.decrypt(row[3])
                    })

        except InvalidToken:
            QMessageBox.critical(self, "Error", "A decryption error occurred. Cannot complete export.")
            return

        json_string = json.dumps(vault_data, indent=4)
        export_key = derive_key(export_password)
        f = Fernet(export_key)
        encrypted_data = f.encrypt(json_string.encode())

        with open(file_path, 'wb') as f_out:
            f_out.write(encrypted_data)

        QMessageBox.information(self, "Export Successful", f"Vault data successfully exported to {file_path}")

    def _export_csv(self, options):
        reply = QMessageBox.warning(self, "Security Risk", 
            "You are about to export your passwords to an unencrypted CSV file. "
            "This file will be in plain text and can be read by anyone with access to it.\n\n"
            "It is strongly recommended to use the encrypted JSON format instead.\n\n"
            "Do you want to proceed?", QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.No:
            return

        # Suggest a default filename and provide filters
        default_filename = "passy_passwords.csv"
        filters = "CSV File (*.csv);;All Files (*)"
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Unencrypted Passwords", default_filename, filters)
        
        if not file_path:
            return

        # Ensure the file has the correct .csv extension
        if not file_path.lower().endswith('.csv'):
            file_path += '.csv'

        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as f_out:
                writer = csv.writer(f_out)
                writer.writerow(['website', 'username', 'password', 'category'])
                
                self.c.execute("SELECT website, username, password, category FROM passwords WHERE user_id=?", (self.user_id,))
                for row in self.c.fetchall():
                    writer.writerow([
                        row[0], 
                        row[1], 
                        self.decrypt(row[2]), 
                        self.safe_decrypt(row[3])
                    ])
            QMessageBox.information(self, "Export Successful", f"Passwords successfully exported to {file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred during CSV export: {e}")

    def import_vault(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Vault File to Import", "", "Vault Files (*.json *.csv)")
        if not file_path:
            return

        password, ok = QInputDialog.getText(self, "Confirm Identity", "Enter your master password to proceed with the import:", QLineEdit.Password)
        if not ok or not password:
            return
        
        self.c.execute("SELECT master_password_hash FROM users WHERE id=?", (self.user_id,))
        stored_hash = self.c.fetchone()[0]
        if not bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
            QMessageBox.critical(self, "Authentication Failed", "Incorrect master password.")
            return

        if file_path.endswith('.json'):
            self._import_encrypted_json(file_path)
        elif file_path.endswith('.csv'):
            self._import_csv(file_path)
        else:
            QMessageBox.warning(self, "Unsupported File", "The selected file format is not supported.")

    def _import_encrypted_json(self, file_path):
        import_password, ok = QInputDialog.getText(self, "Enter Import Password", "Enter the password used to encrypt this backup file:", QLineEdit.Password)
        if not ok or not import_password:
            return

        try:
            with open(file_path, 'rb') as f_in:
                encrypted_data = f_in.read()
            
            import_key = derive_key(import_password)
            f = Fernet(import_key)
            decrypted_data = f.decrypt(encrypted_data)
            vault_data = json.loads(decrypted_data.decode())

        except (InvalidToken, json.JSONDecodeError, Exception) as e:
            QMessageBox.critical(self, "Import Failed", f"Could not read or decrypt the file. It may be corrupted or the password was incorrect.\nError: {e}")
            return
            
        imported_counts = {"passwords": 0, "notes": 0, "crypto_wallets": 0}
        
        if 'passwords' in vault_data:
            for item in vault_data['passwords']:
                self.c.execute("INSERT INTO passwords (user_id, website, username, password, category) VALUES (?, ?, ?, ?, ?)",
                    (self.user_id, item['website'], item['username'], self.encrypt(item['password']), self.encrypt(item.get('category', 'Uncategorized'))))
                imported_counts['passwords'] += 1
        
        if 'notes' in vault_data:
            for item in vault_data['notes']:
                self.c.execute("INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
                    (self.user_id, self.encrypt(item['title']), self.encrypt(item['content'])))
                imported_counts['notes'] += 1

        if 'crypto_wallets' in vault_data:
            for item in vault_data['crypto_wallets']:
                self.c.execute("INSERT INTO crypto_wallets (user_id, name, wallet_id_str, restore_key, secret_phrase) VALUES (?, ?, ?, ?, ?)",
                    (self.user_id, self.encrypt(item['name']), self.encrypt(item['wallet_id_str']), self.encrypt(item['restore_key']), self.encrypt(item['secret_phrase'])))
                imported_counts['crypto_wallets'] += 1

        self.conn.commit()
        
        self.load_passwords()
        self.load_notes()
        self.load_crypto_wallets()

        summary_message = "Import complete!\n\n"
        summary_message += f" - Passwords imported: {imported_counts['passwords']}\n"
        summary_message += f" - Notes imported: {imported_counts['notes']}\n"
        summary_message += f" - Crypto Wallets imported: {imported_counts['crypto_wallets']}"
        QMessageBox.information(self, "Import Successful", summary_message)

    def _import_csv(self, file_path):
        reply = QMessageBox.question(self, "Confirm CSV Import", 
                                                "This will import passwords from a CSV file.\nPlease ensure the columns are in the order: website, username, password, category.",
                                                QMessageBox.Ok | QMessageBox.Cancel)
        if reply == QMessageBox.Cancel:
            return

        try:
            with open(file_path, 'r', encoding='utf-8') as f_in:
                reader = csv.reader(f_in)
                header = next(reader)
                
                imported_count = 0
                for row in reader:
                    if len(row) < 3: continue # Need at least website, user, pass
                    website = row[0]
                    username = row[1]
                    password = row[2]
                    category = row[3] if len(row) > 3 else "Uncategorized"
                    
                    enc_password = self.encrypt(password)
                    enc_category = self.encrypt(category)
                    
                    self.c.execute("INSERT INTO passwords (user_id, website, username, password, category) VALUES (?, ?, ?, ?, ?)",
                                       (self.user_id, website, username, enc_password, enc_category))
                    imported_count += 1
            
            self.conn.commit()
            self.load_passwords()
            QMessageBox.information(self, "Import Successful", f"{imported_count} password(s) imported successfully from the CSV file.")

        except Exception as e:
            QMessageBox.critical(self, "Import Failed", f"An error occurred while reading the CSV file: {e}")

    def run_password_audit(self):
        # Clear previous results
        self.reused_passwords_table.setRowCount(0)
        self.weak_passwords_table.setRowCount(0)
        self.old_passwords_table.setRowCount(0)
        self.pwned_passwords_table.setRowCount(0)

        # Fetch all passwords for the user
        self.c.execute("SELECT website, username, password, last_modified FROM passwords WHERE user_id=?", (self.user_id,))
        all_passwords = self.c.fetchall()

        if not all_passwords:
            QMessageBox.information(self, "Audit Complete", "No passwords in the vault to audit.")
            return

        password_map = {} # For checking reused passwords
        
        api_error = False
        for website, username, enc_password, last_modified in all_passwords:
            try:
                decrypted_pass = self.decrypt(enc_password)
                
                # --- Check for reused passwords ---
                if decrypted_pass not in password_map:
                    password_map[decrypted_pass] = []
                password_map[decrypted_pass].append(f"{website} ({username})")

                # --- Check for weak passwords ---
                strength = calculate_password_strength(decrypted_pass)
                if strength < 40: # Threshold for weak
                    row_pos = self.weak_passwords_table.rowCount()
                    self.weak_passwords_table.insertRow(row_pos)
                    self.weak_passwords_table.setItem(row_pos, 0, QTableWidgetItem(website))
                    self.weak_passwords_table.setItem(row_pos, 1, QTableWidgetItem(username))
                    self.weak_passwords_table.setItem(row_pos, 2, QTableWidgetItem(f"{strength}%"))

                # --- Check for old passwords ---
                if last_modified:
                    try:
                        # SQLite stores TIMESTAMP as string, need to parse it
                        mod_time = datetime.datetime.fromisoformat(last_modified)
                        if mod_time < datetime.datetime.now() - datetime.timedelta(days=180): # 6 months
                            row_pos = self.old_passwords_table.rowCount()
                            self.old_passwords_table.insertRow(row_pos)
                            self.old_passwords_table.setItem(row_pos, 0, QTableWidgetItem(website))
                            self.old_passwords_table.setItem(row_pos, 1, QTableWidgetItem(username))
                            self.old_passwords_table.setItem(row_pos, 2, QTableWidgetItem(mod_time.strftime("%Y-%m-%d")))
                    except (ValueError, TypeError):
                        # Handle cases where timestamp might be in an unexpected format or None
                        pass
                        
                # --- NEW: Check for pwned passwords ---
                pwn_count = check_pwned(decrypted_pass)
                if pwn_count > 0:
                    row_pos = self.pwned_passwords_table.rowCount()
                    self.pwned_passwords_table.insertRow(row_pos)
                    self.pwned_passwords_table.setItem(row_pos, 0, QTableWidgetItem(website))
                    self.pwned_passwords_table.setItem(row_pos, 1, QTableWidgetItem(username))
                    self.pwned_passwords_table.setItem(row_pos, 2, QTableWidgetItem(f"{pwn_count:,} times"))
                    
                    show_button = QPushButton("Show")
                    show_button.clicked.connect(lambda _, p=decrypted_pass: self.show_reused_password(p))
                    self.pwned_passwords_table.setCellWidget(row_pos, 3, show_button)
                elif pwn_count == -1:
                    api_error = True


            except InvalidToken:
                # Can't audit a password that fails to decrypt
                continue
        
        # --- Populate reused passwords table ---
        for password, accounts in password_map.items():
            if len(accounts) > 1:
                row_pos = self.reused_passwords_table.rowCount()
                self.reused_passwords_table.insertRow(row_pos)
                self.reused_passwords_table.setItem(row_pos, 0, QTableWidgetItem("•" * 10)) # Obfuscate password
                self.reused_passwords_table.setItem(row_pos, 1, QTableWidgetItem(", ".join(accounts)))
                
                show_button = QPushButton("Show")
                # Use a lambda to pass the actual decrypted password to the handler
                show_button.clicked.connect(lambda _, p=password: self.show_reused_password(p))
                self.reused_passwords_table.setCellWidget(row_pos, 2, show_button)

        # Resize columns to fit content
        self.reused_passwords_table.resizeColumnsToContents()
        self.weak_passwords_table.resizeColumnsToContents()
        self.old_passwords_table.resizeColumnsToContents()
        self.pwned_passwords_table.resizeColumnsToContents()

        if api_error:
            QMessageBox.warning(self, "Audit Warning", "Password health audit finished, but could not check for pwned passwords. Please check your internet connection and try again.")
        else:
            QMessageBox.information(self, "Audit Complete", "Password health audit finished.")


# --- Application Entry Point ---
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PasswordManager()
    window.apply_theme('dark') # Apply initial default theme
    window.show()
    sys.exit(app.exec_())
