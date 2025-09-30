import sys
import os
import json
import hmac
import base64
from pathlib import Path
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QPushButton, QLabel, QFileDialog, 
                            QComboBox, QFrame, QMessageBox, QCheckBox, QLineEdit,
                            QToolButton, QTabWidget, QProgressBar)
from PyQt6.QtGui import QFont, QIcon, QLinearGradient, QPalette, QColor, QPainter
from PyQt6.QtCore import Qt, QPoint, QPointF, QRect, QTimer, pyqtSignal, QObject
from aes256 import AES256

class ProgressSignal(QObject):
    progress_update = pyqtSignal(int)
    
    def emit_progress(self, value):
        self.progress_update.emit(value)

class ProcessingWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("""
            QWidget {
                background-color: transparent;
            }
            QLabel {
                color: white;
                font-size: 14px;
                background-color: transparent;
            }
            QProgressBar {
                border: 2px solid white;
                border-radius: 5px;
                text-align: center;
                color: white;
                background-color: rgba(255, 255, 255, 0.1);
                min-height: 20px;
            }
            QProgressBar::chunk {
                background-color: #e056fd;
            }
        """)
        
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignBottom)
        layout.setContentsMargins(10, 10, 10, 10)
        
        self.message_label = QLabel("Processing")
        self.message_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.message_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setFixedHeight(20)
        layout.addWidget(self.progress_bar)
        
        self.hide()
    
    def update_progress(self, value):
        self.progress_bar.setValue(value)
        self.message_label.setText(f"Processing... {value}%")

class GradientWidget(QWidget):
    def paintEvent(self, event):
        painter = QPainter(self)
        gradient = QLinearGradient(QPointF(0, 0), QPointF(self.width(), self.height()))
        gradient.setColorAt(0, QColor("#662d91"))
        gradient.setColorAt(1, QColor("#8e44ad"))
        painter.fillRect(self.rect(), gradient)

class StyledButton(QPushButton):
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                                          stop:0 #e056fd, stop:1 #8e44ad);
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 10px;
                font-size: 12px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                                          stop:0 #8e44ad, stop:1 #e056fd);
            }
        """)

class FileFrame(QFrame):
    def __init__(self, title, parent=None):
        super().__init__(parent)
        self.setStyleSheet("""
            QFrame {
                background: rgba(255, 255, 255, 0.1);
                border-radius: 15px;
                padding: 10px;
            }
        """)
        self.layout = QVBoxLayout(self)
        self.label = QLabel(title)
        self.label.setStyleSheet("color: white;")
        self.path_label = QLabel("No file selected")
        self.path_label.setStyleSheet("color: rgba(255, 255, 255, 0.7);")
        self.select_button = StyledButton("Choose file")
        self.layout.addWidget(self.label)
        self.layout.addWidget(self.path_label)
        self.layout.addWidget(self.select_button)
        
    def reset(self):
        """Reset file frame to initial state"""
        self.path_label.setText("No file selected")
        if hasattr(self, 'file_path'):
            delattr(self, 'file_path')

class AESEncryptionApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Noval Encryption")
        self.setMinimumSize(800, 600)
        self.aes = AES256()
        
        # Create main widget and layout first
        self.main_widget = GradientWidget()
        self.setCentralWidget(self.main_widget)
        self.main_layout = QVBoxLayout(self.main_widget)
        
        # Create header
        header = QLabel("Noval Encryption")
        header.setStyleSheet("QLabel { color: white; font-size: 36px; font-weight: bold; }")
        self.main_layout.addWidget(header)
        
        subtitle = QLabel("Encryption like no other")
        subtitle.setStyleSheet("QLabel { color: rgba(255, 255, 255, 0.9); font-size: 18px; }")
        self.main_layout.addWidget(subtitle)
        
        # Create content widget to hold everything except progress
        self.content_widget = QWidget()
        self.content_layout = QVBoxLayout(self.content_widget)
        self.main_layout.addWidget(self.content_widget)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid rgba(255, 255, 255, 0.2);
                background: rgba(255, 255, 255, 0.05);
                border-radius: 8px;
            }
            
            QTabBar::tab {
                background: rgba(255, 255, 255, 0.1);
                color: white;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                padding: 10px 15px;
                margin-right: 2px;
            }
            
            QTabBar::tab:selected {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, 
                                        stop:0 #e056fd, stop:1 #8e44ad);
            }
            
            QTabBar::tab:!selected {
                margin-top: 2px;
            }
        """)
        
        # Create encryption tab
        self.encrypt_tab = QWidget()
        encrypt_layout = QVBoxLayout(self.encrypt_tab)
        
        # Encryption file selection
        self.encrypt_file_frame = FileFrame("Choose File to Encrypt")
        encrypt_layout.addWidget(self.encrypt_file_frame)
        
        # Encryption password options
        self.password_checkbox = QCheckBox("Use custom password")
        self.password_checkbox.setStyleSheet("QCheckBox { color: white; font-size: 14px; }")
        encrypt_layout.addWidget(self.password_checkbox)
        
        self.encrypt_password_frame = QFrame()
        self.encrypt_password_frame.setStyleSheet("""
            QFrame {
                background: rgba(255, 255, 255, 0.1);
                border-radius: 15px;
                padding: 10px;
            }
        """)
        password_input_layout = QHBoxLayout(self.encrypt_password_frame)
        
        self.encrypt_password_label = QLabel("Enter your password:")
        self.encrypt_password_label.setStyleSheet("color: white;")
        password_input_layout.addWidget(self.encrypt_password_label)
        
        password_field_layout = QVBoxLayout()
        self.encrypt_password_input = QLineEdit()
        self.encrypt_password_input.setStyleSheet("""
            QLineEdit {
                background: rgba(255, 255, 255, 0.2);
                color: white;
                padding: 8px;
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 8px;
            }
        """)
        self.encrypt_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        
        password_container = QWidget()
        password_container_layout = QHBoxLayout(password_container)
        password_container_layout.setContentsMargins(0, 0, 0, 0)
        password_container_layout.addWidget(self.encrypt_password_input)
        
        self.encrypt_toggle_password_btn = QToolButton()
        self.encrypt_toggle_password_btn.setText("👁️")
        self.encrypt_toggle_password_btn.setStyleSheet("""
            QToolButton {
                background: rgba(255, 255, 255, 0.2);
                color: white;
                border: none;
                border-radius: 4px;
                padding: 5px;
            }
            QToolButton:hover {
                background: rgba(255, 255, 255, 0.3);
            }
        """)
        password_container_layout.addWidget(self.encrypt_toggle_password_btn)
        
        password_field_layout.addWidget(password_container)
        
        # Add password requirements and confirmation
        self.password_requirements = QLabel(
            "Password requirements:\n"
            "• Minimum 12 characters\n"
            "• Must contain uppercase and lowercase letters\n"
            "• Must contain numbers\n"
            "• Must contain special characters"
        )
        self.password_requirements.setStyleSheet("""
            QLabel {
                color: rgba(255, 255, 255, 0.7);
                font-size: 12px;
                margin-top: 5px;
            }
        """)
        password_field_layout.addWidget(self.password_requirements)
        self.password_requirements.hide()
        
        self.encrypt_password_confirm = QLineEdit()
        self.encrypt_password_confirm.setStyleSheet("""
            QLineEdit {
                background: rgba(255, 255, 255, 0.2);
                color: white;
                padding: 8px;
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 8px;
            }
        """)
        self.encrypt_password_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self.encrypt_password_confirm.setPlaceholderText("Confirm password")
        password_field_layout.addWidget(self.encrypt_password_confirm)
        self.encrypt_password_confirm.hide()
        
        password_input_layout.addLayout(password_field_layout)
        encrypt_layout.addWidget(self.encrypt_password_frame)
        self.encrypt_password_frame.hide()
        
        # Encrypt button
        self.encrypt_button = StyledButton("Encrypt File")
        encrypt_layout.addWidget(self.encrypt_button)
        encrypt_layout.addStretch()
        
        # Create decryption tab
        self.decrypt_tab = QWidget()
        decrypt_layout = QVBoxLayout(self.decrypt_tab)
        
        # Decryption file selection
        self.decrypt_file_frame = FileFrame("Choose File to Decrypt")
        decrypt_layout.addWidget(self.decrypt_file_frame)
        
        # Add checkbox for decryption password type
        self.decrypt_password_type = QCheckBox("Using generated password")
        self.decrypt_password_type.setStyleSheet("QCheckBox { color: white; font-size: 14px; }")
        decrypt_layout.addWidget(self.decrypt_password_type)
        
        self.key_file_frame = FileFrame("Select Key File (.key)")
        decrypt_layout.addWidget(self.key_file_frame)
        
        # Custom password input frame
        self.decrypt_password_frame = QFrame()
        self.decrypt_password_frame.setStyleSheet("""
            QFrame {
                background: rgba(255, 255, 255, 0.1);
                border-radius: 15px;
                padding: 10px;
            }
        """)
        decrypt_password_layout = QHBoxLayout(self.decrypt_password_frame)
        
        self.decrypt_password_label = QLabel("Enter decryption password:")
        self.decrypt_password_label.setStyleSheet("color: white;")
        decrypt_password_layout.addWidget(self.decrypt_password_label)
        
        decrypt_password_field_layout = QVBoxLayout()
        self.decrypt_password_input = QLineEdit()
        self.decrypt_password_input.setStyleSheet("""
            QLineEdit {
                background: rgba(255, 255, 255, 0.2);
                color: white;
                padding: 8px;
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 8px;
            }
        """)
        self.decrypt_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        
        decrypt_password_container = QWidget()
        decrypt_password_container_layout = QHBoxLayout(decrypt_password_container)
        decrypt_password_container_layout.setContentsMargins(0, 0, 0, 0)
        decrypt_password_container_layout.addWidget(self.decrypt_password_input)
        
        self.decrypt_toggle_password_btn = QToolButton()
        self.decrypt_toggle_password_btn.setText("👁️")
        self.decrypt_toggle_password_btn.setStyleSheet("""
            QToolButton {
                background: rgba(255, 255, 255, 0.2);
                color: white;
                border: none;
                border-radius: 4px;
                padding: 5px;
            }
            QToolButton:hover {
                background: rgba(255, 255, 255, 0.3);
            }
        """)
        decrypt_password_container_layout.addWidget(self.decrypt_toggle_password_btn)
        
        decrypt_password_field_layout.addWidget(decrypt_password_container)
        decrypt_password_layout.addLayout(decrypt_password_field_layout)
        
        decrypt_layout.addWidget(self.decrypt_password_frame)
        
        # Decrypt button
        self.decrypt_button = StyledButton("Decrypt File")
        decrypt_layout.addWidget(self.decrypt_button)
        decrypt_layout.addStretch()
        
        # Add tabs to tab widget
        self.tab_widget.addTab(self.encrypt_tab, "Encrypt")
        self.tab_widget.addTab(self.decrypt_tab, "Decrypt")
        self.content_layout.addWidget(self.tab_widget)
        
        # Add reset button
        self.reset_button = StyledButton("Reset")
        self.reset_button.setStyleSheet("""
            QPushButton {
                background: rgba(255, 255, 255, 0.2);
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 10px;
                font-size: 12px;
            }
            QPushButton:hover {
                background: rgba(255, 255, 255, 0.3);
            }
        """)
        self.content_layout.addWidget(self.reset_button)
        
        # Create processing widget at the bottom
        self.processing_widget = ProcessingWidget()
        self.main_layout.addWidget(self.processing_widget)
        
        # Create and connect progress signal
        self.progress_signal = ProgressSignal()
        self.progress_signal.progress_update.connect(self.processing_widget.update_progress)
        
        # Connect signals
        self.encrypt_file_frame.select_button.clicked.connect(
            lambda: self.select_file(self.encrypt_file_frame))
        self.decrypt_file_frame.select_button.clicked.connect(
            lambda: self.select_file(self.decrypt_file_frame))
        self.key_file_frame.select_button.clicked.connect(
            lambda: self.select_file(self.key_file_frame, "Key Files (*.key)"))
        
        self.encrypt_button.clicked.connect(self.encrypt_file)
        self.decrypt_button.clicked.connect(self.decrypt_file)
        self.reset_button.clicked.connect(self.reset_app)
        
        self.password_checkbox.toggled.connect(self.toggle_password_input)
        self.decrypt_password_type.toggled.connect(self.on_decrypt_password_type_changed)
        
        # Connect password visibility toggles
        self.encrypt_toggle_password_btn.clicked.connect(
            lambda: self.toggle_password_visibility(self.encrypt_password_input, self.encrypt_toggle_password_btn))
        self.decrypt_toggle_password_btn.clicked.connect(
            lambda: self.toggle_password_visibility(self.decrypt_password_input, self.decrypt_toggle_password_btn))
        
        # Connect password validation
        self.encrypt_password_input.textChanged.connect(self.validate_password)

    def on_decrypt_password_type_changed(self, checked):
        """Handle changes in decryption password type"""
        if checked:
            # Hide password input when using generated password
            self.decrypt_password_frame.hide()
        else:
            self.decrypt_password_frame.show()
            self.decrypt_password_label.setText("Enter custom password:")
            self.decrypt_password_input.setPlaceholderText("Enter your custom password")
            self.decrypt_password_input.clear()

    def validate_password(self):
        """Validate password as user types"""
        if self.password_checkbox.isChecked():
            password = self.encrypt_password_input.text()
            is_valid, message = self.aes.validate_password_strength(password)
            
            if is_valid:
                self.encrypt_password_input.setStyleSheet("""
                    QLineEdit {
                        background: rgba(255, 255, 255, 0.2);
                        color: white;
                        padding: 8px;
                        border: 1px solid #2ecc71;
                        border-radius: 8px;
                    }
                """)
            else:
                self.encrypt_password_input.setStyleSheet("""
                    QLineEdit {
                        background: rgba(255, 255, 255, 0.2);
                        color: white;
                        padding: 8px;
                        border: 1px solid #e74c3c;
                        border-radius: 8px;
                    }
                """)

    def toggle_password_input(self, checked):
        """Toggle password input visibility and requirements"""
        self.encrypt_password_frame.setVisible(checked)
        self.password_requirements.setVisible(checked)
        self.encrypt_password_confirm.setVisible(checked)
        if not checked:
            self.encrypt_password_input.clear()
            self.encrypt_password_confirm.clear()

    def toggle_password_visibility(self, password_input, toggle_button):
        if password_input.echoMode() == QLineEdit.EchoMode.Password:
            password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            toggle_button.setText("🔒")
        else:
            password_input.setEchoMode(QLineEdit.EchoMode.Password)
            toggle_button.setText("👁️")

    def select_file(self, frame, file_filter=None):
        if file_filter:
            file_path, _ = QFileDialog.getOpenFileName(self, "Select File", "", file_filter)
        else:
            file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            frame.path_label.setText(os.path.basename(file_path))
            frame.file_path = file_path
            
            # If selecting key file, check for generated password
            if file_filter and file_path.endswith('.key'):
                try:
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        has_generated = 'generated_password' in data
                        self.decrypt_password_type.setChecked(has_generated)
                        self.decrypt_password_type.setEnabled(has_generated)
                        if not has_generated:
                            QMessageBox.information(self, "Password Type", 
                                "This file was encrypted with a custom password.")
                except Exception as e:
                    QMessageBox.warning(self, "Key File Error", 
                        f"Error reading key file: {str(e)}")

    def encrypt_file(self):
        try:
            if not hasattr(self.encrypt_file_frame, 'file_path'):
                QMessageBox.warning(self, "Error", "Please select a file to encrypt")
                return
            
            if self.password_checkbox.isChecked():
                password = self.encrypt_password_input.text()
                confirm_password = self.encrypt_password_confirm.text()
                
                is_valid, message = self.aes.validate_password_strength(password)
                if not is_valid:
                    QMessageBox.warning(self, "Invalid Password", message)
                    return
                
                if password != confirm_password:
                    QMessageBox.warning(self, "Password Mismatch", 
                                     "The passwords you entered do not match")
                    return
                
                user_password = password
            else:
                user_password = None
            
            save_path, _ = QFileDialog.getSaveFileName(
                self, "Save Encrypted File", 
                os.path.basename(self.encrypt_file_frame.file_path) + ".encrypted"
            )
            
            if save_path:
                try:
                    self.processing_widget.show()
                    self.processing_widget.progress_bar.setValue(0)
                    QApplication.processEvents()
                    
                    encrypted_path, key_file = self.aes.encrypt_file_with_password(
                        self.encrypt_file_frame.file_path,
                        save_path,
                        user_password,
                        progress_callback=self.progress_signal.emit_progress
                    )
                    
                    self.processing_widget.hide()
                    
                    QMessageBox.information(
                        self, "Success", 
                        f"File encrypted successfully!\n\nEncryption data has been saved to:\n{key_file}\n\n"
                        "IMPORTANT: Keep this key file safe - you'll need it for decryption."
                    )
                    
                    self.reset_app()
                    
                except Exception as e:
                    self.processing_widget.hide()
                    QMessageBox.critical(self, "Error", f"An error occurred during encryption: {str(e)}")
                    self.reset_app()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")
            self.reset_app()

    def decrypt_file(self):
        try:
            if not all(hasattr(frame, 'file_path') for frame in [self.decrypt_file_frame, self.key_file_frame]):
                QMessageBox.warning(
                    self, "Error", 
                    "Please select both the encrypted file and the key file"
                )
                return
            
            try:
                iv, hmac_key, salt, stored_password = self.aes.load_encryption_data(
                    self.key_file_frame.file_path
                )
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load key file: {str(e)}")
                return

            if self.decrypt_password_type.isChecked():
                if stored_password is None:
                    QMessageBox.warning(self, "Error", 
                        "This file was encrypted with a custom password, not a generated one.")
                    return
                password = stored_password
            else:
                if not self.decrypt_password_input.text():
                    QMessageBox.warning(self, "Error", "Please enter the decryption password")
                    return
                password = self.decrypt_password_input.text().encode()

            save_path, _ = QFileDialog.getSaveFileName(
                self, "Save Decrypted File",
                os.path.basename(self.decrypt_file_frame.file_path).replace('.encrypted', '')
            )
            
            if save_path:
                try:
                    self.processing_widget.show()
                    self.processing_widget.progress_bar.setValue(0)
                    QApplication.processEvents()
                    
                    # Verify file integrity and password before decryption
                    with open(self.decrypt_file_frame.file_path, 'rb') as f:
                        file_content = f.read()
                        
                    if len(file_content) < 32 + 16 + 32:
                        raise ValueError("Invalid encrypted file: file is corrupted")
                        
                    stored_salt = file_content[:32]
                    stored_iv = file_content[32:48]
                    hmac_value = file_content[-32:]
                    
                    # Verify all parameters before proceeding
                    if not hmac.compare_digest(stored_salt, salt):
                        raise ValueError("Invalid password or corrupted file")
                    if not hmac.compare_digest(stored_iv, iv):
                        raise ValueError("Invalid password or corrupted file")
                    if not self.aes._verify_hmac(file_content[:-32], hmac_key, hmac_value):
                        raise ValueError("Invalid password or corrupted file")
                    
                    try:
                        decrypted_path = self.aes.decrypt_file_with_password(
                            self.decrypt_file_frame.file_path,
                            password,
                            iv, hmac_key, salt,
                            save_path,
                            progress_callback=self.progress_signal.emit_progress
                        )
                    except Exception as e:
                        raise ValueError("Invalid password or corrupted file")
                    
                    self.processing_widget.hide()
                    
                    QMessageBox.information(
                        self, "Success", 
                        "File decrypted successfully!"
                    )
                    
                    self.reset_app()
                    
                except ValueError as ve:
                    self.processing_widget.hide()
                    QMessageBox.critical(
                        self, "Decryption Error", 
                        str(ve) + "\n\nPlease ensure you are using the correct password and key file."
                    )
                    self.reset_app()
                except Exception as e:
                    self.processing_widget.hide()
                    QMessageBox.critical(self, "Error", str(e))
                    self.reset_app()
                    
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")
            self.reset_app()

    def reset_app(self):
        """Reset application to initial state"""
        # Reset file frames
        self.encrypt_file_frame.reset()
        self.decrypt_file_frame.reset()
        self.key_file_frame.reset()
        
        # Reset password inputs
        self.encrypt_password_input.clear()
        self.encrypt_password_confirm.clear()
        self.decrypt_password_input.clear()
        
        # Reset checkboxes
        self.password_checkbox.setChecked(False)
        self.decrypt_password_type.setChecked(False)
        self.decrypt_password_type.setEnabled(True)
        
        # Hide password frames
        self.encrypt_password_frame.hide()
        self.password_requirements.hide()
        self.encrypt_password_confirm.hide()
        
        # Update UI
        self.processing_widget.hide()

def main():
    try:
        app = QApplication(sys.argv)
        window = AESEncryptionApp()
        window.show()
        return app.exec()
    except Exception as e:
        if not QApplication.instance():
            app = QApplication(sys.argv)
        QMessageBox.critical(None, "Fatal Error", f"Failed to start application: {str(e)}")
        return 1

if __name__ == "__main__":
    main()