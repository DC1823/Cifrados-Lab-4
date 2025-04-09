import sys
import os
import requests
from base64 import b64encode, b64decode

from PySide6.QtWidgets import (
    QApplication, QWidget, QStackedWidget, QVBoxLayout, QHBoxLayout,
    QLineEdit, QPushButton, QListWidget, QListWidgetItem, QMessageBox, QFileDialog
)
from PySide6.QtGui import QColor

from Backend.Encrypt import generate_rsa_keys, encrypt, decrypt
from Backend.Sign import *

API_URL = "http://127.0.0.1:8000"

STYLE = """
    QWidget {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #f2f2f2, stop:1 #cfcfcf);
        font-family: "Segoe UI", sans-serif;
    }
    QLineEdit {
        border: 2px solid #0078D7;
        border-radius: 5px;
        padding: 5px;
        font-size: 14px;
        background-color: white;
    }
    QPushButton {
        background-color: #0078D7;
        border: none;
        border-radius: 5px;
        color: white;
        padding: 8px 12px;
        font-size: 14px;
    }
    QPushButton:hover {
        background-color: #005A9E;
    }
    QListWidget {
        border: 2px solid #0078D7;
        border-radius: 5px;
        padding: 5px;
        font-size: 14px;
        background-color: white;
    }
"""

def show_message(title, message):
    msg = QMessageBox()
    msg.setWindowTitle(title)
    msg.setText(message)
    msg.exec()

class App(QWidget):
    def __init__(self):
        super().__init__()
        self.token = ""
        self.pub_key = ""
        self.priv_key = ""
        self.init_ui()

    def init_ui(self):
        self.stacked_widget = QStackedWidget(self)
        self.login_widget = QWidget()
        login_layout = QVBoxLayout()
        login_layout.setContentsMargins(40, 40, 40, 40)
        login_layout.setSpacing(15)

        self.input_username = QLineEdit()
        self.input_username.setPlaceholderText("Username")
        self.input_username.returnPressed.connect(lambda: self.input_password.setFocus())

        self.input_password = QLineEdit()
        self.input_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.input_password.setPlaceholderText("Password")
        self.input_password.returnPressed.connect(self.login)

        login_layout.addWidget(self.input_username)
        login_layout.addWidget(self.input_password)

        btn_login_layout = QHBoxLayout()
        self.btn_register = QPushButton("Register")
        self.btn_register.clicked.connect(self.register)
        self.btn_login = QPushButton("Login")
        self.btn_login.clicked.connect(self.login)
        btn_login_layout.addWidget(self.btn_register)
        btn_login_layout.addWidget(self.btn_login)

        login_layout.addLayout(btn_login_layout)
        self.login_widget.setLayout(login_layout)

        self.main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(10)

        top_button_layout = QHBoxLayout()
        self.btn_logout = QPushButton("Logout")
        self.btn_logout.clicked.connect(self.logout)
        self.btn_list_files = QPushButton("List Files")
        self.btn_list_files.clicked.connect(self.list_files)
        self.btn_upload = QPushButton("Upload File")
        self.btn_upload.clicked.connect(self.upload_file)
        self.btn_upload_sign = QPushButton("Upload Signed File")
        self.btn_upload_sign.clicked.connect(self.upload_signed_file)
        self.btn_verify = QPushButton("Verify File")
        self.btn_verify.clicked.connect(self.verify_file)

        for btn in [self.btn_logout, self.btn_list_files, self.btn_upload, self.btn_upload_sign, self.btn_verify]:
            top_button_layout.addWidget(btn)

        main_layout.addLayout(top_button_layout)

        self.file_view = QListWidget()
        self.file_view.itemDoubleClicked.connect(self.download_file)
        main_layout.addWidget(self.file_view)

        self.main_widget.setLayout(main_layout)

        self.stacked_widget.addWidget(self.login_widget)
        self.stacked_widget.addWidget(self.main_widget)

        overall_layout = QVBoxLayout()
        overall_layout.addWidget(self.stacked_widget)
        self.setLayout(overall_layout)
        self.setWindowTitle("Secure File Manager")
        self.resize(600, 400)
        self.setStyleSheet(STYLE)

    def register(self):
        username = self.input_username.text().strip()
        password = self.input_password.text().strip()
        if username == "" or password == "":
            show_message("Register", "Empty Credentials")
            return

        response = requests.post(f"{API_URL}/register", json={"username": username, "password": password})
        if response.status_code != 200:
            show_message("Register", f'Error: {response.json().get("detail", "Error")}')
        else:
            pub_key, priv_key = generate_rsa_keys()
            if not os.path.exists("./Keys"):
                os.makedirs("./Keys")
            with open(f"./Keys/{username}.pub", "w") as f:
                f.write(pub_key)
            with open(f"./Keys/{username}", "w") as f:
                f.write(priv_key)
            show_message("Register", "Successfully Registered")
            self.login()

    def login(self):
        username = self.input_username.text().strip()
        password = self.input_password.text().strip()
        if username == "" or password == "":
            show_message("Login", "Empty Credentials")
            return

        response = requests.post(f"{API_URL}/login", json={"username": username, "password": password})
        if response.status_code != 200:
            show_message("Login", "Invalid Credentials")
            self.logout()
        else:
            self.token = response.json()["access_token"]
            with open(f"./Keys/{username}.pub", "r") as f:
                self.pub_key = f.read()
            with open(f"./Keys/{username}", "r") as f:
                self.priv_key = f.read()
            self.stacked_widget.setCurrentWidget(self.main_widget)
            self.list_files()

    def logout(self):
        self.input_username.clear()
        self.input_password.clear()
        self.stacked_widget.setCurrentWidget(self.login_widget)

    def list_files(self):
        headers = {"Authorization": f"Bearer {self.token}"}
        response = requests.get(f"{API_URL}/archivos", headers=headers)
        if response.status_code == 200:
            files = response.json()
            self.file_view.clear()
            for file in files:
                item = QListWidgetItem(file.get("file_name", "ERROR"))
                item.setToolTip(f"Hash: {file.get('hash', 'ERROR')}")
                if file.get("signed", False):
                    item.setForeground(QColor(100, 255, 100))
                self.file_view.addItem(item)
        else:
            show_message("Error", "Failed to retrieve files")

    def upload_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if not file_path:
            return

        with open(file_path, "rb") as f:
            file_content = f.read()
        file_data = b64encode(encrypt(file_content, self.pub_key)).decode()

        headers = {"Authorization": f"Bearer {self.token}"}
        response = requests.post(
            f"{API_URL}/guardar",
            data={
                "file_name": os.path.basename(file_path),
                "file_data": file_data,
                "file_pub_key": self.pub_key
            },
            headers=headers
        )
        show_message("Upload", response.text)
        self.list_files()

    def upload_signed_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if not file_path:
            return

        with open(file_path, "rb") as f:
            file_content = f.read()
        file_data = b64encode(encrypt(file_content, self.pub_key)).decode()

        headers = {"Authorization": f"Bearer {self.token}"}
        response = requests.post(
            f"{API_URL}/guardar",
            data={
                "file_name": os.path.basename(file_path),
                "file_data": file_data,
                "file_pub_key": self.pub_key,
                "sign_priv_key": self.priv_key
            },
            headers=headers
        )
        show_message("Upload", response.text)
        self.list_files()

    def download_file(self, item: QListWidgetItem):
        folder_path = QFileDialog.getExistingDirectory(self, "Select Location", "./Out")
        if not folder_path:
            return

        headers = {"Authorization": f"Bearer {self.token}"}
        response = requests.get(f"{API_URL}/archivos/{item.text()}/descargar", headers=headers)
        if response.status_code == 200:
            try:
                file_data = decrypt(b64decode(response.json().get("content", "")), self.priv_key)
            except Exception as e:
                show_message("Error", "This file does not belong to you.")
                return

            output_filename = response.json().get("filename", os.path.basename(item.text()))
            with open(os.path.join(folder_path, output_filename), "wb") as f:
                f.write(file_data)
            show_message("Download", "File downloaded successfully!")
        else:
            show_message("Error", response.json().get("detail", "Unknown error"))

    def verify_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Verify")
        if not file_path:
            return

        with open(file_path, "rb") as f:
            file_content = f.read()
        file_data = b64encode(encrypt(file_content, self.pub_key)).decode()

        headers = {"Authorization": f"Bearer {self.token}"}
        response = requests.post(
            f"{API_URL}/verificar",
            data={
                "file_name": os.path.basename(file_path),
                "file_data": file_data,
                "sign_pub_key": self.pub_key
            },
            headers=headers
        )
        if response.status_code == 200:
            show_message("Verification", "Signature & Hash match.")
        else:
            show_message("Verification", response.json().get("detail", "Unknown error"))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = App()
    window.show()
    sys.exit(app.exec())
