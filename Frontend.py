import sys
import requests
from PySide6.QtWidgets import *

API_URL = "http://127.0.0.1:8000"

def show_message(title, message):
	msg = QMessageBox()
	msg.setWindowTitle(title)
	msg.setText(message)
	msg.exec()

class App(QWidget):
	def __init__(self):
		super().__init__()
		self.token = ""
		self.init_ui()

	def init_ui(self):
		layout = QVBoxLayout()

		self.label_email = QLabel("Username:")
		self.input_email = QLineEdit()

		self.label_password = QLabel("Password:")
		self.input_password = QLineEdit()
		self.input_password.setEchoMode(QLineEdit.Password)

		self.btn_register = QPushButton("Register")
		self.btn_register.clicked.connect(self.register)

		self.btn_login = QPushButton("Login")
		self.btn_login.clicked.connect(self.login)

		self.btn_list_files = QPushButton("List Files")
		self.btn_list_files.clicked.connect(self.list_files)

		self.btn_upload = QPushButton("Upload File")
		self.btn_upload.clicked.connect(self.upload_file)

		self.btn_upload_sign = QPushButton("Upload Signed File")
		self.btn_upload_sign.clicked.connect(self.upload_signed_file)

		self.btn_download = QPushButton("Download File")
		self.btn_download.clicked.connect(self.download_file)

		self.btn_verify = QPushButton("Verify File")
		self.btn_verify.clicked.connect(self.verify_file)

		self.output_console = QTextEdit()
		self.output_console.setReadOnly(True)
		
		layout.addWidget(self.label_email)
		layout.addWidget(self.input_email)
		layout.addWidget(self.label_password)
		layout.addWidget(self.input_password)
		layout.addWidget(self.btn_register)
		layout.addWidget(self.btn_login)
		layout.addWidget(self.btn_list_files)
		layout.addWidget(self.btn_upload)
		layout.addWidget(self.btn_upload_sign)
		layout.addWidget(self.btn_download)
		layout.addWidget(self.btn_verify)
		layout.addWidget(self.output_console)
		
		self.setLayout(layout)
		self.setWindowTitle("Secure File Manager")

	def register(self):
		email = self.input_email.text()
		password = self.input_password.text()
		response = requests.post(f"{API_URL}/register", json={"username": email, "password": password})
		show_message("Register", response.json().get("message", "Error"))

	def login(self):
		email = self.input_email.text()
		password = self.input_password.text()
		response = requests.post(f"{API_URL}/login", json={"username": email, "password": password})
		if response.status_code == 200:
			self.token = response.json()["access_token"]
			show_message("Login", "Login Successful!")
		else:
			show_message("Login", "Invalid Credentials")

	def list_files(self):
		if not self.token:
			show_message("Error", "Please login first!")
			return
		headers = {"Authorization": f"Bearer {self.token}"}
		response = requests.get(f"{API_URL}/archivos", headers=headers)
		if response.status_code == 200:
			files = response.json()
			self.output_console.setText("\n".join(files) if files else "No files found.")
		else:
			show_message("Error", "Failed to retrieve files")

	def upload_file(self):
		if not self.token:
			show_message("Error", "Please login first!")
			return
		file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
		if not file_path:
			return
		with open(file_path, "rb") as f:
			files = {"file": f}
			headers = {"Authorization": f"Bearer {self.token}"}
			response = requests.post(f"{API_URL}/guardar", files=files, headers=headers)
		show_message("Upload", response.text)

	def upload_signed_file(self):
		if not self.token:
			show_message("Error", "Please login first!")
			return
		file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
		if not file_path:
			return
		with open(file_path, "rb") as f:
			files = {"file": f}
			headers = {"Authorization": f"Bearer {self.token}"}
			response = requests.post(f"{API_URL}/guardar", files=files, headers=headers)
		show_message("Upload", response.text)

	def download_file(self):
		filename, ok = QFileDialog.getSaveFileName(self, "Save File")
		if not filename:
			return
		response = requests.get(f"{API_URL}/archivos")
		if response.status_code == 200:
			files = response.json()
			if files:
				response = requests.get(f"{API_URL}/archivos/{files[0]}/descargar")
				with open(filename, "wb") as f:
					f.write(response.json().get("content", "").encode())
				show_message("Download", "File downloaded successfully!")
		else:
			show_message("Error", "No files found")

	def verify_file(self):
		if not self.token:
			show_message("Error", "Please login first!")
			return
		filename, _ = QFileDialog.getOpenFileName(self, "Select File to Verify")
		if not filename:
			return
		public_key, ok = QInputDialog.getText(self, "Public Key", "Enter Public Key:")
		if not ok or not public_key:
			return
		signature, ok = QInputDialog.getText(self, "Signature", "Enter Signature:")
		if not ok or not signature:
			return
		response = requests.post(f"{API_URL}/verificar", json={"filename": filename, "signature": signature, "public_key": public_key})
		if response.status_code == 200:
			show_message("Verify", "Signature is valid!")
		else:
			show_message("Verify", "Invalid signature")

if __name__ == "__main__":
	app = QApplication(sys.argv)
	window = App()
	window.show()
	sys.exit(app.exec())