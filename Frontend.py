
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

		self.input_username = QLineEdit()
		self.input_username.setPlaceholderText("Username")
		self.input_username.returnPressed.connect(lambda: self.input_password.setFocus())

		self.input_password = QLineEdit()
		self.input_password.setEchoMode(QLineEdit.EchoMode.Password)
		self.input_password.setPlaceholderText("Password")
		self.input_password.returnPressed.connect(self.login)

		self.btn_register = QPushButton("Register")
		self.btn_register.clicked.connect(self.register)

		self.btn_login = QPushButton("Login")
		self.btn_login.clicked.connect(self.login)

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

		self.file_view = QListWidget()
		self.file_view.itemDoubleClicked.connect(self.download_file)

		layout.addWidget(self.input_username)
		layout.addWidget(self.input_password)
		layout.addWidget(self.btn_register)
		layout.addWidget(self.btn_login)

		layout.addWidget(self.btn_logout)
		layout.addWidget(self.btn_list_files)
		layout.addWidget(self.btn_upload)
		layout.addWidget(self.btn_upload_sign)
		layout.addWidget(self.btn_verify)
		layout.addWidget(self.file_view)

		self.btn_logout.hide()
		self.btn_list_files.hide()
		self.btn_upload.hide()
		self.btn_upload_sign.hide()
		self.btn_verify.hide()
		self.file_view.hide()

		self.setLayout(layout)
		self.setWindowTitle("Secure File Manager")

	def register(self):
		email = self.input_username.text()
		password = self.input_password.text()
		response = requests.post(f"{API_URL}/register", json={"username": email, "password": password})
		if response.status_code != 200:
			show_message("Register", f'Error: {response.json().get("detail", "Error")}')
		else:
			show_message("Register", "Successfully Registered")

	def login(self):
		email = self.input_username.text()
		password = self.input_password.text()
		response = requests.post(f"{API_URL}/login", json={"username": email, "password": password})
		if response.status_code != 200:
			show_message("Login", "Invalid Credentials")
			self.logout()
		else:
			self.token = response.json()["access_token"]
			self.input_username.hide()
			self.input_password.hide()
			self.btn_register.hide()
			self.btn_login.hide()

			self.btn_logout.show()
			self.btn_list_files.show()
			self.btn_upload.show()
			self.btn_upload_sign.show()
			self.btn_verify.show()
			self.file_view.show()
			self.list_files()

	def logout(self):
		self.input_username.clear()
		self.input_password.clear()

		self.input_username.show()
		self.input_password.show()
		self.btn_register.show()
		self.btn_login.show()

		self.btn_logout.hide()
		self.btn_list_files.hide()
		self.btn_upload.hide()
		self.btn_upload_sign.hide()
		self.btn_verify.hide()
		self.file_view.hide()

	def list_files(self):
		headers = {"Authorization": f"Bearer {self.token}"}
		response = requests.get(f"{API_URL}/archivos", headers=headers)
		if response.status_code == 200:
			files = response.json()
			self.file_view.clear()
			self.file_view.addItems(files)
		else:
			show_message("Error", "Failed to retrieve files")

	def upload_file(self):
		file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
		if not file_path:
			return
		with open(file_path, "rb") as f:
			files = {"file": f}
			headers = {"Authorization": f"Bearer {self.token}"}
			response = requests.post(f"{API_URL}/guardar", files=files, headers=headers)
		show_message("Upload", response.text)
		self.list_files()

	def upload_signed_file(self):
		file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
		if not file_path:
			return
		with open(file_path, "rb") as f:
			data = {"sign": "true"}
			files = {"file": f}
			headers = {"Authorization": f"Bearer {self.token}"}
			response = requests.post(f"{API_URL}/guardar", files=files, data=data, headers=headers)
		show_message("Upload", response.text)
		self.list_files()

	def download_file(self, item: QListWidgetItem):
		folder_path = QFileDialog.getExistingDirectory(self, "Select Location", "./Out")
		if not folder_path:
			return
		headers = {"Authorization": f"Bearer {self.token}"}
		response = requests.get(f"{API_URL}/archivos/{item.text()}/descargar", headers=headers)
		if response.status_code == 200:
			with open(f"{folder_path}/{item.text()}", "wb") as f:
				f.write(response.json().get("content", "").encode())
			show_message("Download", "File downloaded successfully!")
		else:
			show_message("Error", f"Error: {response.text}")

	def verify_file(self):
		filename, _ = QFileDialog.getOpenFileName(self, "Select File to Verify")
		if not filename:
			return

		public_key, ok = QInputDialog.getMultiLineText(self, "Public Key", "Paste the public key:")
		signature, ok2 = QInputDialog.getText(self, "Signature", "Paste the file signature:")

		if not ok or not ok2:
			return

		with open(filename, "rb") as f:
			files = {"file": f}
			data = {"signature": signature, "public_key": public_key}
			response = requests.post(f"{API_URL}/verificar", files=files, data=data)

		if response.status_code == 200:
			show_message("Verification", "File is authentic")
		else:
			show_message("Verification", f"Invalid: {response.text}")

if __name__ == "__main__":
	app = QApplication(sys.argv)
	window = App()
	window.show()
	sys.exit(app.exec())