import sys
import requests
from PySide6.QtWidgets import *
from PySide6.QtGui import *

from Backend.Encrypt import *
from Backend.Sign import *

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
		self.pub_key = ""
		self.priv_key = ""
		self.init_ui()

	def init_ui(self):
		layout = QVBoxLayout()

		self.input_username = QLineEdit()
		self.input_username.setPlaceholderText("Username")
		self.input_username.setText("123")
		self.input_username.returnPressed.connect(lambda: self.input_password.setFocus())

		self.input_password = QLineEdit()
		self.input_password.setEchoMode(QLineEdit.EchoMode.Password)
		self.input_password.setPlaceholderText("Password")
		self.input_password.setText("123")
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
		username = self.input_username.text()
		password = self.input_password.text()
		if username == "" or password == "":
			show_message("Register", "Empty Credentials")
		else:
			response = requests.post(f"{API_URL}/register", json={"username": username, "password": password})
			if response.status_code != 200:
				show_message("Register", f'Error: {response.json().get("detail", "Error")}')
			else:
				pub_key, priv_key = generate_rsa_keys()
				if not os.path.exists("./Keys"): os.makedirs("./Keys")
				open(f"./Keys/{username}.pub", "w").write(pub_key)
				open(f"./Keys/{username}", "w").write(priv_key)
				show_message("Register", "Successfully Registered")
				self.login()

	def login(self):
		username = self.input_username.text()
		password = self.input_password.text()
		if username == "" or password == "":
			show_message("Register", "Empty Credentials")
		else:
			response = requests.post(f"{API_URL}/login", json={"username": username, "password": password})
			if response.status_code != 200:
				show_message("Login", "Invalid Credentials")
				self.logout()
			else:
				self.token = response.json()["access_token"]
				self.pub_key = open(f"./Keys/{username}.pub", "r").read()
				self.priv_key = open(f"./Keys/{username}", "r").read()

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
		# GET
		response = requests.get(
			f"{API_URL}/archivos",
			headers=headers
		)
		# GET
		if response.status_code == 200:
			files = response.json()
			self.file_view.clear()
			for file in files:
				item = QListWidgetItem(file.get("file_name", "ERROR"))
				item.setToolTip(f"Hash: {file.get('hash', 'ERROR')}")
				if (file.get("signed", False)):
					item.setForeground(QColor(100, 255, 100))
				self.file_view.addItem(item)
		else:
			show_message("Error", "Failed to retrieve files")

	def upload_file(self):
		file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
		if not file_path:
			return

		file_data = b64encode(encrypt(open(file_path, "rb").read(), self.pub_key)).decode()

		headers = {"Authorization": f"Bearer {self.token}"}
		# POST
		response = requests.post(
			f"{API_URL}/guardar",
			data={
				"file_name": os.path.basename(file_path),
				"file_data": file_data,
				"file_pub_key": self.pub_key
			},
			headers=headers
		)
		# POST
		show_message("Upload", response.text)
		self.list_files()

	def upload_signed_file(self):
		file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
		if not file_path:
			return

		file_data = b64encode(encrypt(open(file_path, "rb").read(), self.pub_key)).decode()

		headers = {"Authorization": f"Bearer {self.token}"}
		# POST
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
		# POST
		show_message("Upload", response.text)
		self.list_files()

	def download_file(self, item: QListWidgetItem):
		folder_path = QFileDialog.getExistingDirectory(self, "Select Location", "./Out")
		if not folder_path:
			return

		headers = {"Authorization": f"Bearer {self.token}"}
		# GET
		response = requests.get(
			f"{API_URL}/archivos/{item.text()}/descargar",
			headers=headers
		)
		# GET
		if response.status_code == 200:
			print(response.json())
			file_data = decrypt(b64decode(response.json().get("content", "")), self.priv_key)
			open(f"{folder_path}/{response.json().get('filename', '')}", "wb").write(file_data)
			show_message("Download", "File downloaded successfully!")
		else:
			show_message("Error", response.json().get("detail", "Unknown error"))

	def verify_file(self):
		file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Verify")
		if not file_path:
			return

		file_data = b64encode(encrypt(open(file_path, "rb").read(), self.pub_key)).decode()

		headers = {"Authorization": f"Bearer {self.token}"}
		# POST
		response = requests.post(
			f"{API_URL}/verificar",
			data={
				"file_name": os.path.basename(file_path),
				"file_data": file_data,
				"sign_pub_key": self.pub_key
			},
			headers=headers
		)
		#POST

		if response.status_code == 200:
			show_message("Verification", "Signature & Hash match.")
		else:
			show_message("Verification", response.json().get("detail", "Unknown error"))

if __name__ == "__main__":
	app = QApplication(sys.argv)
	window = App()
	window.show()
	sys.exit(app.exec())