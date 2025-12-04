import os
import sys
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QProgressBar,
    QVBoxLayout,
    QWidget,
)

import psutil


def default_profile_path() -> str:
    local = os.environ.get("LOCALAPPDATA", "")
    if local:
        p = Path(local) / "Google/Chrome/User Data/Default"
        return str(p)
    return str(Path.home() / "AppData/Local/Google/Chrome/User Data/Default")


class PasswordDialog(QDialog):
    def __init__(self, parent=None, confirm=False):
        super().__init__(parent)
        self.setWindowTitle("Enter Password")
        self.pw = QLineEdit()
        self.pw.setEchoMode(QLineEdit.Password)
        self.pw_confirm = QLineEdit()
        self.pw_confirm.setEchoMode(QLineEdit.Password)
        self.show_toggle = QCheckBox("Show password")
        self.show_toggle.stateChanged.connect(self._toggle)
        form = QFormLayout()
        form.addRow("Password", self.pw)
        if confirm:
            form.addRow("Confirm", self.pw_confirm)
        form.addRow(self.show_toggle)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout()
        layout.addLayout(form)
        layout.addWidget(buttons)
        self.setLayout(layout)
        self._confirm = confirm

    def _toggle(self, state):
        mode = QLineEdit.Normal if state == Qt.Checked else QLineEdit.Password
        self.pw.setEchoMode(mode)
        self.pw_confirm.setEchoMode(mode)

    def get(self):
        if self.exec() == QDialog.Accepted:
            a = self.pw.text()
            if self._confirm:
                b = self.pw_confirm.text()
                if a != b:
                    QMessageBox.warning(self, "Password", "Passwords do not match")
                    return None
            if not a:
                QMessageBox.warning(self, "Password", "Password cannot be empty")
                return None
            return a
        return None


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Halal Google Profile Protector")
        self.resize(820, 560)
        central = QWidget()
        self.setCentralWidget(central)

        self.path_edit = QLineEdit(default_profile_path())
        browse = QPushButton("Browse…")
        browse.clicked.connect(self.browse)
        path_row = QHBoxLayout()
        path_row.addWidget(QLabel("Profile path"))
        path_row.addWidget(self.path_edit, 1)
        path_row.addWidget(browse)

        self.skip_caches = QCheckBox("Skip caches for speed/size")
        self.encrypt_btn = QPushButton("Encrypt Profile")
        self.decrypt_btn = QPushButton("Decrypt Profile")
        self.encrypt_btn.clicked.connect(self.encrypt_flow)
        self.decrypt_btn.clicked.connect(self.decrypt_flow)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.log = QTextEdit()
        self.log.setReadOnly(True)

        actions = QHBoxLayout()
        actions.addWidget(self.encrypt_btn)
        actions.addWidget(self.decrypt_btn)
        actions.addStretch(1)

        col = QVBoxLayout()
        col.addLayout(path_row)
        col.addWidget(self.skip_caches)
        col.addLayout(actions)
        col.addWidget(QLabel("Progress"))
        col.addWidget(self.progress)
        col.addWidget(QLabel("Log"))
        col.addWidget(self.log, 1)
        central.setLayout(col)

        menubar = self.menuBar()
        file_menu = menubar.addMenu("File")
        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

    def browse(self):
        d = QFileDialog.getExistingDirectory(self, "Select Chrome Default folder", self.path_edit.text())
        if d:
            self.path_edit.setText(d)

    def check_chrome_closed(self) -> bool:
        names = {"chrome.exe", "chrome"}
        for p in psutil.process_iter(["name"]):
            try:
                n = (p.info.get("name") or "").lower()
            except Exception:
                n = ""
            if n in names:
                return False
        return True

    def ensure_chrome_closed(self) -> bool:
        if self.check_chrome_closed():
            return True
        r = QMessageBox.question(self, "Chrome is running", "Chrome appears to be running. Close it and retry.")
        return False

    def encrypt_flow(self):
        if not self.ensure_chrome_closed():
            return
        d = Path(self.path_edit.text())
        if not d.exists() or not d.is_dir():
            QMessageBox.warning(self, "Path", "Profile path is invalid")
            return
        pd = PasswordDialog(self, confirm=True)
        pw = pd.get()
        if not pw:
            return
        QMessageBox.information(self, "Encrypt", "Encryption will be implemented next. GUI is ready.")

    def decrypt_flow(self):
        if not self.ensure_chrome_closed():
            return
        d = Path(self.path_edit.text())
        if not d.exists() or not d.is_dir():
            QMessageBox.warning(self, "Path", "Profile path is invalid")
            return
        pd = PasswordDialog(self, confirm=False)
        pw = pd.get()
        if not pw:
            return
        QMessageBox.information(self, "Decrypt", "Decryption will be implemented next. GUI is ready.")


def main():
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
