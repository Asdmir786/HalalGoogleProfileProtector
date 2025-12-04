import os
import sys
import shutil
import time
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
from .ops import encrypt_directory, decrypt_archive, Progress
from . import __version__


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
        self.show_toggle.toggled.connect(self._toggle)
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

    def _toggle(self, checked: bool):
        mode = QLineEdit.Normal if checked else QLineEdit.Password
        self.pw.setEchoMode(mode)
        if self._confirm:
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
        self.setWindowTitle(f"Halal Google Profile Protector v{__version__}")
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
        # Determine archive path next to the Default folder
        out_file = d.parent / "Default.hgp"
        if out_file.exists():
            resp = QMessageBox.question(
                self,
                "Overwrite?",
                f"Archive already exists:\n{out_file}\n\nOverwrite?",
                QMessageBox.Yes | QMessageBox.No,
            )
            if resp != QMessageBox.Yes:
                return

        # Prepare UI
        self.encrypt_btn.setEnabled(False)
        self.decrypt_btn.setEnabled(False)
        self.progress.setValue(0)
        self.log.clear()
        self._log(f"Encrypting {d} -> {out_file}")
        skip = self.skip_caches.isChecked()

        def on_prog(p: Progress):
            self.progress.setValue(max(0, min(100, p.percent)))
            self._log(p.step)
            QApplication.processEvents()

        enc_ok = False
        t0 = time.perf_counter()
        try:
            encrypt_directory(d, out_file, pw, skip, progress=on_prog)
            enc_ok = True
            self.progress.setValue(100)
            elapsed = time.perf_counter() - t0
            try:
                size_mb = (out_file.stat().st_size) / (1024 * 1024)
                self._log(f"Encryption completed in {elapsed:.2f}s; archive size {size_mb:.2f} MiB")
            except Exception:
                self._log(f"Encryption completed in {elapsed:.2f}s")
        except Exception as e:
            QMessageBox.critical(self, "Encrypt failed", str(e))
        finally:
            self.encrypt_btn.setEnabled(True)
            self.decrypt_btn.setEnabled(True)

        # Delete the original profile folder only if encryption succeeded
        if enc_ok:
            try:
                if d.exists():
                    shutil.rmtree(d)
                    self._log(f"Deleted original profile folder: {d}")
            except Exception as e:
                QMessageBox.warning(self, "Delete failed", f"Could not delete profile folder:\n{d}\n\n{e}")

    def decrypt_flow(self):
        if not self.ensure_chrome_closed():
            return
        d = Path(self.path_edit.text())
        # Allow decrypt even if the profile folder (Default) does not exist anymore
        # as long as its parent directory exists.
        if not d.exists() or not d.is_dir():
            parent = d.parent
            if not parent.exists() or not parent.is_dir():
                QMessageBox.warning(self, "Path", "Profile path or its parent directory is invalid")
                return
        pd = PasswordDialog(self, confirm=False)
        pw = pd.get()
        if not pw:
            return
        arch = d.parent / "Default.hgp"
        if not arch.exists():
            QMessageBox.warning(self, "Missing archive", f"Archive not found:\n{arch}")
            return

        # Prepare UI
        self.encrypt_btn.setEnabled(False)
        self.decrypt_btn.setEnabled(False)
        self.progress.setValue(0)
        self.log.clear()
        self._log(f"Decrypting {arch}")

        def on_prog(p: Progress):
            self.progress.setValue(max(0, min(100, p.percent)))
            self._log(p.step)
            QApplication.processEvents()

        # Decrypt to a temp directory
        dest_new = d.parent / "Default.new"
        if dest_new.exists():
            try:
                shutil.rmtree(dest_new)
            except Exception:
                QMessageBox.warning(self, "Cleanup", f"Remove folder then retry:\n{dest_new}")
                self.encrypt_btn.setEnabled(True)
                self.decrypt_btn.setEnabled(True)
                return

        ok = False
        t0 = time.perf_counter()
        try:
            decrypt_archive(arch, dest_new, pw, progress=on_prog)
            ok = True
            self.progress.setValue(95)
            elapsed = time.perf_counter() - t0
            try:
                size_mb = (arch.stat().st_size) / (1024 * 1024)
                self._log(f"Decryption completed in {elapsed:.2f}s; archive size {size_mb:.2f} MiB")
            except Exception:
                self._log(f"Decryption completed in {elapsed:.2f}s")
        except Exception as e:
            QMessageBox.critical(self, "Decrypt failed", str(e))
        
        # Replace atomically
        if ok:
            orig = d
            bak = d.parent / "Default.bak"
            try:
                if bak.exists():
                    shutil.rmtree(bak, ignore_errors=True)
                if orig.exists():
                    orig.rename(bak)
                dest_new.rename(orig)
                self.progress.setValue(100)
                self._log("Decryption completed and profile restored")
                # Offer to remove backup
                rm = QMessageBox.question(
                    self,
                    "Cleanup backup?",
                    f"A backup exists:\n{bak}\n\nDelete it?",
                    QMessageBox.Yes | QMessageBox.No,
                )
                if rm == QMessageBox.Yes:
                    shutil.rmtree(bak, ignore_errors=True)
                rm_arch = QMessageBox.question(
                    self,
                    "Delete archive?",
                    f"Delete the archive file now?\n{arch}",
                    QMessageBox.Yes | QMessageBox.No,
                )
                if rm_arch == QMessageBox.Yes:
                    try:
                        arch.unlink(missing_ok=True)
                        self._log(f"Deleted archive: {arch}")
                    except Exception as e:
                        QMessageBox.warning(self, "Archive delete failed", str(e))
            except Exception as e:
                # Rollback
                self._log(f"Restore failed: {e}")
                try:
                    if orig.exists():
                        shutil.rmtree(orig, ignore_errors=True)
                    if bak.exists():
                        bak.rename(orig)
                except Exception as e2:
                    self._log(f"Rollback issue: {e2}")
                QMessageBox.critical(self, "Restore failed", str(e))
            finally:
                self.encrypt_btn.setEnabled(True)
                self.decrypt_btn.setEnabled(True)
        else:
            self.encrypt_btn.setEnabled(True)
            self.decrypt_btn.setEnabled(True)

    def _log(self, msg: str):
        self.log.append(msg)


def main():
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
