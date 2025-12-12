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
    QListWidget,
    QListWidgetItem,
    QAbstractItemView
)

import psutil
from .ops import encrypt_directory, decrypt_archive, Progress
from . import __version__


def get_user_data_dir() -> Path:
    local = os.environ.get("LOCALAPPDATA", "")
    if local:
        return Path(local) / "Google/Chrome/User Data"
    return Path.home() / "AppData/Local/Google/Chrome/User Data"


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
        self.resize(850, 650)
        central = QWidget()
        self.setCentralWidget(central)

        # Profile List
        self.profile_list = QListWidget()
        self.profile_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.profile_list.itemChanged.connect(self.on_item_changed)
        
        # Determine User Data path
        self.user_data_dir = get_user_data_dir()

        # Selection Buttons
        btn_layout = QHBoxLayout()
        btn_refresh = QPushButton("Refresh List")
        btn_refresh.clicked.connect(self.scan_profiles)
        btn_browse = QPushButton("Browse Folder…")
        btn_browse.clicked.connect(self.browse)
        btn_select_all = QPushButton("Select All")
        btn_select_all.clicked.connect(self.select_all)
        btn_deselect_all = QPushButton("Deselect All")
        btn_deselect_all.clicked.connect(self.deselect_all)
        
        btn_layout.addWidget(btn_refresh)
        btn_layout.addWidget(btn_browse)
        btn_layout.addWidget(btn_select_all)
        btn_layout.addWidget(btn_deselect_all)
        btn_layout.addStretch(1)

        # Action Area
        self.skip_caches = QCheckBox("Skip caches for speed/size (Encryption only)")
        self.encrypt_btn = QPushButton("Encrypt Selected")
        self.decrypt_btn = QPushButton("Decrypt Selected")
        self.encrypt_btn.clicked.connect(self.batch_encrypt)
        self.decrypt_btn.clicked.connect(self.batch_decrypt)
        
        actions = QHBoxLayout()
        actions.addWidget(self.encrypt_btn)
        actions.addWidget(self.decrypt_btn)
        actions.addStretch(1)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.log = QTextEdit()
        self.log.setReadOnly(True)

        col = QVBoxLayout()
        col.addWidget(QLabel(f"Chrome User Data: {self.user_data_dir}"))
        col.addWidget(self.profile_list)
        col.addLayout(btn_layout)
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

        # Scan on startup (AFTER UI setup)
        self.scan_profiles()

    def scan_profiles(self):
        self.profile_list.clear()
        if not self.user_data_dir.exists():
            self._log(f"User Data directory not found: {self.user_data_dir}")
            return

        # Find folders: Default, Profile *
        # Find archives: Default.hgp, Profile *.hgp
        found = []
        try:
            for entry in self.user_data_dir.iterdir():
                name = entry.name
                if entry.is_dir():
                    if name == "Default" or name.startswith("Profile "):
                        # Check if it has preferences or seems valid?
                        # For now, just assume folder name is enough
                        found.append((name, "Folder"))
                elif entry.is_file() and name.endswith(".hgp"):
                    stem = entry.stem
                    if stem == "Default" or stem.startswith("Profile "):
                        found.append((stem, "Archive"))
        except Exception as e:
            self._log(f"Error scanning profiles: {e}")

        # Sort naturally
        found.sort()

        for name, kind in found:
            item = QListWidgetItem(f"{name} [{kind}]")
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Unchecked)
            # Store real data
            item.setData(Qt.UserRole, {"name": name, "kind": kind, "path": self.user_data_dir / name})
            self.profile_list.addItem(item)
        
        self._log(f"Scanned {len(found)} items.")

    def browse(self):
        d = QFileDialog.getExistingDirectory(self, "Select Chrome Profile Folder", str(self.user_data_dir))
        if d:
            path = Path(d)
            name = path.name
            # Check if exists in list
            # We treat manually added folders as "Custom" kind
            item = QListWidgetItem(f"{name} [Custom]")
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked)
            item.setData(Qt.UserRole, {"name": name, "kind": "Folder", "path": path})
            self.profile_list.addItem(item)
            self._log(f"Added custom path: {path}")

    def select_all(self):
        for i in range(self.profile_list.count()):
            self.profile_list.item(i).setCheckState(Qt.Checked)

    def deselect_all(self):
        for i in range(self.profile_list.count()):
            self.profile_list.item(i).setCheckState(Qt.Unchecked)

    def on_item_changed(self, item):
        # Could update button states here based on what is checked
        pass

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

    def get_checked_items(self):
        items = []
        for i in range(self.profile_list.count()):
            item = self.profile_list.item(i)
            if item.checkState() == Qt.Checked:
                items.append((item, item.data(Qt.UserRole)))
        return items

    def batch_encrypt(self):
        targets = self.get_checked_items()
        if not targets:
            QMessageBox.warning(self, "No Selection", "Please select at least one profile to encrypt.")
            return

        # Filter only Folders
        to_encrypt = []
        for item, data in targets:
            path = data["path"]
            if data["kind"] == "Folder" and path.exists() and path.is_dir():
                to_encrypt.append(path)
            elif data["kind"] == "Archive":
                self._log(f"Skipping {data['name']}: Already an archive.")
        
        if not to_encrypt:
            QMessageBox.info(self, "Info", "No valid unencrypted folders selected.")
            return

        if not self.ensure_chrome_closed():
            return

        pd = PasswordDialog(self, confirm=True)
        pw = pd.get()
        if not pw:
            return

        self.encrypt_btn.setEnabled(False)
        self.decrypt_btn.setEnabled(False)
        self.progress.setValue(0)
        self.log.clear()
        
        total = len(to_encrypt)
        current = 0
        
        for d in to_encrypt:
            current += 1
            self._log(f"--- Encrypting {d.name} ({current}/{total}) ---")
            
            out_file = d.parent / f"{d.name}.hgp"
            if out_file.exists():
                # For batch, we might want to auto-skip or ask. 
                # Let's ask once per conflict? Or just log and skip to be safe?
                # Safer: Skip and log
                self._log(f"Skipping {d.name}: Archive {out_file.name} already exists.")
                continue

            skip_cache = self.skip_caches.isChecked()
            
            def on_prog(p: Progress):
                # We won't update the main bar for individual steps to avoid jumping
                # Or we can just show text
                QApplication.processEvents()

            try:
                t0 = time.perf_counter()
                encrypt_directory(d, out_file, pw, skip_cache, progress=on_prog)
                elapsed = time.perf_counter() - t0
                self._log(f"Encrypted {d.name} in {elapsed:.2f}s")
                
                # Delete original
                try:
                    shutil.rmtree(d)
                    self._log(f"Deleted original folder: {d.name}")
                except Exception as e:
                    self._log(f"Failed to delete {d.name}: {e}")
                    
            except Exception as e:
                self._log(f"ERROR encrypting {d.name}: {e}")
        
        self.encrypt_btn.setEnabled(True)
        self.decrypt_btn.setEnabled(True)
        self.progress.setValue(100)
        self._log("Batch encryption finished.")
        self.scan_profiles()

    def batch_decrypt(self):
        targets = self.get_checked_items()
        if not targets:
            QMessageBox.warning(self, "No Selection", "Please select at least one profile to decrypt.")
            return

        # Filter only Archives
        to_decrypt = []
        for item, data in targets:
            path = data["path"] # This is the folder path usually, we need to construct archive path if it came from Folder scan?
            # Actually scan_profiles stores:
            # For Folder: path = .../Default
            # For Archive: path = .../Default (but derived from Default.hgp logic?)
            # Wait, let's fix scan logic:
            # If kind is Archive, path should point to the .hgp file?
            # Let's check scan_profiles...
            # if entry.is_file() ... name.endswith(".hgp") ... found.append...
            # item.setData... "path": self.user_data_dir / name
            # So yes, data["path"] is the full path to .hgp file for archives.
            
            if data["kind"] == "Archive" and path.exists() and path.is_file():
                to_decrypt.append(path)
            elif data["kind"] == "Folder":
                self._log(f"Skipping {data['name']}: It is not an archive.")

        if not to_decrypt:
            QMessageBox.information(self, "Info", "No valid archives selected.")
            return

        if not self.ensure_chrome_closed():
            return

        pd = PasswordDialog(self, confirm=False)
        pw = pd.get()
        if not pw:
            return

        self.encrypt_btn.setEnabled(False)
        self.decrypt_btn.setEnabled(False)
        self.progress.setValue(0)
        self.log.clear()

        total = len(to_decrypt)
        current = 0

        for arch in to_decrypt:
            current += 1
            self._log(f"--- Decrypting {arch.name} ({current}/{total}) ---")
            
            # arch is .../Default.hgp
            # dest is .../Default
            folder_name = arch.stem # Default
            dest = arch.parent / folder_name
            
            if dest.exists():
                self._log(f"Skipping {arch.name}: Destination folder {folder_name} already exists.")
                continue
                
            dest_new = arch.parent / f"{folder_name}.new"
            if dest_new.exists():
                try:
                    shutil.rmtree(dest_new)
                except Exception:
                    self._log(f"Skipping {arch.name}: Could not clear temp folder {dest_new.name}")
                    continue

            def on_prog(p: Progress):
                QApplication.processEvents()

            try:
                t0 = time.perf_counter()
                decrypt_archive(arch, dest_new, pw, progress=on_prog)
                elapsed = time.perf_counter() - t0
                
                # Rename .new to real
                dest_new.rename(dest)
                self._log(f"Decrypted {arch.name} in {elapsed:.2f}s")
                
                # Delete archive
                try:
                    arch.unlink()
                    self._log(f"Deleted archive: {arch.name}")
                except Exception as e:
                    self._log(f"Failed to delete archive {arch.name}: {e}")
                    
            except Exception as e:
                self._log(f"ERROR decrypting {arch.name}: {e}")
                # Cleanup
                if dest_new.exists():
                    shutil.rmtree(dest_new, ignore_errors=True)

        self.encrypt_btn.setEnabled(True)
        self.decrypt_btn.setEnabled(True)
        self.progress.setValue(100)
        self._log("Batch decryption finished.")
        self.scan_profiles()

    def _log(self, msg: str):
        self.log.append(msg)


def main():
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
