import os
import sys
import shutil
import time
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal, QObject
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


class Worker(QThread):
    progress_update = Signal(int)
    log_update = Signal(str)
    finished_task = Signal()
    
    def __init__(self, mode, targets, password, skip_caches=False, overwrite=False):
        super().__init__()
        self.mode = mode # 'encrypt' or 'decrypt'
        self.targets = targets
        self.password = password
        self.skip_caches = skip_caches
        self.overwrite = overwrite
        self._stop = False

    def run(self):
        total = len(self.targets)
        current = 0
        
        if self.mode == 'encrypt':
            for d in self.targets:
                if self._stop: break
                current += 1
                self.log_update.emit(f"--- Encrypting {d.name} ({current}/{total}) ---")
                
                out_file = d.parent / f"{d.name}.hgp"
                if out_file.exists():
                    self.log_update.emit(f"Skipping {d.name}: Archive {out_file.name} already exists.")
                    continue

                def on_prog(p: Progress):
                    # We can maybe use p.percent for a granular bar, but for batch 
                    # let's just pulsate or keep it simple.
                    pass

                try:
                    t0 = time.perf_counter()
                    encrypt_directory(d, out_file, self.password, self.skip_caches, progress=on_prog)
                    elapsed = time.perf_counter() - t0
                    self.log_update.emit(f"Encrypted {d.name} in {elapsed:.2f}s")
                    
                    try:
                        shutil.rmtree(d)
                        self.log_update.emit(f"Deleted original folder: {d.name}")
                    except Exception as e:
                        self.log_update.emit(f"Failed to delete {d.name}: {e}")
                        
                except Exception as e:
                    self.log_update.emit(f"ERROR encrypting {d.name}: {e}")
                    
        elif self.mode == 'decrypt':
            for arch in self.targets:
                if self._stop: break
                current += 1
                self.log_update.emit(f"--- Decrypting {arch.name} ({current}/{total}) ---")
                
                folder_name = arch.stem
                dest = arch.parent / folder_name
                
                if dest.exists():
                    if self.overwrite:
                        self.log_update.emit(f"Overwrite selected: Removing existing folder {folder_name}...")
                        try:
                            shutil.rmtree(dest)
                        except Exception as e:
                            self.log_update.emit(f"ERROR: Could not delete {folder_name}: {e}")
                            continue
                    else:
                        self.log_update.emit(f"Skipping {arch.name}: Destination folder {folder_name} already exists.")
                        continue
                    
                dest_new = arch.parent / f"{folder_name}.new"
                if dest_new.exists():
                    try:
                        shutil.rmtree(dest_new)
                    except Exception:
                        self.log_update.emit(f"Skipping {arch.name}: Could not clear temp folder {dest_new.name}")
                        continue

                def on_prog(p: Progress):
                    pass

                try:
                    t0 = time.perf_counter()
                    decrypt_archive(arch, dest_new, self.password, progress=on_prog)
                    elapsed = time.perf_counter() - t0
                    
                    dest_new.rename(dest)
                    self.log_update.emit(f"Decrypted {arch.name} in {elapsed:.2f}s")
                    
                    try:
                        arch.unlink()
                        self.log_update.emit(f"Deleted archive: {arch.name}")
                    except Exception as e:
                        self.log_update.emit(f"Failed to delete archive {arch.name}: {e}")
                        
                except Exception as e:
                    self.log_update.emit(f"ERROR decrypting {arch.name}: {e}")
                    if dest_new.exists():
                        shutil.rmtree(dest_new, ignore_errors=True)

        self.finished_task.emit()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"Halal Google Profile Protector v{__version__}")
        self.resize(850, 650)
        central = QWidget()
        self.setCentralWidget(central)

        self.profile_list = QListWidget()
        self.profile_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.profile_list.itemChanged.connect(self.on_item_changed)
        
        self.user_data_dir = get_user_data_dir()

        btn_layout = QHBoxLayout()
        self.btn_refresh = QPushButton("Refresh List")
        self.btn_refresh.clicked.connect(self.scan_profiles)
        self.btn_browse = QPushButton("Browse Folder…")
        self.btn_browse.clicked.connect(self.browse)
        self.btn_select_all = QPushButton("Select All")
        self.btn_select_all.clicked.connect(self.select_all)
        self.btn_deselect_all = QPushButton("Deselect All")
        self.btn_deselect_all.clicked.connect(self.deselect_all)
        
        btn_layout.addWidget(self.btn_refresh)
        btn_layout.addWidget(self.btn_browse)
        btn_layout.addWidget(self.btn_select_all)
        btn_layout.addWidget(self.btn_deselect_all)
        btn_layout.addStretch(1)

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
        self.progress.setRange(0, 0) # Indeterminate by default when working
        self.progress.hide()
        
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

        self.worker = None
        self.scan_profiles()

    def scan_profiles(self):
        self.profile_list.clear()
        if not self.user_data_dir.exists():
            self._log(f"User Data directory not found: {self.user_data_dir}")
            return

        found = []
        try:
            for entry in self.user_data_dir.iterdir():
                name = entry.name
                if entry.is_dir():
                    if name == "Default" or name.startswith("Profile "):
                        found.append((name, "Folder"))
                elif entry.is_file() and name.endswith(".hgp"):
                    stem = entry.stem
                    if stem == "Default" or stem.startswith("Profile "):
                        found.append((stem, "Archive"))
        except Exception as e:
            self._log(f"Error scanning profiles: {e}")

        found.sort()

        for name, kind in found:
            item = QListWidgetItem(f"{name} [{kind}]")
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked)
            item.setData(Qt.UserRole, {"name": name, "kind": kind, "path": self.user_data_dir / name})
            self.profile_list.addItem(item)
        
        self._log(f"Scanned {len(found)} items.")

    def browse(self):
        d = QFileDialog.getExistingDirectory(self, "Select Chrome Profile Folder", str(self.user_data_dir))
        if d:
            path = Path(d)
            name = path.name
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

    def _lock_ui(self, locked=True):
        # Top buttons
        self.btn_refresh.setEnabled(not locked)
        self.btn_browse.setEnabled(not locked)
        self.btn_select_all.setEnabled(not locked)
        self.btn_deselect_all.setEnabled(not locked)
        
        # Main list and check
        self.profile_list.setEnabled(not locked)
        self.skip_caches.setEnabled(not locked)
        
        # Action buttons
        self.encrypt_btn.setEnabled(not locked)
        self.decrypt_btn.setEnabled(not locked)
        
        if locked:
            self.progress.show()
        else:
            self.progress.hide()

    def batch_encrypt(self):
        targets = self.get_checked_items()
        if not targets:
            QMessageBox.warning(self, "No Selection", "Please select at least one profile to encrypt.")
            return

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

        self._start_worker('encrypt', to_encrypt, pw)

    def batch_decrypt(self):
        targets = self.get_checked_items()
        if not targets:
            QMessageBox.warning(self, "No Selection", "Please select at least one profile to decrypt.")
            return

        to_decrypt = []
        for item, data in targets:
            path = data["path"]
            # Relaxed check: trust the scan results if it says "Archive", even if file check fails transiently
            # or if the path construction was slightly off.
            # But wait, scan_profiles constructs path as: user_data_dir / name
            # If name is "Default", path is .../Default
            # If kind is Archive, it was found because of .hgp extension
            # Let's double check scan_profiles logic.
            
            # scan_profiles: 
            # if entry.is_file() and name.endswith(".hgp"):
            #    stem = entry.stem (e.g. "Default")
            #    found.append((stem, "Archive"))
            # item.setData(..., "path": self.user_data_dir / stem) -> This path is the FOLDER path (e.g. .../Default)
            
            # So data["path"] points to where the folder WOULD be.
            # But for decryption, we need the ARCHIVE path (e.g. .../Default.hgp).
            
            if data["kind"] == "Archive":
                # Reconstruct archive path
                archive_path = path.parent / f"{path.name}.hgp"
                if archive_path.exists() and archive_path.is_file():
                    to_decrypt.append(archive_path)
                else:
                     self._log(f"Skipping {data['name']}: Archive file not found at {archive_path}")
            elif data["kind"] == "Folder":
                self._log(f"Skipping {data['name']}: It is not an archive.")

        if not to_decrypt:
            QMessageBox.information(self, "Info", "No valid archives selected.")
            return

        # Pre-check for existing folders
        conflicts = []
        for arch in to_decrypt:
            folder_name = arch.stem
            dest = arch.parent / folder_name
            if dest.exists():
                conflicts.append(folder_name)
        
        overwrite = False
        if conflicts:
            msg = "The following profile folders already exist and would be overwritten:\n\n"
            msg += "\n".join(conflicts[:10])
            if len(conflicts) > 10:
                msg += "\n...and more."
            msg += "\n\nDo you want to DELETE these existing folders and restore from the archives?"
            
            resp = QMessageBox.warning(self, "Overwrite Conflicts", msg, 
                                       QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel)
            
            if resp == QMessageBox.Yes:
                overwrite = True
            elif resp == QMessageBox.No:
                # Filter out conflicts
                to_decrypt = [a for a in to_decrypt if not (a.parent / a.stem).exists()]
                if not to_decrypt:
                     return
            else:
                return # Cancel

        if not self.ensure_chrome_closed():
            return

        pd = PasswordDialog(self, confirm=False)
        pw = pd.get()
        if not pw:
            return

        self._start_worker('decrypt', to_decrypt, pw, overwrite_existing=overwrite)

    def _start_worker(self, mode, targets, password, overwrite_existing=False):
        self._lock_ui(True)
        self.log.clear()
        
        skip = self.skip_caches.isChecked()
        self.worker = Worker(mode, targets, password, skip, overwrite=overwrite_existing)
        self.worker.log_update.connect(self._log)
        self.worker.finished_task.connect(self._on_worker_finished)
        self.worker.start()

    def _on_worker_finished(self):
        self._lock_ui(False)
        self._log("Operation completed.")
        self.scan_profiles()
        self.worker = None

    def _log(self, msg: str):
        self.log.append(msg)


def main():
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
