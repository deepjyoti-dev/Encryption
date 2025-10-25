# -*- coding: utf-8 -*-
"""
Created on Sat Oct 25 07:36:08 2025

@author: deepj
"""

"""
aes_gui_encryptor.py

Features:
 - AES-GCM streaming encryption/decryption (supports large files)
 - Password -> key derivation with PBKDF2 (configurable key length: 16 or 32 bytes)
 - GUI with Tkinter: browse, optional drag-and-drop, encrypt/decrypt single file or whole folder
 - Progress bar + threading to keep UI responsive
 - Encrypted file format: MAGIC(8) | salt(16) | nonce(12) | tag(16) | ciphertext...
"""

import os
import threading
import struct
import traceback
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from functools import partial

# Optional DnD support
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    DND_AVAILABLE = True
except Exception:
    DND_AVAILABLE = False

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ---- Config ----
MAGIC = b'AEGCMv1!'   # 8 bytes magic to identify format
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
KDF_ITERS = 200_000
CHUNK_SIZE = 64 * 1024  # 64 KB per chunk

# ---- Key derivation ----
def derive_key(password: bytes, salt: bytes, key_len: int):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_len,
        salt=salt,
        iterations=KDF_ITERS,
        backend=default_backend()
    )
    return kdf.derive(password)

# ---- Streaming encryption (AES-GCM) ----
def encrypt_stream(in_path: str, out_path: str, password: str, key_len: int, progress_callback=None):
    """
    Stream-encrypt in_path -> out_path. Writes header first with placeholder tag,
    writes ciphertext in chunks, then seeks back to write tag.
    """
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password.encode('utf-8'), salt, key_len=key_len)
    nonce = os.urandom(NONCE_SIZE)

    # Create encryptor
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    total = os.path.getsize(in_path)
    processed = 0

    with open(in_path, 'rb') as fin, open(out_path, 'wb') as fout:
        # Write header: MAGIC | salt | nonce | tag_placeholder
        fout.write(MAGIC)
        fout.write(salt)
        fout.write(nonce)
        fout.write(b'\x00' * TAG_SIZE)  # placeholder for tag; will overwrite later

        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            ct = encryptor.update(chunk)
            if ct:
                fout.write(ct)
            processed += len(chunk)
            if progress_callback:
                progress_callback(processed, total)

        # finalize and get tag
        final = encryptor.finalize()
        if final:
            fout.write(final)
        tag = encryptor.tag  # 16 bytes

        # seek back to write tag (after MAGIC + salt + nonce)
        fout.seek(len(MAGIC) + SALT_SIZE + NONCE_SIZE)
        fout.write(tag)

    if progress_callback:
        progress_callback(total, total)

# ---- Streaming decryption (AES-GCM) ----
def decrypt_stream(in_path: str, out_path: str, password: str, key_len: int, progress_callback=None):
    """
    Read header to get salt, nonce, tag; then stream decrypt ciphertext.
    """
    total = os.path.getsize(in_path)
    # minimal header size check
    header_size = len(MAGIC) + SALT_SIZE + NONCE_SIZE + TAG_SIZE
    if total < header_size:
        raise ValueError("File too small or not in expected format.")

    with open(in_path, 'rb') as fin:
        magic = fin.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError("File magic mismatch; not an encrypted file of this format.")
        salt = fin.read(SALT_SIZE)
        nonce = fin.read(NONCE_SIZE)
        tag = fin.read(TAG_SIZE)

        # ciphertext starts here
        ct_start = fin.tell()
        ct_total = total - ct_start

        key = derive_key(password.encode('utf-8'), salt, key_len=key_len)

        # Create decryptor with supplied tag
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()

        processed = 0
        with open(out_path, 'wb') as fout:
            # read ciphertext in chunks from fin
            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break
                pt = decryptor.update(chunk)
                if pt:
                    fout.write(pt)
                processed += len(chunk)
                if progress_callback:
                    progress_callback(processed, ct_total)
            # finalize - this will raise if tag invalid (tampered or wrong password)
            final = decryptor.finalize()
            if final:
                fout.write(final)

        if progress_callback:
            progress_callback(ct_total, ct_total)

# ---- Utility folder processing ----
def gather_files_for_encryption(folder_path: str):
    # We'll encrypt regular files only (skip directories)
    files = []
    for root, dirs, filenames in os.walk(folder_path):
        for fn in filenames:
            full = os.path.join(root, fn)
            files.append(full)
    return files

def gather_files_for_decryption(folder_path: str):
    # We'll try to decrypt files with .enc extension OR files that match MAGIC on read
    files = []
    for root, dirs, filenames in os.walk(folder_path):
        for fn in filenames:
            full = os.path.join(root, fn)
            files.append(full)
    return files

# ---- GUI Application ----
class AESGuiApp:
    def __init__(self, master):
        self.master = master
        master.title("AES-GCM File Encryptor/Decryptor (128/256)")
        master.geometry("640x420")
        master.resizable(False, False)

        self.path_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.mode_var = tk.StringVar(value="file")  # 'file' or 'folder'
        self.keysize_var = tk.IntVar(value=128)  # 128 or 256
        self.status_var = tk.StringVar(value="Ready.")
        self.progress_var = tk.DoubleVar(value=0.0)

        self._build_ui()
        if DND_AVAILABLE:
            self._enable_dnd()

        # lock to prevent double-run
        self._running = False

    def _build_ui(self):
        frm = ttk.Frame(self.master, padding=10)
        frm.pack(fill="both", expand=True)

        # Path selection
        ttk.Label(frm, text="File / Folder:").grid(row=0, column=0, sticky="w")
        entry = ttk.Entry(frm, textvariable=self.path_var, width=60)
        entry.grid(row=1, column=0, columnspan=3, padx=(0,10), sticky="w")
        ttk.Button(frm, text="Browse File", command=self.browse_file).grid(row=1, column=3, sticky="w")
        ttk.Button(frm, text="Browse Folder", command=self.browse_folder).grid(row=1, column=4, sticky="w", padx=(5,0))

        # Mode radio
        ttk.Radiobutton(frm, text="Single File", variable=self.mode_var, value="file").grid(row=2, column=0, sticky="w", pady=(8,0))
        ttk.Radiobutton(frm, text="Folder (recursive)", variable=self.mode_var, value="folder").grid(row=2, column=1, sticky="w", pady=(8,0))

        # Password
        ttk.Label(frm, text="Password:").grid(row=3, column=0, sticky="w", pady=(10,0))
        ttk.Entry(frm, textvariable=self.password_var, show="*", width=40).grid(row=4, column=0, columnspan=2, sticky="w")

        # Keysize (128 / 256)
        ttk.Label(frm, text="AES Key Size:").grid(row=3, column=2, sticky="w", pady=(10,0))
        ttk.Radiobutton(frm, text="128-bit", variable=self.keysize_var, value=128).grid(row=4, column=2, sticky="w")
        ttk.Radiobutton(frm, text="256-bit", variable=self.keysize_var, value=256).grid(row=4, column=3, sticky="w")

        # Encrypt / Decrypt buttons
        ttk.Button(frm, text="Encrypt ▶", command=self._on_encrypt, width=12).grid(row=5, column=0, pady=(20,0))
        ttk.Button(frm, text="Decrypt ◀", command=self._on_decrypt, width=12).grid(row=5, column=1, pady=(20,0))

        # Progress bar and status
        self.progress = ttk.Progressbar(frm, orient="horizontal", length=520, mode="determinate", variable=self.progress_var)
        self.progress.grid(row=6, column=0, columnspan=5, pady=(20,0), sticky="w")
        ttk.Label(frm, textvariable=self.status_var).grid(row=7, column=0, columnspan=5, pady=(8,0), sticky="w")

        # Instructions / small help
        help_text = "Tip: You can drag & drop files onto the window (if tkinterdnd2 is installed).\n" \
                    "Folder mode will process all files under the selected folder recursively.\n" \
                    "Encrypted files have header and .enc suffix appended automatically for single files."
        ttk.Label(frm, text=help_text, wraplength=620, foreground="gray").grid(row=8, column=0, columnspan=5, pady=(12,0), sticky="w")

    def _enable_dnd(self):
        # If tkinterdnd2 is available, wrap the root as TkinterDnD.Tk and bind drop
        try:
            # We assume the provided master is already a Tk or TkinterDnD.Tk
            # Bind to the main window drop
            self.master.drop_target_register(DND_FILES)
            self.master.dnd_bind('<<Drop>>', self._on_drop)
            self.status_var.set("Drag & drop enabled.")
        except Exception:
            # if anything fails, ignore
            self.status_var.set("Drag & drop unavailable (tkinterdnd2 import succeeded but binding failed).")

    def _on_drop(self, event):
        """Handle dropped files: event.data may contain a list of paths."""
        try:
            data = event.data
            # tkinterdnd2 returns a string with file paths; split by space unless path contains spaces with braces
            # We'll attempt a simple parse: if it's wrapped in { } it's one path with spaces.
            if data.startswith("{") and data.endswith("}"):
                # possibly multiple braced entries; split on }{
                parts = []
                cur = ""
                i = 0
                while i < len(data):
                    if data[i] == "{":
                        j = data.find("}", i)
                        if j == -1:
                            break
                        parts.append(data[i+1:j])
                        i = j+1
                    else:
                        i += 1
                if parts:
                    self.path_var.set(parts[0])
                else:
                    self.path_var.set(data)
            else:
                # simple split
                p = data.split()
                self.path_var.set(p[0])
            self.status_var.set("Path set from drop.")
        except Exception:
            self.status_var.set("Drop failed to parse path.")

    def browse_file(self):
        p = filedialog.askopenfilename()
        if p:
            self.path_var.set(p)
            self.mode_var.set("file")
            self.status_var.set("File selected.")

    def browse_folder(self):
        p = filedialog.askdirectory()
        if p:
            self.path_var.set(p)
            self.mode_var.set("folder")
            self.status_var.set("Folder selected.")

    # ---- Buttons callback ----
    def _on_encrypt(self):
        if self._running:
            messagebox.showinfo("Busy", "Another operation is running. Please wait.")
            return
        path = self.path_var.get().strip()
        pw = self.password_var.get()
        if not path or not pw:
            messagebox.showwarning("Missing", "Please provide a path and password.")
            return
        mode = self.mode_var.get()
        key_len = 16 if self.keysize_var.get() == 128 else 32
        if mode == "file":
            if not os.path.isfile(path):
                messagebox.showerror("Error", "Selected path is not a file.")
                return
            out = path + ".enc"
            t = threading.Thread(target=self._run_encrypt_file, args=(path, out, pw, key_len), daemon=True)
            t.start()
        else:
            if not os.path.isdir(path):
                messagebox.showerror("Error", "Selected path is not a folder.")
                return
            t = threading.Thread(target=self._run_encrypt_folder, args=(path, pw, key_len), daemon=True)
            t.start()

    def _on_decrypt(self):
        if self._running:
            messagebox.showinfo("Busy", "Another operation is running. Please wait.")
            return
        path = self.path_var.get().strip()
        pw = self.password_var.get()
        if not path or not pw:
            messagebox.showwarning("Missing", "Please provide a path and password.")
            return
        mode = self.mode_var.get()
        key_len = 16 if self.keysize_var.get() == 128 else 32
        if mode == "file":
            if not os.path.isfile(path):
                messagebox.showerror("Error", "Selected path is not a file.")
                return
            # default out path for single file: remove .enc or append _decrypted
            if path.endswith(".enc"):
                out = path[:-4] + "_decrypted"
            else:
                out = path + "_decrypted"
            t = threading.Thread(target=self._run_decrypt_file, args=(path, out, pw, key_len), daemon=True)
            t.start()
        else:
            if not os.path.isdir(path):
                messagebox.showerror("Error", "Selected path is not a folder.")
                return
            t = threading.Thread(target=self._run_decrypt_folder, args=(path, pw, key_len), daemon=True)
            t.start()

    # ---- Worker wrappers ----
    def _run_encrypt_file(self, in_path, out_path, pw, key_len):
        try:
            self._set_running(True)
            self._set_status(f"Encrypting file: {in_path} ...")
            self._set_progress(0.0)
            def pc(processed, total):
                self.master.after(0, lambda: self._update_progress(processed, total))
            encrypt_stream(in_path, out_path, pw, key_len, progress_callback=pc)
            self._set_status(f"Encrypted: {out_path}")
            messagebox.showinfo("Done", f"Encrypted file saved to:\n{out_path}")
        except Exception as e:
            traceback.print_exc()
            messagebox.showerror("Encryption Error", f"{e}")
            self._set_status("Encryption failed.")
        finally:
            self._set_running(False)

    def _run_decrypt_file(self, in_path, out_path, pw, key_len):
        try:
            self._set_running(True)
            self._set_status(f"Decrypting file: {in_path} ...")
            self._set_progress(0.0)
            def pc(processed, total):
                self.master.after(0, lambda: self._update_progress(processed, total))
            decrypt_stream(in_path, out_path, pw, key_len, progress_callback=pc)
            self._set_status(f"Decrypted: {out_path}")
            messagebox.showinfo("Done", f"Decrypted file saved to:\n{out_path}")
        except Exception as e:
            traceback.print_exc()
            messagebox.showerror("Decryption Error", f"{e}")
            self._set_status("Decryption failed.")
        finally:
            self._set_running(False)

    def _run_encrypt_folder(self, folder_path, pw, key_len):
        try:
            self._set_running(True)
            files = gather_files_for_encryption(folder_path)
            if not files:
                messagebox.showinfo("No files", "No files found in folder.")
                return
            self._set_status(f"Encrypting {len(files)} files...")
            for idx, fpath in enumerate(files, 1):
                # skip if directory etc.
                if not os.path.isfile(fpath):
                    continue
                outp = fpath + ".enc"
                self._set_status(f"Encrypting ({idx}/{len(files)}): {fpath}")
                def pc(processed, total):
                    self.master.after(0, lambda: self._update_progress(processed, total, prefix=f"File {idx}/{len(files)}"))
                try:
                    encrypt_stream(fpath, outp, pw, key_len, progress_callback=pc)
                except Exception as e:
                    # continue processing other files but report
                    traceback.print_exc()
                    self.master.after(0, lambda e=e, p=fpath: messagebox.showwarning("File failed", f"Failed to encrypt {p}: {e}"))
                # small pause to update UI
            self._set_status("Folder encryption complete.")
            messagebox.showinfo("Done", "Folder encryption complete.")
        finally:
            self._set_running(False)
            self._set_progress(0.0)

    def _run_decrypt_folder(self, folder_path, pw, key_len):
        try:
            self._set_running(True)
            files = gather_files_for_decryption(folder_path)
            if not files:
                messagebox.showinfo("No files", "No files found in folder.")
                return
            self._set_status(f"Decrypting {len(files)} files...")
            for idx, fpath in enumerate(files, 1):
                if not os.path.isfile(fpath):
                    continue
                # Attempt to detect format quickly by reading magic (safe small read)
                try:
                    with open(fpath, 'rb') as fh:
                        magic = fh.read(len(MAGIC))
                    if magic != MAGIC:
                        # Skip non-matching files when folder decrypt mode
                        continue
                except Exception:
                    continue

                outp = None
                if fpath.endswith(".enc"):
                    outp = fpath[:-4] + "_decrypted"
                else:
                    outp = fpath + "_decrypted"

                self._set_status(f"Decrypting ({idx}/{len(files)}): {fpath}")
                def pc(processed, total):
                    self.master.after(0, lambda: self._update_progress(processed, total, prefix=f"File {idx}/{len(files)}"))
                try:
                    decrypt_stream(fpath, outp, pw, key_len, progress_callback=pc)
                except Exception as e:
                    traceback.print_exc()
                    self.master.after(0, lambda e=e, p=fpath: messagebox.showwarning("File failed", f"Failed to decrypt {p}: {e}"))
            self._set_status("Folder decryption complete.")
            messagebox.showinfo("Done", "Folder decryption complete.")
        finally:
            self._set_running(False)
            self._set_progress(0.0)

    # ---- UI helpers ----
    def _set_running(self, val: bool):
        self._running = val
        # optionally disable widgets when running (not implemented to keep code short)

    def _set_status(self, txt: str):
        self.master.after(0, lambda: self.status_var.set(txt))

    def _set_progress(self, val: float):
        self.master.after(0, lambda: self.progress_var.set(val))

    def _update_progress(self, processed, total, prefix=None):
        if total == 0:
            percent = 100.0
        else:
            percent = (processed / total) * 100.0
        self.progress_var.set(percent)
        if prefix:
            self.status_var.set(f"{prefix}: {processed}/{total} bytes ({percent:.1f}%)")
        else:
            self.status_var.set(f"{processed}/{total} bytes ({percent:.1f}%)")

# ---- Run app ----
def main():
    # If tkinterdnd2 is available, create TkinterDnD.Tk; otherwise regular Tk
    if DND_AVAILABLE:
        try:
            root = TkinterDnD.Tk()
        except Exception:
            root = tk.Tk()
    else:
        root = tk.Tk()

    app = AESGuiApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
