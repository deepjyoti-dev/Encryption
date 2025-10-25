# Encryption
# AES-GCM File Encryptor/Decryptor GUI

A Python-based GUI tool for secure **AES-GCM encryption and decryption** of large files or folders. Supports streaming, password-derived keys (PBKDF2), and progress tracking in a responsive Tkinter interface.

---

## Features

- **AES-GCM Streaming Encryption:** Encrypts large files efficiently in chunks (64 KB per chunk).
- **Password-Derived Keys:** PBKDF2 with SHA-256; supports 128-bit or 256-bit keys.
- **Folder & Single File Support:** Encrypt/decrypt entire folders recursively.
- **GUI Interface:** Tkinter GUI with browse buttons, progress bar, and status messages.
- **Optional Drag & Drop:** Supports drag & drop if `tkinterdnd2` is installed.
- **Safe Encrypted Format:**  
  `MAGIC(8) | salt(16) | nonce(12) | tag(16) | ciphertext...`  
  Ensures integrity and easy detection of encrypted files.
- **Responsive UI:** Uses threading to prevent the interface from freezing during processing.

---

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/aes-gui-encryptor.git
    cd aes-gui-encryptor
    ```

2. Install required dependencies:
    ```bash
    pip install cryptography tk
    ```
    Optional (for drag & drop support):
    ```bash
    pip install tkinterdnd2
    ```

3. Run the application:
    ```bash
    python aes_gui_encryptor.py
    ```

---

## Usage

### Single File
1. Select **Single File** mode.
2. Browse for the file to encrypt/decrypt.
3. Enter a password.
4. Select AES key size (128-bit or 256-bit).
5. Click **Encrypt ▶** or **Decrypt ◀**.
6. Encrypted files get a `.enc` extension; decrypted files get `_decrypted` appended.

### Folder Mode
1. Select **Folder (recursive)** mode.
2. Browse for the folder.
3. Enter a password and key size.
4. Click **Encrypt ▶** or **Decrypt ◀**.
5. All files in the folder (recursively) will be processed; non-encrypted files are skipped during decryption.

### Drag & Drop
- If `tkinterdnd2` is installed, you can drag files or folders directly onto the GUI window.

---

## Technical Details

- **Streaming Encryption:** AES-GCM with chunked reads/writes to handle large files.
- **Key Derivation:** PBKDF2 with configurable key length (128-bit / 256-bit).
- **Encrypted File Structure:**  
  `MAGIC | SALT | NONCE | TAG | CIPHERTEXT`
- **Threaded GUI:** Ensures the UI remains responsive while processing large files.
- **Folder Processing:** Recursively encrypts/decrypts all regular files in a directory.

---

## Notes

- Encrypted files are platform-independent and can be transferred securely.
- Ensure passwords are kept safe; decryption requires the exact password.
- Use folder mode with care; non-encrypted files will be skipped during decryption.

---

## License

This project is licensed under the MIT License. See `LICENSE` for details.

---

## Screenshots

*(Add GUI screenshots here to showcase interface, progress bar, and file selection)*

---

## Acknowledgments

- Python `tkinter` for GUI.
- `cryptography` library for secure AES-GCM encryption.
- Inspired by best practices for secure streaming encryption of large files.
