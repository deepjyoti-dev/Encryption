🔐 AES-GCM File Encryptor/Decryptor GUI

A Python-based GUI tool for secure AES-GCM encryption and decryption of large files or folders.
Supports streaming, password-derived keys (PBKDF2), and progress tracking in a responsive Tkinter interface.

✨ Features

⚡ AES-GCM Streaming Encryption: Encrypts large files efficiently in 64 KB chunks

🔑 Password-Derived Keys: PBKDF2 with SHA-256; supports 128-bit or 256-bit keys

📁 Folder & Single File Support: Encrypt/decrypt entire folders recursively

🖥️ GUI Interface: Tkinter GUI with browse buttons, progress bar, and status messages

🖱️ Optional Drag & Drop: If tkinterdnd2 is installed

🛡️ Safe Encrypted Format:

MAGIC(8) | salt(16) | nonce(12) | tag(16) | ciphertext...


Ensures integrity and easy detection of encrypted files

🧵 Responsive UI: Threaded processing to prevent freezing during large file operations

🔧 Installation

Clone the repository:

git clone https://github.com/yourusername/aes-gui-encryptor.git
cd aes-gui-encryptor


Install dependencies:

pip install cryptography tk


Optional (for drag & drop support):

pip install tkinterdnd2


Run the application:

python aes_gui_encryptor.py

🛠️ Usage
Single File Mode

Select Single File

Browse for the file

Enter a password

Select AES key size (128-bit / 256-bit)

Click Encrypt ▶ or Decrypt ◀

Output: .enc for encrypted, _decrypted appended for decrypted

Folder Mode

Select Folder (recursive)

Browse for folder

Enter password & key size

Click Encrypt ▶ or Decrypt ◀

All regular files processed recursively; non-encrypted files skipped during decryption

Drag & Drop

Drag files/folders onto GUI if tkinterdnd2 is installed

🧠 Technical Details

Streaming Encryption: Handles large files efficiently

Key Derivation: PBKDF2 with SHA-256

Encrypted File Structure: MAGIC | SALT | NONCE | TAG | CIPHERTEXT

Threaded GUI: Keeps interface responsive

Folder Processing: Recursive encryption/decryption

⚠️ Notes

Encrypted files are platform-independent

Keep passwords safe — exact password required for decryption

Use folder mode carefully; non-encrypted files are skipped during decryption

🏷️ Tags

#python #tkinter #gui #encryption #aes-gcm #cryptography #file-security

🧑‍💻 Author

Deepjyoti Das
🔗 https://www.linkedin.com/in/deepjyotidas1

💻 GitHub
