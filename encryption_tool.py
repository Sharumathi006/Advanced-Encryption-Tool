import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog

# Key Derivation from password
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Encrypt a file
def encrypt_file(filepath: str, password: str):
    with open(filepath, 'rb') as file:
        data = file.read()

    salt = os.urandom(16)
    key = derive_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(data)

    with open(filepath + '.enc', 'wb') as file:
        file.write(salt + encrypted_data)

# Decrypt a file
def decrypt_file(filepath: str, password: str):
    with open(filepath, 'rb') as file:
        content = file.read()

    salt = content[:16]
    encrypted_data = content[16:]

    key = derive_key(password, salt)
    f = Fernet(key)

    try:
        decrypted_data = f.decrypt(encrypted_data)
        new_path = filepath.replace('.enc', '')
        with open(new_path, 'wb') as file:
            file.write(decrypted_data)
        messagebox.showinfo("Success", "File decrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", "Incorrect password or corrupted file.")

# GUI setup
def encrypt_gui():
    filepath = filedialog.askopenfilename()
    if filepath:
        password = simpledialog.askstring("Password", "Enter password for encryption:", show='*')
        if password:
            encrypt_file(filepath, password)
            messagebox.showinfo("Success", "File encrypted successfully!")

def decrypt_gui():
    filepath = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
    if filepath:
        password = simpledialog.askstring("Password", "Enter password to decrypt:", show='*')
        if password:
            decrypt_file(filepath, password)

# GUI main window
root = tk.Tk()
root.title("Advanced Encryption Tool (AES-256)")
root.geometry("400x200")

label = tk.Label(root, text="Select an action below:", font=('Helvetica', 14))
label.pack(pady=20)

encrypt_button = tk.Button(root, text="Encrypt File", command=encrypt_gui, width=20, bg="green", fg="white")
encrypt_button.pack(pady=10)

decrypt_button = tk.Button(root, text="Decrypt File", command=decrypt_gui, width=20, bg="blue", fg="white")
decrypt_button.pack(pady=10)

root.mainloop()
