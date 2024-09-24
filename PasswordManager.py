import tkinter as tk
from tkinter import ttk, messagebox
import json
import hashlib
import base64
import binascii
from urllib.parse import quote, unquote
from cryptography.fernet import Fernet

# Generate a key for encryption
def generate_key():
    return Fernet.generate_key()

# Encrypt a message
def encrypt_message(message, key):
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message.decode()

# Decrypt a message
def decrypt_message(encrypted_message, key):
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message.encode())
    return decrypted_message.decode()

# Function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Load and save password data
def load_passwords(filename="passwords.json", encryption_key=None):
    try:
        with open(filename, "r") as file:
            data = json.load(file)
        if encryption_key:
            for item in data:
                item['password'] = decrypt_message(item['encrypted'], encryption_key)
                item['encoded'] = decrypt_message(item['encoded'], encryption_key)
        return data
    except FileNotFoundError:
        return []

def save_passwords(passwords, filename="passwords.json", encryption_key=None):
    if encryption_key:
        for item in passwords:
            item['encrypted'] = encrypt_message(item['password'], encryption_key)
            item['encoded'] = encrypt_message(item['encoded'], encryption_key)
            del item['password']
    with open(filename, "w") as file:
        json.dump(passwords, file, indent=4)

# Encoding and decoding passwords
def encode_password(password, method):
    if method == 'Base64':
        return base64.b64encode(password.encode()).decode()
    elif method == 'Hex':
        return binascii.hexlify(password.encode()).decode()
    elif method == 'Rot13':
        return password.translate(str.maketrans(
            "ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz",
            "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm"))
    elif method == 'URL':
        return quote(password)
    elif method == 'ASCII85':
        return base64.a85encode(password.encode()).decode()
    return password

def decode_password(encoded_password, method):
    if method == 'Base64':
        return base64.b64decode(encoded_password.encode()).decode()
    elif method == 'Hex':
        return binascii.unhexlify(encoded_password.encode()).decode()
    elif method == 'Rot13':
        return encoded_password.translate(str.maketrans(
            "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm",
            "ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz"))
    elif method == 'URL':
        return unquote(encoded_password)
    elif method == 'ASCII85':
        return base64.a85decode(encoded_password.encode()).decode()
    return encoded_password

# Main application class
class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Password Manager")
        self.encryption_key = None  # Placeholder for encryption key
        self.setup_styles()
        self.setup_login_ui()

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TFrame', background='#333')
        self.style.configure('TLabel', background='#333', foreground='#DDD')
        self.style.configure('TEntry', background='#555', foreground='#DDD', fieldbackground='#555')
        self.style.configure('TButton', background='#555', foreground='#DDD')
        self.style.configure('TListbox', background='#555', foreground='#DDD')
        self.root.configure(background='#333')

    def setup_login_ui(self):
        self.frame = ttk.Frame(self.root)
        self.frame.pack(pady=20)
        ttk.Label(self.frame, text="Enter Master Password:").grid(row=0, column=0)
        self.password_entry = ttk.Entry(self.frame, show='*')
        self.password_entry.grid(row=0, column=1)
        self.password_entry.bind("<Return>", lambda e: self.login())
        ttk.Button(self.frame, text="Login", command=self.login).grid(row=1, columnspan=2)
        self.msg_label = ttk.Label(self.root, text="")
        self.msg_label.pack()

    def login(self):
        entered_password = self.password_entry.get()
        if hash_password(entered_password) == hash_password(""):                #Manual Code insert for Master Password, First time setup with password creation to be implimented at a later time
            self.encryption_key = generate_key()
            self.passwords = load_passwords(encryption_key=self.encryption_key)
            self.setup_password_manager_ui()
        else:
            messagebox.showerror("Error", "Incorrect password!")

    def setup_password_manager_ui(self):
        self.frame.destroy()
        self.manager_frame = ttk.Frame(self.root)
        self.manager_frame.pack(pady=20)
        ttk.Label(self.manager_frame, text="Password Label:").grid(row=0, column=0)
        self.label_entry = ttk.Entry(self.manager_frame)
        self.label_entry.grid(row=0, column=1)
        ttk.Label(self.manager_frame, text="Password:").grid(row=1, column=0)
        self.password_entry = ttk.Entry(self.manager_frame)
        self.password_entry.grid(row=1, column=1)
        self.password_entry.bind("<Return>", lambda e: self.add_password())
        ttk.Label(self.manager_frame, text="Encoding Method:").grid(row=2, column=0)
        self.method_combo = ttk.Combobox(self.manager_frame, values=['Base64', 'Hex', 'Rot13', 'URL', 'ASCII85'])
        self.method_combo.grid(row=2, column=1)
        self.method_combo.set('Base64')
        ttk.Button(self.manager_frame, text="Add Password", command=self.add_password).grid(row=3, columnspan=2)
        self.password_listbox = tk.Listbox(self.root, height=10, width=50)
        self.password_listbox.pack(pady=20)
        self.populate_listbox()
        self.menu = tk.Menu(self.root, tearoff=0)
        self.menu.add_command(label="Edit", command=self.edit_password)
        self.menu.add_command(label="Delete", command=self.delete_password)
        self.password_listbox.bind("<Button-3>", self.show_menu)

    def populate_listbox(self):
        self.password_listbox.delete(0, tk.END)
        for item in self.passwords:
            display_text = f"{item['label']}: {decrypt_message(item['encoded'], self.encryption_key)} ({item['method']})"
            self.password_listbox.insert(tk.END, display_text)

    def add_password(self):
        label = self.label_entry.get()
        password = self.password_entry.get()
        method = self.method_combo.get()
        encoded = encode_password(password, method)
        self.passwords.append({'label': label, 'password': password, 'encoded': encoded, 'method': method})
        save_passwords(self.passwords, encryption_key=self.encryption_key)
        self.populate_listbox()

    def show_menu(self, event):
        try:
            self.menu.selection = self.password_listbox.curselection()[0]
            self.menu.post(event.x_root, event.y_root)
        except IndexError:
            pass

    def edit_password(self):
        index = self.menu.selection
        item = self.passwords[index]
        edit_window = tk.Toplevel(self.root)
        edit_window.title("Edit Password")
        ttk.Label(edit_window, text="Label:").grid(row=0, column=0)
        label_entry = ttk.Entry(edit_window)
        label_entry.insert(0, item['label'])
        label_entry.grid(row=0, column=1)
        ttk.Label(edit_window, text="Password:").grid(row=1, column=0)
        password_entry = ttk.Entry(edit_window)
        decrypted_password = decrypt_message(item['encoded'], self.encryption_key)
        password_entry.insert(0, decrypted_password)
        password_entry.grid(row=1, column=1)
        ttk.Label(edit_window, text="Encoding Method:").grid(row=2, column=0)
        method_combo = ttk.Combobox(edit_window, values=['Base64', 'Hex', 'Rot13', 'URL', 'ASCII85'])
        method_combo.set(item['method'])
        method_combo.grid(row=2, column=1)
        ttk.Button(edit_window, text="Save Changes", command=lambda: self.save_edited_password(index, label_entry, password_entry, method_combo, edit_window)).grid(row=3, columnspan=2)

    def save_edited_password(self, index, label_entry, password_entry, method_combo, edit_window):
        self.passwords[index]['label'] = label_entry.get()
        self.passwords[index]['password'] = password_entry.get()
        self.passwords[index]['encoded'] = encode_password(password_entry.get(), method_combo.get())
        self.passwords[index]['method'] = method_combo.get()
        save_passwords(self.passwords, encryption_key=self.encryption_key)
        self.populate_listbox()
        edit_window.destroy()

    def delete_password(self):
        index = self.menu.selection
        del self.passwords[index]
        save_passwords(self.passwords, encryption_key=self.encryption_key)
        self.populate_listbox()

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
