import os
import tkinter as tk
import requests
import random
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization

server_url = "http://localhost:5000"
KEY_FILE = "client_private_key.pem"

# Load or generate Client's DSA Private Key and save/load from file
if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as key_file:
        client_private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
else:
    client_private_key = dsa.generate_private_key(key_size=2048)
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(
            client_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
client_public_key = client_private_key.public_key()

root = tk.Tk()
root.title("Banking System")

# Registration Frame
register_frame = tk.Frame(root)
register_frame.pack()

tk.Label(register_frame, text="New Username:").grid(row=0, column=0)
new_username_entry = tk.Entry(register_frame)
new_username_entry.grid(row=0, column=1)

tk.Label(register_frame, text="New Password:").grid(row=1, column=0)
new_password_entry = tk.Entry(register_frame, show="*")
new_password_entry.grid(row=1, column=1)

def register():
    new_username = new_username_entry.get()
    new_password = new_password_entry.get()
    # Serialize public key to PEM format
    public_key_pem = client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    response = requests.post(
        f"{server_url}/register",
        json={
            "username": new_username,
            "password": new_password,
            "public_key": public_key_pem
        }
    )
    result = response.json()
    if result["status"] == "Success":
        tk.Label(register_frame, text="Registration Successful!", fg="green").grid(row=2, columnspan=2)
    else:
        tk.Label(register_frame, text="Registration Failed", fg="red").grid(row=2, columnspan=2)

tk.Button(register_frame, text="Register", command=register).grid(row=3, columnspan=2)

# Login Frame
login_frame = tk.Frame(root)
login_frame.pack()

tk.Label(login_frame, text="Username:").grid(row=0, column=0)
username_entry = tk.Entry(login_frame)
username_entry.grid(row=0, column=1)

tk.Label(login_frame, text="Password:").grid(row=1, column=0)
password_entry = tk.Entry(login_frame, show="*")
password_entry.grid(row=1, column=1)

def login():
    username = username_entry.get()
    password = password_entry.get()
    response = requests.post(f"{server_url}/login", json={"username": username, "password": password})
    result = response.json()
    
    if result["status"] == "Success":
        login_frame.pack_forget()
        open_dashboard(username)
    else:
        tk.Label(login_frame, text="Login Failed", fg="red").grid(row=2, columnspan=2)

tk.Button(login_frame, text="Login", command=login).grid(row=3, columnspan=2)

# Dashboard
def open_dashboard(username):
    dashboard_frame = tk.Frame(root)
    dashboard_frame.pack()
    
    tk.Label(dashboard_frame, text=f"Welcome, {username}").pack()

    balance_var = tk.StringVar()
    balance_label = tk.Label(dashboard_frame, textvariable=balance_var)
    balance_label.pack()

    def fetch_balance():
        response = requests.post(f"{server_url}/balance", json={"username": username})
        result = response.json()
        if result["status"] == "Success":
            balance_var.set(f"Current Balance: {result['balance']}")
        else:
            balance_var.set("Balance: Error")

    def transfer():
        receiver = receiver_entry.get()
        amount = amount_entry.get()
        transaction_id = random.randint(100000, 999999)
        transaction_data = f"{username}-{receiver}-{amount}-{transaction_id}"
        signature = client_private_key.sign(transaction_data.encode(), hashes.SHA256())

        response = requests.post(f"{server_url}/transfer_currency", json={
            "sender": username,
            "receiver": receiver,
            "amount": amount,
            "transaction_id": transaction_id,
            "signature": signature.hex()
        })
        
        transfer_result.config(text=response.json()["message"])
        fetch_balance()  # Update balance after transfer

    tk.Label(dashboard_frame, text="Transfer To:").pack()
    receiver_entry = tk.Entry(dashboard_frame)
    receiver_entry.pack()

    tk.Label(dashboard_frame, text="Amount:").pack()
    amount_entry = tk.Entry(dashboard_frame)
    amount_entry.pack()

    tk.Button(dashboard_frame, text="Transfer", command=transfer).pack()
    transfer_result = tk.Label(dashboard_frame, text="")
    transfer_result.pack()
    tk.Button(dashboard_frame, text="Reload", command=fetch_balance).pack()
    

    fetch_balance()  # Show balance on dashboard open

root.mainloop()