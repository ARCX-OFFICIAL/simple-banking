from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization
import hashlib

app = Flask(__name__)

# Simulated Database
users = {}  # {"username": {"password": hashed_password, "public_key": user_public_key}}
transactions = []  # Stores transactions
INITIAL_BALANCE = 50  # New accounts start with 50

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data["username"]
    password = hash_password(data["password"])
    public_key_pem = data.get("public_key")
    
    if username in users:
        return jsonify({"status": "Failure", "message": "Username already exists"})
    
    # Load public key from PEM
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
    except Exception as e:
        return jsonify({"status": "Failure", "message": "Invalid public key"})
    
    users[username] = {"password": password, "public_key": public_key}
    # Give initial balance by creating a "system" transaction
    transactions.append({"sender": "SYSTEM", "receiver": username, "amount": INITIAL_BALANCE, "transaction_id": f"init_{username}"})
    
    return jsonify({"status": "Success", "message": "Account created!"})

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data["username"]
    password = hash_password(data["password"])
    
    if username not in users or users[username]["password"] != password:
        return jsonify({"status": "Failure", "message": "Invalid username or password"})
    
    return jsonify({"status": "Success", "message": "Login successful!"})

@app.route("/transfer_currency", methods=["POST"])
def transfer_currency():
    data = request.json
    sender = data["sender"]
    print(sender)
    receiver = data["receiver"]
    amount = data["amount"]
    transaction_id = data["transaction_id"]
    signature = bytes.fromhex(data["signature"])  # Convert back to bytes

    if sender not in users or receiver not in users:
        return jsonify({"status": "Failure", "message": "Invalid sender or receiver"})

    # Ensure identical encoding before verification
    transaction_data = f"{sender}-{receiver}-{amount}-{transaction_id}".encode()

    sender_public_key = users[sender]["public_key"]
    try:
        sender_public_key.verify(signature, transaction_data, hashes.SHA256())
    except Exception as e:
        return jsonify({"status": "Failure", "message": "Invalid signature"})

    # Check sender balance before allowing transfer
    sender_balance = 0
    for tx in transactions:
        if tx["receiver"] == sender:
            sender_balance += int(tx["amount"])
        if tx["sender"] == sender:
            sender_balance -= int(tx["amount"])
    if sender_balance < int(amount):
        return jsonify({"status": "Failure", "message": "Insufficient funds"})

    transactions.append({"sender": sender, "receiver": receiver, "amount": amount, "transaction_id": transaction_id})
    return jsonify({"status": "Success", "message": "Transaction successful!"})

@app.route("/balance", methods=["POST"])
def balance():
    data = request.json
    username = data["username"]
    if username not in users:
        return jsonify({"status": "Failure", "message": "Invalid username"})
    # Calculate balance: +amount for received, -amount for sent
    balance = 0
    for tx in transactions:
        if tx["receiver"] == username:
            balance += int(tx["amount"])
        if tx["sender"] == username:
            balance -= int(tx["amount"])
    return jsonify({"status": "Success", "balance": balance})

if __name__ == "__main__":
    app.run(port=5000, debug=True)