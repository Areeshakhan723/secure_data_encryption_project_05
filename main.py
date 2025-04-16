# Import required libraries
import streamlit as st
import json
from cryptography.fernet import Fernet
import hashlib
import time    
from hashlib import pbkdf2_hmac
from base64 import urlsafe_b64encode
import os

# === Security Configuration ===
DATA_FILE = "secure_data.json"  # File to store encrypted data
SALT = b"secure_salt_value"    # Cryptographic salt (should be kept secret)
LOCKOUT_TIME_DURATION = 60     # Lockout duration after failed attempts (seconds)

# === User Session Management ===
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None  # Track logged-in user

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0  # Track failed login attempts

if "lockout_time" not in st.session_state:      
    st.session_state.lockout_time = 0  # Track lockout expiration time

# === Data Management Functions ===
def load_data():
    """Load encrypted data from file"""
    try:
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, "r") as f:
             return json.load(f)
    except json.JSONDecodeError:
            return {}  # Handle empty or corrupted file        
    return {}

def save_data(data):
    """Save data to file"""
    with open(DATA_FILE,"w") as f:
        json.dump(data, f, indent=4)

# === Cryptographic Functions ===
def generate_key(passkey):
    """Generate encryption key from passkey"""
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    """Create secure password hash"""
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def encrypt_data(text, key):
    """Encrypt text using provided key"""
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_data, key):
    """Decrypt data using provided key"""
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_data.encode()).decode()
    except:
        return None  # Returns None if decryption fails

# Load existing data
stored_data = load_data()     

# === Application UI ===
st.set_page_config(page_title="Secure Data Encryption System", page_icon="🔒")
st.title("🔒 Your Personal Secure Vault")

# Navigation menu
menu = ["Home", "Register", "Login","Logout", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Select an option", menu)

# === Page Handlers ===
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    st.write(
        """    
            **Features:**
            - 🔐 Military-grade AES-128 encryption
            - 🔑 Passkey-protected data
            - 🛡️ Brute-force protection
            - 💾 Secure cloud storage
            
            **How to use:**
            1. Register an account
            2. Login to your vault
            3. Store sensitive data
            4. Retrieve when needed
        """
    )   

elif choice == "Register":
    """User registration"""
    st.subheader("📝 Register a New User")  
    user_name = st.text_input("Enter a user name:")
    password = st.text_input("Enter a password:", type="password")

    if st.button("Register"):
        if user_name and password:
            if user_name in stored_data:
                st.warning("⚠️User already exists")
            else:
                # Store hashed password and empty data list
                stored_data[user_name] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("✅ Registration successful!")

elif choice == "Login":
    """User authentication"""
    st.subheader("🔑 User Login")
    
    # Check if user is temporarily locked out
    if time.time() < st.session_state.lockout_time:
        remaining_time = st.session_state.lockout_time - time.time()
        st.error(f"🚫 Account locked. Try again in {int(remaining_time)} seconds.")
        st.stop()

    user_name = st.text_input("Enter your username:")
    password = st.text_input("Enter your password:", type="password")

    if st.button("Login"):
        # Verify credentials
        if user_name in stored_data and stored_data[user_name]["password"] == hash_password(password):
            st.session_state.authenticated_user = user_name
            st.session_state.failed_attempts = 0  # Reset counter
            st.success(f"✅ Welcome {user_name}!")
        else:
            # Handle failed attempt
            st.session_state.failed_attempts += 1
            remaining_attempts = 3 - st.session_state.failed_attempts
            st.error(f"🚫 Invalid credentials. Attempts left: {remaining_attempts}")

            # Lock account after 3 failures
            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_TIME_DURATION
                st.error("🚫 Account locked for 60 seconds.")
                st.stop()

elif choice == "Store Data":
    """Data encryption and storage"""
    if not st.session_state.authenticated_user:
        st.warning("🔒 Please login first")
    else:
        st.subheader("📂 Store Data Securely")
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Encrypt and Save"):
            if data and passkey:
                # Encrypt and store data
                encrypted = encrypt_data(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("✅ Data saved successfully!")

elif choice == "Retrieve Data":
    """Data decryption and retrieval"""
    if not st.session_state.authenticated_user:
        st.warning("🔒 Please login first")
    else:
        st.subheader("🔍 Retrieve Your Data")  
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("ℹ️ No stored data found")
        else:
            # Display all encrypted entries
            st.write("🔐 Your encrypted data:") 
            for item in user_data:
                st.code(item, language="text")

            # Decryption interface
            encrypted_input = st.text_area("Enter Encrypted Text")
            passkey = st.text_input("Enter Passkey to Decrypt", type="password")

            if st.button("Decrypt"):
                if encrypted_input and passkey:
                    result = decrypt_data(encrypted_input, passkey)
                    if result:
                        st.success(f"✅ Decrypted: {result}")
                    else:
                        st.error("❌ Decryption failed - wrong passkey?")

elif choice == "Logout":
    if st.session_state.authenticated_user:
        username = st.session_state.authenticated_user
        st.session_state.authenticated_user = None
        st.success(f"Logged out successfully. Goodbye, {username}!")
        time.sleep(1)
    else:
        st.warning("You are not currently logged in")
