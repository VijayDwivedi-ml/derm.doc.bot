import streamlit as st
import sqlite3
from sqlite3 import Error
import bcrypt
import uuid
import re
from datetime import datetime
import time

# -------------------- Configuration --------------------

# Constants
DB_NAME = 'users.db'

# ------------------------------------------------------

# -------------------- Database Functions --------------------

def create_connection(db_file=DB_NAME):
    """Create a database connection to the SQLite database."""
    conn = None
    try:
        conn = sqlite3.connect(db_file, check_same_thread=False)
        return conn
    except Error as e:
        st.error(f"Error connecting to database: {e}")
    return conn

def initialize_db(conn):
    """Create users table if it doesn't exist."""
    cursor = conn.cursor()
    
    create_users_table = """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE COLLATE NOCASE,
        mobile TEXT NOT NULL,
        password TEXT,
        is_guest INTEGER DEFAULT 0,
        guest_number INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """
    try:
        cursor.execute(create_users_table)
        conn.commit()
    except Error as e:
        st.error(f"Error creating table: {e}")

def add_user(conn, full_name, email, mobile, password=None, is_guest=0, guest_number=None):
    """Add a new user to the users table."""
    try:
        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO users(full_name, email, mobile, password, is_guest, guest_number)
               VALUES (?, ?, ?, ?, ?, ?)''',
            (full_name, email, mobile, password, is_guest, guest_number)
        )
        conn.commit()
        return cursor.lastrowid
    except sqlite3.IntegrityError:
        st.error("Error: Email already exists.")
        return None
    except Error as e:
        st.error(f"Error adding user: {e}")
        return None

def get_user_by_email(conn, email):
    """Retrieve a user from the users table by email."""
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ? COLLATE NOCASE", (email.strip(),))
        return cursor.fetchone()
    except Error as e:
        st.error(f"Error retrieving user: {e}")
        return None

def get_guest_count(conn):
    """Get the current number of guests."""
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users WHERE is_guest = 1")
    return cursor.fetchone()[0]

def update_password(conn, email, new_password):
    """Update the user's password."""
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password = ? WHERE email = ? COLLATE NOCASE", 
                      (new_password, email.strip()))
        conn.commit()
        return True
    except Error as e:
        st.error(f"Error updating password: {e}")
        return False

# Initialize the database
conn = create_connection()
initialize_db(conn)

# -------------------- Utility Functions --------------------

def hash_password(password):
    """Hash a password using bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user."""
    try:
        return bcrypt.checkpw(
            provided_password.encode('utf-8'),
            stored_password.encode('utf-8')
        )
    except Exception as e:
        st.error(f"Error verifying password: {str(e)}")
        return False

def is_valid_email(email):
    """Validate email format."""
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return bool(re.match(pattern, email))

def is_valid_mobile(mobile):
    """Validate mobile number format."""
    pattern = r'^\d{10}$'
    return bool(re.match(pattern, mobile))

def is_password_strong(password):
    """Check if password meets minimum requirements."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    return True, "Password is strong"

def generate_reset_token():
    """Generate a unique token for password reset."""
    return str(uuid.uuid4())

def get_greeting():
    """Get time-based greeting."""
    hour = datetime.now().hour
    if 5 <= hour < 12:
        return "Good Morning"
    elif 12 <= hour < 17:
        return "Good Afternoon"
    else:
        return "Good Evening"

def back_to_main_button():
    """Display a button to return to the main page."""
    if st.sidebar.button("← Back to Main"):
        st.session_state.show_register = False
        st.session_state.show_forgot_password = False
        st.rerun()

# -------------------- UI Components --------------------

def create_welcome_dashboard(user):
    """Create a welcoming dashboard for logged-in users."""
    # Header with greeting
    st.title(f"{get_greeting()}, {user['full_name']}! 👋")
    
    # Dashboard layout
    col1, col2, col3 = st.columns([1, 1, 1])
    
    with col1:
        st.markdown("### 👤 Profile Information")
        st.markdown(f"**Name:** {user['full_name']}")
        st.markdown(f"**Email:** {user['email']}")
        st.markdown(f"**Mobile:** {user['mobile']}")
        if user['is_guest']:
            st.markdown(f"**Guest Number:** {user['guest_number']}")
            st.warning("*You are currently logged in as a guest*")

    with col2:
        st.markdown("### 🔄 Quick Actions")
        if st.button("📝 Edit Profile"):
            st.session_state.show_edit_profile = True
        if st.button("🔑 Change Password"):
            st.session_state.show_change_password = True
        if not user['is_guest']:
            if st.button("📊 View Activity"):
                st.session_state.show_activity = True

    with col3:
        st.markdown("### ℹ️ System Information")
        st.markdown(f"**Login Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        st.markdown("**Status:** Active ✅")

    # Features Section
    st.markdown("---")
    st.header("📱 Available Features")
    
    feat_col1, feat_col2, feat_col3 = st.columns(3)
    
    with feat_col1:
        st.markdown("### 📊 Dashboard")
        st.markdown("View your personalized dashboard and statistics")
        
    with feat_col2:
        st.markdown("### 📁 Documents")
        st.markdown("Access and manage your documents")
        
    with feat_col3:
        st.markdown("### ⚙️ Settings")
        st.markdown("Configure your account settings")

    # Additional Information
    if not user['is_guest']:
        st.markdown("---")
        st.header("📅 Recent Activity")
        st.info("Your recent account activity will be displayed here")

def display_user_info():
    """Display user information in the header."""
    user = st.session_state.user
    if user:
        col1, col2, col3 = st.columns([2, 8, 2])
        with col1:
            st.markdown(f"**{user['full_name']}**")
            if user['is_guest']:
                st.markdown(f"*Guest {user['guest_number']}*")
            st.markdown(f"📧 {user['email']}")
        with col3:
            if st.button("🚪 Logout"):
                st.session_state.logged_in = False
                st.session_state.user = None
                st.rerun()
        st.markdown("---")

# -------------------- Authentication Functions --------------------

def login_sidebar():
    """Display login sidebar."""
    st.sidebar.title("🔐 Authentication")
    login_option = st.sidebar.radio("Login Method", ["Email Login", "Guest Login"])

    if login_option == "Email Login":
        email_login()
    elif login_option == "Guest Login":
        guest_login()

def email_login():
    """Handle email login."""
    st.sidebar.subheader("📧 Email Login")
    
    with st.sidebar.form("login_form"):
        email = st.text_input("Email").strip()
        password = st.text_input("Password", type="password")
        submit_button = st.form_submit_button("🔑 Login")

    if submit_button:
        if not email or not password:
            st.sidebar.error("Please enter both email and password.")
            return
        
        if not is_valid_email(email):
            st.sidebar.error("Please enter a valid email address.")
            return

        try:
            user = get_user_by_email(conn, email)
            if user:
                stored_password = user[4]
                if stored_password and verify_password(stored_password, password):
                    st.session_state.logged_in = True
                    st.session_state.user = {
                        "id": user[0],
                        "full_name": user[1],
                        "email": user[2],
                        "mobile": user[3],
                        "is_guest": user[5],
                        "guest_number": user[6]
                    }
                    st.sidebar.success("Login successful! 🎉")
                    st.rerun()
                else:
                    st.sidebar.error("Invalid credentials.")
            else:
                st.sidebar.error("User not found. Please register.")
        except Exception as e:
            st.sidebar.error(f"Login error: {str(e)}")

    col1, col2 = st.sidebar.columns(2)
    with col1:
        if st.button("📝 Register"):
            st.session_state.show_register = True
            st.session_state.show_forgot_password = False
            st.rerun()
    with col2:
        if st.button("🔑 Forgot Password?"):
            st.session_state.show_forgot_password = True
            st.session_state.show_register = False
            st.rerun()

def register():
    """Handle user registration."""
    back_to_main_button()
    st.sidebar.subheader("📝 Register New Account")
    
    with st.sidebar.form("registration_form"):
        full_name = st.text_input("Full Name").strip()
        email = st.text_input("Email").strip()
        mobile = st.text_input("Mobile Number").strip()
        password = st.text_input("Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        submit_button = st.form_submit_button("📝 Register")

    if submit_button:
        if not all([full_name, email, mobile, password, confirm_password]):
            st.sidebar.error("Please fill in all fields.")
            return

        if not is_valid_email(email):
            st.sidebar.error("Please enter a valid email address.")
            return

        if not is_valid_mobile(mobile):
            st.sidebar.error("Please enter a valid 10-digit mobile number.")
            return

        if password != confirm_password:
            st.sidebar.error("Passwords do not match.")
            return

        is_strong, password_message = is_password_strong(password)
        if not is_strong:
            st.sidebar.error(password_message)
            return

        if get_user_by_email(conn, email):
            st.sidebar.error("User with this email already exists.")
            return

        try:
            hashed_pw = hash_password(password)
            user_id = add_user(conn, full_name, email, mobile, hashed_pw)
            
            if user_id:
                st.sidebar.success("Registration successful! 🎉")
                time.sleep(1)
                st.session_state.show_register = False
                st.rerun()
            else:
                st.sidebar.error("Registration failed. Please try again.")
        except Exception as e:
            st.sidebar.error(f"Registration error: {str(e)}")

def guest_login():
    """Handle guest login."""
    st.sidebar.subheader("👥 Guest Login")
    if st.sidebar.button("👤 Continue as Guest"):
        try:
            guest_number = get_guest_count(conn) + 1
            guest_email = f"guest{guest_number}@example.com"
            guest_name = f"Guest {guest_number}"
            
            user_id = add_user(
                conn, 
                guest_name, 
                guest_email, 
                "0000000000", 
                is_guest=1, 
                guest_number=guest_number
            )
            
            if user_id:
                user = get_user_by_email(conn, guest_email)
                if user:
                    st.session_state.logged_in = True
                    st.session_state.user = {
                        "id": user[0],
                        "full_name": user[1],
                        "email": user[2],
                        "mobile": user[3],
                        "is_guest": user[5],
                        "guest_number": user[6]
                    }
                    st.sidebar.success(f"Logged in as {guest_name} 👋")
                    st.rerun()
                else:
                    st.sidebar.error("Error creating guest account.")
            else:
                st.sidebar.error("Error creating guest account.")
        except Exception as e:
            st.sidebar.error(f"Guest login error: {str(e)}")

def forgot_password():
    """Handle password reset."""
    back_to_main_button()
    st.sidebar.subheader("🔑 Reset Password")
    
    with st.sidebar.form("reset_password_form"):
        email = st.text_input("Enter your email").strip()
        submit_email = st.form_submit_button("Verify Email")

    if submit_email:
        if not email or not is_valid_email(email):
            st.sidebar.error("Please enter a valid email address.")
            return
        
        user = get_user_by_email(conn, email)
        if user:
            st.session_state.reset_email = email
            st.session_state.show_new_password = True
        else:
            st.sidebar.error("Email not found in our records.")
            return

    # Show new password form if email is verified
    if hasattr(st.session_state, 'show_new_password') and st.session_state.show_new_password:
        with st.sidebar.form("new_password_form"):
            st.write(f"Setting new password for: {st.session_state.reset_email}")
            new_password = st.text_input("Enter new password", type="password")
            confirm_password = st.text_input("Confirm new password", type="password")
            submit_password = st.form_submit_button("Reset Password")

        if submit_password:
            if not new_password or not confirm_password:
                st.sidebar.error("Please fill in all fields.")
                return

            if new_password != confirm_password:
                st.sidebar.error("Passwords do not match.")
                return

            is_strong, password_message = is_password_strong(new_password)
            if not is_strong:
                st.sidebar.error(password_message)
                return

            # Hash and update the new password
            hashed_pw = hash_password(new_password)
            if update_password(conn, st.session_state.reset_email, hashed_pw):
                st.sidebar.success("Password reset successful! Please login with your new password.")
                # Clear the session state
                st.session_state.show_new_password = False
                if hasattr(st.session_state, 'reset_email'):
                    del st.session_state.reset_email
                st.session_state.show_forgot_password = False
                time.sleep(2)
                st.rerun()
            else:
                st.sidebar.error("Failed to reset password. Please try again.")

    # Add cancel button
    if st.sidebar.button("Cancel Reset"):
        st.session_state.show_new_password = False
        if hasattr(st.session_state, 'reset_email'):
            del st.session_state.reset_email
        st.session_state.show_forgot_password = False
        st.rerun()

def main():
    """Main application function."""
    # Set page config
    st.set_page_config(
        page_title="Authentication System",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Initialize session state
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
        st.session_state.user = None
        st.session_state.show_register = False
        st.session_state.show_forgot_password = False

    # Main application logic
    if st.session_state.logged_in:
        display_user_info()
        create_welcome_dashboard(st.session_state.user)
    else:
        if st.session_state.show_register:
            register()
        elif st.session_state.show_forgot_password:
            forgot_password()
        else:
            # Show welcome message in main area
            st.title("🔐 Welcome to the Authentication System")
            st.write("Please log in or register to continue.")
            
            # Show features
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("""
                ### ✨ Features:
                - 🔒 Secure password hashing
                - ✉️ Email validation
                - 🔑 Password strength requirements
                - 👥 Guest login functionality
                - 🔄 Password reset capability
                """)
            
            with col2:
                st.markdown("""
                ### 🛡️ Security Measures:
                - 🔒 Bcrypt password hashing
                - 🧹 Input sanitization
                - ✉️ Email format validation
                - 📱 Mobile number validation
                - 🔑 Strong password enforcement
                """)
            
            login_sidebar()

if __name__ == "__main__":
    main()