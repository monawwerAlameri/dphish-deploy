import re
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_db
import logging

logging.basicConfig(filename='phishing_detection.log', level=logging.INFO)

class AuthManager:
    @staticmethod
    def validate_email(email):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    @staticmethod
    def validate_password(password):
        # No restrictions - accept any password
        return True, "Password accepted"

    @staticmethod
    def validate_username(username):
        if len(username) < 3:
            return False, "Username must be at least 3 characters long"
        if len(username) > 50:
            return False, "Username must not exceed 50 characters"
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            return False, "Username can only contain letters, numbers, underscores, and hyphens"
        return True, "Username is valid"

    @staticmethod
    def register_user(username, email, full_name, password, confirm_password):
        db = get_db()
        is_valid, message = AuthManager.validate_username(username)
        if not is_valid:
            return False, message, None
        if not AuthManager.validate_email(email):
            return False, "Invalid email format", None
        if not full_name or len(full_name) < 2:
            return False, "Full name must be at least 2 characters long", None
        is_valid, message = AuthManager.validate_password(password)
        if not is_valid:
            return False, message, None
        if password != confirm_password:
            return False, "Passwords do not match", None
        if db.get_user_by_username(username):
            return False, "Username already exists", None
        if db.get_user_by_email(email):
            return False, "Email already registered", None
        password_hash = generate_password_hash(password)
        try:
            db.insert_user(username, email, full_name, password_hash)
            registered_user = db.get_user_by_username(username)
            logging.info(f"User registered successfully: {username}")
            return True, "Registration successful! Please log in.", registered_user['id'] if registered_user else None
        except Exception as e:
            logging.error(f"Registration error: {e}")
            return False, "Registration failed. Please try again.", None

    @staticmethod
    def login_user(username, password):
        db = get_db()
        user = db.get_user_by_username(username)
        if not user:
            logging.warning(f"Login attempt with non-existent username: {username}")
            return False, "Invalid username or password", None
        if not user['is_active']:
            logging.warning(f"Login attempt with inactive user: {username}")
            return False, "Your account is inactive", None
        if not check_password_hash(user['password_hash'], password):
            logging.warning(f"Failed login attempt for user: {username}")
            return False, "Invalid username or password", None
        logging.info(f"User logged in successfully: {username}")
        return True, "Login successful", user

    @staticmethod
    def update_profile(user_id, full_name, email):
        db = get_db()
        if not AuthManager.validate_email(email):
            return False, "Invalid email format"
        if not full_name or len(full_name) < 2:
            return False, "Full name must be at least 2 characters long"
        user = db.get_user_by_email(email)
        if user and user['id'] != user_id:
            return False, "Email is already in use"
        try:
            db.update_user_profile(user_id, full_name, email)
            logging.info(f"User profile updated: user_id={user_id}")
            return True, "Profile updated successfully"
        except Exception as e:
            logging.error(f"Profile update error: {e}")
            return False, "Profile update failed"

    @staticmethod
    def change_password(user_id, old_password, new_password, confirm_password):
        db = get_db()
        user = db.get_user_by_id(user_id)
        if not user:
            return False, "User not found"
        if not check_password_hash(user['password_hash'], old_password):
            return False, "Current password is incorrect"
        is_valid, message = AuthManager.validate_password(new_password)
        if not is_valid:
            return False, message
        if new_password != confirm_password:
            return False, "New passwords do not match"
        if old_password == new_password:
            return False, "New password must be different from old password"
        try:
            new_password_hash = generate_password_hash(new_password)
            query = "UPDATE users SET password_hash = %s WHERE id = %s"
            db.execute_query(query, (new_password_hash, user_id))
            logging.info(f"Password changed for user: user_id={user_id}")
            return True, "Password changed successfully"
        except Exception as e:
            logging.error(f"Password change error: {e}")
            return False, "Password change failed"