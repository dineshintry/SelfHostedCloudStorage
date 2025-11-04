from .database import User, db

class UserManager:
    @staticmethod
    def register_user(username, password):
        db.connect()
        try:
            user = User.create_user(username, password)
            if user:
                print(f"User '{username}' registered successfully.")
                return True
            else:
                print(f"User '{username}' already exists.")
                return False
        finally:
            db.close()

    @staticmethod
    def login_user(username, password):
        db.connect()
        try:
            user = User.get_or_none(User.username == username)
            if user and user.verify_password(password):
                print(f"User '{username}' logged in successfully.")
                return user
            else:
                print("Invalid username or password.")
                return None
        finally:
            db.close()

# Example usage:
# user_manager = UserManager()
# user_manager.register_user("testuser", "password123")
# logged_in_user = user_manager.login_user("testuser", "password123")
# if logged_in_user:
#     print(f"Welcome, {logged_in_user.username}!")
# else:
#     print("Login failed.")

pass