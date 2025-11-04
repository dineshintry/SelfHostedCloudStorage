from peewee import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import base64
import sys

# Determine the base path for the application
if getattr(sys, 'frozen', False):
    # Running in a PyInstaller bundle, use the current working directory for writable data
    data_dir = os.path.join(os.getcwd(), 'data')
else:
    # Running in a normal Python environment, use the project root's data directory
    data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data'))

# Ensure the data directory exists
os.makedirs(data_dir, exist_ok=True)

# Define the database path
database_path = os.path.join(data_dir, 'storage.db')
db = SqliteDatabase(database_path)

class BaseModel(Model):
    class Meta:
        database = db

class User(BaseModel):
    username = CharField(unique=True)
    password_hash = CharField()
    salt = CharField()

class StorageSpace(BaseModel):
    name = CharField()
    owner = ForeignKeyField(User, backref='storage_spaces')
    allocated_size_gb = IntegerField(default=0)
    path = CharField() # Local path where the storage space data is kept

    class Meta:
        indexes = (
            (('owner', 'name'), True), # Ensure unique storage space names per user
        )

class Device(BaseModel):
    device_id = CharField(unique=True) # A unique identifier for the device
    user = ForeignKeyField(User, backref='devices')
    device_name = CharField()
    is_online = BooleanField(default=False)

    @staticmethod
    def hash_password(password, salt=None):
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode('utf-8'))
        return base64.urlsafe_b64encode(key).decode('utf-8'), base64.urlsafe_b64encode(salt).decode('utf-8')

    @classmethod
    def create_user(cls, username, password):
        if cls.select().where(cls.username == username).exists():
            return None # User already exists
        password_hash, salt = cls.hash_password(password)
        user = cls.create(username=username, password_hash=password_hash, salt=salt)
        return user

    def verify_password(self, password):
        stored_password_hash = self.password_hash
        stored_salt = base64.urlsafe_b64decode(self.salt)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=stored_salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode('utf-8'))
        return base64.urlsafe_b64encode(key).decode('utf-8') == stored_password_hash

class FileMetadata(BaseModel):
    storage_space = ForeignKeyField(StorageSpace, backref='files')
    filepath = CharField() # Relative path within the storage space
    filename = CharField()
    file_hash = CharField() # SHA256 hash of the file content
    size = BigIntegerField() # Size in bytes
    last_modified = DateTimeField()

    class Meta:
        indexes = (
            (('storage_space', 'filepath'), True), # Ensure unique file paths within a storage space
        )

def initialize_db():
    db.connect()
    db.create_tables([User, StorageSpace, Device, FileMetadata])
    db.close()

if __name__ == '__main__':
    initialize_db()
    print("Database initialized and tables created.")
    # Example usage:
    # user = User.create_user("testuser", "password123")
    # if user:
    #     print(f"User {user.username} created.")
    #     if user.verify_password("password123"):
    #         print("Password verified successfully.")
    #     else:
    #         print("Password verification failed.")
    # else:
    #     print("User already exists.")