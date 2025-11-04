from os import makedirs, path, remove, rmdir
from peewee import DoesNotExist
from cryptography.fernet import Fernet
import base64
import datetime
from .database import db, StorageSpace, User, FileMetadata

class StorageManager:
    def __init__(self, user):
        self.user = user

    def create_storage_space(self, name, allocated_size_gb):
        storage_path = path.join(path.dirname(__file__), "..", "data", self.user.username, name)
        db.connect()
        try:
            makedirs(storage_path, exist_ok=True)
            
            key = Fernet.generate_key()
            key_file = path.join(storage_path, 'encryption.key')
            with open(key_file, 'wb') as f:
                f.write(key)
            
            storage_space = StorageSpace.create(
                name=name,
                owner=self.user,
                allocated_size_gb=allocated_size_gb,
                path=storage_path
            )
            
            print(f"Storage space '{name}' created successfully at '{storage_path}'")
            return storage_space
        except Exception as e:
            print(f"Error creating storage space: {e}")
            return None
        finally:
            db.close()

    def get_storage_space(self, name=None, storage_id=None):
        db.connect()
        try:
            if name:
                return StorageSpace.get(
                    (StorageSpace.owner == self.user) &
                    (StorageSpace.name == name)
                )
            if storage_id:
                return StorageSpace.get(
                    (StorageSpace.owner == self.user) &
                    (StorageSpace.id == storage_id)
                )
            return None
        except DoesNotExist:
            return None
        finally:
            db.close()

    def list_storage_spaces(self):
        db.connect()
        try:
            return StorageSpace.select().where(StorageSpace.owner == self.user)
        finally:
            db.close()

    def update_storage_space(self, storage_space, name=None, allocated_size_gb=None):
        db.connect()
        try:
            if name:
                storage_space.name = name
            if allocated_size_gb:
                storage_space.allocated_size_gb = allocated_size_gb
            storage_space.save()
            print(f"Storage space '{storage_space.name}' updated successfully")
            return True
        except Exception as e:
            print(f"Error updating storage space: {e}")
            return False
        finally:
            db.close()

    def delete_storage_space(self, storage_space):
        db.connect()
        try:
            for file_meta in storage_space.files:
                file_path = path.join(storage_space.path, file_meta.filepath)
                if path.exists(file_path):
                    remove(file_path)
            
            key_file = path.join(storage_space.path, 'encryption.key')
            if path.exists(key_file):
                remove(key_file)
            
            if path.exists(storage_space.path):
                if storage_space.path != path.dirname(path.dirname(storage_space.path)):
                    rmdir(storage_space.path)
            
            storage_space.delete_instance()
            print(f"Storage space '{storage_space.name}' deleted successfully")
            return True
        except Exception as e:
            print(f"Error deleting storage space: {e}")
            return False
        finally:
            db.close()

if __name__ == '__main__':
    from auth import UserManager
    from database import initialize_db, User
    
    initialize_db()
    
    user_manager = UserManager()
    test_username = "testuser"
    test_password = "password123"
    test_storage_name = "TestStorageSpace"
    test_allocated_size = 5  # GB
    
    user_manager.register_user(test_username, test_password)
    user = user_manager.login_user(test_username, test_password)

    if user:
        storage_manager = StorageManager(user)
        storage_space = storage_manager.create_storage_space(
            name=test_storage_name,
            allocated_size_gb=test_allocated_size
        )
        
        if storage_space:
            print(f"Storage Space Details:")
            print(f"Name: {storage_space.name}")
            print(f"Path: {storage_space.path}")
            print(f"Allocated Size: {storage_space.allocated_size_gb} GB")
            print(f"Owner: {storage_space.owner.username}")
            
            print("\nListing storage spaces:")
            for space in storage_manager.list_storage_spaces():
                print(f"- {space.name} ({space.allocated_size_gb}GB)")

            # Clean up
            storage_manager.delete_storage_space(storage_space)
            print("Test storage space deleted.")
        else:
            print("Failed to create storage space")
    else:
        print("Failed to login user")