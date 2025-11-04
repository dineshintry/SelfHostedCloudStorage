import os
import hashlib
import datetime
import json
from cryptography.fernet import Fernet
from .database import db, StorageSpace, FileMetadata
from peewee import DoesNotExist

def calculate_file_hash(filepath, block_size=65536):
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            hasher.update(block)
    return hasher.hexdigest()

def get_fernet_key_for_storage_space(storage_space):
    key_file = os.path.join(storage_space.path, 'encryption.key')
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            key = f.read()
        return Fernet(key)
    return None

def encrypt_file(input_filepath, output_filepath, fernet_instance):
    with open(input_filepath, 'rb') as f_in:
        file_data = f_in.read()
    encrypted_data = fernet_instance.encrypt(file_data)
    with open(output_filepath, 'wb') as f_out:
        f_out.write(encrypted_data)

def decrypt_file(input_filepath, output_filepath, fernet_instance):
    with open(input_filepath, 'rb') as f_in:
        encrypted_data = f_in.read()
    decrypted_data = fernet_instance.decrypt(encrypted_data)
    with open(output_filepath, 'wb') as f_out:
        f_out.write(decrypted_data)

def add_file_to_storage_space(storage_space, local_filepath, relative_filepath):
    db.connect()
    try:
        full_storage_path = os.path.join(storage_space.path, relative_filepath)
        os.makedirs(os.path.dirname(full_storage_path), exist_ok=True)

        fernet = get_fernet_key_for_storage_space(storage_space)
        if not fernet:
            print(f"Error: Encryption key not found for storage space '{storage_space.name}'.")
            return None

        # Encrypt the file before storing
        temp_encrypted_filepath = full_storage_path + ".enc_temp"
        encrypt_file(local_filepath, temp_encrypted_filepath, fernet)

        # Calculate hash of the *original* file for metadata
        original_file_hash = calculate_file_hash(local_filepath)
        file_size = os.path.getsize(local_filepath)
        last_modified = datetime.datetime.fromtimestamp(os.path.getmtime(local_filepath))

        # Move the encrypted file to its final destination
        os.replace(temp_encrypted_filepath, full_storage_path)

        file_metadata, created = FileMetadata.get_or_create(
            storage_space=storage_space,
            filepath=relative_filepath,
            defaults={
                'filename': os.path.basename(relative_filepath),
                'file_hash': original_file_hash,
                'size': file_size,
                'last_modified': last_modified
            }
        )
        if not created:
            file_metadata.filename = os.path.basename(relative_filepath)
            file_metadata.file_hash = original_file_hash
            file_metadata.size = file_size
            file_metadata.last_modified = last_modified
            file_metadata.save()
        
        print(f"File '{relative_filepath}' added/updated in storage space '{storage_space.name}'.")
        return file_metadata
    except Exception as e:
        print(f"Error adding file to storage space: {e}")
        return None
    finally:
        db.close()

def get_file_from_storage_space(storage_space, relative_filepath, destination_filepath):
    db.connect()
    try:
        file_metadata = FileMetadata.get(
            (FileMetadata.storage_space == storage_space) &
            (FileMetadata.filepath == relative_filepath)
        )
        
        full_storage_path = os.path.join(storage_space.path, relative_filepath)
        if not os.path.exists(full_storage_path):
            print(f"Error: File '{relative_filepath}' not found in storage.")
            return False

        fernet = get_fernet_key_for_storage_space(storage_space)
        if not fernet:
            print(f"Error: Encryption key not found for storage space '{storage_space.name}'.")
            return False

        # Decrypt the file
        os.makedirs(os.path.dirname(destination_filepath), exist_ok=True)
        decrypt_file(full_storage_path, destination_filepath, fernet)
        print(f"File '{relative_filepath}' retrieved and decrypted to '{destination_filepath}'.")
        return True
    except DoesNotExist:
        print(f"Error: File metadata for '{relative_filepath}' not found.")
        return False
    except Exception as e:
        print(f"Error getting file from storage space: {e}")
        return False
    finally:
        db.close()

def delete_file_from_storage_space(storage_space, relative_filepath):
    db.connect()
    try:
        file_metadata = FileMetadata.get(
            (FileMetadata.storage_space == storage_space) &
            (FileMetadata.filepath == relative_filepath)
        )
        
        full_storage_path = os.path.join(storage_space.path, relative_filepath)
        if os.path.exists(full_storage_path):
            os.remove(full_storage_path)
            print(f"File '{relative_filepath}' deleted from storage.")
        
        file_metadata.delete_instance()
        print(f"File metadata for '{relative_filepath}' deleted.")
        return True
    except DoesNotExist:
        print(f"Error: File metadata for '{relative_filepath}' not found.")
        return False
    except Exception as e:
        print(f"Error deleting file from storage space: {e}")
        return False
    finally:
        db.close()

def get_all_file_metadata(storage_space):
    db.connect()
    try:
        return list(FileMetadata.select().where(FileMetadata.storage_space == storage_space))
    finally:
        db.close()

if __name__ == '__main__':
    from auth import register_user, login_user
    from storage_manager import create_storage_space
    from database import initialize_db, User

    initialize_db()

    test_username = "fileuser"
    test_password = "filepass"
    test_storage_name = "MyFileStorage"
    test_storage_path = os.path.join(os.getcwd(), "..", "data", "file_test_storage")
    test_file_content = "This is a test file for synchronization."
    test_local_file_path = "test_local_file.txt"
    test_relative_file_path = "documents/test_local_file.txt"
    test_download_path = "downloaded_test_file.txt"

    db.connect()
    try:
        user = User.get_or_none(User.username == test_username)
        if not user:
            register_user(test_username, test_password)
            user = login_user(test_username, test_password)

        if user:
            storage_space = StorageSpace.get_or_none(StorageSpace.name == test_storage_name, StorageSpace.owner == user)
            if not storage_space:
                storage_space = create_storage_space(user, test_storage_name, 10, test_storage_path)

            if storage_space:
                # Create a dummy local file
                with open(test_local_file_path, 'w') as f:
                    f.write(test_file_content)

                # Add file to storage space
                metadata = add_file_to_storage_space(storage_space, test_local_file_path, test_relative_file_path)
                if metadata:
                    print(f"Metadata for added file: {metadata.filename}, Hash: {metadata.file_hash}")

                # Get all file metadata
                all_files = get_all_file_metadata(storage_space)
                print("\nFiles in storage space:")
                for f_meta in all_files:
                    print(f"- {f_meta.filepath} (Hash: {f_meta.file_hash})")

                # Retrieve file from storage space
                if get_file_from_storage_space(storage_space, test_relative_file_path, test_download_path):
                    with open(test_download_path, 'r') as f:
                        downloaded_content = f.read()
                    print(f"Downloaded file content: {downloaded_content}")
                    assert downloaded_content == test_file_content
                    print("Downloaded content matches original.")

                # Clean up
                os.remove(test_local_file_path)
                os.remove(test_download_path)
                # delete_file_from_storage_space(storage_space, test_relative_file_path)
                # os.rmdir(os.path.join(test_storage_path, "documents")) # Only if empty
                # os.rmdir(test_storage_path) # Only if empty
            else:
                print("Failed to create or retrieve storage space.")
        else:
            print("Failed to get user for file manager testing.")
    finally:
        db.close()
        # Clean up generated key file
        key_file = os.path.join(test_storage_path, 'encryption.key')
        if os.path.exists(key_file):
            os.remove(key_file)
        if os.path.exists(os.path.join(test_storage_path, "documents")):
            os.rmdir(os.path.join(test_storage_path, "documents"))
        if os.path.exists(test_storage_path):
            os.rmdir(test_storage_path)