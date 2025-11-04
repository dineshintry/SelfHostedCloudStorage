import argparse
import os
import logging
import sys

# Add the project root to the Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

from src.auth import UserManager
from src.database import initialize_db, User, Device, StorageSpace
from src.storage_manager import StorageManager
from src.p2p_network import NetworkManager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def register_user(username, password):
    """Registers a new user."""
    user_manager = UserManager()
    try:
        user_manager.register_user(username, password)
        logger.info(f"User '{username}' registered successfully.")
    except ValueError as e:
        logger.error(f"Registration failed: {e}")

def login_user(username, password):
    """Logs in an existing user."""
    user_manager = UserManager()
    user = user_manager.login_user(username, password)
    if user:
        logger.info(f"User '{username}' logged in successfully.")
        return user
    else:
        logger.error(f"Login failed for user '{username}'.")
        return None

def create_storage_space(user, space_name, capacity_gb):
    """Creates a new storage space for a user."""
    storage_manager = StorageManager(user)
    try:
        storage_manager.create_storage_space(space_name, capacity_gb)
        logger.info(f"Storage space '{space_name}' created for user '{user.username}' with {capacity_gb}GB capacity.")
    except ValueError as e:
        logger.error(f"Failed to create storage space: {e}")

def list_storage_spaces(user):
    """Lists all storage spaces for a user."""
    storage_manager = StorageManager(user)
    spaces = storage_manager.list_storage_spaces()
    if spaces:
        logger.info(f"Storage spaces for user '{user.username}':")
        for space in spaces:
            logger.info(f"- {space.name} ({space.capacity_gb}GB, Used: {space.used_gb}GB)")
    else:
        logger.info(f"No storage spaces found for user '{user.username}'.")

def start_network_manager(user, device_id, device_name, password):
    """Starts the P2P network manager."""
    network_manager = NetworkManager(password=password)
    network_manager.storage_manager = StorageManager(user) # Assign storage manager
    network_manager.start_udp_server()
    network_manager.start_tcp_server()
    network_manager.send_announcement(device_id, device_name, user.id)
    logger.info("Network manager started. Press Ctrl+C to stop.")
    try:
        while True:
            pass
    except KeyboardInterrupt:
        network_manager.stop_udp_server()
        logger.info("Network manager stopped.")

def main():
    initialize_db()

    parser = argparse.ArgumentParser(description="Self-hosted Cloud Storage CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Register command
    register_parser = subparsers.add_parser("register", help="Register a new user")
    register_parser.add_argument("--username", required=True, help="Username for registration")
    register_parser.add_argument("--password", required=True, help="Password for registration")

    # Login command
    login_parser = subparsers.add_parser("login", help="Login an existing user")
    login_parser.add_argument("--username", required=True, help="Username for login")
    login_parser.add_argument("--password", required=True, help="Password for login")

    # Create storage space command
    create_space_parser = subparsers.add_parser("create-space", help="Create a new storage space")
    create_space_parser.add_argument("--username", required=True, help="Username of the owner")
    create_space_parser.add_argument("--password", required=True, help="Password of the owner")
    create_space_parser.add_argument("--name", required=True, help="Name of the storage space")
    create_space_parser.add_argument("--capacity", type=int, required=True, help="Capacity in GB")

    # List storage spaces command
    list_spaces_parser = subparsers.add_parser("list-spaces", help="List storage spaces for a user")
    list_spaces_parser.add_argument("--username", required=True, help="Username of the owner")
    list_spaces_parser.add_argument("--password", required=True, help="Password of the owner")

    # Start network manager command
    start_network_parser = subparsers.add_parser("start-network", help="Start the P2P network manager")
    start_network_parser.add_argument("--username", required=True, help="Username of the current user")
    start_network_parser.add_argument("--password", required=True, help="Password of the current user")
    start_network_parser.add_argument("--device-id", required=True, help="Unique ID for this device")
    start_network_parser.add_argument("--device-name", required=True, help="Name of this device")

    args = parser.parse_args()

    if args.command == "register":
        register_user(args.username, args.password)
    elif args.command == "login":
        login_user(args.username, args.password)
    elif args.command == "create-space":
        user = login_user(args.username, args.password)
        if user:
            create_storage_space(user, args.name, args.capacity)
    elif args.command == "list-spaces":
        user = login_user(args.username, args.password)
        if user:
            list_storage_spaces(user)
    elif args.command == "start-network":
        user = login_user(args.username, args.password)
        if user:
            start_network_manager(user, args.device_id, args.device_name, args.password)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()