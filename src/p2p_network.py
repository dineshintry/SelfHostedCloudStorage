
from socket import socket, SOCK_DGRAM, SOCK_STREAM, AF_INET
from datetime import datetime
import hashlib
from threading import Thread
import json
import logging
from src.database import Device
from src.security import SecurityManager
import os

logger = logging.getLogger(__name__)

class NetworkManager:
    def __init__(self, host='0.0.0.0', password=None):
        self.host = host
        self.port_udp = 5555
        self.port_tcp = 5556
        self.tcp_socket = None
        self.udp_socket = None
        self.running = False
        self.storage_manager = None
        self.file_synchronizer = None
        self.security_manager = SecurityManager(password if password else os.environ.get("APP_SECRET_KEY", "supersecretpassword"))

    def start_udp_server(self):
        """Start UDP server for device discovery"""
        self.udp_socket = socket(AF_INET, SOCK_DGRAM)
        self.udp_socket.bind((self.host, self.port_udp))
        self.running = True
        Thread(target=self.handle_udp_messages).start()
        logger.info("UDP server started on port %d", self.port_udp)

    def stop_udp_server(self):
        """Stop UDP server"""
        if self.udp_socket:
            self.udp_socket.close()
            self.udp_socket = None
            self.running = False
            logger.info("UDP server stopped")

    def handle_udp_messages(self):
        """Handle incoming UDP messages"""
        while self.running:
            data, addr = self.udp_socket.recvfrom(1024)
            if data:
                self.process_message(data, addr)

    def process_message(self, data, addr):
        """Process incoming message"""
        try:
            decrypted_data = self.security_manager.decrypt_data(data.decode('utf-8'))
            message = json.loads(decrypted_data)
            if message['type'] == 'announcement':
                self.handle_device_announcement(message, addr)
        except Exception as e:
            logger.error("Error processing message: %s", str(e))

    def handle_device_announcement(self, message, addr):
        """Handle device announcement"""
        device_info = {
            'device_id': message['device_id'],
            'device_name': message['device_name'],
            'ip_address': addr[0],
            'port': addr[1]
        }
        
        # Update device information in database
        device, created = Device.get_or_create(
            device_id=device_info['device_id'],
            defaults={
                'user': message['user_id'],
                'device_name': device_info['device_name'],
                'is_online': True
            }
        )
        
        if not created:
            device.is_online = True
            device.save()
            
        logger.info("Device %s announced: %s", device_info['device_id'], device_info)

    def send_announcement(self, device_id, device_name, user_id):
        """Send device announcement"""
        message = {
            'type': 'announcement',
            'device_id': device_id,
            'device_name': device_name,
            'user_id': user_id
        }
        
        encrypted_message = self.security_manager.encrypt_data(json.dumps(message))
        self.udp_socket.sendto(
            encrypted_message.encode('utf-8'),
            ('<broadcast>', self.port_udp)
        )
        logger.info("Sent device announcement")

    def start_tcp_server(self):
        """Start TCP server for file transfers"""
        self.tcp_socket = socket(AF_INET, SOCK_STREAM)
        self.tcp_socket.bind((self.host, self.port_tcp))
        self.tcp_socket.listen(5)
        Thread(target=self.handle_tcp_connections).start()
        logger.info("TCP server started on port %d", self.port_tcp)

    def handle_tcp_connections(self):
        """Handle incoming TCP connections"""
        while self.running:
            client_socket, addr = self.tcp_socket.accept()
            Thread(target=self.handle_file_transfer, args=(client_socket, addr)).start()
            logger.info("New connection from %s:%d", addr[0], addr[1])

    def handle_file_transfer(self, client_socket, addr):
        """Handle file transfer operations"""
        try:
            # Receive file metadata
            encrypted_metadata = client_socket.recv(1024).decode('utf-8')
            decrypted_metadata = self.security_manager.decrypt_data(encrypted_metadata)
            metadata = json.loads(decrypted_metadata)
            
            if metadata['action'] == 'upload':
                self.handle_file_upload(client_socket, metadata)
            elif metadata['action'] == 'download':
                self.handle_file_download(client_socket, metadata)
            elif metadata['action'] == 'sync-request':
                self.handle_sync_request(client_socket, metadata)
        except Exception as e:
            logger.error("Error handling file transfer: %s", str(e))
        finally:
            client_socket.close()

    def handle_sync_request(self, client_socket, metadata):
        """Handle synchronization request from remote device"""
        try:
            # Get local file information
            local_files = self.storage_manager.get_storage_space_files(metadata['storage_space'])
            
            # Send local file list to remote device
            client_socket.send(json.dumps(local_files).encode('utf-8'))
            
            # Receive remote file list
            remote_files = json.loads(client_socket.recv(1024).decode('utf-8'))
            
            # Determine synchronization actions
            sync_actions = self.file_synchronizer.compare_file_lists(local_files, remote_files)
            
            # Send synchronization actions to remote device
            client_socket.send(json.dumps(sync_actions).encode('utf-8'))
            
            # Perform synchronization
            self.file_synchronizer.execute_sync_actions(sync_actions, client_socket)
            
            logger.info("File synchronization completed successfully")
        except Exception as e:
            logger.error("Error handling synchronization request: %s", str(e))

    def _calculate_file_hash(self, file_path):
        """Calculate SHA256 hash of a file"""
        with open(file_path, 'rb') as f:
            file_data = f.read()
            return hashlib.sha256(file_data).hexdigest()

    def _get_file_metadata(self, file_path):
        """Get metadata for a file"""
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        modification_time = datetime.fromtimestamp(os.path.getmtime(file_path))
        return {
            'file_name': file_name,
            'file_size': file_size,
            'modification_time': modification_time.isoformat(),
            'file_hash': self._calculate_file_hash(file_path)
        }


    def handle_sync_request(self, client_socket, metadata):
        """Handle file synchronization request from remote device"""
        try:
            logging.info("Processing sync request from remote device")
            
            # Initialize logger
            sync_logger = logging.getLogger("sync")
            sync_logger.info("Starting synchronization process")
            
            # Parse metadata
            if not metadata or "file_list" not in metadata:
                sync_logger.error("Invalid metadata received")
                client_socket.sendall(json.dumps({"status": "error", "message": "Invalid metadata"}).encode())
                return
               
            # Get remote file list
            remote_file_list = metadata["file_list"]
            sync_logger.info(f"Received remote file list with {len(remote_file_list)} files")
            
            # Get local file list
            local_file_list = self.storage_manager.get_file_list()
            sync_logger.info(f"Local file list contains {len(local_file_list)} files")
            
            # Compare files and determine synchronization actions
            sync_actions = []
            for file in remote_file_list:
                if file not in local_file_list or file["timestamp"] > local_file_list[file]["timestamp"]:
                    sync_actions.append({"action": "download", "file": file})
            
            for file in local_file_list:
                if file not in remote_file_list or local_file_list[file]["timestamp"] > remote_file_list.get(file, {}):
                    sync_actions.append({"action": "upload", "file": file})
                    
            # Send synchronization actions to client
            client_socket.sendall(json.dumps({"status": "sync_actions", "actions": sync_actions}).encode())
            
            # Handle file transfers based on actions
            for action in sync_actions:
                if action["action"] == "download":
                    self.handle_file_download(client_socket, action["file"])
                elif action["action"] == "upload":
                    self.handle_file_upload(client_socket, action["file"])
            
            sync_logger.info("Synchronization process completed successfully")
            client_socket.sendall(json.dumps({"status": "success", "message": "Synchronization completed"}).encode())
            
        except Exception as e:
            sync_logger.error(f"Synchronization error: {str(e)}")
            client_socket.sendall(json.dumps({"status": "error", "message": str(e)}).encode())

    def handle_file_upload(self, client_socket, metadata):
        """Handle file upload from remote device with encryption."""
        try:
            client_socket.send('Ready to receive file'.encode('utf-8'))
            
            encrypted_file_data = b''
            while True:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                encrypted_file_data += chunk
            
            decrypted_file_data = self.security_manager.decrypt_data(encrypted_file_data.decode('utf-8'))
            
            storage_path = os.path.join(metadata['storage_space'], metadata['file_path'])
            os.makedirs(os.path.dirname(storage_path), exist_ok=True)
            with open(storage_path, 'wb') as f:
                f.write(decrypted_file_data.encode('utf-8'))
                
            file_metadata = self._get_file_metadata(storage_path)
            self.storage_manager.update_file_metadata(metadata['file_path'], file_metadata)
            
            logger.info("File %s uploaded successfully", metadata['file_name'])
        except Exception as e:
            logger.error("Error handling file upload: %s", str(e))
        finally:
            client_socket.close()

    def handle_file_download(self, client_socket, metadata):
        """Handle file download to remote device with encryption."""
        try:
            client_socket.send('File ready to send'.encode('utf-8'))
            client_socket.settimeout(300)
            
            file_path = os.path.join(metadata['storage_space'], metadata['file_path'])
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            encrypted_file_data = self.security_manager.encrypt_data(file_data.decode('utf-8'))
            client_socket.sendall(encrypted_file_data.encode('utf-8'))
            
            logger.info("File %s downloaded successfully", metadata['file_name'])
        except Exception as e:
            logger.error("Error handling file download: %s", str(e))
        finally:
            client_socket.close()
