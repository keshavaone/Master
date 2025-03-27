# api/encryption/kms_handler.py
"""
AWS KMS encryption handler.

This module provides a secure interface for encryption/decryption operations
using AWS Key Management Service (KMS).
"""

import os
import base64
import logging
import json
from typing import Optional, Dict, Any, Union
from cryptography.fernet import Fernet, InvalidToken

import boto3
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger("api.encryption.kms")
logger.setLevel(logging.INFO)

class KMSHandler:
    """
    KMS handler for encryption/decryption operations.
    
    This class provides a secure interface for encryption/decryption operations
    using AWS Key Management Service (KMS).
    """

    def __init__(self, region_name: str = None):
        """
        Initialize the KMS handler.
        
        Args:
            region_name (str, optional): AWS region name. Defaults to environment variable or 'us-east-1'.
        """
        # Set up logging
        self.logger = logging.getLogger("api.encryption.kms")
        
        # Get region from environment or parameter
        self.region_name = region_name or os.environ.get('AWS_REGION', 'us-east-1')
        
        # Initialize AWS clients
        self.kms_client = boto3.client('kms', region_name=self.region_name)
        self.secrets_client = boto3.client('secretsmanager', region_name=self.region_name)
        
        # Initialize cipher suite and key attributes
        self.cipher_suite = None
        self.key_id = None
        self.__key = None  # Plaintext key (protected)
        self.storing_key = None  # Encrypted key (CiphertextBlob)
        self.initialized = False
        
        # Log initialization
        self.logger.info(f"KMS handler initialized with region: {self.region_name}")

    def initialize_from_secret(self, secret_name: str) -> bool:
        """
        Initialize encryption using a key stored in AWS Secrets Manager.
        
        Args:
            secret_name (str): Name of the secret containing the KMS key ID
            
        Returns:
            bool: True if initialization was successful
        """
        try:
            # Get the secret
            self.logger.info(f"Retrieving encryption key from secret: {secret_name}")
            
            
            
            # Get the key ID
            self.key_id = secret_name
            
            # Get the encoded key
            self.storing_key = base64.b64decode(secret_name)
            self.key_id = self._decrypt_key(self.storing_key)
            
            self.initialized = True
            self.logger.info("Successfully initialized encryption")
                
                
        except Exception as e:
            self.logger.error(f"Unexpected error during initialization: {e}")
            return False

    
    def _decrypt_key(self, encrypted_key: bytes) -> bool:
        """
        Decrypt the encrypted key data.
        
        Args:
            encrypted_key (bytes): Encrypted key data
            
        Returns:
            bool: True if decryption was successful
        """
        try:
            if not encrypted_key:
                self.logger.error("No encrypted key provided")
                return False
            
            # Decrypt the key
            self.logger.info("Decrypting key data")
            response = self.kms_client.decrypt(
                CiphertextBlob=encrypted_key
            )
            
            # Store the plaintext key
            self.__key = response['Plaintext']
            
            # Initialize Fernet cipher with the key
            fernet_key = base64.urlsafe_b64encode(self.__key)
            self.cipher_suite = Fernet(fernet_key)
            self.logger.info("Key decrypted successfully")
            return True
            
        except ClientError as e:
            self.logger.error(f"AWS error decrypting key: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error during key decryption: {e}")
            return False


    def encrypt(self, data: Union[str, bytes]) -> Optional[bytes]:
        """
        Encrypt data using the cipher suite.
        
        Args:
            data (str or bytes): Data to encrypt
            
        Returns:
            bytes: Encrypted data or None if encryption failed
        """
        try:
            if not self.cipher_suite:
                self.logger.error("Cipher suite not initialized")
                return None
            
            # Convert string to bytes if needed
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Encrypt the data
            encrypted_data = self.cipher_suite.encrypt(data)
            return encrypted_data
            
        except Exception as e:
            self.logger.error(f"Error encrypting data: {e}")
            return None

    def decrypt(self, encrypted_data: bytes) -> Optional[bytes]:
        """
        Decrypt data using the cipher suite.
        
        Args:
            encrypted_data (bytes): Encrypted data
            
        Returns:
            bytes: Decrypted data or None if decryption failed
        """
        try:
            if not self.cipher_suite:
                self.logger.error("Cipher suite not initialized")
                return None
            # Decrypt the data
            decrypted_data = self.cipher_suite.decrypt(encrypted_data)
            return decrypted_data
            
        except InvalidToken:
            self.logger.error("Invalid token or corrupted data")
            return None
        except Exception as e:
            self.logger.error(f"Error decrypting data: {e}")
            return None

    def encrypt_to_base64(self, data: Union[str, bytes]) -> Optional[str]:
        """
        Encrypt data and return as base64 string.
        
        Args:
            data (str or bytes): Data to encrypt
            
        Returns:
            str: Base64-encoded encrypted data or None if encryption failed
        """
        encrypted_data = self.encrypt(data)
        if encrypted_data:
            return base64.b64encode(encrypted_data).decode('utf-8')
        return None

    def decrypt_from_base64(self, b64_data: str) -> Optional[bytes]:
        """
        Decrypt base64-encoded data.
        
        Args:
            b64_data (str): Base64-encoded encrypted data
            
        Returns:
            bytes: Decrypted data or None if decryption failed
        """
        try:
            # Decode base64
            encrypted_data = base64.b64decode(b64_data)
            # Decrypt
            decrypted_data = self.decrypt(encrypted_data)
            return decrypted_data
            
        except Exception as e:
            self.logger.error(f"Error decoding or decrypting base64 data: {e}")
            return None

    def decrypt_to_string(self, encrypted_data: Union[str, bytes]) -> Optional[str]:
        """
        Decrypt data and return as UTF-8 string.
        
        Args:
            encrypted_data (str or bytes): Encrypted data (base64 string or raw bytes)
            
        Returns:
            str: Decrypted string or None if decryption failed
        """
        # Handle base64 string input
        if isinstance(encrypted_data, str):
            decrypted = self.decrypt_from_base64(encrypted_data)
        else:
            decrypted = self.decrypt(encrypted_data)
        
        if decrypted:
            try:
                return decrypted.decode('utf-8')
            except UnicodeDecodeError:
                # Fallback to latin-1 if UTF-8 decoding fails
                self.logger.warning("UTF-8 decoding failed, falling back to latin-1")
                return decrypted.decode('latin-1')
        return None

    def get_encryption_context(self) -> Dict[str, Any]:
        """
        Get information about the current encryption context.
        
        Returns:
            dict: Encryption context information
        """
        return {
            "key_id": self.key_id,
            "has_key": self.__key is not None,
            "has_storing_key": self.storing_key is not None,
            "has_cipher_suite": self.cipher_suite is not None,
            "initialized": self.initialized,
            "region": self.region_name
        }

    def save_key_to_secret(self, secret_name: str) -> bool:
        """
        Save the encrypted key to AWS Secrets Manager.
        
        Args:
            secret_name (str): Name of the secret to store the key
            
        Returns:
            bool: True if save was successful
        """
        try:
            if not self.storing_key:
                self.logger.error("No encrypted key available to save")
                return False
            
            if not self.key_id:
                self.logger.error("No KMS key ID set")
                return False
            
            # Prepare the secret data
            secret_data = {
                "KMS_KEY_ID": self.key_id,
                "ENCRYPTED_DATA_KEY": base64.b64encode(self.storing_key).decode('utf-8')
            }
            
            # Check if secret exists and update it
            try:
                self.secrets_client.get_secret_value(SecretId=secret_name)
                
                # Secret exists, update it
                self.logger.info(f"Updating secret: {secret_name}")
                self.secrets_client.update_secret(
                    SecretId=secret_name,
                    SecretString=json.dumps(secret_data)
                )
            except self.secrets_client.exceptions.ResourceNotFoundException:
                # Secret doesn't exist, create it
                self.logger.info(f"Creating new secret: {secret_name}")
                self.secrets_client.create_secret(
                    Name=secret_name,
                    SecretString=json.dumps(secret_data)
                )
            
            self.logger.info("Encrypted key saved to Secrets Manager")
            return True
            
        except ClientError as e:
            self.logger.error(f"AWS error saving key to Secrets Manager: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error saving key: {e}")
            return False

    @staticmethod
    def is_base64(sb: Union[str, bytes]) -> bool:
        """
        Check if a string is base64 encoded.
        
        Args:
            sb (str or bytes): String to check
            
        Returns:
            bool: True if base64 encoded
        """
        try:
            if isinstance(sb, str):
                # If there's any unicode here, an exception will be thrown and the function will return false
                sb_bytes = bytes(sb, 'ascii')
            elif isinstance(sb, bytes):
                sb_bytes = sb
            else:
                raise ValueError("Argument must be string or bytes")
            return base64.b64encode(base64.b64decode(sb_bytes)) == sb_bytes
        except Exception:
            return False

    @staticmethod
    def _fix_base64_padding(data: str) -> str:
        """
        Fix base64 padding if needed.
        
        Args:
            data (str): Base64 encoded string that might need padding
            
        Returns:
            str: Properly padded base64 string
        """
        # Add padding if needed
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return data

