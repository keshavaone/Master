import boto3
import os
from dataclasses import dataclass
import base64
import logging
import json
from typing import Optional, Dict, Any, Union
from botocore.exceptions import ClientError
from cryptography.fernet import Fernet, InvalidToken
import pandas as pd
import ast

class KMS:
    """
    Enhanced Key Management Service class for encryption/decryption operations.
    
    This class provides both the original API for backward compatibility and
    enhanced functionality with improved security, error handling, and AWS integration.
    """

    def __init__(self, region_name: str = None):
        """
        Initialize the KMS client and set up paths.
        
        Args:
            region_name (str, optional): AWS region name. Defaults to environment variable or 'us-east-1'.
        """
        # Set up logging
        self.logger = logging.getLogger('KMS')
        
        # Change to the current directory if given file path
        try:
            script_dir = os.path.dirname(os.path.realpath(__file__))
            os.chdir(script_dir)
        except Exception as e:
            self.logger.warning(f"Could not change directory: {e}")
        
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
        self.data_path = None
        self.__df = None

    # Legacy method for backward compatibility
    def decrypt_my_key(self, key):
        """
        Decrypt a KMS key for use with Fernet encryption.
        
        Legacy method for backward compatibility.
        
        Args:
            key: The encrypted KMS key (string or bytes)
            
        Returns:
            Fernet: Initialized cipher suite
            
        Raises:
            ValueError: If decryption fails
        """
        try:
            # Ensure 'key' is in byte format
            if isinstance(key, str):
                try:
                    # Convert from base64-encoded string to bytes
                    key = base64.b64decode(key)
                except Exception as e:
                    self.logger.error(f"Error decoding base64 key: {e}")
                    raise
            
            # Call the new implementation internally
            self.storing_key = key
            success = self._decrypt_key(key)
            
            if not success:
                raise ValueError("Failed to decrypt key")
                
            return self.cipher_suite
            
        except Exception as e:
            self.logger.error(f"Error in decrypt_my_key: {e}")
            raise

    # Legacy method for backward compatibility
    def generate_secure_key(self, key_spec='AES_256'):
        """
        Generate a new data key using AWS KMS.
        
        Legacy method for backward compatibility.
        
        Args:
            key_spec (str): Key specification (e.g., 'AES_256')
            
        Returns:
            dict: AWS KMS response containing key data
            
        Raises:
            AssertionError: If AWS_KEY environment variable is not set
        """
        # Get KMS key ID from environment
        aws_key = os.getenv('AWS_KEY')
        assert aws_key is not None, "AWS_KEY environment variable not set"
        
        self.key_id = aws_key
        
        try:
            # Generate new key
            response = self.kms_client.generate_data_key(
                KeyId=self.key_id,
                KeySpec=key_spec
            )
            
            # Store key material
            self.__key = response['Plaintext']
            self.storing_key = response['CiphertextBlob']
            
            # Initialize cipher suite
            fernet_key = base64.urlsafe_b64encode(self.__key)
            self.cipher_suite = Fernet(fernet_key)
            
            return response
            
        except Exception as e:
            self.logger.error(f"Error generating secure key: {e}")
            raise

    # Legacy method for backward compatibility
    def create_new_key(self):
        """
        Create a new encryption key and initialize the cipher suite.
        
        Legacy method for backward compatibility.
        
        Returns:
            Fernet: Initialized cipher suite
        """
        try:
            # Check if data path is set
            if not self.data_path:
                self.data_path = os.environ.get('AWS_FILE', 'data.xlsx')
            
            # Try to read Excel file if it exists
            try:
                if os.path.exists(self.data_path):
                    self.__df = pd.read_excel(self.data_path)
            except Exception as e:
                self.logger.warning(f"Could not read Excel file: {e}")
            
            # Generate new key
            self.key = self.generate_secure_key('AES_256')
            self.__key = self.key['Plaintext']
            self.storing_key = self.key['CiphertextBlob']
            
            # Initialize cipher suite
            self.cipher_suite = Fernet(base64.urlsafe_b64encode(self.__key))
            
            return self.cipher_suite
            
        except Exception as e:
            self.logger.error(f"Error creating new key: {e}")
            raise

    # Legacy method for backward compatibility
    def decrypt_data(self, data):
        """
        Decrypt data using the initialized cipher suite.
        
        Legacy method for backward compatibility.
        
        Args:
            data (bytes): Encrypted data
            
        Returns:
            str: Decrypted data as UTF-8 string
            
        Raises:
            AttributeError: If cipher_suite is not initialized
        """
        if self.cipher_suite is None:
            raise AttributeError("Cipher suite not initialized. Call decrypt_my_key first.")
            
        try:
            return self.cipher_suite.decrypt(data).decode('utf-8')
        except Exception as e:
            self.logger.error(f"Error decrypting data: {e}")
            raise

    # Enhanced methods with improved security and error handling

    def initialize_from_secret(self, secret_name: str) -> bool:
        """
        Initialize encryption using a key stored in AWS Secrets Manager.
        
        Args:
            secret_name (str): Name of the secret containing the KMS key ID
            
        Returns:
            bool: True if initialization was successful
        """
        try:
            # Get the secret using the same approach as the original code
            from API.store_secrets import get_secret
            
            secret_string = get_secret()
            if not secret_string:
                self.logger.error("Failed to retrieve secret")
                return False
                
            # Parse the secret data
            secret_data = ast.literal_eval(secret_string)
            
            # Extract KMS key information - use the same key as original code
            if 'KMS_KEY_ID' not in secret_data:
                self.logger.error("Secret does not contain KMS_KEY_ID")
                return False
            
            # Get the encoded key
            encoded_key = secret_data['KMS_KEY_ID']
            if not encoded_key:
                self.logger.error("KMS_KEY_ID value is empty")
                return False
                
            self.logger.info("Successfully retrieved KMS key from secret")
            
            # Use the same decrypt_my_key approach as original code
            if isinstance(encoded_key, str):
                try:
                    # Convert from base64-encoded string to bytes
                    encoded_key = base64.b64decode(encoded_key)
                except Exception as e:
                    self.logger.error(f"Error decoding base64 key: {e}")
                    return False
            
            # Store the encrypted key
            self.storing_key = encoded_key
            
            # Decrypt the key using KMS (same as original decrypt_my_key)
            try:
                response = self.kms_client.decrypt(CiphertextBlob=encoded_key)
                fernet_key = base64.urlsafe_b64encode(response['Plaintext'])
                self.cipher_suite = Fernet(fernet_key)
                print('Successfully initialized the cipher suite')
                self.logger.info("Successfully initialized cipher suite")
                return True
            except Exception as e:
                self.logger.error(f"Error decrypting key: {e}")
                return False
                
        except Exception as e:
            self.logger.error(f"Unexpected error during initialization: {e}")
            return False

    def generate_data_key(self, key_spec: str = 'AES_256') -> bool:
        """
        Generate a new data key for encryption.
        
        Args:
            key_spec (str): Key specification (e.g., 'AES_256')
            
        Returns:
            bool: True if key generation was successful
        """
        try:
            # Validate key ID
            if not self.key_id:
                self.logger.error("KMS key ID not set. Call initialize_from_secret first.")
                return False
            
            # Generate data key
            self.logger.info(f"Generating new data key using KMS key: {self.key_id}")
            response = self.kms_client.generate_data_key(
                KeyId=self.key_id,
                KeySpec=key_spec
            )
            
            # Store the plaintext data key and encrypted data key
            self.__key = response['Plaintext']
            self.storing_key = response['CiphertextBlob']
            
            # Initialize Fernet cipher with the data key
            fernet_key = base64.urlsafe_b64encode(self.__key)
            self.cipher_suite = Fernet(fernet_key)
            
            self.logger.info("Data key generated successfully")
            return True
            
        except ClientError as e:
            self.logger.error(f"AWS error generating data key: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error during key generation: {e}")
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

    def rotate_key(self) -> bool:
        """
        Rotate the encryption key for enhanced security.
        
        Returns:
            bool: True if key rotation was successful
        """
        self.logger.info("Rotating encryption key")
        return self.generate_data_key()

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
            return self.decrypt(encrypted_data)
            
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
            return decrypted.decode('utf-8')
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
            
            # Check if secret exists and update it
            try:
                self.secrets_client.get_secret_value(SecretId=secret_name)
                
                # Secret exists, update it
                self.logger.info(f"Updating secret: {secret_name}")
                self.secrets_client.update_secret(
                    SecretId=secret_name,
                    SecretString=json.dumps({
                        "KMS_KEY_ID": self.key_id,
                        "ENCRYPTED_DATA_KEY": base64.b64encode(self.storing_key).decode('utf-8')
                    })
                )
            except self.secrets_client.exceptions.ResourceNotFoundException:
                # Secret doesn't exist, create it
                self.logger.info(f"Creating new secret: {secret_name}")
                self.secrets_client.create_secret(
                    Name=secret_name,
                    SecretString=json.dumps({
                        "KMS_KEY_ID": self.key_id,
                        "ENCRYPTED_DATA_KEY": base64.b64encode(self.storing_key).decode('utf-8')
                    })
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