import os
import base64
import logging
import json
from typing import Optional, Dict, Any, Union
from cryptography.fernet import Fernet, InvalidToken

import boto3
from botocore.exceptions import ClientError
from CONSTANTS import ENCRYPTION_KEY as encrypted_key
# Configure logging
logger = logging.getLogger("api.encryption.kms")
logger.setLevel(logging.INFO)

class KMSHandler:
    """
    KMS handler for encryption/decryption operations.
    """

    def __init__(self, region_name: str = None):
        self.logger = logging.getLogger("api.encryption.kms")
        self.region_name = region_name or os.environ.get('AWS_REGION', 'us-east-1')
        self.kms_client = boto3.client('kms', region_name=self.region_name)
        self.secrets_client = boto3.client('secretsmanager', region_name=self.region_name)
        
        # Cipher attributes
        self.cipher_suite = None
        self.key_id = None  # (Metadata from KMS)
        self.__key = None   # Decrypted plaintext key (bytes)
        self.storing_key = None  # Encrypted key (CiphertextBlob) as bytes
        self.initialized = False
        
        self.logger.info(f"KMS handler initialized with region: {self.region_name}")

    @staticmethod
    def _fix_base64_padding(data: str) -> str:
        """
        Fix base64 padding by appending '=' characters if necessary.
        """
        return data + '=' * (-len(data) % 4)

    def initialize_from_secret(self, stored_key_b64: str) -> bool:
        """
        Initialize decryption by processing the stored encrypted key (CiphertextBlob)
        that is provided as a base64 string.
        """
        try:
            self.logger.info("Initializing decryption from stored key.")
            # Fix padding for the stored key string before decoding
            stored_key_b64 = self._fix_base64_padding(stored_key_b64)
            self.storing_key = base64.b64decode(stored_key_b64)
            
            if not self._decrypt_key(self.storing_key):
                self.logger.error("Key decryption failed during initialization.")
                return False
            
            self.initialized = True
            self.logger.info("Successfully initialized decryption.")
            return True
        except Exception as e:
            self.logger.error(f"Unexpected error during initialization: {e}")
            return False

    def _decrypt_key(self, encrypted_key: bytes) -> bool:
        """
        Decrypt the encrypted key data using AWS KMS and initialize the Fernet cipher.
        """
        try:
            if not encrypted_key:
                self.logger.error("No encrypted key provided")
                return False

            self.logger.info("Decrypting key data using KMS")
            response = self.kms_client.decrypt(CiphertextBlob=encrypted_key)
            self.__key = response['Plaintext']
            self.logger.info(f"KMS decryption returned key of length: {len(self.__key)} bytes")
            if len(self.__key) != 32:
                self.logger.error(f"Unexpected key length: {len(self.__key)} (expected 32 bytes)")
                return False
            
            # Initialize Fernet cipher with the derived key
            fernet_key = base64.urlsafe_b64encode(self.__key)
            self.cipher_suite = Fernet(fernet_key)
            self.logger.info("Fernet cipher initialized successfully.")
            self.key_id = response.get('KeyId')
            return True
            
        except ClientError as e:
            self.logger.error(f"AWS error decrypting key: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error during key decryption: {e}")
            return False

    def decrypt_from_base64(self, b64_data: str) -> Optional[bytes]:
        """
        Decrypt a base64-encoded encrypted data string.
        """
        try:
            # Fix padding for the encrypted data string
            b64_data = self._fix_base64_padding(b64_data)
            encrypted_data = base64.b64decode(b64_data)
            decrypted_data = self.decrypt(encrypted_data)
            return decrypted_data
        except Exception as e:
            self.logger.error(f"Error decoding or decrypting base64 data: {e}")
            return None

    def decrypt(self, encrypted_data: bytes) -> Optional[bytes]:
        """
        Decrypt raw encrypted data bytes using the Fernet cipher.
        """
        try:
            if not self.cipher_suite:
                self.logger.error("Cipher suite not initialized")
                return None
            decrypted_data = self.cipher_suite.decrypt(encrypted_data)
            return decrypted_data
        except InvalidToken:
            self.logger.error("Invalid token or corrupted data")
            return None
        except Exception as e:
            self.logger.error(f"Error decrypting data: {e}")
            return None

    def decrypt_to_string(self, encrypted_data: Union[str, bytes]) -> Optional[str]:
        """
        Decrypt data and return a UTF-8 string.
        """
        print('Decrypting PII data...', encrypted_data)
        if isinstance(encrypted_data, str):
            decrypted = self.decrypt_from_base64(encrypted_data)
        else:
            decrypted = self.decrypt(encrypted_data)
        
        if decrypted:
            try:
                return decrypted.decode('utf-8')
            except UnicodeDecodeError:
                self.logger.warning("UTF-8 decoding failed, falling back to latin-1")
                return decrypted.decode('latin-1')
        return None
    
    def decrypt_pii_data(self, encrypted_data: str) -> Optional[str]:
        """
        Decrypt PII data from a base64-encoded string.
        """
        stored_encrypted_key_b64 = encrypted_key
        if not self.initialize_from_secret(stored_encrypted_key_b64):
            logger.error("Initialization failed.")
        else:
            decrypted_text = self.decrypt_to_string(encrypted_data)
            if decrypted_text is not None:
                logger.info(f"Decrypted text: {decrypted_text}")
                return decrypted_text
            else:
                logger.error("Decryption failed.")
