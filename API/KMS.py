import boto3
import os
from dataclasses import dataclass
import base64
import pandas as pd
import API.CONSTANTS as CONSTANTS
from cryptography.fernet import Fernet


class KMS:
    """
    Key Management Service class for encryption/decryption operations.
    """
    def __init__(self):
        """Initialize the KMS client and set up paths."""
        os.chdir(os.path.dirname(os.path.realpath(__file__)))
        self.kms = boto3.client('kms')
        self.data_path = CONSTANTS.AWS_FILE
        self.cipher_suite = None

    def decrypt_my_key(self, key):
        """
        Decrypt a KMS key for use with Fernet encryption.
        
        Args:
            key: The encrypted KMS key (string or bytes)
            
        Returns:
            Fernet: Initialized cipher suite
            
        Raises:
            ValueError: If decryption fails
        """
        kms_client = boto3.client('kms')

        # Ensure 'key' is in byte format
        if isinstance(key, str):
            try:
                # Convert from base64-encoded string to bytes
                key = base64.b64decode(key)
            except Exception as e:
                print("Error decoding base64 key:", e)
                raise

        try:
            response = kms_client.decrypt(CiphertextBlob=key)
            fernet_key = base64.urlsafe_b64encode(response['Plaintext'])
            self.cipher_suite = Fernet(fernet_key)
            return self.cipher_suite
        except kms_client.exceptions.InvalidCiphertextException:
            print("Decryption failed: Invalid ciphertext")
            raise
        except Exception as e:
            print("General decryption error:", e)
            raise

    def generate_secure_key(self, key_spec):
        """
        Generate a new data key using AWS KMS.
        
        Args:
            key_spec (str): Key specification (e.g., 'AES_256')
            
        Returns:
            dict: AWS KMS response containing key data
            
        Raises:
            AssertionError: If AWS_KEY environment variable is not set
        """
        aws_key = os.getenv('AWS_KEY')
        assert aws_key is not None, "AWS_KEY environment variable not set"
        self.__key_id = aws_key
        response = self.kms.generate_data_key(
            KeyId=self.__key_id,
            KeySpec=key_spec
        )
        return response

    def create_new_key(self):
        """
        Create a new encryption key and initialize the cipher suite.
        
        Returns:
            Fernet: Initialized cipher suite
        """
        try:
            self.__df = pd.read_excel(self.data_path)
            self.key = self.generate_secure_key('AES_256')
            self.__key = self.key['Plaintext']
            self.storing_key = self.key['CiphertextBlob']
            self.cipher_suite = Fernet(base64.urlsafe_b64encode(self.__key))
            return self.cipher_suite
        except Exception as e:
            print(f"Error creating new key: {e}")
            raise

    def decrypt_data(self, item):
        """
        Decrypt data using the initialized cipher suite.
        
        Args:
            item (bytes): Encrypted data
            
        Returns:
            str: Decrypted data as UTF-8 string
            
        Raises:
            AttributeError: If cipher_suite is not initialized
        """
        if self.cipher_suite is None:
            raise AttributeError("Cipher suite not initialized. Call decrypt_my_key first.")
        return self.cipher_suite.decrypt(item).decode('utf-8')