
# api/encryption/__init__.py
"""
Encryption module for the API.

This module provides encryption and secret management functionality for the API.
"""

import os,ast
from api.encryption.kms_handler import KMSHandler
from api.encryption.store_secrets import get_secret

__all__ = [
    "KMSHandler",
    "get_kms_handler"
]

# Global instances for singleton pattern
_kms_handler = None
_secret_manager = None

def get_kms_handler() -> KMSHandler:
    """
    Get the KMS handler instance.
    
    Returns:
        KMSHandler: The KMS handler instance
    """
    global _kms_handler
    
    if _kms_handler is None:
        # Create a new KMS handler
        _kms_handler = KMSHandler(region_name=os.environ.get('AWS_REGION'))
        
        # Initialize with secret if available
        secret_name = os.environ.get('KMS_SECRET_NAME')
        if secret_name:
            try:
                # Get secret value and parse it
                secret_value = get_secret()
                if secret_value:
                    secret_data = ast.literal_eval(secret_value)
                    actual_secret_name = secret_data.get(secret_name)
                    
                    # Initialize with the actual secret name
                    if actual_secret_name:
                        print(f"Initializing KMS handler with secret: {actual_secret_name}")
                        success = _kms_handler.initialize_from_secret(actual_secret_name)
                        if not success:
                            print("Failed to initialize KMS handler with secret")
                    else:
                        print(f"Secret name {secret_name} not found in secret data")
                else:
                    print("Failed to retrieve secret value")
            except Exception as e:
                print(f"Error initializing KMS handler with secret: {e}")
                # Fall back to environment variable
                print("Falling back to environment variable for KMS initialization")
                _kms_handler.initialize_from_secret("env-key")
        else:
            # No secret name provided, initialize with development mode
            print("No KMS_SECRET_NAME provided, initializing with development mode")
            _kms_handler.initialize_from_secret("dev-key")
            
        # Verify initialization
        if not _kms_handler.initialized:
            print("WARNING: KMS handler was not properly initialized!")
        
    return _kms_handler
