
# api/encryption/__init__.py
"""
Encryption module for the API.

This module provides encryption and secret management functionality for the API.
"""

import os,ast
from api.encryption.kms_handler import KMSHandler
from api.encryption.store_secrets import get_secret

__all__ = [
    "KMSHandler"
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
            
            secret_name = ast.literal_eval(get_secret()).get(secret_name,None)
            _kms_handler.initialize_from_secret(secret_name)
        
    return _kms_handler
