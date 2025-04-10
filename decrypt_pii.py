#!/usr/bin/env python3
# decrypt_pii.py - Script to test DynamoDB PII field decryption

import os
import sys
import json
import base64
import logging
from typing import Dict, Any

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("decrypt_pii")

# Add project root to path so we can import the API modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from api.data.database import DatabaseHandler
from api.encryption import get_kms_handler

# The encrypted data to decrypt (for basic testing)
ENCRYPTED_DATA = "Z0FBQUFBQm0zNlBsOEpLZWs2Nkp3aDgxdFVLR2Q3QzJ1bFBvSl9KQnZLbjJMd2NwbkNvcTNZUFV2M29Kc1VUa01rV01lZF9jM0UwT2wyWVc2ZmF4VVFrVndVdFNjWF8xZm1CRm55MzNRcUZRQzZJRmIxcmhfU3dULTBQMHlwdzE5bVNNS01oV0pRa3hFNVhsTXZ2YkIzamYyUzhIcEd2UlgyTnFGMnBxNnZyTlo0c0xzRTctSDJvT0tocGNXbVQ3Wjh0SnJBOXlRQTNXSzZhSkVIa3FsZTRjTkw1R3ZMcHJtZz09"

def setup_environment():
    """Set up the environment for testing"""
    print("\n========== SETTING UP TEST ENVIRONMENT ==========")
    
    # Set FERNET_KEY for testing if not already set
    if not os.environ.get("FERNET_KEY"):
        test_key = "TIMrXpIGNc2iXpHJmTQClGTMOp4YhmNHN_Wht92GuI0="
        print(f"Setting test FERNET_KEY: {test_key[:10]}...")
        os.environ["FERNET_KEY"] = test_key
    else:
        print(f"Using existing FERNET_KEY: {os.environ.get('FERNET_KEY')[:10]}...")
    
    # Set USE_MOCK_DB for development mode
    if os.environ.get("USE_MOCK_DB") is None:
        print("Setting USE_MOCK_DB=true for development mode")
        os.environ["USE_MOCK_DB"] = "true"
    else:
        print(f"Using existing USE_MOCK_DB: {os.environ.get('USE_MOCK_DB')}")
    
    # Initialize KMS handler
    print("\nInitializing KMS handler...")
    kms_handler = get_kms_handler()
    
    if kms_handler.initialized:
        print("KMS handler successfully initialized")
        context = kms_handler.get_encryption_context()
        print(f"Encryption context: {context}")
    else:
        print("WARNING: KMS handler failed to initialize")
    
    return kms_handler

def test_basic_encryption_decryption(kms_handler):
    """Test basic encryption and decryption with the KMS handler"""
    print("\n========== TESTING BASIC ENCRYPTION/DECRYPTION ==========")
    
    # Step 1: Try decrypting the test data
    print(f"Data to decrypt: {ENCRYPTED_DATA[:50]}...")
    
    try:
        # Use the correct method
        decrypted_data = kms_handler.decrypt_to_string(ENCRYPTED_DATA)
        
        if decrypted_data:
            print("\nDECRYPTION SUCCESSFUL!")
            print(f"Decrypted data: {decrypted_data}")
        else:
            print("\nDECRYPTION FAILED")
    except Exception as e:
        print(f"Decryption error: {e}")
    
    # Step 2: Test encryption/decryption cycle
    print("\nTESTING ENCRYPTION/DECRYPTION CYCLE")
    print("-" * 60)
    test_data = "This is a test of the PII encryption system"
    print(f"Test data: {test_data}")
    
    # Encrypt using the KMS handler
    encrypted_data = kms_handler.encrypt_to_base64(test_data)
    
    if encrypted_data:
        print(f"Encrypted data: {encrypted_data[:50]}...")
        
        # Decrypt to verify
        verified_data = kms_handler.decrypt_to_string(encrypted_data)
        
        if verified_data == test_data:
            print("Verification successful - data matches!")
        else:
            print(f"Verification failed - data doesn't match: {verified_data}")
    else:
        print("Encryption failed")

def create_test_items() -> Dict[str, Any]:
    """Create a set of test items with different PII formats"""
    kms_handler = get_kms_handler()
    
    # Test string for encryption
    test_string = "Jane Doe,123-45-6789,jdoe@example.com"
    test_list = [
        {"name": "First Name", "value": "Jane"}, 
        {"name": "Last Name", "value": "Doe"}, 
        {"name": "SSN", "value": "123-45-6789"}
    ]
    test_dict = {
        "firstName": "Jane",
        "lastName": "Doe",
        "ssn": "123-45-6789",
        "email": "jdoe@example.com"
    }
    
    # Encrypt these values
    encrypted_string = kms_handler.encrypt_to_base64(test_string)
    
    # For the list, encrypt the values
    encrypted_list = []
    for item in test_list:
        new_item = item.copy()
        if "value" in new_item:
            new_item["value"] = kms_handler.encrypt_to_base64(new_item["value"])
        encrypted_list.append(new_item)
    
    # For the dict, encrypt the values
    encrypted_dict = {}
    for key, value in test_dict.items():
        encrypted_dict[key] = kms_handler.encrypt_to_base64(value)
    
    # Create items with different formats
    test_items = {
        "string_item": {
            "_id": "test-string-01",
            "Category": "Personal",
            "Type": "Contact",
            "PII": encrypted_string,
            "user": "testuser"
        },
        "list_item": {
            "_id": "test-list-01",
            "Category": "Financial",
            "Type": "SSN",
            "PII": json.dumps(encrypted_list),
            "user": "testuser"
        },
        "dict_item": {
            "_id": "test-dict-01",
            "Category": "Account",
            "Type": "Profile",
            "PII": json.dumps(encrypted_dict),
            "user": "testuser"
        },
        "already_decrypted": {
            "_id": "test-plain-01",
            "Category": "Test",
            "Type": "Plain",
            "PII": json.dumps(test_list),
            "user": "testuser"
        },
        "alternative_field": {
            "_id": "test-alt-01",
            "Category": "Test",
            "Type": "Alt",
            "pii": encrypted_string,  # Note lowercase field name
            "user": "testuser"
        }
    }
    
    return test_items

def test_decrypt_item(db_handler: DatabaseHandler, test_items: Dict[str, Any]):
    """Test the decrypt_item function with different item formats"""
    print("\n========== TESTING DECRYPT_ITEM FUNCTION ==========")
    
    for item_name, item in test_items.items():
        print(f"\n----- Testing {item_name} -----")
        print(f"Original item: {item['_id']}, Category: {item['Category']}")
        
        # Test the decrypt_item function
        success, result = db_handler.decrypt_item(item)
        
        if success:
            print(f"Successfully decrypted {item_name}")
            
            # Get the decrypted PII value
            pii_value = result.get('PII')
            
            # Print the type and a preview
            print(f"PII type: {type(pii_value)}")
            if isinstance(pii_value, str) and len(pii_value) > 100:
                print(f"PII preview: {pii_value[:100]}...")
            else:
                print(f"PII value: {pii_value}")
        else:
            print(f"Failed to decrypt {item_name}: {result}")

def main():
    print("\n========== PII DECRYPTION TEST ==========")
    
    # Setup environment
    kms_handler = setup_environment()
    
    # Test basic encryption/decryption
    test_basic_encryption_decryption(kms_handler)
    
    # Initialize database handler
    print("\nInitializing database handler...")
    db_handler = DatabaseHandler(table_name="test_pii_table")
    
    # Create test items
    test_items = create_test_items()
    
    # Test decrypt_item function
    test_decrypt_item(db_handler, test_items)
    
    print("\nTest completed.")

if __name__ == "__main__":
    main()