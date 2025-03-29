
# api/data/database.py
"""
Database interface for the API.

This module provides the database interface for storing and retrieving data.
"""

import os
import logging
import uuid
from typing import Dict, Any, List, Optional, Union, Tuple
from datetime import datetime

import boto3
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError

from api.data.models import PIIItemCreate, PIIItemUpdate, PIIItemDelete, PIIItemResponse, AuditLogEntry
from api.encryption import get_kms_handler

# Configure logging
logger = logging.getLogger("api.data.database")
logger.setLevel(logging.DEBUG)

class DatabaseHandler:
    """
    Database handler for DynamoDB.
    
    This class provides an interface for storing and retrieving data from DynamoDB.
    """
    
    def __init__(self, table_name: str = None, region_name: str = None):
        """
        Initialize the database handler.
        
        Args:
            table_name (str, optional): DynamoDB table name
            region_name (str, optional): AWS region name
        """
        # Set up logging
        self.logger = logging.getLogger("api.data.database")
        
        # Get configuration
        self.table_name = table_name or os.environ.get('DYNAMODB_TABLE_NAME', 'myPII')
        self.region_name = region_name or os.environ.get('AWS_REGION', 'us-east-1')
        
        # Initialize DynamoDB client and table
        self.dynamodb = boto3.resource('dynamodb', region_name=self.region_name)
        self.table = self.dynamodb.Table(self.table_name)
        
        # Get KMS handler for encryption
        self.kms_handler = get_kms_handler()
        
        # Track current operation for logging
        self.operation_id = str(uuid.uuid4())
        
        # Log initialization
        self.logger.info(f"Database handler initialized with table: {self.table_name}")
    
    def get_all_items(self) -> Tuple[bool, Union[List[Dict[str, Any]], str]]:
        """
        Get all items from the database.
        
        Returns:
            Tuple[bool, Union[List[Dict], str]]: Success flag and items or error message
        """
        try:
            # Get all items from the table
            response = self.table.scan()
            items = response.get('Items', [])
            
            # Handle pagination if there are more items
            while 'LastEvaluatedKey' in response:
                response = self.table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
                items.extend(response.get('Items', []))
            # Log success
            self.logger.info(f"Retrieved {len(items)} items from database")
            return True, items
        except ClientError as e:
            error_msg = f"DynamoDB client error: {e}"
            self.logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Unexpected error retrieving items: {e}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def get_items_by_category(self, category: str) -> Tuple[bool, Union[List[Dict[str, Any]], str]]:
        """
        Get items by category.
        
        Args:
            category (str): Category to filter by
            
        Returns:
            Tuple[bool, Union[List[Dict], str]]: Success flag and items or error message
        """
        try:
            # Query items by category
            response = self.table.scan(
                FilterExpression=Attr('Category').eq(category)
            )
            items = response.get('Items', [])
            
            # Handle pagination if there are more items
            while 'LastEvaluatedKey' in response:
                response = self.table.scan(
                    ExclusiveStartKey=response['LastEvaluatedKey'],
                    FilterExpression=Attr('Category').eq(category)
                )
                items.extend(response.get('Items', []))
            
            # Log success
            self.logger.info(f"Retrieved {len(items)} items for category '{category}'")
            return True, items
        except ClientError as e:
            error_msg = f"DynamoDB client error: {e}"
            self.logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Unexpected error retrieving items by category: {e}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def get_item_by_type(self, item_type: str) -> Tuple[bool, Union[Dict[str, Any], str]]:
        """
        Get item by type.
        
        Args:
            item_type (str): Type to filter by
            
        Returns:
            Tuple[bool, Union[Dict, str]]: Success flag and item or error message
        """
        try:
            # Query items by type
            response = self.table.scan(
                FilterExpression=Attr('Type').eq(item_type)
            )
            items = response.get('Items', [])
            
            if not items:
                self.logger.warning(f"No item found for type '{item_type}'")
                return False, f"No item found for type '{item_type}'"
            
            # Return the first item (there should only be one)
            item = items[0]
            
            # Log success
            self.logger.info(f"Retrieved item for type '{item_type}'")
            return True, item
        except ClientError as e:
            error_msg = f"DynamoDB client error: {e}"
            self.logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Unexpected error retrieving item by type: {e}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def get_item_by_id(self, item_id: str) -> Tuple[bool, Union[Dict[str, Any], str]]:
        """
        Get item by ID.
        
        Args:
            item_id (str): ID of the item to retrieve
            
        Returns:
            Tuple[bool, Union[Dict, str]]: Success flag and item or error message
        """
        try:
            # Get the item by its ID
            response = self.table.get_item(
                Key={'_id': item_id}
            )
            
            # Check if the item exists
            if 'Item' not in response:
                self.logger.warning(f"No item found with ID: {item_id}")
                return False, f"No item found with ID: {item_id}"
            
            # Return the item
            item = response['Item']
            
            # Log success
            self.logger.info(f"Retrieved item with ID: {item_id}")
            return True, item
        except ClientError as e:
            error_msg = f"DynamoDB client error: {e}"
            self.logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Unexpected error retrieving item: {e}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def decrypt_item(self, item: Dict[str, Any]) -> Tuple[bool, Union[Dict[str, Any], str]]:
        """
        Decrypt an item's PII data.
        
        Args:
            item (Dict): Item to decrypt
            
        Returns:
            Tuple[bool, Union[Dict, str]]: Success flag and decrypted item or error message
        """
        try:
            # Clone the item to avoid modifying the original
            decrypted_item = item.copy()
            
            # Check if PII field exists
            if 'PII' not in decrypted_item:
                self.logger.warning(f"Item has no PII field: {decrypted_item.get('_id', 'unknown')}")
                return False, "Item has no PII field"
            
            # Get the encrypted PII data
            encrypted_pii = decrypted_item['PII']
            
            # Try to decrypt the PII data
            if isinstance(encrypted_pii, str):
                # Check if it's base64 encoded
                if self.kms_handler.is_base64(encrypted_pii):
                    # Decode base64 and decrypt
                    decrypted_pii = self.kms_handler.decrypt_to_string(encrypted_pii)
                else:
                    # Try to decrypt directly
                    decrypted_pii = self.kms_handler.decrypt_to_string(encrypted_pii.encode('utf-8'))
            else:
                # Try to decrypt directly
                decrypted_pii = self.kms_handler.decrypt_to_string(encrypted_pii)
            
            # Check if decryption was successful
            if not decrypted_pii:
                self.logger.warning(f"Failed to decrypt PII data for item: {decrypted_item.get('_id', 'unknown')}")
                return False, "Failed to decrypt PII data"
            
            # Update the item with decrypted PII data
            decrypted_item['PII'] = decrypted_pii
            
            # Log success
            self.logger.info(f"Decrypted PII data for item: {decrypted_item.get('_id', 'unknown')}")
            return True, decrypted_item
        except Exception as e:
            error_msg = f"Unexpected error decrypting item: {e}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def create_item(self, item: PIIItemCreate, user_id: str, auth_type: str) -> Tuple[bool, Union[Dict[str, Any], str]]:
        """
        Create a new item in the database.
        
        Args:
            item (PIIItemCreate): Item to create
            user_id (str): ID of the user performing the action
            auth_type (str): Authentication type used
            
        Returns:
            Tuple[bool, Union[Dict, str]]: Success flag and created item or error message
        """
        try:
            # Generate a unique ID for the item
            item_id = str(uuid.uuid4())
            
            # Generate an operation ID for this transaction
            operation_id = str(uuid.uuid4())
            
            # Log the operation
            self.logger.info(f"Creating new item with ID: {item_id} (Operation: {operation_id})")
            
            # Encrypt the PII data
            encrypted_pii = self.kms_handler.encrypt_to_base64(item.pii)
            if not encrypted_pii:
                self.logger.error(f"Failed to encrypt PII data for new item: {item_id}")
                return False, "Failed to encrypt PII data"
            
            # Create the item
            db_item = {
                '_id': item_id,
                'Category': item.category,
                'Type': item.type,
                'PII': encrypted_pii,
                'created_at': datetime.now().isoformat(),
                'created_by': user_id
            }
            
            # Put the item in the database
            response = self.table.put_item(Item=db_item)
            
            # Check if the operation was successful
            if response['ResponseMetadata']['HTTPStatusCode'] != 200:
                self.logger.error(f"Failed to create item: {item_id}")
                return False, "Failed to create item"
            
            # Log the audit trail
            self._log_audit_event(
                event_type="ITEM_CREATED",
                message=f"Item created: {item_id}",
                user_id=user_id,
                auth_type=auth_type,
                details={
                    "item_id": item_id,
                    "category": item.category,
                    "type": item.type,
                    "operation_id": operation_id
                }
            )
            
            # Log success
            self.logger.info(f"Created item: {item_id} (Operation: {operation_id})")
            return True, db_item
        except ClientError as e:
            error_msg = f"DynamoDB client error: {e}"
            self.logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Unexpected error creating item: {e}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def update_item(self, item: PIIItemUpdate, user_id: str, auth_type: str) -> Tuple[bool, Union[Dict[str, Any], str]]:
        """
        Update an item in the database.
        
        Args:
            item (PIIItemUpdate): Item to update
            user_id (str): ID of the user performing the action
            auth_type (str): Authentication type used
            
        Returns:
            Tuple[bool, Union[Dict, str]]: Success flag and updated item or error message
        """
        try:
            # Generate an operation ID for this transaction
            operation_id = str(uuid.uuid4())
            
            # Log the operation
            self.logger.info(f"Updating item with ID: {item.id} (Operation: {operation_id})")
            
            # First check if the item exists
            try:
                response = self.table.get_item(Key={'_id': item.id})
                if 'Item' not in response:
                    self.logger.warning(f"Item not found for update: {item.id}")
                    return False, f"Item not found with ID: {item.id}"
                    
                existing_item = response['Item']
            except ClientError as e:
                error_msg = f"DynamoDB client error checking item existence: {e}"
                self.logger.error(error_msg)
                return False, error_msg

            # Set up update expression and expression attribute values and names
            update_expression_parts = []
            expression_values = {
                ":updated_at": datetime.now().isoformat(),
                ":updated_by": user_id
            }
            expression_names = {}  # To handle reserved keywords
            
            # Build update expression based on provided fields
            if item.pii is not None:
                # Encrypt the PII data if provided
                encrypted_pii = self.kms_handler.encrypt_to_base64(item.pii)
                if not encrypted_pii:
                    self.logger.error(f"Failed to encrypt PII data for item: {item.id}")
                    return False, "Failed to encrypt PII data"
                    
                update_expression_parts.append("PII = :pii")
                expression_values[":pii"] = encrypted_pii
            
            # Add category if provided
            if item.category is not None:
                update_expression_parts.append("Category = :category")
                expression_values[":category"] = item.category
            
            # Add type if provided - handle as reserved keyword
            if item.type is not None:
                # Use expression attribute names to handle reserved keyword
                update_expression_parts.append("#item_type = :type")
                expression_values[":type"] = item.type
                expression_names["#item_type"] = "Type"  # Map #item_type to the actual attribute name
            
            # Always update the metadata
            update_expression_parts.append("updated_at = :updated_at")
            update_expression_parts.append("updated_by = :updated_by")
            
            # Construct the final update expression
            update_expression = "SET " + ", ".join(update_expression_parts)
            
            # Prepare update parameters
            update_params = {
                "Key": {'_id': item.id},
                "UpdateExpression": update_expression,
                "ExpressionAttributeValues": expression_values,
                "ReturnValues": "ALL_NEW"
            }
            
            # Add expression attribute names if any
            if expression_names:
                update_params["ExpressionAttributeNames"] = expression_names
            
            # Update the item
            response = self.table.update_item(**update_params)
            
            # Check if the operation was successful
            if response['ResponseMetadata']['HTTPStatusCode'] != 200:
                self.logger.error(f"Failed to update item: {item.id}")
                return False, "Failed to update item"
            
            # Get the updated item
            updated_item = response.get('Attributes', {})
            
            # Log the audit trail
            self._log_audit_event(
                event_type="ITEM_UPDATED",
                message=f"Item updated: {item.id}",
                user_id=user_id,
                auth_type=auth_type,
                details={
                    "item_id": item.id,
                    "category": item.category,
                    "type": item.type,
                    "operation_id": operation_id,
                    "updated_fields": [field for field in ["category", "type", "pii"] 
                                    if getattr(item, field) is not None]
                }
            )
            
            # Log success
            self.logger.info(f"Updated item: {item.id} (Operation: {operation_id})")
            return True, updated_item
        except ClientError as e:
            error_msg = f"DynamoDB client error: {e}"
            self.logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Unexpected error updating item: {e}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def delete_item(self, item: PIIItemDelete, user_id: str, auth_type: str) -> Tuple[bool, Union[Dict[str, Any], str]]:
        """
        Delete an item from the database.
        
        Args:
            item (PIIItemDelete): Item to delete
            user_id (str): ID of the user performing the action
            auth_type (str): Authentication type used
            
        Returns:
            Tuple[bool, Union[Dict, str]]: Success flag and deleted item or error message
        """
        try:
            # Generate an operation ID for this transaction
            operation_id = str(uuid.uuid4())
            
            # Log the operation
            self.logger.info(f"Deleting item with ID: {item.id} (Operation: {operation_id})")
            
            # Delete the item
            response = self.table.delete_item(
                Key={'_id': item.id},
                ReturnValues="ALL_OLD"
            )
            
            # Check if the operation was successful
            if response['ResponseMetadata']['HTTPStatusCode'] != 200:
                self.logger.error(f"Failed to delete item: {item.id}")
                return False, "Failed to delete item"
            
            # Get the deleted item
            deleted_item = response.get('Attributes', {})
            
            # Check if the item existed
            if not deleted_item:
                self.logger.warning(f"Item not found for deletion: {item.id}")
                return False, "Item not found"
            
            # Log the audit trail
            self._log_audit_event(
                event_type="ITEM_DELETED",
                message=f"Item deleted: {item.id}",
                user_id=user_id,
                auth_type=auth_type,
                details={
                    "item_id": item.id,
                    "category": deleted_item.get('Category'),
                    "type": deleted_item.get('Type'),
                    "operation_id": operation_id
                }
            )
            
            # Log success
            self.logger.info(f"Deleted item: {item.id} (Operation: {operation_id})")
            return True, deleted_item
        except ClientError as e:
            error_msg = f"DynamoDB client error: {e}"
            self.logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Unexpected error deleting item: {e}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def _log_audit_event(self, event_type: str, message: str, user_id: str, auth_type: str, details: Dict[str, Any] = None):
        """
        Log an audit event.
        
        Args:
            event_type (str): Type of event
            message (str): Event message
            user_id (str): User who performed the action
            auth_type (str): Authentication type used
            details (Dict, optional): Additional event details
        """
        try:
            # Get the client IP from the details if available
            client_ip = details.get('client_ip', 'unknown') if details else 'unknown'
            
            # Create an audit log entry
            audit_entry = AuditLogEntry(
                event_type=event_type,
                message=message,
                user_id=user_id,
                auth_type=auth_type,
                client_ip=client_ip,
                details=details
            )
            
            # Log the entry
            self.logger.info(f"AUDIT: {audit_entry.json()}")
            
            # In a real application, you might want to store audit logs somewhere
            # For example, in a dedicated DynamoDB table or CloudWatch Logs
        except Exception as e:
            self.logger.error(f"Failed to log audit event: {e}")


