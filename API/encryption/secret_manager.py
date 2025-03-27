
# api/encryption/secret_manager.py
"""
AWS Secrets Manager interface.

This module provides a secure interface for retrieving secrets from AWS Secrets Manager.
"""

import json
import logging
import os
from typing import Optional, Dict, Any

import boto3
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger("api.encryption.secrets")
logger.setLevel(logging.INFO)

class SecretManager:
    """
    AWS Secrets Manager interface.
    
    This class provides a secure interface for retrieving secrets from AWS Secrets Manager.
    """
    
    def __init__(self, region_name: str = None):
        """
        Initialize the secret manager.
        
        Args:
            region_name (str, optional): AWS region name. Defaults to environment variable or 'us-east-1'.
        """
        # Set up logging
        self.logger = logging.getLogger("api.encryption.secrets")
        
        # Get region from environment or parameter
        self.region_name = region_name or os.environ.get('AWS_REGION', 'us-east-1')
        
        # Initialize AWS client
        self.secrets_client = boto3.client('secretsmanager', region_name=self.region_name)
        
        # Log initialization
        self.logger.info(f"Secret manager initialized with region: {self.region_name}")
    
    def get_secret(self, secret_name: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a secret from AWS Secrets Manager.
        
        Args:
            secret_name (str): Name of the secret
            
        Returns:
            Optional[Dict[str, Any]]: Secret data or None if error
        """
        try:
            # Get the secret value
            self.logger.info(f"Retrieving secret: {secret_name}")
            response = self.secrets_client.get_secret_value(SecretId=secret_name)
            
            # Get the secret string
            secret_string = response['SecretString']
            
            # Parse JSON
            try:
                secret_data = json.loads(secret_string)
                return secret_data
            except json.JSONDecodeError:
                # If not JSON, return as a simple string
                return {"value": secret_string}
                
        except ClientError as e:
            self.logger.error(f"Error retrieving secret {secret_name}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error retrieving secret {secret_name}: {e}")
            return None
    
    def create_or_update_secret(self, secret_name: str, secret_data: Dict[str, Any]) -> bool:
        """
        Create or update a secret in AWS Secrets Manager.
        
        Args:
            secret_name (str): Name of the secret
            secret_data (Dict[str, Any]): Secret data
            
        Returns:
            bool: True if successful
        """
        try:
            # Convert data to JSON string
            secret_string = json.dumps(secret_data)
            
            # Check if secret exists
            try:
                self.secrets_client.get_secret_value(SecretId=secret_name)
                
                # Secret exists, update it
                self.logger.info(f"Updating secret: {secret_name}")
                self.secrets_client.update_secret(
                    SecretId=secret_name,
                    SecretString=secret_string
                )
            except self.secrets_client.exceptions.ResourceNotFoundException:
                # Secret doesn't exist, create it
                self.logger.info(f"Creating new secret: {secret_name}")
                self.secrets_client.create_secret(
                    Name=secret_name,
                    SecretString=secret_string
                )
            
            self.logger.info(f"Secret {secret_name} saved successfully")
            return True
            
        except ClientError as e:
            self.logger.error(f"AWS error saving secret {secret_name}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error saving secret {secret_name}: {e}")
            return False
    
    def delete_secret(self, secret_name: str, recovery_window_days: int = 30) -> bool:
        """
        Delete a secret from AWS Secrets Manager.
        
        Args:
            secret_name (str): Name of the secret
            recovery_window_days (int): Recovery window in days
            
        Returns:
            bool: True if successful
        """
        try:
            # Delete the secret
            self.logger.info(f"Deleting secret: {secret_name}")
            self.secrets_client.delete_secret(
                SecretId=secret_name,
                RecoveryWindowInDays=recovery_window_days
            )
            
            self.logger.info(f"Secret {secret_name} deleted successfully")
            return True
            
        except ClientError as e:
            self.logger.error(f"AWS error deleting secret {secret_name}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error deleting secret {secret_name}: {e}")
            return False

