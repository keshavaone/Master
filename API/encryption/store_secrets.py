"""
Secure secret management for the API.

This module provides utilities for retrieving secrets from AWS Secrets Manager
without hardcoding sensitive information.
"""

import os
import boto3
from botocore.exceptions import ClientError
import logging

# Configure logging
logger = logging.getLogger("api.encryption.store_secrets")
logger.setLevel(logging.INFO)

def get_secret():
    """
    Retrieve a secret from AWS Secrets Manager.

    Returns:
        str: The secret string value

    Raises:
        ClientError: If there's an issue retrieving the secret
    """
    # Get secret name from environment variables
    secret_name = os.environ.get("AWS_ACCESS_KEY_SECRET_NAME", "prod/AWS/AccessKey")
    region_name = os.environ.get("AWS_REGION", "us-east-1")

    try:
        # Create a Secrets Manager client
        session = boto3.session.Session()
        client = session.client(
            service_name='secretsmanager',
            region_name=region_name
        )

        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
        secret = get_secret_value_response['SecretString']
        logger.info(f"Successfully retrieved secret: {secret_name}")
        return secret
    except ClientError as e:
        # Handle specific error cases
        error_code = e.response['Error']['Code']
        if error_code == 'ResourceNotFoundException':
            logger.error(f"Secret {secret_name} not found")
        elif error_code == 'InvalidParameterException':
            logger.error(f"Invalid parameter when accessing secret {secret_name}")
        elif error_code == 'InvalidRequestException':
            logger.error(f"Invalid request when accessing secret {secret_name}")
        elif error_code == 'DecryptionFailureException':
            logger.error(f"Decryption failure for secret {secret_name}")
        elif error_code == 'AccessDeniedException':
            logger.error(f"Access denied to secret {secret_name}")
        else:
            logger.error(f"Error retrieving secret {secret_name}: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error retrieving secret: {e}")
        raise