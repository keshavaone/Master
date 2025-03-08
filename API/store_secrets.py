# Use this code snippet in your app.
# If you need more information about configurations
# or implementing the sample code, visit the AWS docs:
# https://aws.amazon.com/developer/language/python/

import boto3
from botocore.exceptions import ClientError


def get_secret():
    """
    Retrieve a secret from AWS Secrets Manager.
    
    Returns:
        str: The secret string value
        
    Raises:
        ClientError: If there's an issue retrieving the secret
    """
    secret_name = "prod/AWS/AccessKey"
    region_name = "us-east-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
        secret = get_secret_value_response['SecretString']
        return secret
    except ClientError as e:
        # Add more specific error handling here if needed
        print(f"Error retrieving secret: {e}")
        raise