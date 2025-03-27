import boto3
from boto3.dynamodb.conditions import Attr
from dataclasses import dataclass, field
import base64
import os
import io
import time
import pandas as pd
import atexit
from API.store_secrets import get_secret
import ast
import API.CONSTANTS as CONSTANTS
from API.KMS import KMS
from bson.objectid import ObjectId
import uuid
import json
from datetime import datetime


@dataclass(eq=False, repr=False, order=False)
class Agent:
    """
    Agent class for handling secure data operations and encryption.

    Attributes:
        s3 (str): S3 bucket name for storage
        file_name (str): File name for data storage
        input_path (str): Path for request input
        stored_file_names (list): List of stored file names
        auth_context (dict): Authentication context for tracking operations
    """
    file_name: str
    input_path: str = 'ReQuest.txt'
    session_token: str = None
    stored_file_names: list[str] = field(default_factory=list)
    auth_context: dict = field(default_factory=dict)

    def __post_init__(self):
        """Initialize the Agent with necessary resources and connections."""
        # Change to the current directory
        os.chdir(os.path.dirname(os.path.realpath(__file__)))
        self.data_path = self.file_name
        self.operation_id = str(uuid.uuid4())  # Track operation ID for audit

        try:
            # Get secrets
            self.__secret = ast.literal_eval(get_secret())
        except Exception as e:
            print(f"Error fetching secrets: {e}")
            raise

        if self.__secret is not None:
            # Initialize S3 - ensure we're using the original key fetching method
            # that was working before
            self.__encoded_key = self.__secret['S3_KEY_ID']
            assert self.__encoded_key is not None, "S3 key not found in secrets"
            self.s3 = boto3.client('s3', region_name="us-east-1",
                                          aws_access_key_id=self.__secret['S3_ACCESS_KEY_ID'],
                                          aws_secret_access_key=self.__secret['S3_SECRET_ACCESS_KEY_ID'])
            print('S3 Client Initialized Successfully')

            # DynamoDB setup
            dynamodb = boto3.resource('dynamodb', region_name="us-east-1")
            table_name = "myPII"
            self.collection = dynamodb.Table(table_name)
            self.__df = self.refresh_data()

            # Initialize KMS - ensure we're using the original key fetching method
            # that was working before
            self.__encoded_key = self.__secret['KMS_KEY_ID']
            assert self.__encoded_key is not None, "KMS key not found in secrets"
            self.kms_client = KMS()
            self.cipher_suite = self.kms_client.decrypt_my_key(self.__encoded_key)
            print('KMS Key Decrypted Successfully')
            # Register cleanup handler
            atexit.register(self.end_work)
            self.chosen_one = None  # Initialize chosen_one attribute
            
            # Initialize security audit trail
            self.audit_trail = []
       
        
    def set_auth_context(self, user_id: str, auth_type: str, client_ip: str = None):
        """
        Set authentication context for audit and operations.
        
        Args:
            user_id (str): ID of the authenticated user
            auth_type (str): Type of authentication used
            client_ip (str, optional): Client IP address
        """
        self.auth_context = {
            "user_id": user_id,
            "auth_type": auth_type,
            "client_ip": client_ip,
            "session_id": str(uuid.uuid4()),
            "login_time": datetime.now().isoformat()
        }
        
        # Log the context for audit
        self._log_security_event(
            "AUTH_CONTEXT_SET", 
            f"Authentication context set for user {user_id}"
        )

    def _log_security_event(self, event_type: str, message: str, details: dict = None):
        """
        Log a security event for audit purposes.
        
        Args:
            event_type (str): Type of security event
            message (str): Event message
            details (dict, optional): Additional event details
        """
        event = {
            "timestamp": datetime.now().isoformat(),
            "operation_id": self.operation_id,
            "event_type": event_type,
            "message": message,
            "user_id": self.auth_context.get("user_id", "unknown"),
            "auth_type": self.auth_context.get("auth_type", "unknown"),
            "client_ip": self.auth_context.get("client_ip", "unknown")
        }
        
        if details:
            event["details"] = details
            
        # Add to in-memory audit trail
        self.audit_trail.append(event)
        
        # Log the event
        print(f"SECURITY EVENT: {json.dumps(event)}")
    
    def validate_session(self):
        """Validate the session token."""
        return bool(self.session_token)

    def fetch_my_key(self):
        """
        Fetch and decrypt the KMS key.

        Raises:
            AssertionError: If KMS key is not found
        """
        try:
            self.__encoded_key = self.__secret['KMS_KEY_ID']
            assert self.__encoded_key is not None, "KMS key not found in secrets"
            self.kms_client = KMS()
            self.cipher_suite = self.kms_client.decrypt_my_key(
                self.__encoded_key)
        except Exception as e:
            print(f"Error fetching key: {e}")
            raise

    
    
    def process_request(self):
        """
        Process an input request.

        Returns:
            Various: The processed output based on the request type
        """
        input_request = self.process_file('r')
        if input_request == 'Download':
            self.download_excel()
            output = self.data_path
        elif input_request == 'Re-Encrypt':
            self.upload_securely()
            output = 'Success'
        else:
            data = self.filter_from_db(input_request)
            pre_output = self.decrypt_data(data)
            post_output = pd.DataFrame(data=pd.read_json(
                io.StringIO(pre_output), orient='records'))
            output = post_output.set_index('Item Name').to_json()
        print('Processed: ', input_request)
        os.remove(self.input_path)
        return output  # Added return statement
    
    def filter_from_db(self, item_name=None, download_request=False):
        """
        Filter data from the database with enhanced error handling.

        Args:
            item_name (str, optional): Name of the item to filter
            download_request (bool, optional): Flag for download requests

        Returns:
            bytes or int: Filtered data or 0 for download requests
        """
        if download_request:
            return 0
        elif item_name is not None:
            try:
                # Make sure we have the latest data
                try:
                    if self.__df is None or self.__df.empty:
                        self.__df = self.refresh_data()
                except Exception as refresh_error:
                    self._log_security_event(
                        "DATA_REFRESH_ERROR", 
                        f"Error refreshing data: {str(refresh_error)}"
                    )
                    # Continue with existing data if refresh fails
                
                # Ensure DataFrame exists and has the right columns
                if self.__df is None or not isinstance(self.__df, pd.DataFrame):
                    self._log_security_event(
                        "DATA_ACCESS_ERROR", 
                        f"Invalid DataFrame: {type(self.__df)}"
                    )
                    return None
                    
                if 'Type' not in self.__df.columns or 'PII' not in self.__df.columns:
                    self._log_security_event(
                        "DATA_FORMAT_ERROR", 
                        f"Missing required columns. Available: {list(self.__df.columns)}"
                    )
                    return None
                
                # Filter for the requested item
                filtered_df = self.__df[self.__df['Type'] == item_name]

                # Check if the filtered DataFrame is not empty
                if not filtered_df.empty:
                    try:
                        # Get the PII data
                        pii_data = filtered_df['PII'].values[0]
                        
                        # Handle different potential formats
                        if isinstance(pii_data, bytes):
                            return pii_data
                        elif isinstance(pii_data, str):
                            # Check if it's base64 encoded
                            if self.kms_client.is_base64(pii_data):
                                try:
                                    # Fix potential padding issues
                                    padded_data = self.kms_client._fix_base64_padding(pii_data)
                                    return base64.b64decode(padded_data)
                                except Exception as decode_error:
                                    self._log_security_event(
                                        "BASE64_DECODE_ERROR", 
                                        f"Error decoding base64 for {item_name}: {str(decode_error)}"
                                    )
                                    # Return as-is if decode fails
                                    return pii_data.encode('utf-8')
                            else:
                                # Not base64, return as bytes
                                return pii_data.encode('utf-8')
                        else:
                            # Convert other types to string then bytes
                            self._log_security_event(
                                "UNEXPECTED_TYPE", 
                                f"Unexpected PII data type for {item_name}: {type(pii_data)}"
                            )
                            return str(pii_data).encode('utf-8')
                            
                    except Exception as e:
                        self._log_security_event(
                            "DATA_ACCESS_ERROR", 
                            f"Error processing PII data for {item_name}: {str(e)}"
                        )
                        return None
                else:
                    # Handle the case where no matching item is found
                    self._log_security_event(
                        "ITEM_NOT_FOUND", 
                        f"No data found for item_name: {item_name}"
                    )
                    return None
            except Exception as e:
                self._log_security_event(
                    "FILTER_ERROR", 
                    f"Error in filter_from_db for {item_name}: {str(e)}"
                )
                return None
    
    def decrypt_data(self, data):
        """
        Decrypt data using KMS with robust error handling and recovery.

        Args:
            data (bytes or str): Data to decrypt

        Returns:
            str: Decrypted data or None if decryption fails
        """
        if not data:
            self._log_security_event(
                "DECRYPT_ERROR", 
                "Cannot decrypt None or empty data"
            )
            return None
        
        try:
            # Ensure KMS client is available
            if not hasattr(self, 'kms_client') or not self.kms_client:
                self._log_security_event(
                    "DECRYPT_ERROR", 
                    "KMS client not initialized"
                )
                return None
            
            # Try to repair data if needed
            try:
                # If data is str and looks like base64, decode it first
                if isinstance(data, str) and self.kms_client.is_base64(data):
                    padded_data = self.kms_client._fix_base64_padding(data)
                    data = base64.b64decode(padded_data)
            except Exception as repair_error:
                self._log_security_event(
                    "DATA_REPAIR_ATTEMPT", 
                    f"Failed to repair data: {repair_error}"
                )
                # Continue with original data if repair fails
            
            # Try different decryption methods based on what's available
            decrypted = None
            decrypt_error = None
            
            # First try the enhanced decrypt method if available
            if hasattr(self.kms_client, 'decrypt'):
                try:
                    decrypted_bytes = self.kms_client.decrypt(data)
                    if decrypted_bytes:
                        if isinstance(decrypted_bytes, str):
                            return decrypted_bytes
                        else:
                            try:
                                return decrypted_bytes.decode('utf-8')
                            except UnicodeDecodeError:
                                # Try different encodings if UTF-8 fails
                                return decrypted_bytes.decode('latin-1')
                except Exception as e:
                    decrypt_error = f"Enhanced decrypt failed: {str(e)}"
                    # Continue to next method if this fails
            
            # Fall back to legacy decrypt_data method if enhanced method failed or isn't available
            if not decrypted and hasattr(self.kms_client, 'decrypt_data'):
                try:
                    decrypted = self.kms_client.decrypt_data(data)
                except Exception as e:
                    if decrypt_error:
                        decrypt_error += f"; Legacy decrypt failed: {str(e)}"
                    else:
                        decrypt_error = f"Legacy decrypt failed: {str(e)}"
            
            # If both methods failed, try a direct approach as last resort
            if not decrypted and self.kms_client.cipher_suite:
                try:
                    # Ensure data is in bytes format
                    if isinstance(data, str):
                        try:
                            # Try to decode base64 if it looks like base64
                            padded_data = self.kms_client._fix_base64_padding(data)
                            data = base64.b64decode(padded_data)
                        except:
                            # If not base64, encode as UTF-8 bytes
                            data = data.encode('utf-8')
                    
                    # Direct decryption with Fernet
                    decrypted_bytes = self.kms_client.cipher_suite.decrypt(data)
                    if decrypted_bytes:
                        try:
                            return decrypted_bytes.decode('utf-8')
                        except UnicodeDecodeError:
                            # Try different encodings if UTF-8 fails
                            return decrypted_bytes.decode('latin-1')
                except Exception as e:
                    if decrypt_error:
                        decrypt_error += f"; Direct decrypt failed: {str(e)}"
                    else:
                        decrypt_error = f"Direct decrypt failed: {str(e)}"
            
            # Log failure if all methods failed
            if not decrypted:
                self._log_security_event(
                    "DECRYPT_FAILED", 
                    decrypt_error or "All decryption methods failed"
                )
            
            return decrypted
            
        except Exception as e:
            self._log_security_event(
                "DECRYPT_ERROR", 
                f"Unexpected error in decrypt_data: {str(e)}"
            )
            return None
    def get_all_data(self):
        """
        Get all data with improved decryption and robust error handling.

        Returns:
            List[Dict]: All decrypted data as a list of dictionaries
        """
        df = self.refresh_data()
        if df is None or df.empty:
            return []
        data = []
        # self.decrypt_data(base64.b64decode(return_item['PII']))
        for index, row in df.iterrows():
            item = {
                'Category': row['Category'],
                'Type': row['Type']
            }
            try:
                item['PII'] = self.decrypt_data(base64.b64decode(row['PII']))
            except Exception as e:
                item['PII'] = f"Error decrypting data: {str(e)}"
            data.append(item)
        return data
    
    def read_excel_from_file(self, file_path):
        """
        Read Excel data from a file.

        Args:
            file_path (str): Path to the Excel file

        Returns:
            DataFrame: The Excel data

        Raises:
            FileNotFoundError: If the file is not found
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        df = pd.read_excel(file_path)
        return df

    def read_excel_from_s3(self, bucket_name, object_key):
        """
        Read Excel data from an S3 bucket.

        Args:
            bucket_name (str): S3 bucket name
            object_key (str): Object key in the bucket

        Returns:
            DataFrame or None: The Excel data or None if error
        """
        s3 = boto3.client('s3')
        try:
            response = s3.get_object(Bucket=bucket_name, Key=object_key)
            excel_data = response['Body'].read()
            df = pd.read_excel(io.BytesIO(excel_data))
            return df
        except Exception as e:
            print(f"Error reading Excel file from S3: {e}")
            return None

    def refresh_data(self):
        """
        Refresh data from the database.

        Returns:
            DataFrame: The refreshed data
        """
        return pd.DataFrame(self.collection.scan()['Items'])

    

    def get_one_data(self,type_value):
        """
        Get a specific data item.

        Returns:
            str: The data item
        """
        filters = dict()
        filters['Type'] = type_value
        
        return_item = self.collection.scan(FilterExpression=Attr('Type').eq(filters['Type']))['Items'][0]
        return self.decrypt_data(base64.b64decode(return_item['PII']))

    def insert_new_data(self, item):
        """
        Insert new data with encryption and audit logging.

        Args:
            item (dict): Data to insert

        Returns:
            bool or Exception: True if successful, Exception if error
        """
        operation_id = str(uuid.uuid4())
        try:
            self._log_security_event(
                "DATA_INSERT_ATTEMPT", 
                f"Attempting to insert data for category {item.get('Category')}", 
                {"operation_id": operation_id}
            )
            
            encrypted_pii = base64.b64encode(
                self.cipher_suite.encrypt(
                    item['PII'].encode('utf-8')
                )
            ).decode('utf-8')
            
            item = {
                '_id': str(ObjectId()),
                'Category': item['Category'],
                'Type': item['Type'],
                'PII': encrypted_pii
            }
            
            response = self.collection.put_item(Item=item)
            success = response['ResponseMetadata']['HTTPStatusCode'] == 200
            
            if success:
                self._log_security_event(
                    "DATA_INSERT_SUCCESS", 
                    f"Successfully inserted data for category {item['Category']}",
                    {
                        "operation_id": operation_id,
                        "item_id": item['_id'],
                        "category": item['Category'],
                        "type": item['Type']
                    }
                )
            else:
                self._log_security_event(
                    "DATA_INSERT_FAILURE", 
                    f"Failed to insert data for category {item['Category']}",
                    {
                        "operation_id": operation_id,
                        "status_code": response['ResponseMetadata']['HTTPStatusCode']
                    }
                )
                
            return success
        except Exception as e:
            self._log_security_event(
                "DATA_INSERT_ERROR", 
                f"Error inserting data: {str(e)}",
                {"operation_id": operation_id}
            )
            return e

    def update_one_data(self, item):
        """
        Update existing data with improved error handling and audit logging.

        Args:
            item (dict): Data to update

        Returns:
            dict: Update response or error message
        """
        operation_id = str(uuid.uuid4())
        try:
            # Validate input
            if not isinstance(item, dict):
                error_msg = f"Invalid item type: {type(item)}, expected dict"
                self._log_security_event(
                    "DATA_UPDATE_ERROR", 
                    error_msg,
                    {"operation_id": operation_id}
                )
                return {"error": error_msg}
                
            # Check for _id field
            item_id = item.get('_id')
            if not item_id:
                error_msg = "Missing required field: _id"
                self._log_security_event(
                    "DATA_UPDATE_ERROR", 
                    error_msg,
                    {"operation_id": operation_id}
                )
                return {"error": error_msg}
                
            # Log update attempt
            self._log_security_event(
                "DATA_UPDATE_ATTEMPT", 
                f"Attempting to update data for ID {item_id}", 
                {"operation_id": operation_id}
            )
            
            # Check for PII field
            if 'PII' not in item:
                error_msg = "Missing required field: PII"
                self._log_security_event(
                    "DATA_UPDATE_ERROR", 
                    error_msg,
                    {"operation_id": operation_id}
                )
                return {"error": error_msg}
                
            # Encrypt PII data
            try:
                encrypted_pii = self.kms_client.encrypt_to_base64(item['PII'])
                if not encrypted_pii:
                    error_msg = "Failed to encrypt PII data"
                    self._log_security_event(
                        "DATA_UPDATE_ERROR", 
                        error_msg,
                        {"operation_id": operation_id}
                    )
                    return {"error": error_msg}
            except Exception as e:
                error_msg = f"Encryption error: {str(e)}"
                self._log_security_event(
                    "DATA_UPDATE_ERROR", 
                    error_msg,
                    {"operation_id": operation_id}
                )
                return {"error": error_msg}
                
            # Set up update operation
            updated_values = {"PII": encrypted_pii}
            update_expression = "SET " + ", ".join(f"{k} = :{k}" for k in updated_values.keys())
            expression_values = {f":{k}": v for k, v in updated_values.items()}
            
            # Log update details
            self._log_security_event(
                "DATA_UPDATE_DETAILS", 
                f"Updating PII for item ID {item_id}",
                {
                    "operation_id": operation_id,
                    "item_id": item_id,
                    "expression": update_expression,
                    "has_encrypted_pii": bool(encrypted_pii)
                }
            )

            # Perform update with error handling
            try:
                response = self.collection.update_item(
                    Key={"_id": item_id},
                    UpdateExpression=update_expression,
                    ExpressionAttributeValues=expression_values,
                    ReturnValues="UPDATED_NEW"
                )
                
                # Log success
                if 'Attributes' in response:
                    self._log_security_event(
                        "DATA_UPDATE_SUCCESS", 
                        f"Successfully updated data for ID {item_id}",
                        {
                            "operation_id": operation_id,
                            "item_id": item_id
                        }
                    )
                else:
                    self._log_security_event(
                        "DATA_UPDATE_WARNING", 
                        f"Update completed but no attributes returned for ID {item_id}",
                        {
                            "operation_id": operation_id,
                            "item_id": item_id,
                            "status_code": response.get('ResponseMetadata', {}).get('HTTPStatusCode')
                        }
                    )
                    
                return response
            except Exception as e:
                error_msg = f"DynamoDB update error: {str(e)}"
                self._log_security_event(
                    "DATA_UPDATE_ERROR", 
                    error_msg,
                    {"operation_id": operation_id, "item_id": item_id}
                )
                return {"error": error_msg}
                    
        except Exception as e:
            error_msg = f"Error updating data: {str(e)}"
            self._log_security_event(
                "DATA_UPDATE_ERROR", 
                error_msg,
                {"operation_id": operation_id}
            )
            return {"error": error_msg}

    def delete_one_data(self, item):
        """
        Delete data item with robust error handling and audit logging.

        Args:
            item (dict): Item to delete containing at least the _id field

        Returns:
            bool: True if deletion successful, or dict with error details
        """
        operation_id = str(uuid.uuid4())
        try:
            # Validate input
            if not isinstance(item, dict):
                error_msg = f"Invalid item type: {type(item)}, expected dict"
                self._log_security_event(
                    "DATA_DELETE_ERROR", 
                    error_msg,
                    {"operation_id": operation_id}
                )
                return {"error": error_msg}
                
            # Check for _id field
            item_id = item.get('_id')
            if not item_id:
                error_msg = "Missing required field: _id"
                self._log_security_event(
                    "DATA_DELETE_ERROR", 
                    error_msg,
                    {"operation_id": operation_id}
                )
                return {"error": error_msg}
                
            # Log delete attempt with ID
            self._log_security_event(
                "DATA_DELETE_ATTEMPT", 
                f"Attempting to delete data for ID {item_id}", 
                {"operation_id": operation_id}
            )
            
            # Add more contextual info to the log if available
            log_details = {
                "operation_id": operation_id,
                "item_id": item_id
            }
            
            # Add category and type if available
            if 'Category' in item:
                log_details["category"] = item['Category']
            if 'Type' in item:
                log_details["type"] = item['Type']

            # Perform deletion with error handling
            try:
                response = self.collection.delete_item(
                    Key={'_id': item_id},
                    ReturnValues="ALL_OLD"  # Get the deleted item for logging
                )
                
                # Check if something was actually deleted
                if 'Attributes' in response and response['Attributes']:
                    self._log_security_event(
                        "DATA_DELETE_SUCCESS", 
                        f"Successfully deleted data for ID {item_id}",
                        log_details
                    )
                    return True
                else:
                    # Item may not have existed
                    self._log_security_event(
                        "DATA_DELETE_WARNING", 
                        f"Delete operation completed but no item found with ID {item_id}",
                        log_details
                    )
                    # Still return True as the operation didn't fail
                    return True
                    
            except Exception as e:
                error_msg = f"DynamoDB delete error: {str(e)}"
                self._log_security_event(
                    "DATA_DELETE_ERROR", 
                    error_msg,
                    log_details
                )
                return {"error": error_msg}
                    
        except Exception as e:
            error_msg = f"Error deleting data: {str(e)}"
            self._log_security_event(
                "DATA_DELETE_ERROR", 
                error_msg,
                {"operation_id": operation_id}
            )
            return {"error": error_msg}

    # Add method to export audit trail (for compliance purposes)
    def export_audit_trail(self, file_path=None):
        """
        Export the security audit trail to a file.
        
        Args:
            file_path (str, optional): Path to save the audit trail
                If not provided, uses a default path
                
        Returns:
            str: Path to the exported audit trail file
        """
        if not file_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            file_path = f"security_audit_{timestamp}.json"
            
        try:
            # Add export event to trail
            self._log_security_event(
                "AUDIT_EXPORT", 
                f"Exporting audit trail to {file_path}"
            )
            
            # Write to file
            with open(file_path, 'w') as f:
                json.dump(self.audit_trail, f, indent=2)
                
            # Upload to S3 for secure storage
            if self.s3:
                s3_client = boto3.client('s3')
                s3_key = f"audit_logs/{os.path.basename(file_path)}"
                s3_client.upload_file(file_path, self.s3, s3_key)
                
                # Log the S3 upload
                self._log_security_event(
                    "AUDIT_EXPORT_S3", 
                    f"Uploaded audit trail to S3: {self.s3}/{s3_key}"
                )
                
            return file_path
            
        except Exception as e:
            print(f"Error exporting audit trail: {e}")
            return None

    def download_excel(self):
        """
        Download data to Excel with robust handling of different input types.

        Returns:
            bool: True if successful
        """
        try:
            # Get the data
            df = self.get_all_data()
            
            # Convert list to DataFrame if needed
            if isinstance(df, list):
                df = pd.DataFrame(df)
            
            # Ensure we have a DataFrame
            if not isinstance(df, pd.DataFrame):
                # logging.error(f"Unexpected data type for Excel download: {type(df)}")
                return False
            
            # Remove empty columns if any
            df = df.dropna(axis=1, how='all')
            
            # Ensure readable column names
            df.columns = [str(col).strip() for col in df.columns]
            
            # Write to Excel
            df.to_excel(self.data_path, index=False)
            
            print(f'Excel File Downloaded Successfully to {self.data_path}')
            return True
        
        except Exception as e:
            print(f"Error during Excel download: {str(e)}")
            return False

    def get_options_to_choose(self):
        """
        Get category options.

        Returns:
            list: List of unique categories
        """
        df = self.get_all_data()
        return list(set(df['Category'].to_list()))

    def get_sub_options_to_choose(self, category):
        """
        Get sub-options for a category.

        Args:
            category (str): Category to get sub-options for

        Returns:
            list: List of unique types for the category
        """
        try:
            # Log the operation for debugging
            self._log_security_event(
                "CATEGORY_SELECTION", 
                f"Getting sub-options for category: {category}"
            )
            
            # Get all data from the database
            df = self.get_all_data()
            
            # Handle different return types from get_all_data
            if isinstance(df, pd.DataFrame):
                # Standard case - we have a DataFrame
                # Filter the DataFrame by category
                df = df[df['Category'] == category]
                self.chosen_one = category
                
                # Get unique types and convert to a list of strings
                if 'Type' in df.columns:
                    return [str(t) for t in df['Type'].unique() if t is not None]
                else:
                    self._log_security_event(
                        "FORMAT_ERROR", 
                        f"DataFrame does not have a 'Type' column"
                    )
                    return []
                    
            elif isinstance(df, list):
                # Handle case where get_all_data returns a list of dictionaries
                filtered_items = []
                for item in df:
                    # Ensure item is a dictionary
                    if not isinstance(item, dict):
                        continue
                        
                    # Check if the item matches the category
                    if item.get('Category') == category:
                        # Add the Type to our results if it's not None and not already in the list
                        item_type = item.get('Type')
                        if item_type is not None and item_type not in filtered_items:
                            filtered_items.append(str(item_type))
                
                self.chosen_one = category
                return filtered_items
            else:
                # Unknown return type
                self._log_security_event(
                    "FORMAT_ERROR", 
                    f"get_all_data returned unknown type: {type(df)}"
                )
                return []
                
        except Exception as e:
            self._log_security_event(
                "DATA_ACCESS_ERROR", 
                f"Error getting sub-options for {category}: {str(e)}"
            )
            return []

    def get_final_output(self, type_value):
        """
        Get final output for a specific type.

        Args:
            type_value (str): Type to get output for

        Returns:
            Various: The parsed output
        """
        try:
            # Log the operation for debugging
            self._log_security_event(
                "TYPE_SELECTION", 
                f"Getting data for type: {type_value}"
            )
            
            # Make sure chosen_one is set
            if not hasattr(self, 'chosen_one') or self.chosen_one is None:
                self._log_security_event(
                    "DATA_ACCESS_ERROR", 
                    "No category selected (chosen_one is None)"
                )
                return ["No category selected. Please select a category first."]
                
            # Get all data
            df = self.get_all_data()
            
            # Handle different return types from get_all_data
            if isinstance(df, pd.DataFrame):
                # Standard case - we have a DataFrame
                # Filter by category and type
                df = df[df['Category'] == self.chosen_one]
                df = df[df['Type'] == type_value]
                
                # Check if we have results
                if df.empty:
                    self._log_security_event(
                        "DATA_ACCESS_ERROR", 
                        f"No data found for category={self.chosen_one}, type={type_value}"
                    )
                    return ["No data found for this selection."]
                    
                # Get the PII data
                try:
                    pii_data = df['PII'].iloc[0]
                    
                    # Try to parse the PII data as a list of dictionaries
                    try:
                        return ast.literal_eval(pii_data)
                    except (ValueError, SyntaxError):
                        # Try again with newlines replaced
                        try:
                            return ast.literal_eval(pii_data.replace('\n', ' THIS_IS_NEW_LINE '))
                        except (ValueError, SyntaxError):
                            # Return the raw string if parsing fails
                            return [{"Item Name": "Raw Data", "Data": pii_data}]
                except (IndexError, KeyError) as e:
                    self._log_security_event(
                        "DATA_ACCESS_ERROR", 
                        f"Error accessing PII data: {str(e)}"
                    )
                    return ["Error accessing data."]
                    
            elif isinstance(df, list):
                # Handle case where get_all_data returns a list of dictionaries
                matching_items = []
                
                for item in df:
                    # Ensure item is a dictionary
                    if not isinstance(item, dict):
                        continue
                        
                    # Check if the item matches both category and type
                    if item.get('Category') == self.chosen_one and item.get('Type') == type_value:
                        # Get the PII data
                        pii_data = item.get('PII')
                        if pii_data:
                            # Try to parse the PII data
                            try:
                                return ast.literal_eval(pii_data)
                            except (ValueError, SyntaxError):
                                # Try again with newlines replaced
                                try:
                                    return ast.literal_eval(pii_data.replace('\n', ' THIS_IS_NEW_LINE '))
                                except (ValueError, SyntaxError):
                                    # Return as a simple dict if parsing fails
                                    return [{"Item Name": "Raw Data", "Data": pii_data}]
                        else:
                            matching_items.append({"Item Name": "Error", "Data": "No PII data found"})
                
                # If we found matching items but couldn't return earlier
                if matching_items:
                    return matching_items
                    
                # If we didn't find any matching items
                self._log_security_event(
                    "DATA_ACCESS_ERROR", 
                    f"No data found for category={self.chosen_one}, type={type_value}"
                )
                return ["No data found for this selection."]
                
            else:
                # Unknown return type
                self._log_security_event(
                    "FORMAT_ERROR", 
                    f"get_all_data returned unknown type: {type(df)}"
                )
                return ["Error: Unexpected data format."]
                
        except Exception as e:
            self._log_security_event(
                "DATA_ACCESS_ERROR", 
                f"Error getting data for {type_value}: {str(e)}"
            )
            return [{"Item Name": "Error", "Data": f"An error occurred: {str(e)}"}]

    def perform_specific_output(self):
        """
        Perform specific output based on user input.

        This is a CLI function for debug/testing purposes.
        """
        # Fetch all data
        df = self.get_all_data()

        # Get unique categories
        categories = list(set(df['Category'].to_list()))
        for i, category in enumerate(categories):
            print(i, ':', category)

        # Input for selecting a category
        input_category = int(input('Enter the category number: '))
        selected_category = categories[input_category]

        # Filter dataframe based on selected category
        filtered_df = df[df['Category'] == selected_category]

        # Get unique types within the filtered category
        types = list(set(filtered_df['Type'].to_list()))
        for i, type_name in enumerate(types):
            print(i, ':', type_name)

        # Input for selecting a type
        input_type = int(input('Enter the type number: '))
        selected_type = types[input_type]

        # Further filter dataframe based on selected type
        filtered_df = filtered_df[filtered_df['Type'] == selected_type]

        # Extract and parse the PII data
        data_item = filtered_df['PII'].iloc[0].replace(
            '\n', ' THIS_IS_NEW_LINE ')
        data = ast.literal_eval(data_item)

        # Print items in the PII data
        for item in data:
            try:
                print(item['Item Name'], ':', item['Data'])
            except KeyError:
                print(item)

    @staticmethod
    def isBase64(sb):
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

    def process_file(self, mode, data=None, file_path=None):
        """
        Process file operations.

        Args:
            mode (str): File mode (r/w)
            data (str, optional): Data to write
            file_path (str, optional): Path to file

        Returns:
            str or bool: File contents or success status
        """
        if file_path:
            path = file_path
        else:
            path = self.input_path
        if 'r' in mode:
            with open(path, mode) as f:
                data = f.read()
        elif 'w' in mode:
            with open(path, mode) as f:
                f.write(data)
                self.stored_file_names.append(path)
                print('Stored: ', path)
                return True
        return data

    def upload_securely(self):
        """
        Upload data securely to S3.

        Returns:
            bool: True if successful
        """
        self.refresh_data().to_csv(CONSTANTS.DATA_FILE_CSV,
                                   columns=['Type', 'Category', 'PII'])
        s3 = boto3.client('s3')
        df = pd.read_csv(CONSTANTS.DATA_FILE_CSV)
        for i in df.index:
            if df.loc[i, 'Type'] == 'KeyID':
                pass
            else:
                df.loc[i, 'PII'] = base64.b64encode(self.cipher_suite.encrypt(
                    df.loc[i, 'PII'].encode('utf-8'))).decode('utf-8')
        try:
            df.to_csv(CONSTANTS.DATA_FILE_CSV, index=False)
            with open(CONSTANTS.DATA_FILE_CSV, 'rb') as f:
                s3.upload_fileobj(f, self.s3, CONSTANTS.DATA_FILE_CSV)
                os.remove(CONSTANTS.DATA_FILE_CSV)
                return True
        except Exception as e:
            print(f"Error uploading file to S3: {e}")
            return False

    
    
    def verify_encryption_keys(self):
        """
        Verify that encryption keys are valid and working properly.
        
        This function tests the KMS setup by performing a simple
        encryption and decryption test.
        
        Returns:
            bool: True if keys are valid and working
        """
        try:
            # Log the verification attempt
            self._log_security_event(
                "KEY_VERIFICATION_ATTEMPT", 
                "Verifying encryption keys"
            )
            
            # Test string to encrypt/decrypt
            test_string = f"GUARD-TEST-{int(time.time())}"
            test_bytes = test_string.encode('utf-8')
            
            # Verify KMS client is initialized
            if not hasattr(self, 'kms_client') or not self.kms_client:
                self._log_security_event(
                    "KEY_VERIFICATION_ERROR", 
                    "KMS client not initialized"
                )
                return False
                
            # Test encryption
            try:
                encrypted_data = self.kms_client.encrypt(test_bytes)
                if not encrypted_data:
                    self._log_security_event(
                        "KEY_VERIFICATION_ERROR", 
                        "Encryption failed - null result"
                    )
                    return False
                    
                # Test decryption
                decrypted_data = self.kms_client.decrypt(encrypted_data)
                if not decrypted_data:
                    self._log_security_event(
                        "KEY_VERIFICATION_ERROR", 
                        "Decryption failed - null result"
                    )
                    return False
                    
                # Verify the decrypted result matches original
                decrypted_string = decrypted_data.decode('utf-8')
                if decrypted_string != test_string:
                    self._log_security_event(
                        "KEY_VERIFICATION_ERROR", 
                        f"Decryption result mismatch: expected '{test_string}', got '{decrypted_string}'"
                    )
                    return False
                    
                # All tests passed
                self._log_security_event(
                    "KEY_VERIFICATION_SUCCESS", 
                    "Encryption keys verified successfully"
                )
                return True
                
            except Exception as e:
                self._log_security_event(
                    "KEY_VERIFICATION_ERROR", 
                    f"Encryption/decryption test failed: {str(e)}"
                )
                return False
                
        except Exception as e:
            self._log_security_event(
                "KEY_VERIFICATION_ERROR", 
                f"Key verification process failed: {str(e)}"
            )
            return False

    def end_work(self):
        """Clean up resources when the agent is terminated."""
        while self.stored_file_names:
            file = self.stored_file_names.pop()
            try:
                os.remove(file)
                time.sleep(0.2)
            except Exception as e:
                print(f"Error removing file {file}: {e}")
    
    


if __name__ == '__main__':
    agent = Agent( file_name=CONSTANTS.AWS_FILE)
    data = agent.get_all_data()
    print(data)
    
