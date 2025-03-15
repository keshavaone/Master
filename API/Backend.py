import boto3
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
    s3: str
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

        self.status = {'Waking Up Mr.Agent...'}
        try:
            # Get secrets
            self.__secret = ast.literal_eval(get_secret())
            print('Secrets Fetched')

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
        except Exception as e:
            print(f"Error in agent initialization: {e}")
            raise
        
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

    def filter_from_db(self, item_name=None, download_request=False):
        """
        Filter data from the database.

        Args:
            item_name (str, optional): Name of the item to filter
            download_request (bool, optional): Flag for download requests

        Returns:
            bytes or int: Filtered data or 0 for download requests
        """
        if download_request:
            return 0
        elif item_name is not None:
            filtered_df = self.__df[self.__df['Type'] == item_name]

            # Check if the filtered DataFrame is not empty
            if not filtered_df.empty:
                data = base64.b64decode(filtered_df['PII'].values[0])
                return data
            else:
                # Handle the case where no matching item is found
                print(f"No data found for item_name: {item_name}")
                return None

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

    def get_all_data(self):
        """
        Get all data with decryption.

        Returns:
            DataFrame: All decrypted data
        """
        df = self.refresh_data()
        self.__df = df.copy()
        for i in df.index:
            if df.loc[i, 'Type'] == 'KeyID':
                pass
            else:
                try:
                    df.loc[i, 'PII'] = self.kms_client.decrypt_data(
                        self.filter_from_db(df.loc[i, 'Type']))
                except Exception as e:
                    df.loc[i, 'PII'] = 'Data may have inserted in the current session. please restart to see this entry'
        return df

    def get_one_data(self):
        """
        Get a specific data item.

        Returns:
            str: The data item
        """
        return_item = self.collection.find_one(
            {'Category': 'System', 'Type': 'KeyPassword'})
        return return_item['PII']

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
        Update existing data with audit logging.

        Args:
            item (dict): Data to update

        Returns:
            dict: Update response
        """
        operation_id = str(uuid.uuid4())
        try:
            self._log_security_event(
                "DATA_UPDATE_ATTEMPT", 
                f"Attempting to update data for ID {item.get('_id')}", 
                {"operation_id": operation_id}
            )
            
            encrypted_pii = self.kms_client.encrypt_to_base64(item['PII'])
            updated_values = {"PII": encrypted_pii}
            item_id = item['_id']
            update_expression = "SET " + \
                ", ".join(f"{k} = :{k}" for k in updated_values.keys())
            expression_values = {f":{k}": v for k, v in updated_values.items()}

            response = self.collection.update_item(
                Key={"_id": item_id},
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expression_values,
                ReturnValues="UPDATED_NEW"
            )
            
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
                    "DATA_UPDATE_FAILURE", 
                    f"Failed to update data for ID {item_id}",
                    {
                        "operation_id": operation_id,
                        "status_code": response.get('ResponseMetadata', {}).get('HTTPStatusCode')
                    }
                )
                
            return response
        except Exception as e:
            self._log_security_event(
                "DATA_UPDATE_ERROR", 
                f"Error updating data: {str(e)}",
                {"operation_id": operation_id}
            )
            raise

    def delete_one_data(self, item):
        """
        Delete data item with audit logging.

        Args:
            item (dict): Item to delete

        Returns:
            bool: True if deletion successful
        """
        operation_id = str(uuid.uuid4())
        try:
            self._log_security_event(
                "DATA_DELETE_ATTEMPT", 
                f"Attempting to delete data for ID {item.get('_id')}", 
                {"operation_id": operation_id}
            )
            
            response = self.collection.delete_item(Key={'_id': item['_id']})
            success = response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200
            
            if success:
                self._log_security_event(
                    "DATA_DELETE_SUCCESS", 
                    f"Successfully deleted data for ID {item['_id']}",
                    {
                        "operation_id": operation_id,
                        "item_id": item['_id'],
                        "category": item.get('Category', 'unknown'),
                        "type": item.get('Type', 'unknown')
                    }
                )
            else:
                self._log_security_event(
                    "DATA_DELETE_FAILURE", 
                    f"Failed to delete data for ID {item['_id']}",
                    {
                        "operation_id": operation_id,
                        "status_code": response.get('ResponseMetadata', {}).get('HTTPStatusCode')
                    }
                )
                
            return success
        except Exception as e:
            self._log_security_event(
                "DATA_DELETE_ERROR", 
                f"Error deleting data: {str(e)}",
                {"operation_id": operation_id}
            )
            raise

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
        Download data to Excel.

        Returns:
            bool: True if successful
        """
        df = self.get_all_data()
        df.to_excel(self.data_path, index=False)
        print('Excel File Downloaded Successfully')
        return True

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
        df = self.get_all_data()
        df = df[df['Category'] == category]
        self.chosen_one = category
        return list(set(df['Type'].to_list()))

    def get_final_output(self, type):
        """
        Get final output for a specific type.

        Args:
            type (str): Type to get output for

        Returns:
            Various: The parsed output
        """
        df = self.get_all_data()
        df = df[df['Category'] == self.chosen_one]
        df = df[df['Type'] == type]
        try:
            return ast.literal_eval(df['PII'].iloc[0])
        except:
            try:
                return ast.literal_eval(df['PII'].iloc[0].replace('\n', ' THIS_IS_NEW_LINE '))
            except:
                return df['PII'].iloc[0]

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

    def decrypt_data(self, data):
        """
        Decrypt data using KMS.

        Args:
            data (bytes): Data to decrypt

        Returns:
            str: Decrypted data
        """
        try:
            if hasattr(self, 'kms_client') and self.kms_client and data:
                print(f"Attempting to decrypt data of length: {len(data)}")
                decrypted = self.kms_client.decrypt_data(data)
                print(f"Data decryption successful: {bool(decrypted)}")
                return decrypted
            else:
                print("Unable to decrypt: missing KMS client or data")
            return None
        except Exception as e:
            print(f"Error in decrypt_data: {e}")
            return None

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
    agent = Agent(s3=CONSTANTS.AWS_S3, file_name=CONSTANTS.AWS_FILE)
    # agent.get_one_data()
