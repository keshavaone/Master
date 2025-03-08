import boto3
from dataclasses import dataclass, field
import base64
import os
import io
import time
import time
import pandas as pd
import atexit
from API.StoreSecrets import get_secret
import ast
import API.CONSTANTS as CONSTANTS
from API.KMS import KMS
from pymongo import MongoClient
from pymongo.server_api import ServerApi
from bson.objectid import ObjectId


@dataclass(eq=False, repr=False, order=False)
class Agent:
    s3: str
    file_name: str
    input_path: str = 'ReQuest.txt'
    stored_file_names: list[str] = field(default_factory=list)
    os.chdir(os.path.dirname(os.path.realpath(__file__)))

    def __post_init__(self):
        self.data_path: str = self.file_name

        self.status = {'Waking Up Mr.Agent...'}
        self.__secret = ast.literal_eval(get_secret())
        print('Secrets Fetched')

        # Change region if needed
        dynamodb = boto3.resource('dynamodb', region_name="us-east-1")

        # Define the table
        table_name = "myPII"
        self.collection = dynamodb.Table(table_name)
        self.__df = self.refresh_data()
        self.fetch_my_key()
        os.chdir(os.path.dirname(os.path.realpath(__file__)))
        self.data_path: str = self.file_name
        atexit.register(self.end_work)

    def fetch_my_key(self):
        self.__encoded_key = self.__secret['KMS_KEY_ID']
        assert self.__encoded_key is not None
        self.kms_client = KMS()
        self.cipher_suite = self.kms_client.decrypt_my_key(self.__encoded_key)

    def filter_from_db(self, item_name=None, download_request=False):
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
        input_request = self.process_file('r')
        if input_request == 'Download':
            self.download_excel()
            output = self.data_path
        elif input_request == 'Re-Encrypt':
            self.upload_securely(self.file_name)
            output = 'Success'
        else:
            data = self.filter_from_db(input_request)
            pre_output = self.decrypt_data(data)
            post_output = pd.DataFrame(data=pd.read_json(
                io.StringIO(pre_output), orient='records'))
            output = post_output.set_index('Item Name').to_json()
        print('Processed: ', input_request)
        os.remove(self.input_path)

    def read_excel_from_file(self, file_path):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        df = pd.read_excel(file_path)
        return df

    def read_excel_from_s3(self, bucket_name, object_key):
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
        return pd.DataFrame(self.collection.scan()['Items'])

    def get_all_data(self):
        df = self.refresh_data()
        self.__df = df.copy()
        for i in df.index:
            if df.loc[i, 'Type'] == 'KeyID':
                pass
            else:
                try:
                    df.loc[i, 'PII'] = self.kms_client.decrypt_data(
                        self.filter_from_db(df.loc[i, 'Type']))
                except:
                    df.loc[i, 'PII'] = 'Data may have inserted in the current session. please restart to see this entry'
        return df

    def get_one_data(self):
        return_item = self.collection.find_one(
            {'Category': 'System', 'Type': 'KeyPassword'})
        return return_item['PII']

    def insert_new_data(self, item):
        print(item)
        try:
            item = {
                '_id': str(ObjectId()),
                'Category': item['Category'],
                'Type': item['Type'],
                'PII': base64.b64encode(self.cipher_suite.encrypt(item['PII'].encode('utf-8'))).decode('utf-8')
            }
            print(item)
            response = self.collection.put_item(Item=item)
            print(response)
            return response['ResponseMetadata']['HTTPStatusCode'] == 200
        except Exception as e:
            print(e)
            return e

    def update_one_data(self, item):
        print(item)
        updated_values = {"PII": base64.b64encode(
            self.cipher_suite.encrypt(item['PII'].encode('utf-8'))).decode('utf-8')}
        print(item)
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
        return response

    def delete_one_data(self, item):
        response = self.collection.delete_item(Key={'_id': item['_id']})
        return response.acknowledged

    def download_excel(self):
        df = self.get_all_data()
        df.to_excel(self.data_path, index=False)
        print('Excel File Downloaded Successfully')
        return True

    # for Desktop Application

    def get_options_to_choose(self):
        df = self.get_all_data()
        return list(set(df['Category'].to_list()))

    # for Desktop Application
    def get_sub_options_to_choose(self, category):
        df = self.get_all_data()
        df = df[df['Category'] == category]
        self.chosen_one = category
        return list(set(df['Type'].to_list()))

    # for Desktop Application
    def get_final_output(self, type):
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

    # for Source Code
    def perform_specific_output(self):
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

    def isBase64(sb):
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
        if file_path:
            path = file_path
        else:
            path = self.input_path
        if 'r' in mode:
            with open(path, mode) as f:
                data = f.read()
        elif 'w' in mode:
            with open(path, mode) as f:
                data = f.write(data)
                self.stored_file_names.append(path)
                print('Stored: ', path)
                return True
        return data

    def upload_securely(self):
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
        # df.to_csv(file_path, index=False)
        try:
            with open(CONSTANTS.DATA_FILE_CSV, 'rb') as f:
                s3.upload_fileobj(f, self.s3, CONSTANTS.DATA_FILE_CSV)
                os.remove(CONSTANTS.DATA_FILE_CSV)
                # print(f"File {CONSTANTS.DATA_FILE_CSV} uploaded to S3 successfully.")
                return True
        except Exception as e:
            print(f"Error uploading file to S3: {e}")
            return False

    def end_work(self):
        while self.stored_file_names:
            file = self.stored_file_names.pop()
            os.remove(file)
            time.sleep(0.2)
        # self.status['Post Exit CleanUp: All'] = self.get_current_time()


if __name__ == '__main__':

    agent = Agent(s3=CONSTANTS.AWS_S3, file_name=CONSTANTS.AWS_FILE)
    # agent.upload_excel_to_s3('MyPII.PIIData.xlsx')
    # agent.perform_specific_output()
    # agent.download_excel()
    agent.get_one_data()
    # agent.begin_work()
