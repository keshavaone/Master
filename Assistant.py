import boto3
from dataclasses import dataclass
import datetime 


@dataclass
class Assistant:
    s3:str
    
    
    def get_current_time(self):
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
   

    def collect_logs(self):
        s3 = boto3.client('s3')
        log_date = datetime.datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
        with open('application.log','rb') as f:
            s3.upload_fileobj(f, self.s3, f'logs/application_{log_date}.log')
            # os.remove('application.log')
            return True
        return False
    
    def logout(self):
        del self
        return True