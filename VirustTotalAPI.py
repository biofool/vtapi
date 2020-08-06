import requests
import os
import json
import boto3  # Required to interact with AWS
import json   # Required for return object parsing
from botocore.exceptions import ClientError
# Set required variables
secret_name = "VirustTotal/API_KEY"
endpoint_url = "https://secretsmanager.us-east-1.amazonaws.com"
region_name = "us-east-1"
session = boto3.session.Session()
client = session.client(
    service_name='secretsmanager',
    region_name=region_name,
    endpoint_url=endpoint_url
)
try:
    get_secret_value_response = client.get_secret_value(
        SecretId="VirustTotal/API_KEY"
    )
except ClientError as e:
    if e.response['Error']['Code'] == 'ResourceNotFoundException':
        print("The requested secret " + secret_name + " was not found")
    elif e.response['Error']['Code'] == 'InvalidRequestException':
        print("The request was invalid due to:", e)
    elif e.response['Error']['Code'] == 'InvalidParameterException':
        print("The request had invalid params:", e)
else:
    # Decrypted secret using the associated KMS CMK
    # Depending on whether the secret was a string or binary, one of these fields will be populated
    if 'SecretString' in get_secret_value_response:
        secret = json.loads(get_secret_value_response['SecretString'])
    else:
        binary_secret_data = get_secret_value_response['SecretBinary']
API_KEY = secret['API_KEY']
S = '{:<20} {:<20} {:<20} {:>20}'
V2API = 'https://www.virustotal.com/vtapi/v2'
domain = os.environ['VT_DOMAIN']
class vt():
    def __init__(self, api_key):
        self.api_key = api_key
    def domain(self, domain):
        domain = domain
        url = '{}/domain/report'.format(V2API)
        headers = {'apikey': self.api_key, 'domain': domain}
        response = requests.get(url, params=headers)
        return response.json()
    def file(self, resource):
        url = '{}/file/report'.format(V2API)
        headers = {'apikey': self.api_key, 'resource': resource}
        response = requests.get(url, params=headers)
        return response.json()
files = []
try:
    DataBricks = vt(API_KEY)
    Domain = DataBricks.domain(domain)
   # print (json.dumps()) ['sha256']
except:
    print "Error retrieving VT records for:", domain
    exit(1)
if Domain['response_code'] == 0:
    print ("No records detected in Virus_Total for domain", domain)
    exit(0)
for x in Domain ["detected_referrer_samples"]:
    if (x ['positives'] > 5):
        # print(x ['sha256'])
        files.append(DataBricks.file(x ['sha256']))
if files.count:
    print "Referer report for DataBricks"
    print S.format('Engine', 'Version', 'Result', 'Last Update')
    for x in files:
        for reporter in x ['scans']:
            reporter_ = x ['scans'] [reporter]
            if reporter_ ['detected']:
                # print reporter, reporter_
                # Fields
                record = []
                datain = [reporter, reporter_ ['version'], reporter_ ['result'], reporter_ ['update']]
                for data in datain:
                    record.append( (data[:17] + '..') if len(data) > 17 else data)
                print(S.format(record[0], record[1], record[2], record[3]))
else:
    print ('No Referers Detected for domain:',domain)
