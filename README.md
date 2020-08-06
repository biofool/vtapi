# vtapi
This application expects the API key to be in an aws secret located at
secret_name = "VirustTotal/API_KEY"
endpoint_url = "https://secretsmanager.us-east-1.amazonaws.com"
region_name = "us-east-1"
The domain to run the report on is in a shell environment variable settable as:
export VT_DOMAIN='databricks.com'
 
