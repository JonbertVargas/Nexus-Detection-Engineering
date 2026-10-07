import os
import requests

# Your base Elastic Cloud endpoint (do not include ?rule_id= at the end of the URL)
url = "https://my-security-project-b4f666.kb.us-east4.gcp.elastic.cloud/api/detection_engine/rules"

api_key = os.environ.get('ELASTIC_KEY')
headers = {
    'kbn-xsrf': 'true',
    'Content-Type': 'application/json',
    'Authorization': f'ApiKey {api_key}'
}

# The payload must include the rule_id so Elastic knows which rule to target,
# followed by only the specific fields you want to modify.
update_payload = {
    "rule_id": "00000000-0000-0000-0000-000000000001",
    "risk_score": 75,
    "severity": "high",
    "description": "UPDATED: reduced risk score"
}

# Use requests.patch() to execute the partial update
elastic_data = requests.patch(url, headers=headers, json=update_payload).json()
print(f"Updated Rule '{elastic_data.get('name')}': New Risk Score is {elastic_data.get('risk_score')}")