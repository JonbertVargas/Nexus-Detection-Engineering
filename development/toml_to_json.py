import requests
import os
import tomllib

# REPLACE THIS with your actual Elastic deployment URL from the dashboard
url = "https://my-security-project-b4f666.kb.us-east4.gcp.elastic.cloud/api/detection_engine/rules"

api_key = os.environ.get('ELASTIC_KEY')
headers = {
    'kbn-xsrf': 'true',
    'Content-Type': 'application/json',
    'Authorization': f'ApiKey {api_key}'
}

for root, dirs, files in os.walk("detections/"):
    for file in files:
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            with open(full_path, "rb") as toml_file:
                alert = tomllib.load(toml_file)

            # Determine required fields based on rule type
            rule_type = alert['rule'].get('type')
            if rule_type == "query":
                required_fields = ['author', 'description', 'name', 'rule_id', 'risk_score', 'severity', 'type', 'query', 'threat']
            elif rule_type == "eql":
                required_fields = ['author', 'description', 'name', 'rule_id', 'risk_score', 'severity', 'type', 'query', 'language', 'threat']
            elif rule_type == "threshold":
                required_fields = ['author', 'description', 'name', 'rule_id', 'risk_score', 'severity', 'type', 'query', 'threshold', 'threat']
            else:
                print(f"Unsupported rule type found in: {full_path}")
                continue  # Skips to the next file instead of breaking the entire script

            # Build a native Python dictionary instead of manipulating strings
            payload = {}
            for field in alert['rule']:
                if field in required_fields:
                    payload[field] = alert['rule'][field]
            
            payload['enabled'] = True

            # Passing 'json=payload' automatically handles all string formatting and escape characters
            elastic_data = requests.post(url, headers=headers, json=payload)
            
            # Print the status of each file as it uploads
            print(f"Pushed {file}: {elastic_data.status_code}")
            if elastic_data.status_code != 200:
                print(elastic_data.json())