import os
import requests
import tomllib
import json

# Your base Elastic Cloud endpoint (do not include ?rule_id= at the end of the URL)
url = "https://my-security-project-b4f666.kb.us-east4.gcp.elastic.cloud/api/detection_engine/rules"
api_key = os.environ['ELASTIC_KEY']

headers = {
    'Content-Type': 'application/json;charset=UTF-8',
    'kbn-xsrf': 'true',
    'Authorization': 'ApiKey ' + api_key
}

changed_files = os.environ["CHANGED_FILES"]

for root, dirs, files in os.walk("detections/"):
    for file in files:
        if file in changed_files:
            if file.endswith(".toml"):
                full_path = os.path.join(root, file)
                with open(full_path, "rb") as toml:
                    alert = tomllib.load(toml)
                
                # Determine required fields based on rule type
                if alert['rule']['type'] == "query": 
                    required_fields = ['author','description', 'name','rule_id','risk_score','severity','type','query','threat']
                elif alert['rule']['type'] == "eql": 
                    required_fields = ['author','description', 'name','rule_id','risk_score','severity','type','query','language','threat']
                elif alert['rule']['type'] == "threshold": 
                    required_fields = ['author','description', 'name','rule_id','risk_score','severity','type','query','threshold','threat']
                else:
                    print("Unsupported rule type found in: " + full_path)
                    break
                
                # Securely build the JSON payload
                payload = {}
                for field in alert['rule']:
                    if field in required_fields:
                        payload[field] = alert['rule'][field]
                
                payload["enabled"] = True
                data = json.dumps(payload)
            
                # Set up the specific PUT URL for updating existing rules
                rule_id = alert['rule']['rule_id']
                put_url = url + "?rule_id=" + rule_id
            
                # Attempt to update the rule
                elastic_data = requests.put(put_url, headers=headers, data=data).json()
            
                # If it returns 404, the rule doesn't exist yet, so POST it as a new rule using the clean base URL
                if "status_code" in elastic_data and elastic_data["status_code"] == 404:
                    elastic_data = requests.post(url, headers=headers, data=data).json()
                    print(elastic_data)