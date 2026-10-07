import requests

# The URL will be your specific Elastic Cloud endpoint
url = "https://my-security-project-b4f666.kb.us-east4.gcp.elastic.cloud/api/detection_engine/rules"

headers = {
    "kbn-xsrf": "true",
    "Content-Type": "application/json",
    "Authorization": "ApiKey YjZOaUZLRUJFb3diSUZLSm1adDc6empOVEZXQjdRR01iTWE4WkxfbFdIQQ=="
}

data = """
{
  "rule_id": "process_started_by_ms_office_program",
  "risk_score": 50,
  "description": "Process started by MS Office program - possible payload",
  "interval": "1h",
  "name": "Jonor Vargas Test Rule",
  "severity": "low",
  "tags": [
    "child process",
    "ms office"
  ],
  "type": "query",
  "from": "now-70m",
  "query": "process.parent.name:EXCEL.EXE or process.parent.name:MSPUB.EXE or process.parent.name:OUTLOOK.EXE or process.parent.name:POWERPNT.EXE or process.parent.name:WINWORD.EXE",
  "language": "kuery",
  "filters": [
    {
      "query": {
        "match": {
          "event.action": {
            "query": "Process Create (rule: ProcessCreate)",
            "type": "phrase"
          }
        }
      }
    }
  ],
  "enabled": true
}
"""

elastic_data = requests.post(url, headers=headers, data=data).json()
print(elastic_data)