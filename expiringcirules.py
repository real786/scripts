import requests
import json
from datetime import datetime, timezone

# API endpoint
url = "https://us-east1.cloud.twistlock.com/us-2-158290640/api/v1/policies/vulnerability/ci/images?project=Central+Console"

# Your API token (replace with your actual token)
api_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoicmFobWFkQHBhbG9hbHRvbmV0d29ya3MuY29tIiwicm9sZSI6ImFkbWluIiwicm9sZVBlcm1zIjpbWzI1NSwyNTUsMjU1LDI1NSwyNTUsOTVdLFsyNTUsMjU1LDI1NSwyNTUsMjU1LDk1XV0sInNlc3Npb25UaW1lb3V0U2VjIjo2MDAsInNhYXNUb2tlbiI6ImV5SmhiR2NpT2lKSVV6STFOaUo5LmV5SnpkV0lpT2lKeVlXaHRZV1JBY0dGc2IyRnNkRzl1WlhSM2IzSnJjeTVqYjIwaUxDSnpaWEoyYVdObFZYTmhaMlZQYm14NUlqcDBjblZsTENKbWFYSnpkRXh2WjJsdUlqcG1ZV3h6WlN3aWNISnBjMjFoU1dRaU9pSTRNVGt6TVRNeU1EWTNORGd6T1RBME1EQWlMQ0pwY0VGa1pISmxjM01pT2lJek5DNHhNemt1TWpRNUxqRTVNaUlzSW1semN5STZJbWgwZEhCek9pOHZZWEJwTWk1d2NtbHpiV0ZqYkc5MVpDNXBieUlzSW5KbGMzUnlhV04wSWpvd0xDSjFjMlZ5VW05c1pWUjVjR1ZFWlhSaGFXeHpJanA3SW1oaGMwOXViSGxTWldGa1FXTmpaWE56SWpwbVlXeHpaWDBzSW5WelpYSlNiMnhsVkhsd1pVNWhiV1VpT2lKVGVYTjBaVzBnUVdSdGFXNGlMQ0pwYzFOVFQxTmxjM05wYjI0aU9tWmhiSE5sTENKc1lYTjBURzluYVc1VWFXMWxJam94TnpJME9UUTBNamd6Tmprd0xDSmhkV1FpT2lKb2RIUndjem92TDJGd2FUSXVjSEpwYzIxaFkyeHZkV1F1YVc4aUxDSjFjMlZ5VW05c1pWUjVjR1ZKWkNJNk1Td2lZWFYwYUMxdFpYUm9iMlFpT2lKUVFWTlRWMDlTUkNJc0luTmxiR1ZqZEdWa1EzVnpkRzl0WlhKT1lXMWxJam9pVUdGc2J5QkJiSFJ2SUU1bGRIZHZjbXR6SUMwZ05USTVNVFl5TURjMk1qRTVOVGc0TlRnM05pSXNJbk5sYzNOcGIyNVVhVzFsYjNWMElqbzBOU3dpZFhObGNsSnZiR1ZKWkNJNkltSmhNemxsWW1Sa0xUQXpaVGd0TkRnMFpTMWlNV05qTFRZMVlqVTRZMk16WVRZMU1TSXNJbWhoYzBSbFptVnVaR1Z5VUdWeWJXbHpjMmx2Ym5NaU9tWmhiSE5sTENKbGVIQWlPakUzTWpRNU5EazNOVGdzSW1saGRDSTZNVGN5TkRrME9URTFPQ3dpZFhObGNtNWhiV1VpT2lKeVlXaHRZV1JBY0dGc2IyRnNkRzl1WlhSM2IzSnJjeTVqYjIwaUxDSjFjMlZ5VW05c1pVNWhiV1VpT2lKVGVYTjBaVzBnUVdSdGFXNGlmUS5jcFVkMDRERHlCWTBTSWV4cVRNQU5ybEVJUTJRbDcwX0FtWXV5eFM2MVA0IiwiaXNzIjoidHdpc3Rsb2NrIiwiZXhwIjoxNzI0OTUyNzU4fQ.d6dShMBuOy0Ms9ys54nZQZJS8OLuPDpsOOakGNUW7ws"

# Set up headers with the API token
headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {api_token}"
}

# Make the API request
try:
    response = requests.get(url, headers=headers)

    # Print the status code and raw response content for debugging
    print(f"Status Code: {response.status_code}")

    # Check if the request was successful
    if response.status_code == 200:
        try:
            # Parse the JSON response
            data = response.json()
            rules = data.get('rules', [])
        except json.JSONDecodeError as e:
            print("Error decoding JSON response:", e)
            exit(1)

        # Define a threshold for expiring rules (e.g., 30 days)
        threshold_days = 30
        expiring_rules = []

        # Iterate over the policies to check for expiring CVE rules
        for rule in rules:
            for cve_rule in rule.get('cveRules', []):
                expiration_info = cve_rule.get('expiration', {})
                if expiration_info.get('enabled'):
                    expiration_date_str = expiration_info.get('date')
                    if expiration_date_str:
                        # Parse the expiration date as an offset-aware datetime
                        expiration_date = datetime.strptime(expiration_date_str, "%Y-%m-%dT%H:%M:%S%z")
                        # Get the current time as an offset-aware datetime
                        current_time = datetime.now(timezone.utc)
                        # Calculate days to expiration
                        days_to_expiration = (expiration_date - current_time).days
                        if days_to_expiration <= threshold_days:
                            expiring_rules.append({
                                "policy_name": rule.get('name'),
                                "cve_id": cve_rule.get('id'),
                                "expiration_date": expiration_date_str,
                                "days_to_expiration": days_to_expiration
                            })

        # Print the expiring CVE rules
        if expiring_rules:
            print("Expiring CVE Rules:")
            for exp_rule in expiring_rules:
                print(f"Policy: {exp_rule['policy_name']}, CVE ID: {exp_rule['cve_id']}, Expiration Date: {exp_rule['expiration_date']}, Days to Expiration: {exp_rule['days_to_expiration']}")
        else:
            print("No CVE rules expiring within the threshold.")
    else:
        print(f"Failed to retrieve policies: {response.status_code} - {response.text}")
except requests.exceptions.RequestException as e:
    print(f"An error occurred while making the API request: {e}")
