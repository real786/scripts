import requests

# Step 1: Authenticate using Access Key and Secret Key
def authenticate(access_key, secret_key):
    auth_url = "https://api2.prismacloud.io/login"
    headers = {
        "Content-Type": "application/json"
    }
    
    payload = {
        "username": access_key,
        "password": secret_key
    }
    
    response = requests.post(auth_url, headers=headers, json=payload)
    
    if response.status_code == 200:
        return response.json().get('token')
    else:
        print(f"Failed to authenticate. Status Code: {response.status_code}, Response: {response.text}")
        return None

# Step 2: Create users with JWT Token
def create_user(user_data, token):
    api_url = "https://api2.prismacloud.io/v2/user"
    
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {token}"
    }
    
    payload = {
        "firstName": user_data["firstName"],
        "lastName": user_data["lastName"],
        "email": user_data["email"],
        "roleIds": ["ba39ebdd-03e8-484e-b1cc-65b58cc3a651"],  # Default role ID
        "defaultRoleId": "ba39ebdd-03e8-484e-b1cc-65b58cc3a651",  # Default role ID
        "timeZone": "America/New_York"  # Adjust as necessary
    }
    
    response = requests.post(api_url, headers=headers, json=payload)
    
    # Check for empty response content
    if response.status_code == 201:
        print(f"User {user_data['firstName']} {user_data['lastName']} created successfully.")
    elif response.status_code == 200:
        if not response.text.strip():
            print(f"Request succeeded, but no content was returned for user {user_data['firstName']} {user_data['lastName']}.")
        else:
            print(f"User {user_data['firstName']} {user_data['lastName']} created successfully. Response: {response.text}")
    else:
        print(f"Failed to create user {user_data['firstName']} {user_data['lastName']}. Status Code: {response.status_code}, Response: {response.text}")

# Input your access key and secret key
access_key = input("Enter your access key: ")
secret_key = input("Enter your secret key: ")

# Authenticate and get JWT token
token = authenticate(access_key, secret_key)

if token:
    # User data
    users = [
        {
            "firstName": "Amberto",
            "lastName": "Medina",
            "email": "amedina@paloaltonetworks.com"
        },
        {
            "firstName": "Cameron",
            "lastName": "Wilder",
            "email": "cwilder@paloaltonetworks.com"
        },
        {
            "firstName": "Julie",
            "lastName": "Merrall",
            "email": "jmerrall@paloaltonetworks.com"
        },
        {
            "firstName": "John",
            "lastName": "Spears",
            "email": "jspears@paloaltonetworks.com"
        },
        {
            "firstName": "Madhukar",
            "lastName": "Bayakati",
            "email": "mbayakati@paloaltonetworks.com"
        },
        {
            "firstName": "Tara",
            "lastName": "Cochran",
            "email": "tcochran@paloaltonetworks.com"
        }
    ]
    
    # Create users with the authenticated JWT token
    for user in users:
        create_user(user, token)
