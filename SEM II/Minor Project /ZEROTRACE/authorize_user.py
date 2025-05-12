import os
import sys
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def authorize(user):
    token_file = f"token_{user}.json"
    creds = None

    if os.path.exists(token_file):
        creds = Credentials.from_authorized_user_file(token_file, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
            with open(token_file, "w") as token:
                token.write(creds.to_json())
    print(f"[✓] Authorization complete for: {user}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python authorize_user.py <username>")
        print("Example: python authorize_user.py rahul")
        sys.exit(1)
    
    username = sys.argv[1]
    authorize(username)

