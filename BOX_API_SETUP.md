# Box API Setup Guide

## Prerequisites
- Box Enterprise Admin access
- Python 3.8 or higher installed

## Step 1: Create a Box Application

1. **Navigate to Box Developer Console**
   - Go to https://app.box.com/developers/console
   - Click "Create New App"

2. **Choose Application Type**
   - Select "Custom App"
   - Choose "Server Authentication (with JWT)"
   - Name your app (e.g., "FedRAMP Compliance Auditor")

3. **Configure Application Settings**
   - Navigate to your app's Configuration tab
   - Under "Application Access", select "Enterprise"
   - Under "Application Scopes", enable:
     - Read all files and folders stored in Box
     - Read all users and groups
     - Manage enterprise security settings
     - Read enterprise events
     - Read retention policies
     - Read legal holds
     - Read security classifications

4. **Generate Public/Private Keypair**
   - Scroll to "Add and Manage Public Keys"
   - Click "Generate a Public/Private Keypair"
   - Download the JSON config file (keep this secure!)
   - The file will be named something like: `1234567_abcdefg_config.json`

## Step 2: Authorize the Application

1. **Get App Authorization**
   - In the Configuration tab, find your "Client ID"
   - Send this to your Box Enterprise Admin with this message:
   ```
   Please authorize this Box application for enterprise access:
   Client ID: [YOUR_CLIENT_ID]
   
   This app performs read-only security compliance audits.
   ```

2. **Admin Authorization Steps** (for Box Admin)
   - Go to Admin Console → Apps → Custom App Manager
   - Click "Authorize New App"
   - Enter the Client ID
   - Review and Approve

## Step 3: Set Up Authentication File

1. **Rename Config File**
   ```bash
   mv ~/Downloads/*_config.json ./box_config.json
   ```

2. **Verify Config Structure**
   Your `box_config.json` should contain:
   ```json
   {
     "boxAppSettings": {
       "clientID": "...",
       "clientSecret": "...",
       "appAuth": {
         "publicKeyID": "...",
         "privateKey": "-----BEGIN ENCRYPTED PRIVATE KEY-----\n...",
         "passphrase": "..."
       }
     },
     "enterpriseID": "..."
   }
   ```

## Step 4: Install Dependencies

```bash
pip install -r requirements.txt
```

## Security Best Practices

1. **Protect Your Config File**
   ```bash
   chmod 600 box_config.json
   echo "box_config.json" >> .gitignore
   ```

2. **Use Environment Variables (Alternative)**
   ```bash
   export BOX_CONFIG_PATH="/secure/location/box_config.json"
   ```

3. **Rotate Keys Regularly**
   - Generate new keypairs every 90 days
   - Remove old public keys from Box app

## Troubleshooting

### "App not authorized" Error
- Ensure your Box admin has approved the app
- Verify the Enterprise ID in your config matches your Box instance

### "Insufficient permissions" Error
- Check that all required scopes are enabled
- Confirm app has "Enterprise" level access

### "Authentication failed" Error
- Verify your config file is valid JSON
- Ensure the private key hasn't been corrupted
- Check that the passphrase is correct

## Quick Test

Save this as `test_connection.py`:

```python
from boxsdk import JWTAuth, Client

def test_box_connection():
    try:
        auth = JWTAuth.from_settings_file('box_config.json')
        client = Client(auth)
        user = client.user().get()
        print(f"✓ Connected as: {user.name}")
        print(f"✓ User ID: {user.id}")
        print(f"✓ Enterprise: {user.enterprise.name}")
        return True
    except Exception as e:
        print(f"✗ Connection failed: {str(e)}")
        return False

if __name__ == "__main__":
    test_box_connection()
```

Run: `python test_connection.py`

## Next Steps

Once connected, you can run the compliance audit:

```bash
python box_audit.py --output-format html
```