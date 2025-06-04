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