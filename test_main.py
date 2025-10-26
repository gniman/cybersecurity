import unittest
import os
import sqlite3
import time
from main import setup_database, save_private_key, load_private_key, load_valid_public_keys, generate_key, DB_FILE

# --- Setup for Testing ---
# Define a separate database file name for testing
TEST_DB_FILE = "test_" + DB_FILE

# Temporarily patch the DB_FILE variable in main to use the test file
import main
original_db_file = main.DB_FILE
main.DB_FILE = TEST_DB_FILE


# --- Test Key Management and DB Functions ---

class TestKeyManagement(unittest.TestCase):
    
    def setUp(self):
        """Setup fresh test DB."""
        if os.path.exists(TEST_DB_FILE):
            os.remove(TEST_DB_FILE)
        setup_database()
        
    def tearDown(self):
        """Cleanup test DB."""
        if os.path.exists(TEST_DB_FILE):
            os.remove(TEST_DB_FILE)

    def test_01_db_setup_and_existence(self):
        """Test that setup_database creates the file and the keys table."""
        self.assertTrue(os.path.exists(TEST_DB_FILE))
        conn = sqlite3.connect(TEST_DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='keys';")
        self.assertIsNotNone(cursor.fetchone())
        conn.close()

    def test_02_valid_key_workflow(self):
        """Test saving and loading a valid key."""
        key_obj = generate_key()
        valid_kid = save_private_key(key_obj, 3600) 
        
        loaded_kid, loaded_key_obj = load_private_key(expired=False)
        self.assertEqual(valid_kid, loaded_kid)

    def test_03_expired_key_workflow_and_filtering(self):
        """Test saving and loading expired key, ensuring it's not valid."""
        key_obj = generate_key()
        expired_kid = save_private_key(key_obj, -1) 
        
        # Load expired
        loaded_kid, loaded_key_obj = load_private_key(expired=True)
        self.assertEqual(expired_kid, loaded_kid)
        
        # Ensure it's not returned when asking for valid
        self.assertIsNone(load_private_key(expired=False)[0])

    def test_04_jwks_filtering(self):
        """Test JWKS only returns valid keys."""
        valid_kid = save_private_key(generate_key(), 3600)
        save_private_key(generate_key(), -1) 

        jwks = load_valid_public_keys()
        
        self.assertEqual(len(jwks["keys"]), 1)
        self.assertIn("n", jwks["keys"][0])

    def test_05_empty_db_handling(self):
        """Test empty DB returns None."""
        self.assertIsNone(load_private_key(expired=True)[0])
        self.assertIsNone(load_private_key(expired=False)[0])


# --- Mocks for HTTP Handler Coverage ---

class MockWriter:
    """Mock object to capture HTTP response body."""
    def __init__(self):
        self.output = b''
    def write(self, data):
        self.output += data
        
class MockHandler:
    """Mock handler to simulate BaseHTTPRequestHandler methods."""
    def __init__(self):
        self.headers = {}
        self.response_code = None
        self.wfile = MockWriter()
        self.path = ""
        
    def send_response(self, code):
        self.response_code = code
        
    def send_header(self, key, value):
        self.headers[key] = value
        
    def end_headers(self):
        pass

    # Directly import the handler logic methods from main.MyServer
    from main import MyServer
    do_GET = MyServer.do_GET
    do_POST = MyServer.do_POST
    do_PUT = MyServer.do_PUT
    do_DELETE = MyServer.do_DELETE
    do_HEAD = MyServer.do_HEAD
    do_PATCH = MyServer.do_PATCH


class TestMyServerCoverage(unittest.TestCase):
    
    def setUp(self):
        """Setup fresh DB with one key for testing handler functionality."""
        if os.path.exists(TEST_DB_FILE):
            os.remove(TEST_DB_FILE)
        setup_database()
        save_private_key(generate_key(), 3600)
        save_private_key(generate_key(), -1)

    def test_06_unsupported_methods_405(self):
        """Test all unsupported methods return 405."""
        handler = MockHandler()
        
        # FIX: Call the method without the extra 'handler' argument
        handler.do_PUT()
        self.assertEqual(handler.response_code, 405)
        
        handler.do_DELETE()
        self.assertEqual(handler.response_code, 405)
        
        handler.do_HEAD()
        self.assertEqual(handler.response_code, 405)

        handler.do_PATCH()
        self.assertEqual(handler.response_code, 405)
        
    def test_07_get_jwks_success(self):
        """Test GET /.well-known/jwks.json returns 200 and JSON."""
        handler = MockHandler()
        handler.path = "/.well-known/jwks.json"
        # FIX
        handler.do_GET()
        
        self.assertEqual(handler.response_code, 200)
        self.assertEqual(handler.headers['Content-type'], 'application/json')
        
    def test_08_get_invalid_path_405(self):
        """Test GET to a wrong path returns 405."""
        handler = MockHandler()
        handler.path = "/not-the-right-path"
        # FIX
        handler.do_GET()
        
        self.assertEqual(handler.response_code, 405)

    def test_09_post_auth_success(self):
        """Test POST /auth returns 200 and a JWT."""
        handler = MockHandler()
        handler.path = "/auth"
        # FIX
        handler.do_POST()
        
        self.assertEqual(handler.response_code, 200)
        
    def test_10_post_invalid_path_405(self):
        """Test POST to a wrong path returns 405."""
        handler = MockHandler()
        handler.path = "/not-auth"
        # FIX
        handler.do_POST()
        
        self.assertEqual(handler.response_code, 405)

# --- Final Execution ---

if __name__ == '__main__':
    # Run the tests
    unittest.main(exit=False)
    
    # Restore DB_FILE and clean up
    main.DB_FILE = original_db_file
    if os.path.exists(TEST_DB_FILE):
        os.remove(TEST_DB_FILE)