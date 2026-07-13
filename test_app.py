import unittest
import os
import json
import sqlite3
from io import BytesIO
from app import app, get_db_connection
from models import predict_url, predict_network_threat

class SecureNetTestSuite(unittest.TestCase):

    def setUp(self):
        # Configure Flask app for testing
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()
        
        # Make sure database is seeded
        from database import init_db
        init_db()

    # --- 1. MODEL UNIT TESTS ---
    
    def test_predict_url_safe(self):
        """Test predicting a known safe URL pattern."""
        prediction, confidence = predict_url("https://google.com")
        self.assertEqual(prediction, "Safe")
        self.assertGreaterEqual(confidence, 0.5)

    def test_predict_url_malicious(self):
        """Test predicting a known phishing/malicious URL pattern."""
        prediction, confidence = predict_url("http://login-verify-paypal-accounts-secure.info/signin")
        self.assertEqual(prediction, "Malicious")
        self.assertGreaterEqual(confidence, 0.5)

    def test_predict_network_threat_dos(self):
        """Test model classification of DoS attack signature."""
        threat_type, confidence, severity = predict_network_threat(
            duration=0.01, protocol_str="tcp", packet_size=64, error_rate=0.98, connection_count=450
        )
        self.assertEqual(threat_type, "DoS")
        self.assertEqual(severity, "High")

    def test_predict_network_threat_malware(self):
        """Test model classification of Malware download signature."""
        threat_type, confidence, severity = predict_network_threat(
            duration=150.0, protocol_str="tcp", packet_size=350000, error_rate=0.01, connection_count=1
        )
        self.assertEqual(threat_type, "Malware")
        self.assertEqual(severity, "High")

    def test_predict_network_threat_bruteforce(self):
        """Test model classification of Brute-Force SSH/login signature."""
        threat_type, confidence, severity = predict_network_threat(
            duration=20.0, protocol_str="tcp", packet_size=400, error_rate=0.75, connection_count=80
        )
        self.assertEqual(threat_type, "Brute-Force")
        self.assertEqual(severity, "Medium")

    def test_predict_network_threat_normal(self):
        """Test model classification of Normal network traffic."""
        threat_type, confidence, severity = predict_network_threat(
            duration=2.5, protocol_str="tcp", packet_size=1000, error_rate=0.0, connection_count=3
        )
        self.assertEqual(threat_type, "Normal")
        self.assertEqual(severity, "Low")

    # --- 2. INTEGRATION / FLASK CONTROLLER TESTS ---

    def test_login_success(self):
        """Test login redirect with correct credentials."""
        response = self.client.post('/login', data=dict(
            username='admin',
            password='admin123'
        ), follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/dashboard', response.headers['Location'])

    def test_login_invalid_password(self):
        """Test login page error rendering on wrong password."""
        response = self.client.post('/login', data=dict(
            username='admin',
            password='wrongpassword'
        ), follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Invalid username or password.', response.data)

    def test_login_empty_credentials(self):
        """Test login error rendering on empty input."""
        response = self.client.post('/login', data=dict(
            username='',
            password=''
        ), follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Please fill in all fields.', response.data)

    def test_dashboard_requires_login(self):
        """Test dashboard route redirects to login when unauthorized."""
        response = self.client.get('/dashboard', follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response.headers['Location'])

    def test_api_scan_url_safe_endpoint(self):
        """Test URL Scan API response for a safe URL."""
        # Log client in first
        with self.client.session_transaction() as sess:
            sess['logged_in'] = True
            sess['user_id'] = 1
            sess['username'] = 'admin'
            sess['role'] = 'admin'
            
        response = self.client.post('/api/scan/url', data=dict(
            url='https://wikipedia.org'
        ))
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertEqual(data['prediction'], 'Safe')

    def test_api_scan_url_malicious_endpoint(self):
        """Test URL Scan API response for a malicious URL."""
        with self.client.session_transaction() as sess:
            sess['logged_in'] = True
            sess['user_id'] = 1
            sess['username'] = 'admin'
            sess['role'] = 'admin'
            
        response = self.client.post('/api/scan/url', data=dict(
            url='http://verify-bank-security-alert-free.net/login'
        ))
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertEqual(data['prediction'], 'Malicious')

    def test_api_scan_url_invalid_format(self):
        """Test URL Scan API response for a malformed/invalid URL."""
        with self.client.session_transaction() as sess:
            sess['logged_in'] = True
            sess['user_id'] = 1
            
        response = self.client.post('/api/scan/url', data=dict(
            url='not-a-valid-url-input'
        ))
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertFalse(data['success'])
        self.assertIn('Invalid URL format', data['error'])

    def test_api_scan_url_empty(self):
        """Test URL Scan API response for empty string input."""
        with self.client.session_transaction() as sess:
            sess['logged_in'] = True
            sess['user_id'] = 1
            
        response = self.client.post('/api/scan/url', data=dict(
            url=''
        ))
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data)
        self.assertFalse(data['success'])
        self.assertIn('cannot be empty', data['error'])

    def test_api_scan_network_csv(self):
        """Test network intrusion classification via uploaded CSV dataset."""
        with self.client.session_transaction() as sess:
            sess['logged_in'] = True
            sess['user_id'] = 1
            sess['username'] = 'admin'
            sess['role'] = 'admin'
            
        csv_data = (
            "duration,protocol_type,packet_size,error_rate,connection_count\n"
            "0.5,tcp,750,0.01,4\n"      # Normal
            "0.02,tcp,64,0.95,350\n"    # DoS
            "120.4,tcp,450000,0.02,1\n" # Malware
            "15.2,tcp,350,0.65,65\n"    # Brute-Force
        )
        
        response = self.client.post(
            '/api/scan/network',
            data={'file': (BytesIO(csv_data.encode('utf-8')), 'test_log.csv')},
            content_type='multipart/form-data'
        )
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['success'])
        self.assertEqual(data['total_records'], 4)
        self.assertEqual(data['threats_detected'], 3)
        self.assertEqual(data['breakdown']['Normal'], 1)
        self.assertEqual(data['breakdown']['DoS'], 1)
        self.assertEqual(data['breakdown']['Malware'], 1)
        self.assertEqual(data['breakdown']['Brute-Force'], 1)

if __name__ == '__main__':
    unittest.main()
