import os
import pickle
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
URL_MODEL_PATH = os.path.join(BASE_DIR, "url_model.pkl")
NETWORK_MODEL_PATH = os.path.join(BASE_DIR, "network_model.pkl")

# --- URL FEATURE EXTRACTION ---
def extract_url_features(url):
    """
    Extracts enhanced numerical features from a URL for ML classification.
    Features (18 total):
    1. Length of URL
    2. Number of dots ('.')
    3. Number of hyphens ('-')
    4. Presence of '@' (phishing redirection)
    5. Presence of '?' (query parameter)
    6. Presence of '='
    7. Is IP address used as host
    8. HTTPS used
    9. Suspicious keywords count
    10. Subdomain count
    11. Path length
    12. Number of special characters
    13. Digit ratio in URL
    14. TLD length
    15. Has numeric TLD
    16. URL entropy (randomness measure)
    17. Consecutive character count
    18. Has port number
    """
    if not url:
        return np.zeros(18)
        
    url_lower = url.lower()
    url_len = len(url)
    dots = url.count('.')
    hyphens = url.count('-')
    has_at = 1 if '@' in url else 0
    has_question = 1 if '?' in url else 0
    has_equal = 1 if '=' in url else 0
    
    # Check IP in domain
    try:
        parsed = urlparse(url)
        host = parsed.netloc
        if not host and parsed.path:
            host = parsed.path.split('/')[0]
        
        # Simple check if host is an IP
        parts = host.split('.')
        is_ip = 1 if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts) else 0
        https = 1 if parsed.scheme == 'https' else 0
        
        # Extract subdomain count
        if host:
            subdomain_parts = host.split('.')
            subdomain_count = max(0, len(subdomain_parts) - 2)  # subtract domain and TLD
        else:
            subdomain_count = 0
            
        # Extract TLD
        if host and '.' in host:
            tld = host.split('.')[-1]
            tld_len = len(tld)
            has_numeric_tld = 1 if any(c.isdigit() for c in tld) else 0
        else:
            tld_len = 0
            has_numeric_tld = 0
            
        # Path length
        path = parsed.path
        path_len = len(path)
        
        # Check for port
        has_port = 1 if ':' in host and not host.startswith('[') else 0
        
    except Exception:
        is_ip = 0
        https = 0
        host = ""
        subdomain_count = 0
        tld_len = 0
        has_numeric_tld = 0
        path_len = 0
        has_port = 0
        
    # Enhanced suspicious keywords list
    suspicious_words = [
        'login', 'verify', 'free', 'update', 'secure', 'banking', 'signin', 
        'account', 'paypal', 'webscr', 'confirm', 'password', 'wallet', 'crypto',
        'bitcoin', 'token', 'claim', 'reward', 'prize', 'gift', 'bonus',
        'urgent', 'alert', 'suspended', 'blocked', 'restore', 'recover',
        'support', 'security', 'authentication', 'validation', 'identity'
    ]
    word_count = sum(1 for word in suspicious_words if word in url_lower)
    
    # Special characters count
    special_chars = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~"
    special_count = sum(1 for c in url if c in special_chars)
    
    # Digit ratio
    digits = sum(1 for c in url if c.isdigit())
    digit_ratio = digits / max(1, url_len)
    
    # URL entropy (measure of randomness)
    import math
    from collections import Counter
    if url_len > 0:
        char_counts = Counter(url)
        entropy = 0
        for count in char_counts.values():
            p = count / url_len
            entropy -= p * math.log2(p) if p > 0 else 0
    else:
        entropy = 0
    
    # Consecutive character count (repeated characters)
    consecutive_count = 0
    for i in range(len(url) - 1):
        if url[i] == url[i + 1]:
            consecutive_count += 1
    
    return np.array([
        url_len, dots, hyphens, has_at, has_question, has_equal, is_ip, https, 
        word_count, subdomain_count, path_len, special_count, digit_ratio, 
        tld_len, has_numeric_tld, entropy, consecutive_count, has_port
    ])

# --- NETWORK FEATURE EXTRACTION ---
# Features for network scan (from CSV rows):
# 1. duration (seconds)
# 2. protocol_type (TCP=0, UDP=1, ICMP=2)
# 3. packet_size (bytes)
# 4. error_rate (0.0 to 1.0)
# 5. connection_count (integer)

def parse_protocol(proto_str):
    proto_str = str(proto_str).lower().strip()
    if 'tcp' in proto_str:
        return 0
    elif 'udp' in proto_str:
        return 1
    elif 'icmp' in proto_str:
        return 2
    return 0

# --- SYNTHETIC DATA GENERATION & TRAINING ---
def generate_and_train_models():
    print("Generating enhanced synthetic datasets & training ML models...")
    
    # 1. URL Model Setup with Enhanced Training Data
    urls_data = [
        # Safe URLs - legitimate domains
        ("https://google.com", 0),
        ("https://github.com", 0),
        ("https://wikipedia.org", 0),
        ("https://amazon.com", 0),
        ("https://stackoverflow.com", 0),
        ("https://apple.com", 0),
        ("https://microsoft.com", 0),
        ("https://netflix.com", 0),
        ("https://linkedin.com", 0),
        ("https://yahoo.com", 0),
        ("https://medium.com", 0),
        ("https://nytimes.com", 0),
        ("https://reddit.com", 0),
        ("https://zoom.us", 0),
        ("https://spotify.com", 0),
        ("https://twitter.com", 0),
        ("https://facebook.com", 0),
        ("https://instagram.com", 0),
        ("https://youtube.com", 0),
        ("https://twitch.tv", 0),
        ("https://discord.com", 0),
        ("https://slack.com", 0),
        ("https://dropbox.com", 0),
        ("https://drive.google.com", 0),
        ("https://docs.google.com", 0),
        # Safe URLs with paths and parameters
        ("https://example.com/page", 0),
        ("https://shop.example.com/products?id=123", 0),
        ("https://blog.example.com/post/how-to-code", 0),
        ("https://api.example.com/v1/users", 0),
        ("https://sub.domain.co.uk/path/to/resource", 0),
        # Malicious URLs - phishing patterns
        ("http://192.168.1.99/free-giftcard-login", 1),
        ("http://secure-paypal-update-login.com/account", 1),
        ("http://login-verify-wellsfargo-accounts.net/signin", 1),
        ("http://runescape-free-gold.xyz/play", 1),
        ("http://netflix-billing-update.info/login.php", 1),
        ("http://chase-bank-verify-alert.org", 1),
        ("http://free-steam-codes-generator.temp", 1),
        ("http://apple-login-update-service.cc", 1),
        ("http://facebook-security-check.xyz", 1),
        ("http://microsoft-win-defender-scan.info/alert", 1),
        ("http://185.220.101.5/exploit.html", 1),
        ("http://secure-banking-alert.net/login?id=233", 1),
        # Additional malicious patterns
        ("http://confirm-paypal-account-secure.com/verify", 1),
        ("http://apple-id-restore-service.net/login", 1),
        ("http://google-account-recovery-alert.org/signin", 1),
        ("http://amazon-verify-purchase-update.com", 1),
        ("http://netflix-account-suspended.info", 1),
        ("http://crypto-wallet-claim-free-btc.xyz", 1),
        ("http://bitcoin-giveaway-reward-token.com", 1),
        ("http://urgent-security-alert-bank.com", 1),
        ("http://support-identity-verification.net", 1),
        ("http://password-reset-secure-account.org", 1),
    ]
    
    # Generate more diverse synthetic samples
    safe_tlds = ['.com', '.org', '.net', '.io', '.co', '.edu', '.gov']
    malicious_tlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.info', '.biz']
    
    for i in range(150):
        # Generate safe URLs with realistic patterns
        domain = f"site{i}{safe_tlds[i % len(safe_tlds)]}"
        paths = ['', '/home', '/about', '/contact', '/products', '/blog/post-1']
        urls_data.append((f"https://{domain}{paths[i % len(paths)]}", 0))
        
        # Generate malicious URLs with phishing patterns
        mal_words = ["login", "verify", "secure", "bank", "free", "update", "account", "confirm", "password", "wallet"]
        brands = ["paypal", "apple", "google", "amazon", "netflix", "facebook", "microsoft", "chase"]
        
        word1 = mal_words[i % len(mal_words)]
        brand = brands[i % len(brands)]
        tld = malicious_tlds[i % len(malicious_tlds)]
        
        # Create various malicious URL patterns
        if i % 3 == 0:
            url = f"http://{brand}-{word1}-account-{i}{tld}/signin.php"
        elif i % 3 == 1:
            url = f"http://{word1}-{brand}-secure-{i}{tld}?id={i}&ref=email"
        else:
            url = f"http://{brand}-security-alert-{i}{tld}/confirm-account"
        
        urls_data.append((url, 1))

    X_url = []
    y_url = []
    for url, label in urls_data:
        X_url.append(extract_url_features(url))
        y_url.append(label)
        
    X_url = np.array(X_url)
    y_url = np.array(y_url)
    
    # Use more trees and better parameters for improved accuracy
    url_clf = RandomForestClassifier(
        n_estimators=100, 
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42
    )
    url_clf.fit(X_url, y_url)
    
    with open(URL_MODEL_PATH, "wb") as f:
        pickle.dump(url_clf, f)
    print(f"Enhanced URL model trained with {len(urls_data)} samples and saved.")

    # 2. Network Threat Model Setup
    # Categories: 0: Normal, 1: DoS, 2: Malware, 3: Brute-Force
    # Features: duration, protocol_type (0/1/2), packet_size, error_rate, connection_count
    net_data = []
    
    # Normal traffic: low duration, normal size, 0 error, moderate connections
    for _ in range(150):
        net_data.append({
            'duration': np.random.uniform(0.1, 5.0),
            'protocol_type': np.random.choice([0, 1]), # TCP, UDP
            'packet_size': np.random.uniform(500, 1500),
            'error_rate': np.random.uniform(0.0, 0.05),
            'connection_count': np.random.randint(1, 10),
            'label': 0 # Normal
        })
        
    # DoS attack: low duration, tiny/same packet size, high connection count, moderate error_rate
    for _ in range(100):
        net_data.append({
            'duration': np.random.uniform(0.01, 0.5),
            'protocol_type': 0, # TCP SYN flood
            'packet_size': np.random.uniform(64, 128),
            'error_rate': np.random.uniform(0.7, 1.0),
            'connection_count': np.random.randint(80, 500),
            'label': 1 # DoS
        })

    # Malware download: high duration, very large packet size, low connection count, low error_rate
    for _ in range(100):
        net_data.append({
            'duration': np.random.uniform(10.0, 300.0),
            'protocol_type': 0, # TCP
            'packet_size': np.random.uniform(50000, 500000),
            'error_rate': np.random.uniform(0.0, 0.1),
            'connection_count': np.random.randint(1, 3),
            'label': 2 # Malware
        })

    # Brute-Force: high connection count, small packets, high error_rate (unsuccessful logins)
    for _ in range(100):
        net_data.append({
            'duration': np.random.uniform(1.0, 30.0),
            'protocol_type': 0, # TCP SSH/FTP
            'packet_size': np.random.uniform(200, 800),
            'error_rate': np.random.uniform(0.4, 0.8),
            'connection_count': np.random.randint(20, 100),
            'label': 3 # Brute-Force
        })

    df_net = pd.DataFrame(net_data)
    X_net = df_net[['duration', 'protocol_type', 'packet_size', 'error_rate', 'connection_count']].values
    y_net = df_net['label'].values
    
    net_clf = RandomForestClassifier(n_estimators=50, random_state=42)
    net_clf.fit(X_net, y_net)
    
    with open(NETWORK_MODEL_PATH, "wb") as f:
        pickle.dump(net_clf, f)
    print("Network threat model trained and saved.")

# --- PREDICTION FUNCTIONS ---
def load_url_model():
    if not os.path.exists(URL_MODEL_PATH):
        generate_and_train_models()
    with open(URL_MODEL_PATH, "rb") as f:
        return pickle.load(f)

def load_network_model():
    if not os.path.exists(NETWORK_MODEL_PATH):
        generate_and_train_models()
    with open(NETWORK_MODEL_PATH, "rb") as f:
        return pickle.load(f)

def predict_url(url):
    """
    Predicts if a URL is Safe or Malicious.
    Returns: (prediction_str, confidence_score)
    """
    model = load_url_model()
    features = extract_url_features(url).reshape(1, -1)
    pred_class = model.predict(features)[0]
    prob = model.predict_proba(features)[0]
    
    prediction_str = "Malicious" if pred_class == 1 else "Safe"
    confidence_score = float(prob[pred_class])
    return prediction_str, confidence_score

def predict_network_threat(duration, protocol_str, packet_size, error_rate, connection_count):
    """
    Predicts threat type of a network connection:
    Normal, DoS, Malware, Brute-Force
    Returns: (threat_type_str, confidence_score, severity_str)
    """
    model = load_network_model()
    proto_encoded = parse_protocol(protocol_str)
    features = np.array([[
        float(duration),
        float(proto_encoded),
        float(packet_size),
        float(error_rate),
        float(connection_count)
    ]])
    
    pred_class = model.predict(features)[0]
    prob = model.predict_proba(features)[0]
    confidence_score = float(prob[pred_class])
    
    labels = {0: "Normal", 1: "DoS", 2: "Malware", 3: "Brute-Force"}
    threat_type = labels.get(pred_class, "Normal")
    
    # Assign severity
    if threat_type == "Normal":
        severity = "Low"
    elif threat_type == "Brute-Force":
        severity = "Medium"
    else: # DoS, Malware
        severity = "High"
        
    return threat_type, confidence_score, severity

# Initialize on import to make sure pickle files exist
if not os.path.exists(URL_MODEL_PATH) or not os.path.exists(NETWORK_MODEL_PATH):
    generate_and_train_models()
