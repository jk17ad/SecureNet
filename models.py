import os
import math
import pickle
import numpy as np
import pandas as pd
from collections import Counter
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
URL_MODEL_PATH = os.path.join(BASE_DIR, "url_model.pkl")
NETWORK_MODEL_PATH = os.path.join(BASE_DIR, "network_model.pkl")

# ── Whitelist: registered domains known to be safe ─────────────────────────────
SAFE_DOMAINS = {
    # Google
    'google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com',
    'googlevideo.com', 'google.co.uk', 'google.co.in',
    # Microsoft
    'microsoft.com', 'microsoftonline.com', 'office.com', 'live.com',
    'outlook.com', 'azure.com', 'windowsupdate.com', 'visualstudio.com', 'bing.com',
    # Apple
    'apple.com', 'icloud.com', 'mzstatic.com',
    # Amazon / AWS
    'amazon.com', 'amazonaws.com', 'amazon.co.uk',
    # Social
    'facebook.com', 'fb.com', 'fbcdn.net',
    'twitter.com', 'x.com', 't.co',
    'instagram.com', 'cdninstagram.com',
    'linkedin.com', 'licdn.com',
    'reddit.com', 'redd.it', 'redditmedia.com', 'redditstatic.com',
    'youtube.com', 'ytimg.com',
    'tiktok.com', 'snapchat.com', 'pinterest.com',
    'discord.com', 'discordapp.com',
    'twitch.tv', 'jtvnw.net',
    'slack.com',
    # Dev / Tech
    'github.com', 'githubusercontent.com', 'githubassets.com',
    'stackoverflow.com', 'stackexchange.com',
    'npmjs.com', 'pypi.org', 'rubygems.org', 'pkg.dev',
    'docker.com', 'atlassian.com', 'jira.com', 'bitbucket.org',
    'gitlab.com', 'cloudflare.com', 'fastly.com', 'akamai.com',
    # Entertainment / Media
    'netflix.com', 'nflximg.com', 'spotify.com',
    'medium.com', 'substack.com', 'nytimes.com', 'bbc.com',
    'cnn.com', 'theguardian.com', 'washingtonpost.com', 'reuters.com',
    # Communication
    'zoom.us', 'zoomgov.com', 'dropbox.com', 'notion.so', 'figma.com',
    # Finance / Commerce
    'paypal.com', 'ebay.com', 'shopify.com', 'stripe.com',
    'chase.com', 'wellsfargo.com', 'bankofamerica.com', 'citibank.com',
    'venmo.com', 'coinbase.com',
    # Delivery
    'usps.com', 'fedex.com', 'ups.com', 'dhl.com',
    # Other popular
    'wikipedia.org', 'wikimedia.org',
    'wordpress.com', 'wordpress.org',
    'squarespace.com', 'wix.com', 'tumblr.com',
    'adobe.com', 'salesforce.com', 'hubspot.com',
    'twilio.com', 'sendgrid.com', 'mailchimp.com',
    'yahoo.com', 'duckduckgo.com', 'brave.com',
    'mozilla.org', 'firefox.com', 'opera.com',
}

# ── Brand → legitimate registered domain ───────────────────────────────────────
BRAND_TO_DOMAIN = {
    'paypal':         'paypal.com',
    'apple':          'apple.com',
    'google':         'google.com',
    'amazon':         'amazon.com',
    'netflix':        'netflix.com',
    'facebook':       'facebook.com',
    'microsoft':      'microsoft.com',
    'chase':          'chase.com',
    'wellsfargo':     'wellsfargo.com',
    'citibank':       'citibank.com',
    'bankofamerica':  'bankofamerica.com',
    'instagram':      'instagram.com',
    'twitter':        'twitter.com',
    'youtube':        'youtube.com',
    'linkedin':       'linkedin.com',
    'dropbox':        'dropbox.com',
    'spotify':        'spotify.com',
    'steam':          'steampowered.com',
    'ebay':           'ebay.com',
    'walmart':        'walmart.com',
    'usps':           'usps.com',
    'fedex':          'fedex.com',
    'irs':            'irs.gov',
    'venmo':          'venmo.com',
    'coinbase':       'coinbase.com',
    'binance':        'binance.com',
    'metamask':       'metamask.io',
    'github':         'github.com',
    'discord':        'discord.com',
}

# ── Malicious TLDs (commonly abused, free, disposable) ─────────────────────────
MALICIOUS_TLDS = {
    'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'click', 'link',
    'work', 'party', 'loan', 'racing', 'win', 'download', 'stream',
    'pw', 'zip', 'review', 'country', 'kim', 'bid', 'men',
    'accountants', 'science', 'date', 'faith', 'trade', 'webcam',
    'cricket', 'ninja', 'tokyo', 'club', 'icu', 'buzz', 'fun',
    'rest', 'ink', 'bar', 'space', 'site', 'website', 'online',
    'host', 'press', 'uno', 'vip',
}

# ── Domain-only suspicious keywords ────────────────────────────────────────────
# ONLY words that almost never appear in LEGITIMATE domain names.
# Words like 'security', 'accounts', 'signin', 'support' are intentionally excluded
# because they appear in real domains (security.microsoft.com, accounts.google.com).
DOMAIN_SUSPICIOUS_WORDS = [
    'verify', 'free', 'update', 'banking', 'webscr', 'confirm', 'password',
    'wallet', 'crypto', 'bitcoin', 'claim', 'reward', 'prize', 'gift',
    'bonus', 'urgent', 'suspended', 'blocked', 'restore', 'recover',
    'giveaway', 'winner', 'congratulations', 'discount', 'promo',
    'billing', 'invoice', 'refund', 'unusual', 'activity',
]


# ── Helper: extract registered domain ──────────────────────────────────────────
def get_registered_domain(url):
    """Return 'google.com' from 'accounts.google.com' or 'sub.example.co.uk'."""
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        if ':' in host:
            host = host.split(':')[0]
        host = host.strip('.')
        parts = [p for p in host.split('.') if p]
        if len(parts) >= 3 and len(parts[-2]) <= 3 and len(parts[-1]) <= 3:
            return '.'.join(parts[-3:])   # e.g. example.co.uk
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return host
    except Exception:
        return ''


# ── Feature extraction (20 features) ───────────────────────────────────────────
def extract_url_features(url):
    """
    Extract 20 numerical features from a URL for ML classification.

     #   Feature                    Notes
    ─── ─────────────────────────── ────────────────────────────────────────────
     1  url_len                     Total character length
     2  dots                        '.' count in full URL
     3  hyphens                     '-' count in full URL
     4  has_at                      '@' present (phishing redirect trick)
     5  has_question                '?' present
     6  has_equal                   '=' present
     7  is_ip                       IP address used as host
     8  https                       Scheme is https
     9  domain_suspicious_count     Suspicious words found in hostname only
    10  subdomain_count             Depth above registered domain
    11  path_len                    Length of URL path component
    12  special_count               Non-alphanumeric char count
    13  digit_ratio                 Fraction of digits in full URL
    14  tld_len                     Length of TLD
    15  has_numeric_tld             TLD contains a digit
    16  entropy                     Shannon entropy of full URL
    17  domain_hyphens              Hyphens in hostname only
    18  has_port                    Non-standard port present
    19  is_malicious_tld            TLD is in the known-bad list
    20  brand_impersonation         Brand name in hostname but wrong domain
    """
    if not url:
        return np.zeros(20)

    url_lower = url.lower()
    url_len = len(url)
    dots = url.count('.')
    hyphens = url.count('-')
    has_at = 1 if '@' in url else 0
    has_question = 1 if '?' in url else 0
    has_equal = 1 if '=' in url else 0

    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        host_no_port = host.split(':')[0].strip('.') if ':' in host else host.strip('.')

        if not host_no_port and parsed.path:
            host_no_port = parsed.path.split('/')[0].lower()

        parts = [p for p in host_no_port.split('.') if p]
        is_ip = 1 if (len(parts) == 4 and all(
            p.isdigit() and 0 <= int(p) <= 255 for p in parts)) else 0
        https = 1 if parsed.scheme == 'https' else 0

        subdomain_count = max(0, len(parts) - 2)
        tld = parts[-1] if parts else ''
        tld_len = len(tld)
        has_numeric_tld = 1 if any(c.isdigit() for c in tld) else 0
        path_len = len(parsed.path)
        has_port = 1 if parsed.port else 0
        is_malicious_tld = 1 if tld in MALICIOUS_TLDS else 0
        domain_hyphens = host_no_port.count('-')

        # Suspicious word count in hostname only
        domain_suspicious_count = sum(
            1 for w in DOMAIN_SUSPICIOUS_WORDS if w in host_no_port
        )

        # Brand impersonation: brand appears in hostname but registered domain ≠ legit domain
        reg_domain = get_registered_domain(url)
        brand_impersonation = 0
        for brand, legit_domain in BRAND_TO_DOMAIN.items():
            if brand in host_no_port and reg_domain != legit_domain:
                brand_impersonation = 1
                break

    except Exception:
        is_ip = https = subdomain_count = tld_len = has_numeric_tld = 0
        path_len = has_port = is_malicious_tld = domain_hyphens = 0
        domain_suspicious_count = brand_impersonation = 0
        tld = ''

    special_chars = set("!@#$%^&*()_+-=[]{}|;':\",./<>?`~")
    special_count = sum(1 for c in url if c in special_chars)
    digits = sum(1 for c in url if c.isdigit())
    digit_ratio = digits / max(1, url_len)

    if url_len > 0:
        cc = Counter(url)
        entropy = -sum((v / url_len) * math.log2(v / url_len) for v in cc.values() if v > 0)
    else:
        entropy = 0.0

    return np.array([
        url_len, dots, hyphens, has_at, has_question, has_equal,
        is_ip, https, domain_suspicious_count, subdomain_count,
        path_len, special_count, digit_ratio, tld_len, has_numeric_tld,
        entropy, domain_hyphens, has_port, is_malicious_tld, brand_impersonation
    ])


# ── Network feature helpers ────────────────────────────────────────────────────
def parse_protocol(proto_str):
    proto_str = str(proto_str).lower().strip()
    if 'tcp' in proto_str:
        return 0
    elif 'udp' in proto_str:
        return 1
    elif 'icmp' in proto_str:
        return 2
    return 0


# ── Training data & model generation ──────────────────────────────────────────
def generate_and_train_models():
    print("Training improved ML models…")

    # ── URL dataset ────────────────────────────────────────────────────────────
    urls_data = [
        # ── Safe: top-level domains ─────────────────────────────────────────
        ("https://google.com", 0),
        ("https://www.google.com", 0),
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
        ("https://stripe.com", 0),
        ("https://paypal.com", 0),
        ("https://ebay.com", 0),
        ("https://bing.com", 0),
        ("https://adobe.com", 0),
        ("https://cloudflare.com", 0),

        # ── Safe: subdomains with "suspicious-sounding" words (the key test) ─
        ("https://accounts.google.com", 0),
        ("https://accounts.google.com/signin/v2/identifier", 0),
        ("https://myaccount.google.com/security", 0),
        ("https://security.microsoft.com/alerts", 0),
        ("https://account.microsoft.com", 0),
        ("https://login.microsoftonline.com", 0),
        ("https://support.apple.com/account", 0),
        ("https://support.apple.com/billing", 0),
        ("https://signin.apple.com", 0),
        ("https://support.google.com", 0),
        ("https://support.microsoft.com", 0),
        ("https://help.twitter.com/en/managing-your-account", 0),
        ("https://www.facebook.com/login", 0),
        ("https://www.facebook.com/recover/initiate", 0),
        ("https://www.linkedin.com/login", 0),
        ("https://login.live.com", 0),
        ("https://outlook.live.com/mail", 0),
        ("https://mail.google.com", 0),
        ("https://drive.google.com", 0),
        ("https://docs.google.com", 0),
        ("https://aws.amazon.com/console", 0),
        ("https://console.aws.amazon.com/billing/home", 0),
        ("https://developer.apple.com/account", 0),
        ("https://id.apple.com", 0),
        ("https://appleid.apple.com", 0),
        ("https://portal.azure.com", 0),
        ("https://github.com/login", 0),
        ("https://api.github.com/users", 0),
        ("https://discord.com/login", 0),
        ("https://www.reddit.com/login", 0),
        ("https://secure.paypal.com/myaccount/summary", 0),
        ("https://www.paypal.com/signin", 0),
        ("https://www.paypal.com/us/webapps/mpp/account-selection", 0),
        ("https://www.amazon.com/ap/signin", 0),
        ("https://sellercentral.amazon.com/account/summary", 0),
        ("https://bankofamerica.com/online-banking/sign-in", 0),
        ("https://www.chase.com/digital/resources/privacy-security", 0),
        ("https://coinbase.com/signin", 0),
        ("https://venmo.com/account/sign-in", 0),
        ("https://office.com/login", 0),
        ("https://outlook.office365.com", 0),

        # ── Safe: .gov and .edu ─────────────────────────────────────────────
        ("https://irs.gov", 0),
        ("https://ssa.gov", 0),
        ("https://usps.gov", 0),
        ("https://cdc.gov", 0),
        ("https://nasa.gov", 0),
        ("https://mit.edu", 0),
        ("https://harvard.edu/login", 0),
        ("https://stanford.edu", 0),

        # ── Safe: paths with query params (normal) ──────────────────────────
        ("https://shop.example.com/products?id=123", 0),
        ("https://blog.example.com/post/how-to-code", 0),
        ("https://api.example.com/v1/users", 0),
        ("https://sub.domain.co.uk/path/to/resource", 0),
        ("https://www.bbc.com/news/technology-update", 0),
        ("https://store.steampowered.com/app/1234/GameName", 0),

        # ── Malicious: classic phishing patterns ────────────────────────────
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
        ("http://confirm-paypal-account-secure.com/verify", 1),
        ("http://apple-id-restore-service.net/login", 1),
        ("http://google-account-recovery-alert.org/signin", 1),
        ("http://amazon-verify-purchase-update.com", 1),
        ("http://netflix-account-suspended.info", 1),
        ("http://crypto-wallet-claim-free-btc.xyz", 1),
        ("http://bitcoin-giveaway-reward-token.com", 1),
        ("http://urgent-security-alert-bank.com", 1),
        ("http://password-reset-secure-account.org", 1),

        # ── Malicious: brand impersonation ──────────────────────────────────
        ("http://paypal-secure-login.xyz/verify", 1),
        ("http://paypal-account-update.com/signin", 1),
        ("http://secure-paypal-help.net/login", 1),
        ("http://apple-id-restore.xyz/login", 1),
        ("http://appleid-verify-suspended.club/restore", 1),
        ("http://google-verify-login-alert.xyz", 1),
        ("http://microsoft-security-update-required.top/login", 1),
        ("http://amazon-order-confirm-update.xyz/account", 1),
        ("http://netflix-billing-confirm.top/update", 1),
        ("http://facebook-login-verify-account.ml", 1),
        ("http://instagram-account-blocked-restore.xyz", 1),
        ("http://twitter-suspended-verify.top", 1),
        ("http://chase-bank-login-verify-urgent.com/signin", 1),
        ("http://wellsfargo-account-update-alert.net", 1),
        ("http://irs-tax-refund-claim-now.xyz", 1),
        ("http://coinbase-wallet-recover-urgent.top", 1),
        ("http://binance-wallet-verify-claim.xyz", 1),
        ("http://metamask-restore-wallet-urgent.net", 1),
        ("http://discord-gift-claim-free-nitro.xyz", 1),
        ("http://steam-free-games-gift-claim.ml", 1),
        ("http://spotify-premium-free-claim.top", 1),
        ("http://venmo-payment-confirm-urgent.xyz", 1),
        ("http://usps-package-delivery-confirm.xyz/track", 1),
        ("http://fedex-package-suspended-claim.top", 1),
        ("http://walmart-prize-winner-claim.xyz", 1),

        # ── Malicious: IP-based ─────────────────────────────────────────────
        ("http://45.142.212.100/login.php", 1),
        ("http://192.168.0.1/admin", 1),
        ("http://10.0.0.1/update-account", 1),
        ("http://185.220.101.5/verify.html", 1),
        ("http://91.108.4.1/login-secure", 1),

        # ── Malicious: bad TLDs ─────────────────────────────────────────────
        ("http://login-secure.tk/account", 1),
        ("http://free-bitcoin.ml/claim", 1),
        ("http://update-required.ga/login", 1),
        ("http://account-verify.cf/signin", 1),
        ("http://win-prize.gq/claim-now", 1),
        ("http://banking-alert.pw/confirm", 1),
        ("http://reward-token.buzz/free", 1),
        ("http://wallet-recover.icu/urgent", 1),
        ("http://pay-verify.vip/login", 1),
        ("http://account-blocked.uno/restore", 1),
    ]

    # ── Synthetic safe samples ─────────────────────────────────────────────────
    safe_domains = [
        'example.com', 'mysite.org', 'techblog.io', 'newstore.co',
        'learnpython.net', 'healthnews.com', 'sportsupdates.com',
        'localbank.com', 'citycouncil.gov', 'university.edu',
        'weatherapp.com', 'fooddelivery.co', 'travelbooking.net',
        'gamingforum.com', 'musicstream.io',
    ]
    safe_paths = [
        '', '/home', '/about', '/contact', '/products',
        '/blog/post-1', '/news/latest', '/docs/getting-started',
        '/account/profile', '/support/faq',
    ]
    for i in range(150):
        d = safe_domains[i % len(safe_domains)]
        p = safe_paths[i % len(safe_paths)]
        urls_data.append((f"https://{d}{p}", 0))

    # ── Synthetic malicious samples ────────────────────────────────────────────
    mal_words = ['verify', 'update', 'confirm', 'restore', 'claim',
                 'free', 'wallet', 'password', 'billing', 'recover']
    brands     = ['paypal', 'apple', 'google', 'amazon', 'netflix',
                  'facebook', 'microsoft', 'chase', 'instagram', 'discord']
    bad_tlds   = list(MALICIOUS_TLDS)

    for i in range(200):
        word  = mal_words[i % len(mal_words)]
        brand = brands[i % len(brands)]
        tld   = bad_tlds[i % len(bad_tlds)]

        if i % 4 == 0:
            url = f"http://{brand}-{word}-account-{i}.{tld}/signin.php"
        elif i % 4 == 1:
            url = f"http://{word}-{brand}-secure-{i}.{tld}?id={i}&ref=email"
        elif i % 4 == 2:
            url = f"http://{brand}-security-{word}-{i}.{tld}/confirm"
        else:
            url = f"http://secure-{brand}-{word}.{tld}/login?verify={i}"
        urls_data.append((url, 1))

    X_url = np.array([extract_url_features(u) for u, _ in urls_data])
    y_url = np.array([label for _, label in urls_data])

    url_clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=3,
        min_samples_leaf=1,
        class_weight='balanced',
        random_state=42,
    )
    url_clf.fit(X_url, y_url)

    with open(URL_MODEL_PATH, "wb") as f:
        pickle.dump(url_clf, f)
    print(f"URL model trained on {len(urls_data)} samples.")

    # ── Network dataset ────────────────────────────────────────────────────────
    net_data = []

    for _ in range(150):
        net_data.append({'duration': np.random.uniform(0.1, 5.0),
                         'protocol_type': np.random.choice([0, 1]),
                         'packet_size': np.random.uniform(500, 1500),
                         'error_rate': np.random.uniform(0.0, 0.05),
                         'connection_count': np.random.randint(1, 10),
                         'label': 0})
    for _ in range(100):
        net_data.append({'duration': np.random.uniform(0.01, 0.5),
                         'protocol_type': 0,
                         'packet_size': np.random.uniform(64, 128),
                         'error_rate': np.random.uniform(0.7, 1.0),
                         'connection_count': np.random.randint(80, 500),
                         'label': 1})
    for _ in range(100):
        net_data.append({'duration': np.random.uniform(10.0, 300.0),
                         'protocol_type': 0,
                         'packet_size': np.random.uniform(50000, 500000),
                         'error_rate': np.random.uniform(0.0, 0.1),
                         'connection_count': np.random.randint(1, 3),
                         'label': 2})
    for _ in range(100):
        net_data.append({'duration': np.random.uniform(1.0, 30.0),
                         'protocol_type': 0,
                         'packet_size': np.random.uniform(200, 800),
                         'error_rate': np.random.uniform(0.4, 0.8),
                         'connection_count': np.random.randint(20, 100),
                         'label': 3})

    df_net = pd.DataFrame(net_data)
    X_net = df_net[['duration', 'protocol_type', 'packet_size',
                    'error_rate', 'connection_count']].values
    y_net = df_net['label'].values

    net_clf = RandomForestClassifier(n_estimators=50, random_state=42)
    net_clf.fit(X_net, y_net)

    with open(NETWORK_MODEL_PATH, "wb") as f:
        pickle.dump(net_clf, f)
    print("Network model trained.")


# ── Model loaders ──────────────────────────────────────────────────────────────
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


# ── Prediction: URL ────────────────────────────────────────────────────────────
def predict_url(url):
    """
    Hybrid URL threat classifier.

    Step 1 – Whitelist: if the registered domain is in SAFE_DOMAINS or TLD is
             .gov / .edu / .mil  →  return Safe with 97 % confidence.
    Step 2 – ML model: run RandomForest on 20 engineered features.

    Returns: (prediction_str, confidence_float)
    """
    # Normalise scheme
    if url.startswith("//"):
        url = "https:" + url
    elif not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Step 1: whitelist
    reg_domain = get_registered_domain(url)
    try:
        _parsed = urlparse(url)
        host = _parsed.netloc.lower().split(':')[0].strip('.')
        tld = host.rsplit('.', 1)[-1] if '.' in host else ''
    except Exception:
        tld = ''

    if reg_domain in SAFE_DOMAINS or tld in {'gov', 'edu', 'mil'}:
        return "Safe", 0.97

    # Step 2: ML
    model = load_url_model()
    features = extract_url_features(url).reshape(1, -1)
    pred_class = model.predict(features)[0]
    prob = model.predict_proba(features)[0]

    prediction_str = "Malicious" if pred_class == 1 else "Safe"
    confidence_score = float(prob[pred_class])
    return prediction_str, confidence_score


# ── Prediction: Network ────────────────────────────────────────────────────────
def predict_network_threat(duration, protocol_str, packet_size, error_rate, connection_count):
    """
    Predict threat type: Normal, DoS, Malware, Brute-Force.
    Returns: (threat_type_str, confidence_float, severity_str)
    """
    model = load_network_model()
    proto_encoded = parse_protocol(protocol_str)
    features = np.array([[float(duration), float(proto_encoded),
                          float(packet_size), float(error_rate),
                          float(connection_count)]])

    pred_class = model.predict(features)[0]
    prob = model.predict_proba(features)[0]
    confidence_score = float(prob[pred_class])

    labels = {0: "Normal", 1: "DoS", 2: "Malware", 3: "Brute-Force"}
    threat_type = labels.get(pred_class, "Normal")

    if threat_type == "Normal":
        severity = "Low"
    elif threat_type == "Brute-Force":
        severity = "Medium"
    else:
        severity = "High"

    return threat_type, confidence_score, severity


# ── Bootstrap: force retrain on import if models are missing or stale ──────────
_FEATURE_VERSION = "v2-20feat"   # bump this string to force a retrain
_VERSION_FILE = os.path.join(BASE_DIR, ".model_version")

def _needs_retrain():
    if not os.path.exists(URL_MODEL_PATH) or not os.path.exists(NETWORK_MODEL_PATH):
        return True
    if not os.path.exists(_VERSION_FILE):
        return True
    with open(_VERSION_FILE) as f:
        return f.read().strip() != _FEATURE_VERSION

if _needs_retrain():
    generate_and_train_models()
    with open(_VERSION_FILE, "w") as f:
        f.write(_FEATURE_VERSION)
