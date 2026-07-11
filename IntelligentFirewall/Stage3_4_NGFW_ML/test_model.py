from mitmproxy import http
import joblib
import time
import hashlib
import numpy as np

# ==============================
# 📂 LOAD ML MODEL + TOOLS
# ==============================
MODEL_PATH = "Stage 3_4/models/xgboost_firewall.pkl"
SCALER_PATH = "Stage 3_4/models/scaler.pkl"
ENCODER_PATH = "Stage 3_4/models/protocol_encoder.pkl"

print("📦 Loading AI Firewall Model, Scaler, and Encoder...")
try:
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    encoder = joblib.load(ENCODER_PATH)
    print("✅ AI Engine loaded successfully!")
except Exception as e:
    print(f"❌ Failed to load AI models: {e}")
    exit(1)

# Feature list used during training
FEATURES = ["dst_port", "src_port", "duration", "src_bytes", "dst_bytes", "src_packets", "dst_packets", "protocol"]

# ==============================
# ⏱ FLOW TRACKING (for duration)
# ==============================
flow_start_time = {}

# ==============================
# 🧠 PREPROCESS FUNCTION (Optimized for speed)
# ==============================
def preprocess(data):
    # Safely encode protocol (Fallback to 0 if unknown protocol is encountered)
    try:
        protocol_encoded = encoder.transform([str(data["protocol"])])[0]
    except ValueError:
        protocol_encoded = 0 

    # Create a 2D numpy array in the EXACT order of training features
    feature_array = np.array([[
        data["dst_port"],
        data["src_port"],
        data["duration"],
        data["src_bytes"],
        data["dst_bytes"],
        data["src_packets"],
        data["dst_packets"],
        protocol_encoded
    ]])

    # Scale the features
    scaled_features = scaler.transform(feature_array)
    return scaled_features

# ==============================
# 🚨 BLOCK FUNCTION
# ==============================
def block(flow, reason="Blocked by AI Firewall"):
    print(f"🚫 BLOCKED: {flow.request.pretty_url}")
    print(f"   └── Reason: {reason}")
    
    flow.response = http.Response.make(
        403,  # HTTP Status Code
        f"<html><body><h1>Access Denied</h1><p>{reason}</p></body></html>".encode("utf-8"),
        {"Content-Type": "text/html"}
    )

# ==============================
# 📥 REQUEST HANDLER
# ==============================
def request(flow: http.HTTPFlow):
    # Track start time
    flow_id = id(flow)
    flow_start_time[flow_id] = time.time()

    try:
        req = flow.request

        # Extract basic features
        src_bytes = len(req.content or b"")
        dst_port = req.port
        src_port = flow.client_conn.peername[1] if flow.client_conn and flow.client_conn.peername else 12345

        data = {
            "dst_port": dst_port,
            "src_port": src_port,
            "duration": 0.0,  # Duration is 0 at request start
            "src_bytes": src_bytes,
            "dst_bytes": 0,
            "src_packets": 1,
            "dst_packets": 0,
            "protocol": "tcp" # mitmproxy primarily intercepts TCP (HTTP/HTTPS)
        }

        # ==============================
        # 🧠 ML PREDICTION
        # ==============================
        processed = preprocess(data)
        prediction = model.predict(processed)[0]
        
        # XGBoost probabilities
        confidence = model.predict_proba(processed)[0]
        malicious_prob = confidence[1] * 100  # Probability of being class 1

        print(f"🔍 Checking: {req.pretty_url}")
        print(f"   └── AI Prediction: {'Malicious' if prediction == 1 else 'Benign'} (Confidence: {malicious_prob:.2f}%)")

        # ==============================
        # 🚨 BLOCK IF ML FLAGS IT
        # ==============================
        if prediction == 1:
            block(flow, f"AI ML Engine detected malicious anomaly ({malicious_prob:.2f}% confidence)")
            return

        # ==============================
        # 🔥 EXTRA DPI RULES (STRONG)
        # ==============================
        # Use strict=False to prevent UnicodeDecodeError on binary payloads
        body = (req.get_text(strict=False) or "").lower()

        # Keyword detection
        if any(word in body for word in ["malware", "hack", "exploit"]):
            block(flow, "DPI keyword detected in request body")
            return

        # Suspicious domains
        if any(domain in req.host for domain in ["badsite.com", "c2server.com"]):
            block(flow, "Suspicious domain requested")
            return

        # Executable request detection
        if req.pretty_url.split("?")[0].endswith((".exe", ".sh", ".bat")):
            print("   ⚠️ Executable download requested")

    except Exception as e:
        print(f"⚠️ Error in request processing: {e}")

# ==============================
# 📤 RESPONSE HANDLER
# ==============================
def response(flow: http.HTTPFlow):
    flow_id = id(flow)

    try:
        # Calculate duration
        duration = time.time() - flow_start_time.pop(flow_id, time.time())
        
        res = flow.response
        content = res.content or b""

        # File hashing (malware signature detection)
        file_hash = hashlib.md5(content).hexdigest()
        print(f"📦 Response from {flow.request.host} | Size: {len(content)} bytes | Flow Time: {duration:.3f}s")

        # Detect malicious content in response text
        body = (res.get_text(strict=False) or "").lower()

        if "virus" in body or "trojan" in body:
            block(flow, "Malicious payload signature detected in response")
            return

        # Large data exfiltration detection (e.g., larger than 2MB)
        if len(content) > 2000000:  
            print("   ⚠️ Large data transfer detected (Possible Data Exfiltration)")

    except Exception as e:
        print(f"⚠️ Error in response processing: {e}")