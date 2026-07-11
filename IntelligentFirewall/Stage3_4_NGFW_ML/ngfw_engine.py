from mitmproxy import http
import joblib
import time
import hashlib

# ==============================
# 📂 LOAD ML MODEL + TOOLS
# ==============================
# Stage 3_4\models
MODEL_PATH = "C:/Users/Keshav/Desktop/Intelligent Firewall/Stage 3_4/models/protocol_encoder.pkl"
SCALER_PATH = "C:/Users/Keshav/Desktop/Intelligent Firewall/Stage 3_4/models/scaler.pkl"
ENCODER_PATH = "C:/Users/Keshav/Desktop/Intelligent Firewall/Stage 3_4/models/protocol_encoder.pkl"
print("📦 Loading AI Firewall Model...")
model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)
encoder = joblib.load(ENCODER_PATH)

FEATURES = ["dst_port", "src_port", "duration", "src_bytes", "dst_bytes", "src_packets", "dst_packets", "protocol"]

# ==============================
# ⏱ FLOW TRACKING (for duration)
# ==============================
flow_start_time = {}

# ==============================
# 🧠 PREPROCESS FUNCTION
# ==============================
def preprocess(data):
    import pandas as pd

    df = pd.DataFrame([data])

    # Encode protocol
    df['protocol'] = encoder.transform(df['protocol'].astype(str))

    # Order features
    df = df[FEATURES]

    # Scale
    df_scaled = scaler.transform(df)

    return df_scaled

# ==============================
# 🚨 BLOCK FUNCTION
# ==============================
def block(flow, reason="Blocked by AI Firewall"):
    print(f"🚫 BLOCKED: {flow.request.pretty_url} | Reason: {reason}")
    
    flow.response = http.Response.make(
        403,
        b"Blocked by AI Firewall",
        {"Content-Type": "text/plain"}
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
        src_port = 12345  # Simulated (mitmproxy limitation)

        data = {
            "dst_port": dst_port,
            "src_port": src_port,
            "duration": 0,  # will update later
            "src_bytes": src_bytes,
            "dst_bytes": 0,
            "src_packets": 1,
            "dst_packets": 1,
            "protocol": "tcp"
        }

        # ==============================
        # 🧠 ML PREDICTION
        # ==============================
        processed = preprocess(data)
        prediction = model.predict(processed)[0]
        confidence = model.predict_proba(processed)[0]

        print(f"🔍 Checking: {req.pretty_url}")
        print(f"Prediction: {prediction}, Confidence: {confidence}")

        # ==============================
        # 🚨 BLOCK IF MALICIOUS
        # ==============================
        if prediction == 1:
            block(flow, "ML detected malicious traffic")
            return

        # ==============================
        # 🔥 EXTRA DPI RULES (STRONG)
        # ==============================
        body = (req.get_text() or "").lower()

        # Keyword detection
        if any(word in body for word in ["malware", "hack", "exploit"]):
            block(flow, "DPI keyword detected")
            return

        # Suspicious domains
        if any(domain in req.host for domain in ["badsite.com", "c2server.com"]):
            block(flow, "Suspicious domain")
            return

        # File download detection
        if req.pretty_url.endswith(".exe"):
            print("⚠ Executable download detected")

    except Exception as e:
        print("⚠ Error in request processing:", e)


# ==============================
# 📤 RESPONSE HANDLER
# ==============================
def response(flow: http.HTTPFlow):

    flow_id = id(flow)

    try:
        # Calculate duration
        if flow_id in flow_start_time:
            duration = time.time() - flow_start_time[flow_id]
        else:
            duration = 1

        res = flow.response
        content = res.content or b""

        # File hashing (malware detection)
        file_hash = hashlib.md5(content).hexdigest()

        print(f"📦 Response size: {len(content)} bytes | Hash: {file_hash}")

        # Detect malicious content in response
        body = (res.get_text() or "").lower()

        if "virus" in body or "trojan" in body:
            block(flow, "Malicious response detected")
            return

        # Large data exfiltration detection
        if len(content) > 2000000:  # 2MB threshold
            print("⚠ Large data transfer detected")

    except Exception as e:
        print("⚠ Error in response processing:", e)