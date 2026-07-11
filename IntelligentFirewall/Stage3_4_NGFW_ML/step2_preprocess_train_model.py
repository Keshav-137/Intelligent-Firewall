import pandas as pd
import numpy as np
import joblib  # For saving the model
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, accuracy_score

# 📂 Load the Master Dataset you created in Step 1
INPUT_PATH = "./data/processed/master_firewall_data.csv"
MODEL_PATH = "./models/xgboost_firewall.pkl"
SCALER_PATH = "./models/scaler.pkl"
ENCODER_PATH = "./models/protocol_encoder.pkl"

# Create models directory if it doesn't exist
import os
os.makedirs("./models/", exist_ok=True)

def train_and_save_model():
    print("📖 Loading dataset...")
    df = pd.read_csv(INPUT_PATH)
    
    # 1. Feature Engineering: Protocol Encoding
    # We must save the encoder so 'tcp' always = the same number in real-time
    print("🔧 Encoding protocols...")
    le = LabelEncoder()
    df['protocol'] = le.fit_transform(df['protocol'].astype(str))
    joblib.dump(le, ENCODER_PATH) # SAVE ENCODER
    
    # 2. Define Features (X) and Target (y)
    # Ensure these match the columns from your combination script
    features = ["dst_port", "src_port", "duration", "src_bytes", "dst_bytes", "src_packets", "dst_packets", "protocol"]
    X = df[features]
    y = df['label']

    # 3. Sampling for performance (Optional: adjust based on your RAM)
    if len(df) > 500000:
        print(f"⚡ Large dataset detected ({len(df)} rows). Sampling 500,000 for efficiency.")
        X_train_full, X_test_full, y_train_full, y_test_full = train_test_split(X, y, train_size=500000, stratify=y, random_state=42)
    else:
        X_train_full, X_test_full, y_train_full, y_test_full = X, X, y, y

    # 4. Split into Train/Test
    X_train, X_test, y_train, y_test = train_test_split(X_train_full, y_train_full, test_size=0.2, random_state=42)

    # 5. Feature Scaling (CRITICAL for real-time accuracy)
    print("⚖️ Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    joblib.dump(scaler, SCALER_PATH) # SAVE SCALER

    # 6. Train XGBoost
    print("🚀 Training XGBoost Model...")
    model = XGBClassifier(
        n_estimators=100, 
        max_depth=6, 
        learning_rate=0.1, 
        verbosity=1,
        use_label_encoder=False,
        eval_metric='logloss'
    )
    model.fit(X_train_scaled, y_train)

    # 7. Final Validation
    y_pred = model.predict(X_test_scaled)
    print(f"\n✅ Training Complete!")
    print(f"🎯 Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("\n📊 Classification Report:")
    print(classification_report(y_test, y_pred))

    # 8. SAVE THE BRAIN
    joblib.dump(model, MODEL_PATH)
    print(f"\n💾 SUCCESS: Model saved to {MODEL_PATH}")
    print(f"💾 SUCCESS: Scaler saved to {SCALER_PATH}")
    print(f"💾 SUCCESS: Encoder saved to {ENCODER_PATH}")

if __name__ == "__main__":
    train_and_save_model()