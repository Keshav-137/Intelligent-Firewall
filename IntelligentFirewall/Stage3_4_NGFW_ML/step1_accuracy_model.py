import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, accuracy_score

from xgboost import XGBClassifier

# 📂 Load your combined dataset
data = pd.read_csv("Stage 3_4/master_firewall_data.csv")

print("✅ Data Loaded:", data.shape)

# -------------------------------
# 🔧 Step 1: Encode protocol
# -------------------------------
le = LabelEncoder()
data['protocol'] = le.fit_transform(data['protocol'])

# -------------------------------
# 🔧 Step 2: Split features
# -------------------------------
X = data.drop('label', axis=1)
y = data['label']

# -------------------------------
# ⚠️ Step 3: Reduce size (if needed)
# -------------------------------
if len(data) > 200000:
    data = data.sample(n=200000, random_state=42)
    X = data.drop('label', axis=1)
    y = data['label']
    print("⚡ Reduced dataset size:", data.shape)

# -------------------------------
# ⚖️ Step 4: Scaling
# -------------------------------
scaler = StandardScaler()
X = scaler.fit_transform(X)

# -------------------------------
# ✂️ Step 5: Train-Test Split
# -------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# -------------------------------
# 🤖 Step 6: Train XGBoost Model
# -------------------------------
model = XGBClassifier(
    n_estimators=150,
    max_depth=6,
    learning_rate=0.1,
    n_jobs=-1,
    eval_metric='logloss'
)

model.fit(X_train, y_train)

# -------------------------------
# 📊 Step 7: Evaluation
# -------------------------------
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print("\n🔥 Accuracy:", accuracy)
print("\n📊 Classification Report:\n")
print(classification_report(y_test, y_pred))