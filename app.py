import streamlit as st
import numpy as np
import pandas as pd
import joblib

# ================= LOAD MODEL =================
model = joblib.load("svm_model.pkl")   # trained with probability=True
scaler = joblib.load("scaler.pkl")

feature_names = joblib.load("feature_names.pkl")

df = pd.read_csv("test_network_data.csv")

# 🔥 MAGIC LINE
df = df.reindex(columns=feature_names, fill_value=0)

# Step 3: NOW validate
if df.shape[1] != len(feature_names):
    st.error("Invalid network CSV structure")
    st.stop()


df_scaled = scaler.transform(df)
predictions = model.predict(df_scaled)

st.set_page_config(
    page_title="Network Intrusion Detection System",
    page_icon="🔐",
    layout="wide"
)

# ================= SESSION STATE =================
if "prob_history" not in st.session_state:
    st.session_state.prob_history = []

# ================= CSS =================
st.markdown("""
<style>
.card {
    padding: 20px;
    border-radius: 12px;
    background-color: #f6f8fa;
    margin-bottom: 20px;
}
@keyframes pulse {
  0% { background-color: #ff4d4d; }
  50% { background-color: #ff1a1a; }
  100% { background-color: #ff4d4d; }
}
.alert-banner {
  animation: pulse 1.2s infinite;
  padding: 15px;
  border-radius: 10px;
  color: white;
  font-weight: bold;
  text-align: center;
  margin-bottom: 15px;
}
</style>
""", unsafe_allow_html=True)

# ================= HEADER =================
st.markdown(
    """
    <h1 style='text-align: center;'>🔐 Network Intrusion Detection System</h1>
    <p style='text-align: center; font-size:18px;'>
    AI-powered real-time network threat detection dashboard
    </p>
    """,
    unsafe_allow_html=True
)

st.divider()

# ================= SIDEBAR =================
st.sidebar.header("⚙️ Network Traffic Inputs")

# ---- Duration ----
st.sidebar.subheader("⏱ Connection Duration")
duration_value = st.sidebar.slider("Duration", 0.0, 60.0, 5.0, 0.5)
duration_unit = st.sidebar.selectbox("Unit", ["Seconds", "Minutes", "Hours"])

if duration_unit == "Seconds":
    duration = duration_value
elif duration_unit == "Minutes":
    duration = duration_value * 60
else:
    duration = duration_value * 3600

# ---- Source Data ----
st.sidebar.subheader("📤 Source Data")
src_value = st.sidebar.slider("Source Data", 0.0, 50.0, 5.0, 0.5)
src_unit = st.sidebar.selectbox("Source Unit", ["KB", "MB"])

# ---- Destination Data ----
st.sidebar.subheader("📥 Destination Data")
dst_value = st.sidebar.slider("Destination Data", 0.0, 50.0, 3.0, 0.5)
dst_unit = st.sidebar.selectbox("Destination Unit", ["KB", "MB"])

def to_bytes(val, unit):
    return val * 1024 if unit == "KB" else val * 1024 * 1024

src_bytes = to_bytes(src_value, src_unit)
dst_bytes = to_bytes(dst_value, dst_unit)

# ---- Counts ----
count = st.sidebar.slider("Connection Count", 0, 500, 20)
srv_count = st.sidebar.slider("Service Count", 0, 500, 20)

if st.sidebar.button("🔄 Reset Inputs"):
    st.rerun()

st.sidebar.caption("Model trained on NSL-KDD dataset")

# ================= REAL-TIME PREDICTION =================
TOTAL_FEATURES = model.n_features_in_
user_features = np.zeros(TOTAL_FEATURES)

user_features[0] = duration
user_features[1] = src_bytes
user_features[2] = dst_bytes
user_features[3] = count
user_features[4] = srv_count

user_scaled = scaler.transform([user_features])

prediction = model.predict(user_scaled)[0]
attack_prob = model.predict_proba(user_scaled)[0][1] * 100

# ---- Store trend ----
st.session_state.prob_history.append(attack_prob)
if len(st.session_state.prob_history) > 15:
    st.session_state.prob_history.pop(0)

# ---- Risk Logic ----
if attack_prob < 30:
    risk = "Low Risk"
    color = "green"
elif attack_prob < 70:
    risk = "Medium Risk"
    color = "orange"
else:
    risk = "High Risk"
    color = "red"

# ================= MAIN PANEL =================
col1, col2 = st.columns([1, 1])

with col1:
    st.markdown("<div class='card'>", unsafe_allow_html=True)
    st.subheader("📥 Input Summary")
    st.write(f"- **Duration:** {duration_value} {duration_unit}")
    st.write(f"- **Source Data:** {src_value} {src_unit}")
    st.write(f"- **Destination Data:** {dst_value} {dst_unit}")
    st.write(f"- **Connection Count:** {count}")
    st.write(f"- **Service Count:** {srv_count}")
    st.markdown("</div>", unsafe_allow_html=True)

with col2:
    st.markdown("<div class='card'>", unsafe_allow_html=True)
    st.subheader("🤖 Prediction Result")

    if attack_prob >= 70:
        st.markdown(
            "<div class='alert-banner'>🚨 HIGH RISK ALERT: Potential Network Intrusion Detected!</div>",
            unsafe_allow_html=True
        )

    st.markdown(
        f"<h3 style='color:{color};'>🚦 Risk Level: {risk}</h3>",
        unsafe_allow_html=True
    )

    st.write(f"**Attack Probability:** {attack_prob:.2f}%")
    st.progress(int(attack_prob))

    if risk == "Low Risk":
        st.info("Traffic behavior appears normal. No immediate action required.")
    elif risk == "Medium Risk":
        st.warning("Traffic shows unusual characteristics. Continuous monitoring is recommended.")
    else:
        st.error("Traffic strongly matches known intrusion patterns. Immediate investigation advised.")

    st.markdown("</div>", unsafe_allow_html=True)

# ================= TREND =================
st.subheader("📈 Attack Probability Trend")

trend_df = pd.DataFrame({
    "Step": range(1, len(st.session_state.prob_history) + 1),
    "Attack Probability (%)": st.session_state.prob_history
})

st.line_chart(trend_df.set_index("Step"))

st.divider()

# ================= CSV UPLOAD =================

st.subheader("📂 Batch Prediction (CSV Upload)")

uploaded_file = st.file_uploader("Upload Network CSV File", type=["csv"])

if uploaded_file:
    df = pd.read_csv(uploaded_file)

    # Save original column count (for warning)
    original_cols = df.shape[1]

    # 🔥 ALIGN FEATURES FIRST (THIS FIXES EVERYTHING)
    df = df.reindex(columns=feature_names, fill_value=0)

    # Optional but professional warning
    if original_cols < len(feature_names):
        st.warning(
            f"Uploaded CSV had {original_cols} columns. "
            f"Missing features were auto-filled."
        )

    # Numeric validation AFTER reindexing
    if not np.all(df.applymap(np.isreal)):
        st.error("❌ CSV contains non-numeric values.")
    else:
        # Scale & predict
        df_scaled = scaler.transform(df)
        preds = model.predict(df_scaled)

        df["Prediction"] = np.where(preds == 1, "Attack", "Normal")

        total = len(df)
        attacks = (df["Prediction"] == "Attack").sum()
        normal = (df["Prediction"] == "Normal").sum()

        c1, c2, c3 = st.columns(3)
        c1.metric("Total Records", total)
        c2.metric("Attacks Detected", attacks)
        c3.metric("Normal Traffic", normal)

        st.dataframe(df.head())
        st.bar_chart(df["Prediction"].value_counts())

# ================= MODEL INFO =================
with st.expander("ℹ️ Model & Dataset Information"):
    st.write("""
    **Model:** Support Vector Machine (SVM)  
    **Dataset:** NSL-KDD  
    **Features:** Preprocessed & scaled network attributes  
    **Accuracy:** ~97%  
    **Key Metric:** Recall (Intrusion Detection)
    """)

st.caption("🔐 Network IDS Dashboard • Final Version")
