# ---------------------------
# 1. Import Dependencies
# ---------------------------
'''import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt
import joblib

# ---------------------------
# 2. Load the Dataset
# ---------------------------
# Replace with your actual file path
df = pd.read_csv(r"E:\LIL\friday.csv\friday_datas.csv")

print("Initial shape:", df.shape)
print("Columns:", df.columns.tolist())

# ---------------------------
# 3. Data Cleaning
# ---------------------------

# Drop irrelevant columns if they exist
cols_to_drop = ['Flow ID', 'Timestamp', 'Fwd Header Length.1']
df = df.drop(columns=[col for col in cols_to_drop if col in df.columns], errors='ignore')

# Replace infinite and NaN values
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

print("Shape after cleaning:", df.shape)

# ---------------------------
# 4. Label Encoding (Binary: PortScan = 1, Normal = 0)
# ---------------------------
df['Label'] = df['Label'].apply(lambda x: 1 if 'PortScan' in x else 0)

# ---------------------------
# 5. Feature Selection
# ---------------------------
# Keep only numeric features
X = df.select_dtypes(include=['number']).drop(columns=['Label'])
y = df['Label']

# ---------------------------
# 6. Feature Scaling
# ---------------------------
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# ---------------------------
# 7. Train/Test Split
# ---------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)

# ---------------------------
# 8. Train Model
# ---------------------------
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# ---------------------------
# 9. Make Predictions
# ---------------------------
y_pred = model.predict(X_test)

# ---------------------------
# 10. Evaluation
# ---------------------------
print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# ---------------------------
# 11. Visualization
# ---------------------------
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(6,4))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
plt.title('Confusion Matrix')
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.tight_layout()
plt.show()

# ---------------------------
# 12. Save the Model
# ---------------------------
joblib.dump(model, 'portscan_detector.pkl')
joblib.dump(scaler, 'scaler.pkl')

print("\nModel and scaler saved as 'portscan_detector.pkl' and 'scaler.pkl'")'''
   
import streamlit as st
import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

# Load model and scaler
model = joblib.load('portscan_detector.pkl')
scaler = joblib.load('scaler.pkl')

st.set_page_config(page_title="Port Scan Detector", layout="wide")
st.title("🚨 Port Scan Attack Detector")
st.markdown("Upload network traffic data to detect **port scanning attacks** using a pre-trained ML model.")

# File uploader
uploaded_file = st.file_uploader("Upload a CSV File", type=["csv"])

if uploaded_file is not None:
    try:
        df = pd.read_csv(r'E:\LIL\friday.csv\friday_datas.csv')

        st.subheader("📊 Raw Data Preview")
        st.write(df.head())

        # Drop irrelevant columns
        drop_cols = ['Flow ID', 'Timestamp', 'Fwd Header Length.1', 'Label']
        df = df.drop(columns=[col for col in drop_cols if col in df.columns], errors='ignore')

        # Clean data
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)

        # Numeric features only
        X = df.select_dtypes(include=['number'])

        # Scale
        X_scaled = scaler.transform(X)

        # Predict
        predictions = model.predict(X_scaled)
        df['Prediction'] = predictions
        df['Prediction'] = df['Prediction'].apply(lambda x: 'PortScan' if x == 1 else 'Normal')

        st.subheader("✅ Prediction Summary")
        st.write(df[['Prediction']].value_counts().rename_axis('Label').reset_index(name='Count'))

        st.subheader("📈 Visualization")

        col1, col2 = st.columns(2)
        with col1:
            # Pie Chart
            st.markdown("**PortScan vs Normal (Pie Chart)**")
            pie_data = df['Prediction'].value_counts()
            st.pyplot(pie_data.plot.pie(autopct='%1.1f%%', labels=pie_data.index, figsize=(5, 5)).figure)

        with col2:
            # Bar Chart
            st.markdown("**PortScan vs Normal (Bar Plot)**")
            sns.set_style("whitegrid")
            fig, ax = plt.subplots()
            sns.countplot(x='Prediction', data=df, ax=ax, palette="Set2")
            st.pyplot(fig)

        st.subheader("📥 Download Results")
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button("Download CSV with Predictions", data=csv, file_name="predicted_results.csv", mime="text/csv")

    except Exception as e:
        st.error(f"An error occurred: {e}")
