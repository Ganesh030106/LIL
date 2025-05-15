import streamlit as st
import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
import io

# Load model and scaler
model = joblib.load('portscan_detector.pkl')
scaler = joblib.load('scaler.pkl')

st.set_page_config(page_title="Port Scan Detector", layout="wide")
st.title("🚨 Port Scan Attack Detector")
st.markdown("Upload network traffic data **greater than 1 GB** to detect **port scanning attacks** using a pre-trained ML model.")

# File uploader
uploaded_file = st.file_uploader("Upload a CSV File (>1 GB)", type=["csv"])

if uploaded_file is not None:
    file_size = uploaded_file.size  # size in bytes

    if file_size <= 1_073_741_824:  # 1 GB = 1,073,741,824 bytes
        st.error("❌ The uploaded file must be larger than 1 GB.")
    else:
        try:
            df = pd.read_csv(uploaded_file)

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
                st.markdown("**PortScan vs Normal (Pie Chart)**")
                pie_data = df['Prediction'].value_counts()
                st.pyplot(pie_data.plot.pie(autopct='%1.1f%%', labels=pie_data.index, figsize=(5, 5)).figure)

            with col2:
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
