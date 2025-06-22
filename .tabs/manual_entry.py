from utils import log_to_sqlitecloud
# some logic
import streamlit as st
import pandas as pd
import requests
from datetime import datetime
from tabs.utils import API_URL_DNS, API_URL_DOS  # Define both endpoints or use a dynamic switch

def render(traffic_type):
    st.header("Manual Anomaly Prediction")

    data_type = st.selectbox("Select Data Type", ["DNS", "DoS"], index=0)

    if "predictions" not in st.session_state:
        st.session_state.predictions = []

    if data_type == "DNS":
        col1, col2 = st.columns(2)
        with col1:
            inter_arrival_time = st.number_input("Inter Arrival Time", value=0.01, format="%.4f")
        with col2:
            dns_rate = st.number_input("DNS Rate", value=5.0, format="%.2f")

        if st.button("Predict DNS"):
            try:
                res = requests.post(API_URL_DNS, json={
                    "inter_arrival_time": inter_arrival_time,
                    "dns_rate": dns_rate
                })
                result = res.json()
                result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                result["label"] = "Attack" if result["anomaly"] == 1 else "Normal"
                st.session_state.predictions.append(result)
                st.success("Prediction successful!")
            except Exception as e:
                st.error(f"DNS Prediction Error: {e}")

    else:  # DoS
        col1, col2, col3 = st.columns(3)
        with col1:
            packet_rate = st.number_input("Packet Rate", value=120.0, format="%.2f")
        with col2:
            packet_length = st.number_input("Packet Length", value=500.0, format="%.2f")
        with col3:
            inter_arrival_time = st.number_input("Inter Arrival Time", value=0.01, format="%.4f")

        if st.button("Predict DoS"):
            try:
                res = requests.post(API_URL_DOS, json={
                    "packet_rate": packet_rate,
                    "packet_length": packet_length,
                    "inter_arrival_time": inter_arrival_time
                })
                result = res.json()
                result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                result["label"] = "Attack" if result["anomaly"] == 1 else "Normal"
                st.session_state.predictions.append(result)
                st.success("Prediction successful!")
            except Exception as e:
                st.error(f"DoS Prediction Error: {e}")

    if st.session_state.predictions:
        st.subheader("Prediction Results")
        st.dataframe(pd.DataFrame(st.session_state.predictions[::-1]))  # Most recent first
