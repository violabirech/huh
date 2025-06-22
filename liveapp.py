import streamlit as st
import pandas as pd
import numpy as np
import requests
import plotly.express as px
from influxdb_client import InfluxDBClient
from datetime import datetime
from streamlit_autorefresh import st_autorefresh

# --- Configuration ---
st.set_page_config(page_title="Unified Anomaly Detection Dashboard", layout="wide")
st.title("🔍 Unified Real-Time Anomaly Detection")

# --- Secrets ---
INFLUXDB_URL = st.secrets["INFLUXDB_URL"]
INFLUXDB_ORG = st.secrets["INFLUXDB_ORG"]
INFLUXDB_TOKEN = st.secrets["INFLUXDB_TOKEN"]
DISCORD_WEBHOOK = st.secrets["DISCORD_WEBHOOK"]

# --- Constants ---
time_range_query_map = {
    "Last 30 min": "-30m", "Last 1 hour": "-1h", "Last 24 hours": "-24h", "Last 7 days": "-7d"
}
highlight_color = "red"

# --- Sidebar Settings ---
st.sidebar.title("Settings")
dashboard_choice = st.sidebar.radio("Choose Dashboard", ["DNS", "DoS"])
time_range = st.sidebar.selectbox("Time Range", list(time_range_query_map.keys()), index=1)
threshold = st.sidebar.slider("Anomaly Threshold", 0.01, 1.0, 0.1, 0.01)
alerts_enabled = st.sidebar.checkbox("Enable Discord Alerts", value=True)

# --- InfluxDB Queries ---
def query_influx(bucket, measurement, fields, start_range="-1h", limit=200):
    try:
        with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
            query = f'''from(bucket: "{bucket}")
            |> range(start: {start_range})
            |> filter(fn: (r) => r._measurement == "{measurement}")
            |> filter(fn: (r) => { ' or '.join([f'r._field == "{f}"' for f in fields]) })
            |> pivot(rowKey:["_time"], columnKey:["_field"], valueColumn:"_value")
            |> sort(columns: ["_time"], desc: false)
            |> limit(n:{limit})'''
            df = client.query_api().query_data_frame(query)
            df = df.rename(columns={"_time": "timestamp"})
            return df
    except Exception as e:
        st.error(f"InfluxDB error: {e}")
        return pd.DataFrame()

# --- Anomaly Detection via API ---
def detect_anomalies(endpoint, df, features):
    results = []
    for _, row in df.iterrows():
        try:
            data = {f: row[f] for f in features}
            response = requests.post(endpoint, json=data)
            result = response.json()
            row["anomaly"] = result["anomaly"]
            row["score"] = result.get("anomaly_score", result.get("reconstruction_error", 0.0))
        except:
            row["anomaly"] = 0
            row["score"] = 0
        results.append(row)
    return pd.DataFrame(results)

# --- Discord Alert ---
def send_discord_alert(row, typ="DNS"):
    message = {
        "content": f"🚨 **{typ} Anomaly Detected!**\n"
                   f"**Time:** {row['timestamp']}\n"
                   f"**Score:** {row['score']:.4f}"
    }
    try:
        requests.post(DISCORD_WEBHOOK, json=message)
    except:
        pass

# --- Dashboard Tabs ---
tabs = st.tabs(["Overview", "Live Stream", "Manual Entry", "Metrics & Alerts", "Historical Data"])

# Shared Logic
if dashboard_choice == "DNS":
    bucket = "realtime_dns"
    measurement = "dns"
    api_endpoint = "https://violabirech-dos-anomalies-detection.hf.space/predict/dns"
    features = ["dns_rate", "inter_arrival_time"]
elif dashboard_choice == "DoS":
    bucket = "realtime"
    measurement = "network_traffic"
    api_endpoint = "https://violabirech-dos-anomalies-detection.hf.space/predict/dos"
    features = ["packet_rate", "packet_length", "inter_arrival_time"]

# --- Overview Tab ---
with tabs[0]:
    st.header(f"{dashboard_choice} Overview")
    df = query_influx(bucket, measurement, features, start_range=time_range_query_map[time_range])
    if not df.empty:
        df = detect_anomalies(api_endpoint, df, features)
        st.metric("Total Records", len(df))
        st.metric("Anomaly Rate", f"{df['anomaly'].mean():.2%}")
        st.dataframe(df.tail(50))

# --- Live Stream ---
with tabs[1]:
    st_autorefresh(interval=10000, key="live_refresh")
    st.subheader("Live Stream (Refreshes every 10s)")
    df = query_influx(bucket, measurement, features, start_range="-30s")
    df = detect_anomalies(api_endpoint, df, features)
    if alerts_enabled and (df["anomaly"] == 1).any():
        send_discord_alert(df[df["anomaly"] == 1].iloc[-1], typ=dashboard_choice)
        st.warning("🚨 Anomaly Detected!")
    st.dataframe(df)

# --- Manual Entry ---
with tabs[2]:
    st.subheader("Manual Entry")
    inputs = {f: st.number_input(f, min_value=0.0, value=1.0) for f in features}
    if st.button("Submit for Prediction"):
        try:
            res = requests.post(api_endpoint, json=inputs).json()
            st.success(f"Prediction: {'Anomaly' if res['anomaly'] else 'Normal'} - Score: {res.get('anomaly_score', res.get('reconstruction_error', 0.0))}")
        except:
            st.error("API call failed.")

# --- Metrics & Alerts ---
with tabs[3]:
    st.subheader("Metrics & Alerts")
    df = query_influx(bucket, measurement, features, start_range=time_range_query_map[time_range])
    df = detect_anomalies(api_endpoint, df, features)
    if not df.empty:
        pie = px.pie(df, names=df["anomaly"].map({0: "Normal", 1: "Attack"}), title="Anomaly Distribution")
        line = px.line(df, x="timestamp", y="score", title="Anomaly Score Over Time")
        st.plotly_chart(pie)
        st.plotly_chart(line)

# --- Historical Data ---
with tabs[4]:
    st.subheader("Historical Trends")
    df = query_influx(bucket, measurement, features, start_range=time_range_query_map[time_range])
    df = detect_anomalies(api_endpoint, df, features)
    if not df.empty:
        fig = px.line(df, x="timestamp", y=features, color=df["anomaly"].map({0: "Normal", 1: "Anomaly"}), title="Traffic Trends")
        st.plotly_chart(fig)
