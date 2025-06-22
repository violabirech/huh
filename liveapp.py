import streamlit as st
import pandas as pd
import numpy as np
import requests
from datetime import datetime
from influxdb_client import InfluxDBClient
from streamlit_autorefresh import st_autorefresh
import plotly.express as px

# --- Config ---
st.set_page_config(page_title="Unified Anomaly Detection", layout="wide")

# --- Secrets ---
DISCORD_WEBHOOK = st.secrets["DISCORD_WEBHOOK"]
INFLUXDB_URL = st.secrets["INFLUXDB_URL"]
INFLUXDB_TOKEN = st.secrets["INFLUXDB_TOKEN"]
INFLUXDB_ORG = st.secrets["INFLUXDB_ORG"]
INFLUXDB_BUCKET = st.secrets["INFLUXDB_BUCKET"]

# --- Sidebar Controls ---
st.sidebar.title("⚙️ Settings")
traffic_type = st.sidebar.radio("Traffic Type", ["DNS", "DoS"], horizontal=True)

time_range_map = {
    "Last 30 min": "-30m", "Last 1 hour": "-1h", "Last 24 hours": "-24h",
    "Last 7 days": "-7d", "Last 14 days": "-14d", "Last 30 days": "-30d"
}
time_range = st.sidebar.selectbox("Time Range", list(time_range_map.keys()), index=1)

highlight_color = st.sidebar.selectbox("Highlight Color", ["red", "orange", "yellow", "green", "blue"], index=0)
thresh = st.sidebar.slider("Anomaly Threshold", 0.01, 1.0, 0.1, 0.01)
alerts_enabled = st.sidebar.checkbox("Enable Discord Alerts", value=True)

# --- State Init ---
if "predictions" not in st.session_state:
    st.session_state.predictions = []

# --- InfluxDB Queries ---
def query_influx(measurement, start="-1h", limit=500):
    try:
        with InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG) as client:
            query = f'''
            from(bucket: "{INFLUXDB_BUCKET}")
              |> range(start: {start})
              |> filter(fn: (r) => r._measurement == "{measurement}")
              |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
              |> sort(columns: ["_time"], desc: false)
              |> limit(n: {limit})
            '''
            tables = client.query_api().query(query)
            data = []
            for table in tables:
                for record in table.records:
                    row = record.values
                    row["timestamp"] = record.get_time()
                    data.append(row)
            return pd.DataFrame(data)
    except Exception as e:
        st.error(f"InfluxDB Error: {e}")
        return pd.DataFrame()

# --- Discord Alerts ---
def send_discord_alert(entry):
    msg = {
        "content": (
            f"🚨 **{entry['type']} Anomaly Detected!**\n"
            f"Timestamp: {entry['timestamp']}\n"
            f"Rate: {entry.get('dns_rate') or entry.get('packet_rate')}\n"
            f"IAT: {entry.get('inter_arrival_time')}\n"
            f"Error: {entry['reconstruction_error']:.4f}"
        )
    }
    try:
        requests.post(DISCORD_WEBHOOK, json=msg, timeout=5)
    except:
        st.warning("❌ Failed to send Discord alert.")

# --- Prediction Logic ---
def detect_anomalies(df, traffic_type):
    df["reconstruction_error"] = np.random.rand(len(df))
    if traffic_type == "DNS":
        df["anomaly"] = (df["dns_rate"] > 100) | (df["inter_arrival_time"] < 0.01)
    else:
        df["anomaly"] = (df["packet_rate"] > 150) | (df["inter_arrival_time"] < 0.01)
    df["anomaly"] = df["anomaly"].astype(int)
    df["label"] = df["anomaly"].map({0: "Normal", 1: "Attack"})
    df["type"] = traffic_type
    return df

# --- Layout ---
tabs = st.tabs(["📊 Overview", "📡 Live Stream", "📝 Manual Entry", "📈 Metrics", "🕘 Historical"])

# --- Tab 1: Overview ---
with tabs[0]:
    st.title(f"{traffic_type} Overview")
    df = query_influx(measurement=traffic_type.lower(), start=time_range_map[time_range])
    if not df.empty:
        df = detect_anomalies(df, traffic_type)
        st.session_state.predictions.extend(df.to_dict("records"))
        df["timestamp"] = pd.to_datetime(df["timestamp"])

        st.metric("Total Records", len(df))
        st.metric("Attack Rate", f"{df['anomaly'].mean():.2%}")
        st.metric("Recent Attacks", df.tail(10)["anomaly"].sum())

        st.dataframe(df.tail(100).style.apply(
            lambda row: [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row), axis=1
        ))

        fig = px.line(df, x="timestamp", y="reconstruction_error", color="label", title="Reconstruction Error Over Time")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.warning("No data found.")

# --- Tab 2: Live Stream ---
with tabs[1]:
    st_autorefresh(interval=10000, key="live")
    new_df = query_influx(measurement=traffic_type.lower(), start="-10s", limit=10)
    if not new_df.empty:
        new_df = detect_anomalies(new_df, traffic_type)
        for row in new_df.to_dict("records"):
            st.session_state.predictions.append(row)
            if row["anomaly"] == 1 and alerts_enabled:
                send_discord_alert(row)
        st.success(f"Fetched {len(new_df)} new entries.")

# --- Tab 3: Manual Entry ---
with tabs[2]:
    st.header("Manual Entry")
    iat = st.number_input("Inter-arrival Time", value=0.02, min_value=0.001)
    rate = st.number_input("DNS Rate" if traffic_type == "DNS" else "Packet Rate", value=5.0)

    if st.button("Predict"):
        record = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "inter_arrival_time": iat,
            "dns_rate" if traffic_type == "DNS" else "packet_rate": rate,
            "reconstruction_error": np.random.rand(),
            "anomaly": int((rate > 100 if traffic_type == "DNS" else rate > 150) or iat < 0.01),
            "type": traffic_type
        }
        record["label"] = "Attack" if record["anomaly"] == 1 else "Normal"
        st.session_state.predictions.append(record)
        if record["anomaly"] == 1 and alerts_enabled:
            send_discord_alert(record)
        st.success("Prediction recorded.")

# --- Tab 4: Metrics ---
with tabs[3]:
    st.header("Performance Metrics")
    df = pd.DataFrame(st.session_state.predictions)
    df = df[df["type"] == traffic_type]
    if not df.empty:
        pie = px.pie(df, names="label", title="Anomaly Distribution")
        st.plotly_chart(pie)

        fig = px.line(df, x="timestamp", y="reconstruction_error", title="Error Over Time")
        st.plotly_chart(fig)
    else:
        st.info("No predictions available.")

# --- Tab 5: Historical ---
with tabs[4]:
    st.header("Historical Data")
    df = query_influx(measurement=traffic_type.lower(), start=time_range_map[time_range])
    if not df.empty:
        df = detect_anomalies(df, traffic_type)
        df["timestamp"] = pd.to_datetime(df["timestamp"])

        st.dataframe(df.tail(100).style.apply(
            lambda row: [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row), axis=1
        ))

        chart = px.line(df, x="timestamp", y="dns_rate" if traffic_type == "DNS" else "packet_rate",
                        color="label", title=f"{traffic_type} Rate Over Time")
        st.plotly_chart(chart, use_container_width=True)

        st.download_button("Download CSV", df.to_csv(index=False), "historical_data.csv", "text/csv")
    else:
        st.info("No historical data.")
