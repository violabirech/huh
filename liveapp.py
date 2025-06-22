import streamlit as st
from tabs import overview, live_stream, manual_entry, metrics, historical

st.set_page_config(page_title="Unified DNS & DoS Anomaly Dashboard", layout="wide")

# --- Sidebar Settings ---
time_range_query_map = {
    "Last 30 min": "-30m",
    "Last 1 hour": "-1h",
    "Last 24 hours": "-24h",
    "Last 7 days": "-7d",
    "Last 14 days": "-14d",
    "Last 30 days": "-30d"
}
time_range = st.sidebar.selectbox("Time Range", list(time_range_query_map.keys()), index=2)
thresh = st.sidebar.slider("Anomaly Threshold", 0.01, 1.0, 0.1, 0.01)
highlight_color = st.sidebar.selectbox("Highlight Color", ["Red", "Orange", "Yellow", "Green", "Blue"], index=3)
alerts_enabled = st.sidebar.checkbox("Enable Discord Alerts", value=True)
traffic_type = st.sidebar.radio("Traffic Type", ["DNS", "DoS"], index=0)

# --- State Initialization ---
if "predictions" not in st.session_state:
    st.session_state.predictions = []
if "attacks" not in st.session_state:
    st.session_state.attacks = []

# --- Tab Navigation ---
tabs = st.tabs(["Overview", "Live Stream", "Manual Entry", "Metrics", "Historical Data"])

with tabs[0]:
    overview.render(time_range, time_range_query_map, traffic_type)

with tabs[1]:
    live_stream.render(thresh, highlight_color, alerts_enabled, traffic_type)

with tabs[2]:
    manual_entry.render(traffic_type)

with tabs[3]:
    metrics.render(thresh, traffic_type)

with tabs[4]:
    historical.render(thresh, highlight_color, traffic_type)
