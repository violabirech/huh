# --- main.py for Combined DNS & DoS Anomaly Detection ---
import streamlit as st
import pandas as pd
from tabs import overview_dns, overview_dos
from tabs import live_stream_dns, live_stream_dos
from tabs import manual_entry_dns, manual_entry_dos
from tabs import metrics_dns, metrics_dos
from tabs import historical_dns, historical_dos

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
dashboard_choice = st.sidebar.radio("Select View", ["DNS", "DoS"], index=0)

# --- State Initialization ---
if "predictions" not in st.session_state:
    st.session_state.predictions = []
if "attacks" not in st.session_state:
    st.session_state.attacks = []

# --- Tab Layout ---
tabs = st.tabs(["Overview", "Live Stream", "Manual Entry", "Metrics", "Historical Data"])

# --- Route Based on DNS or DoS ---
if dashboard_choice == "DNS":
    with tabs[0]: overview_dns.render(time_range, time_range_query_map)
    with tabs[1]: live_stream_dns.render(thresh, highlight_color, alerts_enabled)
    with tabs[2]: manual_entry_dns.render()
    with tabs[3]: metrics_dns.render(thresh)
    with tabs[4]: historical_dns.render(thresh, highlight_color)
else:
    with tabs[0]: overview_dos.render(time_range, time_range_query_map)
    with tabs[1]: live_stream_dos.render(thresh, highlight_color, alerts_enabled)
    with tabs[2]: manual_entry_dos.render()
    with tabs[3]: metrics_dos.render(thresh)
    with tabs[4]: historical_dos.render(thresh, highlight_color)
