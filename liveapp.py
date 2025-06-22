import streamlit as st
import pandas as pd
import sys
import os

# Add the hidden .tabs folder to sys.path
sys.path.append(os.path.join(os.path.dirname(__file__), ".tabs"))

# Now import modules from .tabs
import overview
import live_stream
import manual_entry
import metrics
import historical

# Page config
st.set_page_config(page_title="DNS & DoS Anomaly Detection Dashboard", layout="wide")

# Sidebar Settings
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

# Session state init
if "predictions" not in st.session_state:
    st.session_state.predictions = []
if "attacks" not in st.session_state:
    st.session_state.attacks = []

# Tabs
tabs = st.tabs(["Overview", "Live Stream", "Manual Entry", "Metrics", "Historical Data"])

# Route to correct traffic type
if dashboard_choice == "DNS":
    with tabs[0]: overview.render(time_range, time_range_query_map, traffic_type="dns")
    with tabs[1]: live_stream.render(thresh, highlight_color, alerts_enabled, traffic_type="dns")
    with tabs[2]: manual_entry.render(traffic_type="dns")
    with tabs[3]: metrics.render(thresh, traffic_type="dns")
    with tabs[4]: historical.render(thresh, highlight_color, traffic_type="dns")
else:
    with tabs[0]: overview.render(time_range, time_range_query_map, traffic_type="dos")
    with tabs[1]: live_stream.render(thresh, highlight_color, alerts_enabled, traffic_type="dos")
    with tabs[2]: manual_entry.render(traffic_type="dos")
    with tabs[3]: metrics.render(thresh, traffic_type="dos")
    with tabs[4]: historical.render(thresh, highlight_color, traffic_type="dos")
