from utils import load_predictions_from_sqlitecloud
# some logic
import streamlit as st
import pandas as pd
import plotly.express as px
from streamlit_autorefresh import st_autorefresh
from tabs.utils import load_predictions_from_sqlitecloud  # Assumes this function supports a `type` param

def render(time_range, time_range_query_map, traffic_type):
    st_autorefresh(interval=30000, key="overview_refresh")

    st.title("📈 Unified Anomaly Detection Overview")
    data_type = st.radio("Select Data Type", ["DNS", "DoS"], horizontal=True)

    query_duration = time_range_query_map.get(time_range, "-24h")
    df = load_predictions_from_sqlitecloud(type=data_type.lower(), time_window=query_duration)

    if not df.empty:
        total_predictions = len(df)
        attack_rate = df["is_anomaly"].mean()

        recent_cutoff = pd.Timestamp.now().replace(tzinfo=None) - pd.Timedelta(hours=1)
        recent_attacks = df[(df["timestamp"] >= recent_cutoff) & (df["is_anomaly"] == 1)]

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Predictions", total_predictions)
        col2.metric("Attack Rate", f"{attack_rate:.2%}")
        col3.metric("Recent Attacks", len(recent_attacks))

        fig = px.line(
            df,
            x="timestamp",
            y="anomaly_score",
            color=df["is_anomaly"].map({1: "Attack", 0: "Normal"}).astype(str),
            labels={"color": "Anomaly Type"},
            title=f"{data_type} Anomaly Score Over Time"
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info(f"No {data_type} predictions available in the selected time range.")
