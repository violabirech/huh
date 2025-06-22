import streamlit as st
import pandas as pd
import requests
from streamlit_autorefresh import st_autorefresh
from tabs.utils import (
    get_dns_data,
    get_dos_data,
    send_discord_alert,
    log_to_sqlitecloud,
    API_URL_DNS,
    API_URL_DOS
)

def render(thresh, highlight_color, alerts_enabled, traffic_type):
    st_autorefresh(interval=10000, key="live_refresh")
    st.header("📡 Live Stream Anomaly Detection")

    data_type = st.radio("Select Data Type", ["DNS", "DoS"], horizontal=True)

    if data_type == "DNS":
        records = get_dns_data()
        api_url = API_URL_DNS
        required_fields = ["inter_arrival_time", "dns_rate"]
    else:
        records = get_dos_data()
        api_url = API_URL_DOS
        required_fields = ["packet_rate", "packet_length", "inter_arrival_time"]

    new_predictions = []

    if records:
        for row in records:
            payload = {key: row[key] for key in required_fields}
            try:
                response = requests.post(api_url, json=payload, timeout=20)
                result = response.json()
                if "anomaly" in result and "reconstruction_error" in result:
                    result.update(row)
                    result["type"] = data_type
                    result["label"] = "Attack" if result["anomaly"] == 1 else "Normal"
                    new_predictions.append(result)
                    if result["anomaly"] == 1 and alerts_enabled:
                        send_discord_alert(result)
            except Exception as e:
                st.warning(f"API error: {e}")

        if new_predictions:
            st.session_state.predictions.extend(new_predictions)
            st.session_state.attacks.extend([r for r in new_predictions if r["anomaly"] == 1])
            for r in new_predictions:
                log_to_sqlitecloud(r)
            st.session_state.predictions = st.session_state.predictions[-1000:]
            st.session_state.attacks = st.session_state.attacks[-1000:]

    df = pd.DataFrame(st.session_state.predictions)
    if not df.empty:
        df = df[df["type"] == data_type] if "type" in df.columns else df
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        rows_per_page = 100
        total_pages = (len(df) - 1) // rows_per_page + 1
        page_number = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1, key="live_page") - 1
        paged_df = df.iloc[page_number * rows_per_page:(page_number + 1) * rows_per_page]

        def highlight(row):
            return [f"background-color: {highlight_color}" if row["anomaly"] == 1 else ""] * len(row)

        st.dataframe(paged_df.style.apply(highlight, axis=1), key="live_table")
    else:
        st.info(f"No {data_type} predictions yet.")
