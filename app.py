
import gradio as gr
import joblib
import numpy as np
import time

# Load trained models
dns_model = joblib.load("dns_model.joblib")
dos_model = joblib.load("dos_model.joblib")

# DNS prediction function with latency
def predict_dns(dns_rate, inter_arrival_time):
    features = np.array([[dns_rate, inter_arrival_time]])
    start = time.time()
    anomaly = int(dns_model.predict(features)[0])
    try:
        score = float(dns_model.decision_function(features)[0])
    except:
        score = 0.0
    latency = time.time() - start
    return {
        "type": "DNS",
        "anomaly": anomaly,
        "score": round(score, 4),
        "dns_rate": dns_rate,
        "inter_arrival_time": inter_arrival_time,
        "latency_sec": round(latency, 4),
        "model_version": "v1.0"
    }

# DoS prediction function with latency
def predict_dos(inter_arrival_time, packet_length):
    features = np.array([[inter_arrival_time, packet_length]])
    start = time.time()
    anomaly = int(dos_model.predict(features)[0])
    try:
        score = float(dos_model.decision_function(features)[0])
    except:
        score = 0.0
    latency = time.time() - start
    return {
        "type": "DoS",
        "anomaly": anomaly,
        "score": round(score, 4),
        "inter_arrival_time": inter_arrival_time,
        "packet_length": packet_length,
        "latency_sec": round(latency, 4),
        "model_version": "v1.0"
    }

# DNS Tab
dns_tab = gr.Interface(
    fn=predict_dns,
    inputs=[
        gr.Number(label="DNS Rate"),
        gr.Number(label="Inter-Arrival Time")
    ],
    outputs="json",
    title="DNS Anomaly Detection"
)

# DoS Tab
dos_tab = gr.Interface(
    fn=predict_dos,
    inputs=[
        gr.Number(label="Inter-Arrival Time"),
        gr.Number(label="Packet Length")
    ],
    outputs="json",
    title="DoS Anomaly Detection"
)

# Combine both into tabs
demo = gr.TabbedInterface(
    interface_list=[dns_tab, dos_tab],
    tab_names=["DNS Detection", "DoS Detection"]
)

demo.launch()
