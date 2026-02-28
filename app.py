import streamlit as st

from siem.parser import parse_logs
from siem.detections import brute_force_alerts

LOG_FILE_DEFAULT = "data/ssh_logs.txt"

st.set_page_config(page_title="Mini SIEM Dashboard", layout="wide")

st.title("Mini SIEM Dashboard")
st.caption("SSH log analysis + basic detections")

with st.sidebar:
    st.header("Input")
    uploaded = st.file_uploader("Upload SSH log file (.txt)", type=["txt"])
    threshold = st.slider("Brute-force threshold (failed attempts per IP)", 3, 50, 5)

if uploaded:
    text = uploaded.read().decode("utf-8", errors="ignore")
else:
    with open(LOG_FILE_DEFAULT, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

df = parse_logs(text)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Events", len(df))
col2.metric("Failed Logins", int((df["event"] == "failed_login").sum()))
col3.metric("Success Logins", int((df["event"] == "success_login").sum()))
col4.metric("Unique IPs", int(df["ip"].nunique(dropna=True)))

st.divider()

left, right = st.columns([1, 1])

with left:
    st.subheader("Top IPs (Failed Logins)")
    top_failed = df[df["event"] == "failed_login"]["ip"].value_counts().head(10)
    st.bar_chart(top_failed)

with right:
    st.subheader("Alerts")
    alerts = brute_force_alerts(df, threshold=threshold)
    if alerts.empty:
        st.success("No brute-force alerts with current threshold.")
    else:
        st.dataframe(alerts, use_container_width=True)

st.divider()
st.subheader("Parsed Events (preview)")
st.dataframe(df.head(200), use_container_width=True)