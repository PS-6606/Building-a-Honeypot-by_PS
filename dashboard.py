import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import os
import time

LOG_FILE = "honeypot.log"

st.set_page_config(page_title="Honeypot Dashboard", layout="wide")

st.title("🛡️ Honeypot Attack Monitoring Dashboard")

# Check if log file exists
if not os.path.exists(LOG_FILE):
    st.warning("No honeypot logs found yet.")
    st.stop()

# Load data
df = pd.read_csv(
    LOG_FILE,
    names=["Time", "Service", "IP", "Port"]
)

# Sidebar
st.sidebar.header("Dashboard Controls")
auto_refresh = st.sidebar.checkbox("Auto Refresh", True)

# Metrics
col1, col2, col3 = st.columns(3)
col1.metric("Total Attacks", len(df))
col2.metric("Unique IPs", df["IP"].nunique())
col3.metric("Services Attacked", df["Service"].nunique())

st.divider()

# Attack Table
st.subheader("📄 Attack Logs")
st.dataframe(df, use_container_width=True)

# Charts
st.subheader("📊 Attack Analysis")

col4, col5 = st.columns(2)

with col4:
    st.write("Attacks per Service")
    service_counts = df["Service"].value_counts()
    fig1, ax1 = plt.subplots()
    service_counts.plot(kind="bar", ax=ax1)
    st.pyplot(fig1)

with col5:
    st.write("Top Attacker IPs")
    ip_counts = df["IP"].value_counts().head(5)
    fig2, ax2 = plt.subplots()
    ip_counts.plot(kind="bar", ax=ax2)
    st.pyplot(fig2)

# Auto refresh
if auto_refresh:
    time.sleep(5)
    st.rerun()
