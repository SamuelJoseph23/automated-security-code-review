import streamlit as st
import json
import pandas as pd
import plotly.express as px
from src.analyzers.security_analyzer import SecurityCodeAnalyzer
import os

st.set_page_config(page_title="Security Analyzer", layout="wide")

st.title("🛡️ Automated Security Code Review")
st.markdown("### Classical ML & Pattern-Based Detection")

# Sidebar
st.sidebar.header("Configuration")
use_ml = st.sidebar.checkbox("Use ML Classifier", value=True)
severity_filter = st.sidebar.multiselect(
    "Filter Severity", 
    ["Critical", "High", "Medium", "Low"],
    default=["Critical", "High"]
)

# File uploader
uploaded_file = st.file_uploader("Upload Code File", type=['py', 'js', 'java'])

if uploaded_file is not None:
    # Save temp file
    with open("temp_scan_file", "wb") as f:
        f.write(uploaded_file.getbuffer())
    
    # Run Analysis
    analyzer = SecurityCodeAnalyzer(use_ml=use_ml)
    with st.spinner('Scanning code...'):
        results = analyzer.analyze_file("temp_scan_file")
    
    # Display Summary Metrics
    col1, col2, col3, col4 = st.columns(4)
    summary = results['summary']
    col1.metric("Total Issues", summary['total_vulnerabilities'])
    col2.metric("Critical", summary['critical'], delta_color="inverse")
    col3.metric("High", summary['high'], delta_color="inverse")
    col4.metric("Medium", summary['medium'])
    
    # Data processing for table
    vulns = results['vulnerabilities']
    if vulns:
        df = pd.DataFrame(vulns)
        
        # Filter
        df_filtered = df[df['severity'].isin(severity_filter)]
        
        # Charts
        st.subheader("Vulnerability Distribution")
        chart_col1, chart_col2 = st.columns(2)
        
        with chart_col1:
            fig_sev = px.pie(df, names='severity', title='By Severity', hole=0.4)
            st.plotly_chart(fig_sev, use_container_width=True)
            
        with chart_col2:
            fig_type = px.bar(df, x='type', title='By Vulnerability Type')
            st.plotly_chart(fig_type, use_container_width=True)
        
        # Detailed Table
        st.subheader("Detailed Findings")
        st.dataframe(
            df_filtered[['type', 'severity', 'line', 'description', 'confidence']],
            use_container_width=True
        )
        
        # Code Viewer with Highlights
        st.subheader("Code Inspector")
        with open("temp_scan_file", "r") as f:
            code_content = f.read()
            
        # Highlight lines (basic logic)
        st.code(code_content, language=results.get('language', 'python'))
        
        # Cleanup
        os.remove("temp_scan_file")
    else:
        st.success("✅ No vulnerabilities found!")
