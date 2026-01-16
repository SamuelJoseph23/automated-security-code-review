import streamlit as st
import pandas as pd
import plotly.express as px
from src.analyzers.security_analyzer import SecurityCodeAnalyzer
import os

# Page config
st.set_page_config(
    page_title="Security Code Review",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Automated Security Code Review")
st.markdown("### Classical ML & Pattern-Based Detection")

# Sidebar
st.sidebar.header("Configuration")
use_ml = st.sidebar.checkbox("Use ML Classifier", value=True)
severity_filter = st.sidebar.multiselect(
    "Filter Severity", 
    ["Critical", "High", "Medium", "Low"],
    default=["Critical", "High", "Medium", "Low"]
)

# File uploader
uploaded_file = st.file_uploader("Upload Code File", type=['py', 'js', 'java', 'c', 'cpp'])

if uploaded_file is not None:
    # Save temp file with correct extension
    file_ext = os.path.splitext(uploaded_file.name)[1]
    temp_filename = f"temp_scan_file{file_ext}"
    
    # Write uploaded file
    with open(temp_filename, "wb") as f:
        f.write(uploaded_file.getbuffer())
    
    try:
        # Run Analysis
        analyzer = SecurityCodeAnalyzer(use_ml=use_ml)
        
        with st.spinner('Scanning code...'):
            results = analyzer.analyze_file(temp_filename)
        
        # --- ERROR HANDLING ---
        if "error" in results:
            st.error(f"❌ Analysis Failed: {results['error']}")
            st.warning("Make sure the file extension is supported (.py, .js, .java, etc.)")
        
        elif "summary" not in results:
            st.error("❌ Unexpected Error: Analysis results missing summary data.")
            with st.expander("See Raw Debug Data"):
                st.json(results)
            
        else:
            # --- SUCCESS PATH ---
            
            # Display Summary Metrics
            summary = results['summary']
            
            # Create 4 columns for metrics
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Total Issues", summary.get('total_vulnerabilities', 0))
            col2.metric("Critical", summary.get('critical', 0))
            col3.metric("High", summary.get('high', 0))
            col4.metric("Medium", summary.get('medium', 0))
            
            st.divider()

            # Process Vulnerabilities
            vulns = results.get('vulnerabilities', [])
            
            if vulns:
                df = pd.DataFrame(vulns)
                
                # Filter by severity
                if 'severity' in df.columns:
                    df_filtered = df[df['severity'].isin(severity_filter)]
                else:
                    df_filtered = df # Fallback if severity missing
                
                if not df_filtered.empty:
                    # Charts
                    st.subheader("📊 Vulnerability Distribution")
                    chart_col1, chart_col2 = st.columns(2)
                    
                    with chart_col1:
                        if 'severity' in df_filtered.columns:
                            fig_sev = px.pie(df_filtered, names='severity', title='Issues by Severity', hole=0.4, 
                                            color='severity',
                                            color_discrete_map={'Critical':'red', 'High':'orange', 'Medium':'gold', 'Low':'green'})
                            st.plotly_chart(fig_sev, use_container_width=True)
                        
                    with chart_col2:
                        if 'type' in df_filtered.columns:
                            fig_type = px.bar(df_filtered, x='type', title='Issues by Type')
                            st.plotly_chart(fig_type, use_container_width=True)
                    
                    # Detailed Table
                    st.subheader("📝 Detailed Findings")
                    
                    # Select specific columns to display
                    display_cols = ['type', 'severity', 'line', 'description', 'fix_recommendation']
                    # Only show columns that actually exist in the dataframe
                    final_cols = [c for c in display_cols if c in df_filtered.columns]
                    
                    st.dataframe(
                        df_filtered[final_cols],
                        use_container_width=True,
                        hide_index=True
                    )
                    
                    # Code Viewer
                    st.subheader("💻 Code Inspector")
                    with open(temp_filename, "r", encoding="utf-8", errors='replace') as f:
                        code_content = f.read()
                    
                    # Simple language mapping for syntax highlighting
                    lang_map = {'.py': 'python', '.js': 'javascript', '.java': 'java', '.c': 'c', '.cpp': 'cpp'}
                    st.code(code_content, language=lang_map.get(file_ext, 'python'))
                else:
                    st.info("No vulnerabilities match the selected filters.")
            else:
                st.success("✅ Clean Scan! No vulnerabilities found in this file.")
                
    except Exception as e:
        st.error(f"An application error occurred: {str(e)}")
        import traceback
        with st.expander("See Error Details"):
            st.code(traceback.format_exc())
        
    finally:
        # Cleanup - ensure temp file is always removed
        try:
            if os.path.exists(temp_filename):
                os.remove(temp_filename)
        except Exception as cleanup_error:
            st.warning(f"Could not cleanup temp file: {cleanup_error}")

else:
    st.info("👆 Upload a source code file to begin security analysis.")
