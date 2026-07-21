"""
================================================================================
AEGIS AI - Network Security Audit Dashboard
================================================================================
Client-facing dashboard for network security analysis.
Calls the live Aegis AI v2 API for predictions.
================================================================================
"""

import streamlit as st
import requests
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
from io import BytesIO
import time

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT


# ==============================================================================
# CONFIG
# ==============================================================================

API_BASE_URL = "https://aegis-ai-v2.onrender.com"
MODEL_VERSION = "2.3.0"
MACRO_F1 = "98.43%"
ACCURACY = "99.88%"

st.set_page_config(
    page_title="Aegis AI - Security Audit Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ==============================================================================
# CUSTOM STYLING
# ==============================================================================

st.markdown("""
<style>
    .stApp {
        background-color: #0a0e14;
    }
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        background: linear-gradient(90deg, #00d4ff, #7b2ff7);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0px;
    }
    .sub-header {
        color: #8b95a5;
        font-size: 0.95rem;
        margin-top: 0px;
    }
    .metric-card {
        background-color: #131722;
        border: 1px solid #2a2f3d;
        border-radius: 10px;
        padding: 20px;
        text-align: center;
    }
    .status-live {
        color: #00e676;
        font-weight: 600;
    }
    .status-down {
        color: #ff5252;
        font-weight: 600;
    }
    div[data-testid="stFileUploader"] {
        border: 2px dashed #2a2f3d;
        border-radius: 10px;
        padding: 20px;
    }
    .stButton>button {
        background: linear-gradient(90deg, #00d4ff, #7b2ff7);
        color: white;
        font-weight: 600;
        border: none;
        border-radius: 8px;
        padding: 0.6rem 2rem;
    }
</style>
""", unsafe_allow_html=True)


# ==============================================================================
# API HELPER FUNCTIONS
# ==============================================================================

def check_api_health():
    """Ping the live API to check status. Returns (is_live, response_time_ms)."""
    try:
        start = time.time()
        resp = requests.get(f"{API_BASE_URL}/health", timeout=10)
        elapsed_ms = (time.time() - start) * 1000
        if resp.status_code == 200:
            return True, elapsed_ms, resp.json()
        return False, elapsed_ms, None
    except requests.exceptions.RequestException:
        return False, None, None


def analyze_file(uploaded_file):
    """Send the uploaded file to /analyze, return the JSON response."""
    files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "text/csv")}
    response = requests.post(f"{API_BASE_URL}/analyze", files=files, timeout=120)
    response.raise_for_status()
    return response.json()


# ==============================================================================
# PDF REPORT GENERATION
# ==============================================================================

def generate_pdf_report(client_name, filename, results):
    """Generate a professional audit report PDF, return as bytes."""
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter,
                             leftMargin=0.6*inch, rightMargin=0.6*inch,
                             topMargin=0.6*inch, bottomMargin=0.6*inch)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('Title', parent=styles['Heading1'],
                                  fontSize=22, textColor=colors.HexColor('#1a1a2e'),
                                  spaceAfter=6)
    subtitle_style = ParagraphStyle('Subtitle', parent=styles['Normal'],
                                     fontSize=11, textColor=colors.HexColor('#666666'),
                                     spaceAfter=20)
    heading_style = ParagraphStyle('SectionHeading', parent=styles['Heading2'],
                                    fontSize=14, textColor=colors.HexColor('#1a1a2e'),
                                    spaceBefore=16, spaceAfter=8)
    body_style = ParagraphStyle('Body', parent=styles['Normal'],
                                 fontSize=10, leading=15)

    story = []

    # Cover section
    story.append(Paragraph("AEGIS AI — Security Audit Report", title_style))
    story.append(Paragraph(
        f"Prepared for: <b>{client_name}</b> &nbsp;|&nbsp; "
        f"Date: {datetime.now().strftime('%B %d, %Y')} &nbsp;|&nbsp; "
        f"File: {filename}",
        subtitle_style
    ))

    # Executive Summary
    story.append(Paragraph("Executive Summary", heading_style))
    total_flows = results.get('total_flows_analyzed', 0)
    total_attacks = results.get('total_attacks_detected', 0)
    attack_rate = (total_attacks / total_flows * 100) if total_flows > 0 else 0

    risk_level = "LOW"
    risk_color = "#00c853"
    if attack_rate > 20:
        risk_level = "CRITICAL"
        risk_color = "#d50000"
    elif attack_rate > 5:
        risk_level = "HIGH"
        risk_color = "#ff6d00"
    elif attack_rate > 0:
        risk_level = "MODERATE"
        risk_color = "#ffab00"

    summary_text = (
        f"This report analyzes <b>{total_flows:,}</b> network flows submitted for review. "
        f"Of these, <b>{total_attacks:,}</b> flows ({attack_rate:.1f}%) were classified as "
        f"potential threats by Aegis AI's machine learning ensemble, which achieves "
        f"{MACRO_F1} macro F1-score across 13 attack categories in benchmark testing."
    )
    story.append(Paragraph(summary_text, body_style))
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        f"<b>Overall Risk Assessment: <font color='{risk_color}'>{risk_level}</font></b>",
        body_style
    ))

    # Findings table
    story.append(Paragraph("Detailed Findings", heading_style))
    breakdown = results.get('attack_breakdown', {})
    table_data = [["Category", "Count", "% of Total"]]
    for label, count in sorted(breakdown.items(), key=lambda x: -x[1]):
        pct = (count / total_flows * 100) if total_flows > 0 else 0
        table_data.append([label, str(count), f"{pct:.1f}%"])

    findings_table = Table(table_data, colWidths=[2.5*inch, 1.5*inch, 1.5*inch])
    findings_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f5f5')]),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(findings_table)

    # Recommendations
    story.append(Paragraph("Recommendations", heading_style))
    if total_attacks > 0:
        rec_text = (
            "Based on the findings above, we recommend the following actions:<br/><br/>"
            "1. <b>Immediate review</b> of flagged flows with highest confidence scores.<br/>"
            "2. <b>Block or rate-limit</b> source IPs associated with confirmed threats.<br/>"
            "3. <b>Establish continuous monitoring</b> to catch similar patterns in real time.<br/>"
            "4. <b>Schedule a follow-up audit</b> in 30 days to verify remediation effectiveness."
        )
    else:
        rec_text = (
            "No threats were detected in this analysis window. We recommend:<br/><br/>"
            "1. <b>Continue regular audits</b> to maintain visibility into network activity.<br/>"
            "2. <b>Establish a baseline</b> monitoring cadence for early threat detection.<br/>"
            "3. <b>Document this audit</b> for compliance and security posture records."
        )
    story.append(Paragraph(rec_text, body_style))

    # Methodology & Scope
    story.append(Paragraph("Methodology & Scope", heading_style))
    method_text = (
        "This audit uses Aegis AI v2.3.0, a stacking ensemble (Random Forest, XGBoost, "
        "LightGBM, with a Logistic Regression meta-learner) trained on 2.8M+ network "
        "flows. The system analyzes network flow metadata to classify traffic into "
        "13 categories including DDoS, port scanning, brute-force attempts, and web "
        "application attacks.<br/><br/>"
        "<b>Scope:</b> This analysis covers network-layer traffic patterns only. It does "
        "not include endpoint security, application code review, or physical security "
        "assessment. Results reflect a point-in-time analysis of the submitted data."
    )
    story.append(Paragraph(method_text, body_style))

    doc.build(story)
    buffer.seek(0)
    return buffer


# ==============================================================================
# SIDEBAR
# ==============================================================================

with st.sidebar:
    st.markdown("### 🛡️ Aegis AI")
    st.markdown("*AI-Powered Network Security*")
    st.markdown("---")

    st.markdown("#### System Status")
    is_live, response_ms, health_data = check_api_health()

    if is_live:
        st.markdown(f'<span class="status-live">🟢 Engine Live</span>', unsafe_allow_html=True)
        st.caption(f"Response: {response_ms:.0f}ms")
    else:
        st.markdown(f'<span class="status-down">🔴 Engine Offline</span>', unsafe_allow_html=True)
        st.caption("Retrying automatically...")

    st.markdown("---")
    st.markdown("#### Model Info")
    st.metric("Version", MODEL_VERSION)
    st.metric("Macro F1", MACRO_F1)
    st.metric("Accuracy", ACCURACY)
    st.caption("13 attack categories detected")

    st.markdown("---")
    st.markdown("#### About")
    st.caption(
        "Aegis AI analyzes network flow data using an ensemble of machine "
        "learning models to detect DDoS, port scanning, brute-force attempts, "
        "botnet activity, and more."
    )
    st.caption("⚠️ Network-layer analysis only — does not cover endpoint or "
               "application security.")


# ==============================================================================
# MAIN AREA
# ==============================================================================

st.markdown('<p class="main-header">Network Security Audit Platform</p>', unsafe_allow_html=True)
st.markdown('<p class="sub-header">Upload network flow data for AI-powered threat analysis</p>', unsafe_allow_html=True)
st.markdown("---")

tab1, tab2, tab3 = st.tabs(["🔍 New Audit", "📁 Past Reports", "ℹ️ About This Tool"])

# ------------------------------------------------------------------------------
# TAB 1: NEW AUDIT
# ------------------------------------------------------------------------------
with tab1:
    col1, col2 = st.columns([1, 1])
    with col1:
        client_name = st.text_input("Client / Company Name", placeholder="e.g. Acme Corp")
    with col2:
        st.write("")

    uploaded_file = st.file_uploader(
        "Upload network flow CSV (CICFlowMeter format)",
        type=["csv"],
        help="Upload a CICFlowMeter-formatted CSV export of network flows"
    )

    analyze_clicked = st.button("🚀 Run Security Audit", disabled=(uploaded_file is None))

    if analyze_clicked and uploaded_file is not None:
        if not is_live:
            st.warning(
                "⏳ The analysis engine appears to be waking up (this can take "
                "30-60 seconds on first use after inactivity). Retrying now — "
                "please wait..."
            )

        with st.spinner("🔄 Analyzing network flows... this may take a moment for larger files."):
            try:
                results = analyze_file(uploaded_file)
                st.session_state['last_results'] = results
                st.session_state['last_client'] = client_name or "Client"
                st.session_state['last_filename'] = uploaded_file.name

                if 'report_history' not in st.session_state:
                    st.session_state['report_history'] = []
                st.session_state['report_history'].append({
                    "client": client_name or "Client",
                    "filename": uploaded_file.name,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M"),
                    "results": results
                })

                st.success("✅ Analysis complete!")

            except requests.exceptions.Timeout:
                st.error(
                    "⏱️ Request timed out. The engine may still be warming up — "
                    "please try again in a moment."
                )
            except requests.exceptions.RequestException as e:
                st.error(f"❌ Analysis failed: {str(e)}")

    # ---- DISPLAY RESULTS ----
    if 'last_results' in st.session_state:
        results = st.session_state['last_results']

        if results.get('status') == 'parsed_only':
            st.info(
                f"📄 File format detected: **{results['detected_format']}**\n\n"
                f"{results.get('note', '')}"
            )
        else:
            st.markdown("### 📊 Audit Summary")

            total_flows = results.get('total_flows_analyzed', 0)
            total_attacks = results.get('total_attacks_detected', 0)
            attack_rate = (total_attacks / total_flows * 100) if total_flows > 0 else 0

            risk_level = "LOW"
            if attack_rate > 20:
                risk_level = "CRITICAL"
            elif attack_rate > 5:
                risk_level = "HIGH"
            elif attack_rate > 0:
                risk_level = "MODERATE"

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Flows Analyzed", f"{total_flows:,}")
            m2.metric("Threats Detected", f"{total_attacks:,}")
            m3.metric("Threat Rate", f"{attack_rate:.1f}%")
            m4.metric("Risk Level", risk_level)

            st.markdown("### 📈 Attack Breakdown")
            breakdown = results.get('attack_breakdown', {})

            if breakdown:
                df_breakdown = pd.DataFrame(
                    list(breakdown.items()), columns=["Category", "Count"]
                ).sort_values("Count", ascending=True)

                colors_map = {"BENIGN": "#00e676"}
                bar_colors = [colors_map.get(x, "#ff5252") for x in df_breakdown["Category"]]

                fig = go.Figure(go.Bar(
                    x=df_breakdown["Count"],
                    y=df_breakdown["Category"],
                    orientation='h',
                    marker_color=bar_colors,
                    text=df_breakdown["Count"],
                    textposition='outside'
                ))
                fig.update_layout(
                    plot_bgcolor='#131722', paper_bgcolor='#131722',
                    font_color='#e0e0e0', height=400,
                    margin=dict(l=10, r=10, t=10, b=10),
                    xaxis=dict(gridcolor='#2a2f3d'),
                    yaxis=dict(gridcolor='#2a2f3d')
                )
                st.plotly_chart(fig, use_container_width=True)

            high_conf = results.get('high_confidence_attacks', [])
            if high_conf:
                st.markdown("### 🎯 High-Confidence Detections")
                df_detections = pd.DataFrame(high_conf)
                df_detections['confidence'] = (df_detections['confidence'] * 100).round(2).astype(str) + '%'
                df_detections.columns = ["Flow #", "Attack Type", "Confidence"]
                st.dataframe(df_detections, use_container_width=True, hide_index=True)

            st.markdown("### 📄 Export Report")
            pdf_buffer = generate_pdf_report(
                st.session_state.get('last_client', 'Client'),
                st.session_state.get('last_filename', 'report'),
                results
            )
            st.download_button(
                label="⬇️ Download Full Audit Report (PDF)",
                data=pdf_buffer,
                file_name=f"Aegis_Audit_{st.session_state.get('last_client', 'Client').replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.pdf",
                mime="application/pdf"
            )

# ------------------------------------------------------------------------------
# TAB 2: PAST REPORTS
# ------------------------------------------------------------------------------
with tab2:
    st.markdown("### 📁 Session Report History")
    if 'report_history' in st.session_state and st.session_state['report_history']:
        for i, report in enumerate(reversed(st.session_state['report_history'])):
            with st.expander(f"{report['client']} — {report['filename']} — {report['timestamp']}"):
                r = report['results']
                st.write(f"**Flows analyzed:** {r.get('total_flows_analyzed', 0):,}")
                st.write(f"**Threats detected:** {r.get('total_attacks_detected', 0):,}")
                st.write(f"**Breakdown:** {r.get('attack_breakdown', {})}")
    else:
        st.info("No audits run yet this session. Reports will appear here after analysis.")

# ------------------------------------------------------------------------------
# TAB 3: ABOUT
# ------------------------------------------------------------------------------
with tab3:
    st.markdown("### ℹ️ About Aegis AI")
    st.markdown("""
    Aegis AI is a machine learning-powered network intrusion detection system, 
    trained on 2.8M+ real network flows to identify 13 categories of cyber threats.

    **What it detects:**
    - DDoS attacks (multiple variants)
    - Port scanning / reconnaissance
    - Brute-force login attempts (FTP, SSH)
    - Web application attacks (SQLi, XSS)
    - Botnet command-and-control traffic
    - Rare/critical exploits (Heartbleed, Infiltration)

    **Model Performance:**
    - Macro F1-Score: 98.43%
    - Overall Accuracy: 99.88%
    - Sub-40ms inference latency per flow

    **Scope & Limitations:**
    - Network-layer analysis only (not endpoint or application security)
    - Optimized for CICFlowMeter-formatted flow data
    - Real-world performance may vary from benchmark; new deployments benefit 
      from a calibration period against your specific traffic baseline

    ---
    **Interested in a security audit for your organization?**  
    Contact: nainprerak15@gmail.com
    """)