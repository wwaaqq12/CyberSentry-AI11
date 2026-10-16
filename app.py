
import json
from pathlib import Path

import streamlit as st
import pandas as pd

from entropy_analyzer import analyze_file

st.set_page_config(
    page_title="CyberEntropy-AI",
    page_icon="🔐",
    layout="wide"
)

st.title("🔐 CyberEntropy-AI")
st.subheader("Cybersecurity File Entropy Analyzer")

st.write(
    "Analyze files in a folder, calculate SHA-256 hashes, "
    "and review file entropy scores."
)

folder_input = st.text_input(
    "Enter the folder path",
    placeholder=r"C:\Users\mobpc\Desktop\test"
)

if st.button("🔍 Scan Folder", type="primary"):
    folder = Path(folder_input.strip().strip('"')).expanduser()

    if not folder.is_dir():
        st.error("Folder not found. Check the path and try again.")
    else:
        results = []

        for file_path in sorted(folder.iterdir()):
            if file_path.is_file():
                if file_path.name != "cyberentropy_report.json":
                    results.append(analyze_file(file_path))

        st.session_state["results"] = results
        st.session_state["folder"] = str(folder.resolve())

if "results" in st.session_state:
    results = st.session_state["results"]

    analyzed = [
        item for item in results
        if item.get("status") == "Analyzed"
    ]

    col1, col2, col3 = st.columns(3)

    col1.metric("Files Found", len(results))
    col2.metric("Files Analyzed", len(analyzed))
    col3.metric(
        "High Entropy",
        sum(item.get("entropy_score", 0) > 7.2 for item in analyzed)
    )

    st.subheader("📊 Scan Results")

    if results:
        st.dataframe(
            pd.DataFrame(results),
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No files found in this folder.")

    report = {
        "tool": "CyberEntropy-AI",
        "folder": st.session_state["folder"],
        "total_files_found": len(results),
        "analyzed_files": len(analyzed),
        "results": results
    }

    st.download_button(
        "📥 Download JSON Report",
        data=json.dumps(report, indent=4, ensure_ascii=False),
        file_name="cyberentropy_report.json",
        mime="application/json"
    )

    st.caption(
        "High entropy alone does not prove a file is malicious. "
        "Use the results as one indicator for further investigation."
    )