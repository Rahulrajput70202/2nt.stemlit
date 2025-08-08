import os
import json
import streamlit as st
from androguard.misc import AnalyzeAPK

# Create folders
UPLOAD_FOLDER = "uploads"
REPORT_FOLDER = "reports"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

# Risky permissions
DANGEROUS_PERMISSIONS = {
    'android.permission.READ_SMS',
    'android.permission.RECORD_AUDIO',
    'android.permission.CAMERA',
    'android.permission.ACCESS_FINE_LOCATION',
    'android.permission.WRITE_EXTERNAL_STORAGE',
    'android.permission.READ_CONTACTS',
    'android.permission.SEND_SMS'
}

# Function to analyze APK
def analyze_apk(apk_path):
    a, d, dx = AnalyzeAPK(apk_path)
    used_permissions = set(a.get_permissions())
    risky_permissions = used_permissions & DANGEROUS_PERMISSIONS

    result = {
        "app_name": a.get_app_name(),
        "package": a.get_package(),
        "permissions": list(used_permissions),
        "risky_permissions": list(risky_permissions),
        "insecure_apis": [],
        "risk_score": 0,
        "risk_level": "Low"
    }

    for method in dx.get_methods():
        method_str = method.method.get_class_name() + "->" + method.method.get_name()
        if 'WebView' in method_str and 'addJavascriptInterface' in method_str:
            result["insecure_apis"].append(method_str)
        if 'HttpURLConnection' in method_str:
            result["insecure_apis"].append(method_str)
        if 'openConnection' in method_str and 'java/net/URL' in method_str:
            result["insecure_apis"].append(method_str)

    score = len(risky_permissions) * 2 + len(result["insecure_apis"]) * 3
    result["risk_score"] = score
    result["risk_level"] = (
        "High" if score > 10 else
        "Medium" if score > 5 else
        "Low"
    )

    with open(f"{REPORT_FOLDER}/{result['package']}.json", "w") as f:
        json.dump(result, f, indent=4)

    return result

# Streamlit UI
st.set_page_config(page_title="Privacy Leak Analyzer", page_icon="🔐", layout="centered")

st.markdown(
    """
    <h1 style='text-align: center; color: white;'>🔐 Privacy Leak Analyzer</h1>
    """,
    unsafe_allow_html=True
)

# File uploader
apk_file = st.file_uploader("Upload APK file", type=["apk"])

if apk_file is not None:
    file_path = os.path.join(UPLOAD_FOLDER, apk_file.name)
    with open(file_path, "wb") as f:
        f.write(apk_file.getbuffer())

    with st.spinner("Analyzing APK... 🔍"):
        try:
            result = analyze_apk(file_path)
        except Exception as e:
            st.error(f"Error analyzing APK: {e}")
            st.stop()
        finally:
            os.remove(file_path)

    # Display results
    st.subheader(f"📋 Report for: {result['app_name']}")
    st.write(f"**📦 Package:** {result['package']}")
    st.write(f"**⚠️ Risk Level:** `{result['risk_level']}`")
    st.write(f"**📈 Risk Score:** {result['risk_score']}")

    # Risk chart
    st.bar_chart({
        "Metrics": [len(result['permissions']), len(result['risky_permissions']), len(result['insecure_apis']), result['risk_score']]
    })

    st.markdown("### 🔐 Used Permissions")
    st.write(result['permissions'])

    st.markdown("### 🚨 Risky Permissions")
    st.write(result['risky_permissions'])

    st.markdown("### 🛡️ Insecure API Usage")
    st.write(result['insecure_apis'])

    # Download report
    json_data = json.dumps(result, indent=4)
    st.download_button(
        label="📥 Download Report (JSON)",
        data=json_data,
        file_name=f"{result['package']}_report.json",
        mime="application/json"
    )
