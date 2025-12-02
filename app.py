import streamlit as st
import pandas as pd
import joblib
import os
import time
from dotenv import load_dotenv
from PIL import Image
import google.generativeai as genai

load_dotenv()

MODEL_PATH = 'final_pipeline.pkl'

PROTOCOL_TYPES = ['TCP', 'UDP', 'ICMP', 'HTTP', 'FTP']
ENCRYPTION_TYPES = ['NONE', 'AES', 'DES', 'RSA', 'TLS']
BROWSER_TYPES = ['Chrome', 'Firefox', 'Safari', 'Edge', 'Other']



GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")


@st.cache_resource
def load_model(path):
    """Load the trained scikit-learn pipeline."""
    if not os.path.exists(path):
        st.error(f"Model file not found at '{path}'.")
        st.warning("Please run the `save_model.py` script first to train and save the model.")
        st.stop()
    try:
        model = joblib.load(path)
        return model
    except Exception as e:
        st.error(f"Error loading model: {e}")
        st.stop()

def predict_attack(pipeline, input_data):
    """Performs prediction on the input data."""
    try:
        input_data['session_duration'] = float(input_data['session_duration'])
        input_data['ip_reputation_score'] = float(input_data['ip_reputation_score'])
    except ValueError:
        st.error("Need input.")
        st.stop()
        
    input_df = pd.DataFrame([input_data])
    
    prediction = pipeline.predict(input_df)[0]

    try:
        probability = pipeline.predict_proba(input_df)[0][1]
    except AttributeError:
        probability = None
        
    return prediction, probability
def input_image_setup(uploaded_file):
    """Converts the Streamlit UploadedFile to a PIL Image."""
    if uploaded_file is not None:
        return Image.open(uploaded_file)
    else:
        raise FileNotFoundError("No file uploaded")

def get_gemini_response(prompt, image):
    try:
        model = genai.GenerativeModel('gemini-2.5-flash') 
        response = model.generate_content([prompt, image])
        return response.text
    except Exception as e:
        return f"An error occurred while calling the Gemini API: {e}"

final_pipeline = load_model(MODEL_PATH)

st.set_page_config(
    page_title="Cybersecurity Intrusion Detector",
    layout="centered",
    initial_sidebar_state="collapsed",
)

st.title("🛡️ Network Intrusion Detector")

tab1, tab2 = st.tabs(["Using Data", "Image Analysis"])

with tab1:
    st.markdown("Use the features below to analyze a network session and predict if an intrusion attack is detected.")
    st.divider()

    network_packet_size = 500
    session_duration = "492.9832634"
    failed_logins = 1
    ip_reputation_score = "0.60681808"
    unusual_time_access = 0
    login_attempts = 5
    protocol_type = 'TCP'
    encryption_used = 'AES'
    browser_type = 'Chrome'

    with st.form("intrusion_form"):
        st.subheader("Numeric Input Features")
        col1, col2 = st.columns(2)
        with col1:
            network_packet_size = st.number_input(
                "Network Packet Size (bytes)", 
                min_value=100, max_value=1500, value=network_packet_size
            )
            session_duration = st.text_input(
                "Session Duration (seconds)", 
                placeholder="492.9832634", value=session_duration
            )
            failed_logins = st.slider(
                "Failed Logins", 
                min_value=0, max_value=5, value=failed_logins, step=1
            )
        
        with col2:
            ip_reputation_score = st.text_input(
                "IP Reputation Score (0.0 to 1.0)", 
                placeholder="0.60681808", value=ip_reputation_score
            )
            unusual_time_access = st.selectbox(
                "Unusual Time Access (1=Yes, 0=No)", 
                options=[0, 1], index=unusual_time_access
            )
            login_attempts = st.slider(
                "Total Login Attempts", 
                min_value=1, max_value=15, value=login_attempts, step=1
            )
        
        st.subheader("Categorical Input Features")
        
        col3, col4, col5 = st.columns(3)
        
        with col3:
            protocol_type = st.selectbox(
                "Protocol Type", 
                options=PROTOCOL_TYPES, index=PROTOCOL_TYPES.index(protocol_type)
            )
            
        with col4:
            encryption_used = st.selectbox(
                "Encryption Used", 
                options=ENCRYPTION_TYPES, index=ENCRYPTION_TYPES.index(encryption_used)
            )
            
        with col5:
            browser_type = st.selectbox(
                "Browser Type", 
                options=BROWSER_TYPES, index=BROWSER_TYPES.index(browser_type)
            )

        submitted = st.form_submit_button("Run Prediction")

    if submitted:
        try:
            float(session_duration)
            float(ip_reputation_score)
        except ValueError:
            st.error("Wrong input.")
            st.stop()


        sample_data = {
            'network_packet_size': network_packet_size,
            'login_attempts': login_attempts,
            'session_duration': session_duration,
            'ip_reputation_score': ip_reputation_score,
            'failed_logins': failed_logins,
            'unusual_time_access': unusual_time_access,
            'protocol_type': protocol_type,
            'encryption_used': encryption_used,
            'browser_type': browser_type
        }

        with st.spinner('Analyzing session data...'):
            time.sleep(1) 
            prediction, probability = predict_attack(final_pipeline, sample_data)

        st.divider()
        
        if prediction == 1:
            st.error("🚨 ATTACK DETECTED", icon="⚠️")
            st.balloons()
            
            if probability is not None:
                st.metric(
                    label="Confidence Score (Attack Probability)",
                    value=f"{probability:.2f}",
                    delta_color="off"
                )
            st.markdown(
                """
                This session exhibits highly suspicious characteristics indicative of a network intrusion. 
                Immediate action should be taken.
                """
            )
            
        else:
            st.success("✅ No Attack Detected", icon="👍")
            if probability is not None:
                st.metric(
                    label="Attack Probability",
                    value=f"{probability:.2f}",
                    delta_color="off"
                )
            st.markdown(
                """
                The session appears normal based on the input features. 
                Always monitor other logs for a full security assessment.
                """
            )

with tab2:
    if not GOOGLE_API_KEY:
        st.error("Image analysis is disabled. Please configure your GOOGLE_API_KEY in a `.env` file.")
    else:
        st.subheader("Image Analysis")
        uploaded_file = st.file_uploader("Upload an image of your data (e.g., a chart, log snippet, or network graph)",
                                         type=["jpg", "jpeg", "png"])
        context_data = {
            'network_packet_size': network_packet_size,
            'login_attempts': login_attempts,
            'session_duration': session_duration,
            'ip_reputation_score': ip_reputation_score,
            'failed_logins': failed_logins,
            'unusual_time_access': unusual_time_access,
            'protocol_type': protocol_type,
            'encryption_used': encryption_used,
            'browser_type': browser_type
        }

        if uploaded_file is not None:
            image = Image.open(uploaded_file)
            st.image(image, caption="Uploaded Data Image.", use_column_width=True)
if st.button("Analyze Data"):
    image_data = input_image_setup(uploaded_file)
    
    prompt = """
    You are an expert data extractor for a cybersecurity system.
    Analyze the uploaded image (e.g., a table or chart) and extract the values for the following features:
    'network_packet_size', 'login_attempts', 'session_duration', 'ip_reputation_score', 'failed_logins', 'unusual_time_access', 'protocol_type', 'encryption_used', and 'browser_type'.
    
    Format your response STRICTLY as a JSON object, and do not include any other text, explanation, or markdown formatting outside of the JSON object. 
    Use the exact keys provided. If a value is not visible in the image, use the value 'N/A'.

    Example Format:
    {"network_packet_size": 1200, "login_attempts": 10, "session_duration": 500.2, "ip_reputation_score": 0.85, "failed_logins": 3, "unusual_time_access": 1, "protocol_type": "TCP", "encryption_used": "AES", "browser_type": "Chrome"}
    """
    
    response_text = get_gemini_response(prompt, image_data)
    
    try:
        import json
        
        extracted_data = json.loads(response_text)
        st.subheader("Extracted Data for ML Model")
        st.json(extracted_data)
        st.subheader("Image Analysis Results (Semantic)")
        st.markdown("**(A second analysis would go here to interpret the image)**")
        
    except json.JSONDecodeError:
        st.error("Failed to parse data. Check the model's output formatting.")
        st.markdown(f"**Raw Output:** \n{response_text}")