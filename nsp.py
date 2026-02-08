import streamlit as st
import numpy as np
import pandas as pd
import re
import string
import time
from datetime import datetime
import plotly.graph_objects as go
import plotly.express as px
import pickle

# Page config
st.set_page_config(
    page_title="🛡️ Cyber Threat Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Minimal, clean styling
st.markdown("""
<style>
    .main {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
    h1, h2, h3 {
        color: white !important;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: rgba(255, 255, 255, 0.1);
        border-radius: 8px;
        padding: 8px 16px;
    }
    .stTabs [aria-selected="true"] {
        background-color: rgba(255, 255, 255, 0.3);
    }
</style>
""", unsafe_allow_html=True)

# Sidebar - Model accuracy only
with st.sidebar:
    st.title("🛡️ Model Performance")
    st.markdown("---")
    
    st.subheader("📧 Spam Detection Accuracy")
    spam_accuracy_data = {
        'MLP': 0.9857,
        'LinearSVC': 0.9821,
        'RandomForest': 0.9767,
        'XGBoost': 0.9740,
        'DecisionTree': 0.9668,
        'LogisticRegression': 0.9668,
        'KNN': 0.9094
    }
    
    for model, acc in list(spam_accuracy_data.items())[:3]:
        st.metric(model, f"{acc*100:.2f}%")
    
    with st.expander("View All Spam Models"):
        for model, acc in list(spam_accuracy_data.items())[3:]:
            st.text(f"{model}: {acc*100:.2f}%")
    
    st.markdown("---")
    st.subheader("🌐 URL Detection Accuracy")
    url_accuracy_data = {
        'RandomForest': 0.9133,
        'DecisionTree': 0.9056,
        'KNN': 0.9018,
        'XGBoost': 0.8970,
        'MLP': 0.8992,
        'LogisticRegression': 0.7179,
        'LinearSVC': 0.7111,
        'GaussianNB': 0.3110
    }
    
    for model, acc in sorted(url_accuracy_data.items(), key=lambda x: x[1], reverse=True)[:3]:
        st.metric(model, f"{acc*100:.2f}%")
    
    with st.expander("View All URL Models"):
        for model, acc in sorted(url_accuracy_data.items(), key=lambda x: x[1], reverse=True)[3:]:
            st.text(f"{model}: {acc*100:.2f}%")

# Header
st.markdown("<h1 style='text-align: center;'>🛡️ Cyber Threat Detection System</h1>", unsafe_allow_html=True)
st.markdown("---")

# Tabs
tab1, tab2 = st.tabs(["📧 Spam Detection", "🌐 URL Analysis"])

# ==================== SPAM DETECTOR ====================
with tab1:
    st.subheader("Email Spam Detection")
    
    # Spam model accuracies
    spam_accuracy_data = {
        'MLP': 0.9857,
        'LinearSVC': 0.9821,
        'RandomForest': 0.9767,
        'XGBoost': 0.9740,
        'DecisionTree': 0.9668,
        'LogisticRegression': 0.9668,
        'KNN': 0.9094
    }
    
    try:
        feature_extraction = pickle.load(open('feature_extraction.pkl', 'rb'))
        spam_models = pickle.load(open('models.pkl', 'rb'))
        
        message = st.text_area(
            'Enter email content to analyze',
            placeholder='Paste your email content here...',
            height=200
        )
        
        col1, col2 = st.columns([1, 3])
        with col1:
            analyze_btn = st.button('🔍 Analyze', use_container_width=True, type="primary")
        
        if analyze_btn and message.strip():
            with st.spinner('Analyzing...'):
                # Extract features
                features = feature_extraction.transform([message])
                
                # Get predictions with probabilities
                predictions = {}
                weighted_score = 0
                total_weight = 0
                
                for name, model in spam_models.items():
                    pred = model.predict(features)[0]
                    predictions[name] = pred
                    
                    # Weighted voting based on accuracy
                    accuracy = spam_accuracy_data.get(name, 0.5)
                    weighted_score += pred * accuracy
                    total_weight += accuracy
                
                # Calculate consensus
                legitimate = sum(1 for p in predictions.values() if p == 1)
                spam = len(predictions) - legitimate
                weighted_result = weighted_score / total_weight if total_weight > 0 else 0.5
                
                # Display results
                st.markdown("---")
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Total Models", len(predictions))
                with col2:
                    st.metric("Safe Votes", legitimate)
                with col3:
                    st.metric("Spam Votes", spam)
                with col4:
                    st.metric("Weighted Score", f"{weighted_result:.2f}")
                
                # Final verdict (using weighted consensus)
                if weighted_result > 0.5:
                    st.success(f"### ✅ LEGITIMATE EMAIL")
                    st.info(f"💡 Weighted consensus: {weighted_result:.2%} confidence this is legitimate (higher accuracy models have more influence)")
                else:
                    st.error(f"### 🚨 SPAM DETECTED")
                    st.warning(f"⚠️ Weighted consensus: {(1-weighted_result):.2%} confidence this is spam (higher accuracy models have more influence)")
                
                # Model breakdown
                with st.expander("View detailed model predictions"):
                    for name in sorted(predictions.keys(), key=lambda x: spam_accuracy_data.get(x, 0), reverse=True):
                        pred = predictions[name]
                        acc = spam_accuracy_data.get(name, 0)
                        
                        col1, col2 = st.columns([3, 1])
                        with col1:
                            if pred == 1:
                                st.success(f"✅ {name}: Legitimate")
                            else:
                                st.error(f"🚨 {name}: Spam")
                        with col2:
                            st.text(f"Acc: {acc*100:.2f}%")
        
        elif analyze_btn:
            st.warning("Please enter message content to analyze")
            
    except FileNotFoundError:
        st.error("❌ Model files not found. Please ensure 'feature_extraction.pkl' and 'models.pkl' exist.")
    except Exception as e:
        st.error(f"❌ Error: {str(e)}")

# ==================== URL SCANNER ====================
with tab2:
    st.subheader("Phishing URL Detection")
    
    # Trusted domains whitelist
    TRUSTED_DOMAINS = {
        'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
        'linkedin.com', 'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com',
        'reddit.com', 'wikipedia.org', 'github.com', 'stackoverflow.com', 'medium.com',
        'yahoo.com', 'bing.com', 'adobe.com', 'dropbox.com', 'spotify.com',
        'twitch.tv', 'zoom.us', 'whatsapp.com', 'telegram.org', 'discord.com',
        'paypal.com', 'ebay.com', 'cloudflare.com', 'openai.com', 'anthropic.com',
        'gmail.com', 'outlook.com', 'slack.com', 'notion.so', 'figma.com'
    }
    
    def is_whitelisted(url_str):
        """Check if URL is trusted"""
        url_lower = url_str.lower()
        url_clean = re.sub(r'^https?://', '', url_lower)
        url_clean = re.sub(r'^www\.', '', url_clean)
        domain = url_clean.split('/')[0].split('?')[0]
        
        for trusted in TRUSTED_DOMAINS:
            if domain == trusted or domain.endswith('.' + trusted):
                return True
        return False
    
    def extract_features_series(urls: pd.Series) -> pd.DataFrame:
        """Extract URL features"""
        s = urls.fillna('').astype(str)
        df = pd.DataFrame({
            'url': s,
            'url_length': s.str.len(),
            'num_digits': s.str.count(r'\d'),
            'num_hyphens': s.str.count(r'-'),
            'num_underscores': s.str.count(r'_'),
            'num_dots': s.str.count(r'\.'),
            'num_slashes': s.str.count(r'/'),
            'num_query_chars': s.str.count(r'\?'),
            'has_ip': s.str.match(r'^(?:http[s]?://)?\d+\.\d+\.\d+\.\d+').astype(int),
            'num_special_chars': s.apply(lambda x: sum(c in string.punctuation for c in x)),
            'num_subdomains': s.str.count(r'\.'),
        })
        df['digits_ratio'] = df['num_digits'] / (df['url_length'].replace(0, 1))
        return df.drop(columns=['url'])
    
    # URL input
    url = st.text_input('Enter URL to analyze', placeholder='https://example.com')
    
    col1, col2 = st.columns([1, 3])
    with col1:
        scan_btn = st.button('🔍 Scan URL', use_container_width=True, type="primary")
    
    if scan_btn and url.strip():
        # Check whitelist first
        if is_whitelisted(url):
            st.success("### 🛡️ VERIFIED TRUSTED DOMAIN")
            st.info("✅ This domain is in our verified whitelist of trusted websites.")
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Status", "Trusted")
            with col2:
                st.metric("Security", "Verified")
            with col3:
                st.metric("Risk Level", "None")
        
        else:
            # Scan with models
            try:
                with st.spinner('Analyzing URL...'):
                    ss = pickle.load(open("scaler.pkl", "rb"))
                    url_models = pickle.load(open("model.pkl", "rb"))
                    
                    # Extract features
                    features = extract_features_series(pd.Series([url]))
                    X_scaled = ss.transform(features.values)
                    
                    # Show URL characteristics
                    st.markdown("#### URL Analysis")
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("Length", features['url_length'].values[0])
                    with col2:
                        st.metric("Dots", features['num_dots'].values[0])
                    with col3:
                        st.metric("Special Chars", features['num_special_chars'].values[0])
                    with col4:
                        st.metric("Has IP", "Yes" if features['has_ip'].values[0] else "No")
                    
                    # Get predictions
                    threat_map = {0: "Benign", 1: "Defacement", 2: "Malware", 3: "Phishing"}
                    predictions = {}
                    threat_counts = {0: 0, 1: 0, 2: 0, 3: 0}
                    
                    for name, model in url_models.items():
                        pred = model.predict(X_scaled)[0]
                        predictions[name] = pred
                        threat_counts[pred] += 1
                    
                    # Calculate weighted consensus
                    benign_count = threat_counts[0]
                    malicious_count = sum([threat_counts[1], threat_counts[2], threat_counts[3]])
                    
                    # Display consensus
                    st.markdown("---")
                    st.markdown("#### Detection Results")
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Models Analyzed", len(predictions))
                    with col2:
                        st.metric("Benign Votes", benign_count)
                    with col3:
                        st.metric("Threat Votes", malicious_count)
                    
                    # Final verdict
                    if benign_count > malicious_count:
                        st.success(f"### ✅ LIKELY SAFE ({benign_count}/{len(predictions)} models)")
                        st.info("💡 Majority consensus indicates this URL appears legitimate. Always exercise caution with unfamiliar links.")
                    else:
                        # Determine primary threat
                        primary_threat = max(threat_counts, key=threat_counts.get)
                        if primary_threat == 1:
                            st.warning(f"### ⚠️ CAUTION - DEFACEMENT DETECTED ({malicious_count}/{len(predictions)} models)")
                        else:
                            st.error(f"### 🚨 DANGER - {threat_map[primary_threat].upper()} DETECTED ({malicious_count}/{len(predictions)} models)")
                        st.error("⛔ Multiple models flagged this URL as malicious. Do not visit.")
                    
                    # Model details
                    with st.expander("View detailed model predictions"):
                        # Sort by accuracy (highest first)
                        sorted_models = sorted(predictions.keys(), key=lambda x: url_accuracy_data.get(x, 0), reverse=True)
                        
                        for name in sorted_models:
                            pred = predictions[name]
                            threat = threat_map[pred]
                            acc = url_accuracy_data.get(name, 0)
                            
                            col1, col2 = st.columns([3, 1])
                            with col1:
                                if pred == 0:
                                    st.success(f"✅ {name}: {threat}")
                                elif pred == 1:
                                    st.warning(f"⚠️ {name}: {threat}")
                                else:
                                    st.error(f"🚨 {name}: {threat}")
                            with col2:
                                st.text(f"Acc: {acc*100:.1f}%")
                    
                    # Feature visualization
                    with st.expander("View feature analysis"):
                        feature_names = features.columns.tolist()
                        feature_values = features.values[0]
                        
                        fig = go.Figure(data=go.Scatterpolar(
                            r=feature_values[:8],
                            theta=feature_names[:8],
                            fill='toself',
                            marker=dict(color='#00d2ff')
                        ))
                        fig.update_layout(
                            polar=dict(
                                bgcolor='rgba(255,255,255,0.1)',
                                radialaxis=dict(gridcolor='white')
                            ),
                            paper_bgcolor='rgba(0,0,0,0)',
                            font=dict(color='white'),
                            height=400
                        )
                        st.plotly_chart(fig, use_container_width=True)
                
            except FileNotFoundError:
                st.error("❌ Model files not found. Please ensure 'scaler.pkl' and 'model.pkl' exist.")
            except Exception as e:
                st.error(f"❌ Error: {str(e)}")
    
    elif scan_btn:
        st.warning("Please enter a URL to scan")

# Footer
st.markdown("---")
st.markdown(f"""
<div style='text-align: center; color: white; font-size: 12px;'>
    🛡️ Cyber Threat Detection System | {datetime.now().strftime("%Y-%m-%d %H:%M")}
</div>
""", unsafe_allow_html=True)