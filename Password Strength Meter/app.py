import streamlit as st
import re
import time
import math

# Function to check password strength
def check_strength(password):
    strength = 0
    suggestions = []

    # Length Check
    if len(password) >= 8:
        strength += 1
    else:
        suggestions.append("Increase the length (minimum 8 characters).")

    # Upper and Lower Case Check
    if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
        strength += 1
    else:
        suggestions.append("Use both uppercase and lowercase letters.")

    # Number Check
    if re.search(r"\d", password):
        strength += 1
    else:
        suggestions.append("Include at least one number.")

    # Special Character Check
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        strength += 1
    else:
        suggestions.append("Use at least one special character (!@#$%^&*).")

    return strength, suggestions

# Custom CSS for RPM-style gauge with enhanced animations
st.markdown("""
<style>
    .gauge-container {
        width: 300px;
        height: 150px;
        position: relative;
        margin: 20px auto;
    }
    .gauge {
        width: 100%;
        height: 100%;
        position: relative;
        background: #1a1a1a;
        border-radius: 150px 150px 0 0;
        overflow: hidden;
    }
    .gauge::before {
        content: '';
        position: absolute;
        width: 100%;
        height: 100%;
        background: linear-gradient(90deg, #ff0000 0%, #ff9900 50%, #00ff00 100%);
        opacity: 0.3;
    }
    .needle {
        width: 4px;
        height: 100px;
        background: #fff;
        position: absolute;
        bottom: 0;
        left: 50%;
        transform-origin: bottom center;
        transform: rotate(-90deg);
        transition: transform 0.8s cubic-bezier(0.4, 0, 0.2, 1);
        z-index: 2;
    }
    .needle::after {
        content: '';
        position: absolute;
        width: 20px;
        height: 20px;
        background: #fff;
        border-radius: 50%;
        bottom: -10px;
        left: -8px;
        box-shadow: 0 0 10px rgba(255, 255, 255, 0.5);
    }
    .gauge-labels {
        position: absolute;
        width: 100%;
        bottom: 20px;
        display: flex;
        justify-content: space-between;
        padding: 0 20px;
        color: white;
        font-weight: bold;
    }
    .strength-text {
        text-align: center;
        font-size: 1.5em;
        font-weight: bold;
        margin-top: 10px;
        color: white;
        transition: color 0.5s ease;
    }
    .gauge-marks {
        position: absolute;
        width: 100%;
        height: 100%;
    }
    .mark {
        position: absolute;
        width: 2px;
        height: 10px;
        background: rgba(255, 255, 255, 0.5);
        bottom: 0;
        left: 50%;
        transform-origin: bottom center;
    }
    .percentage-display {
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background: rgba(0, 0, 0, 0.7);
        padding: 5px 10px;
        border-radius: 5px;
        color: #00ff00;
        font-family: 'Courier New', monospace;
        font-size: 1.2em;
        font-weight: bold;
        text-shadow: 0 0 5px #00ff00;
        transition: color 0.5s ease, text-shadow 0.5s ease;
    }
    @keyframes pulse {
        0% { opacity: 0.3; }
        50% { opacity: 0.6; }
        100% { opacity: 0.3; }
    }
    .gauge::before {
        animation: pulse 2s infinite;
    }
</style>
""", unsafe_allow_html=True)

# Streamlit UI
st.title("🔐 Password Strength Meter")

password = st.text_input("Enter your password:", type="password")

if password:
    strength, suggestions = check_strength(password)
    
    # Calculate needle rotation angle (-90 to 90 degrees)
    strength_percentage = (strength / 4) * 100
    angle = -90 + (180 * strength_percentage / 100)
    
    # Determine color based on strength
    if strength_percentage >= 75:
        color = "#00ff00"  # Green
        strength_text = "Strong"
    elif strength_percentage >= 50:
        color = "#ff9900"  # Yellow
        strength_text = "Medium"
    else:
        color = "#ff0000"  # Red
        strength_text = "Weak"
    
    # Create gauge marks
    marks_html = ""
    for i in range(0, 181, 30):  # Create marks every 30 degrees
        mark_angle = -90 + i
        marks_html += f'<div class="mark" style="transform: rotate({mark_angle}deg);"></div>'
    
    # Display RPM-style gauge with enhanced animation
    st.markdown(f"""
    <div class="gauge-container">
        <div class="gauge">
            <div class="gauge-marks">{marks_html}</div>
            <div class="needle" style="transform: rotate({angle}deg);"></div>
            <div class="percentage-display" style="color: {color}; text-shadow: 0 0 5px {color};">{int(strength_percentage)}%</div>
        </div>
        <div class="gauge-labels">
            <span>Weak</span>
            <span>Strong</span>
        </div>
    </div>
    <div class="strength-text" style="color: {color}; text-shadow: 0 0 10px {color};">{strength_text}</div>
    """, unsafe_allow_html=True)
    
    # Show improvement suggestions
    if suggestions:
        st.write("🔹 Suggestions to improve your password:")
        for s in suggestions:
            st.write(f"- {s}")
