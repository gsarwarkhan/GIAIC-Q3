import streamlit as st
import time

# Set page config for better styling
st.set_page_config(
    page_title="Unit Converter",
    page_icon="📏",
    layout="centered"
)

# Custom CSS for styling
st.markdown("""
    <style>
    .stApp {
        background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
    }
    .stButton>button {
        background-color: #4CAF50;
        color: white;
        border-radius: 5px;
        padding: 10px 20px;
        border: none;
        transition: all 0.3s ease;
    }
    .stButton>button:hover {
        background-color: #45a049;
        transform: scale(1.05);
    }
    .stSelectbox {
        background-color: white;
        border-radius: 5px;
        padding: 10px;
    }
    .stNumberInput {
        background-color: white;
        border-radius: 5px;
        padding: 10px;
    }
    .title {
        color: #2c3e50;
        text-align: center;
        font-size: 2.5em;
        margin-bottom: 20px;
        animation: fadeIn 1s ease-in;
    }
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(-20px); }
        to { opacity: 1; transform: translateY(0); }
    }
    .result-box {
        background-color: white;
        padding: 20px;
        border-radius: 10px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        margin-top: 20px;
        animation: slideIn 0.5s ease-out;
    }
    @keyframes slideIn {
        from { opacity: 0; transform: translateY(20px); }
        to { opacity: 1; transform: translateY(0); }
    }
    </style>
""", unsafe_allow_html=True)

# Conversion functions
def convert_length(value, from_unit, to_unit):
    if from_unit == "Meters" and to_unit == "Kilometers":
        return value / 1000
    elif from_unit == "Kilometers" and to_unit == "Meters":
        return value * 1000
    elif from_unit == "Meters" and to_unit == "Miles":
        return value * 0.000621371
    elif from_unit == "Miles" and to_unit == "Meters":
        return value / 0.000621371
    else:
        return value  # In case of no valid conversion

def convert_weight(value, from_unit, to_unit):
    if from_unit == "Kilograms" and to_unit == "Pounds":
        return value * 2.20462
    elif from_unit == "Pounds" and to_unit == "Kilograms":
        return value / 2.20462
    else:
        return value  # In case of no valid conversion

def convert_temperature(value, from_unit, to_unit):
    if from_unit == "Celsius" and to_unit == "Fahrenheit":
        return (value * 9/5) + 32
    elif from_unit == "Fahrenheit" and to_unit == "Celsius":
        return (value - 32) * 5/9
    else:
        return value  # In case of no valid conversion

# Streamlit UI
st.markdown('<h1 class="title">Unit Converter</h1>', unsafe_allow_html=True)

# Choose conversion type with animation
conversion_type = st.selectbox(
    "Choose Conversion Type",
    ["Length", "Weight", "Temperature"],
    key="conversion_type"
)

# Input value with animation
value = st.number_input(
    "Enter Value",
    min_value=0.0,
    key="value_input"
)

# Select units with animation
if conversion_type == "Length":
    from_unit = st.selectbox("From Unit", ["Meters", "Kilometers", "Miles"], key="length_from")
    to_unit = st.selectbox("To Unit", ["Meters", "Kilometers", "Miles"], key="length_to")
    result = convert_length(value, from_unit, to_unit)

elif conversion_type == "Weight":
    from_unit = st.selectbox("From Unit", ["Kilograms", "Pounds"], key="weight_from")
    to_unit = st.selectbox("To Unit", ["Kilograms", "Pounds"], key="weight_to")
    result = convert_weight(value, from_unit, to_unit)

elif conversion_type == "Temperature":
    from_unit = st.selectbox("From Unit", ["Celsius", "Fahrenheit"], key="temp_from")
    to_unit = st.selectbox("To Unit", ["Celsius", "Fahrenheit"], key="temp_to")
    result = convert_temperature(value, from_unit, to_unit)

# Show result with animation
st.markdown(f"""
    <div class="result-box">
        <h3 style="color: #2c3e50; margin-bottom: 10px;">Converted Value</h3>
        <p style="font-size: 24px; color: #4CAF50; font-weight: bold;">{result:.2f} {to_unit}</p>
    </div>
""", unsafe_allow_html=True)
