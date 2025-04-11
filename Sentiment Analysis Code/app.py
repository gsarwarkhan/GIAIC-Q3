import streamlit as st
from textblob import TextBlob

# Streamlit UI
st.title("📊 Text Sentiment Analysis")
st.subheader("Analyze the sentiment of your text in seconds!")

# User input
user_text = st.text_area("Enter your text below:")

if st.button("Analyze Sentiment"):
    if user_text:
        # Perform Sentiment Analysis
        blob = TextBlob(user_text)
        sentiment_score = blob.sentiment.polarity  # Ranges from -1 to 1

        # Determine sentiment category
        if sentiment_score > 0:
            sentiment = "😊 Positive"
            color = "green"
        elif sentiment_score < 0:
            sentiment = "😠 Negative"
            color = "red"
        else:
            sentiment = "😐 Neutral"
            color = "gray"

        # Display results
        st.markdown(f"<h3 style='color:{color};'>{sentiment}</h3>", unsafe_allow_html=True)
        st.write(f"**Sentiment Score:** {sentiment_score:.2f}")

    else:
        st.warning("Please enter some text to analyze!")

