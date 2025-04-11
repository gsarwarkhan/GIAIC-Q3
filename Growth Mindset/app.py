import streamlit as st
import random

# Configure page
st.set_page_config(page_title="Growth Mindset Quiz", layout="centered")

# Title and description
st.title("🌱 Growth Mindset Quiz")
st.write("Test your mindset and learn how to improve it! 🚀")

# Questions and answers
questions = [
    {
        "question": "What is a growth mindset?",
        "options": ["Believing intelligence is fixed", "Learning and growing through effort"],
        "answer": "Learning and growing through effort"
    },
    {
        "question": "How should you react to failure?",
        "options": ["Give up", "Learn from mistakes and try again"],
        "answer": "Learn from mistakes and try again"
    },
    {
        "question": "Which is a growth mindset statement?",
        "options": ["I'm either good or bad at something", "I can improve with practice"],
        "answer": "I can improve with practice"
    },
    {
        "question": "How can you develop a growth mindset?",
        "options": ["Avoid challenges", "Keep learning new things"],
        "answer": "Keep learning new things"
    },
    {
        "question": "What should you say when facing a tough task?",
        "options": ["I'll never be able to do this", "I can learn this step by step"],
        "answer": "I can learn this step by step"
    }
]

# Shuffle questions once
if "shuffled_questions" not in st.session_state:
    st.session_state.shuffled_questions = random.sample(questions, len(questions))
    st.session_state.current_question = 0
    st.session_state.score = 0

# Get current question
current_q_index = st.session_state.current_question
if current_q_index < len(st.session_state.shuffled_questions):
    question_data = st.session_state.shuffled_questions[current_q_index]

    # Display question
    st.subheader(f"Q{current_q_index + 1}: {question_data['question']}")

    # Show answer choices
    user_answer = st.radio(
        "Choose an answer:", 
        question_data["options"], 
        key=f"q{current_q_index}"
    )

    # Submit button
    if st.button("Submit & Next"):
        if user_answer == question_data["answer"]:
            st.success("✅ Correct!")
            st.session_state.score += 1
        else:
            st.error(f"❌ Incorrect! The right answer is: {question_data['answer']}")

        # Move to next question
        st.session_state.current_question += 1
        st.rerun()

# Show final score
else:
    st.subheader(f"🎯 Your Final Score: {st.session_state.score} / {len(questions)}")
    if st.session_state.score == len(questions):
        st.success("🌟 Excellent! You have a strong growth mindset!")
    elif st.session_state.score >= len(questions) // 2:
        st.info("💡 Good job! Keep learning and improving.")
    else:
        st.warning("🚀 Keep practicing! Growth takes time.")

    # Reset button
    if st.button("Restart Quiz"):
        st.session_state.shuffled_questions = random.sample(questions, len(questions))
        st.session_state.current_question = 0
        st.session_state.score = 0
        st.rerun()
