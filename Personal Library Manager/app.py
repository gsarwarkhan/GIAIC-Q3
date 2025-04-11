import streamlit as st
import sqlite3
import pandas as pd

# Initialize Database
conn = sqlite3.connect("library.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS books (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    author TEXT,
    year INTEGER
)
""")
conn.commit()

# Streamlit UI
st.title("📚 Personal Library Manager")
st.subheader("Track and manage your book collection!")

# 📖 **Add a New Book**
st.sidebar.header("➕ Add New Book")
title = st.sidebar.text_input("Book Title")
author = st.sidebar.text_input("Author")
year = st.sidebar.number_input("Publication Year", min_value=1000, max_value=2050, step=1)

if st.sidebar.button("Add Book"):
    if title and author and year:
        cursor.execute("INSERT INTO books (title, author, year) VALUES (?, ?, ?)", (title, author, year))
        conn.commit()
        st.sidebar.success(f"📖 '{title}' added successfully!")
    else:
        st.sidebar.error("⚠️ Please fill in all fields!")

# 📋 **View Books**
st.subheader("📜 Your Library")
books = pd.read_sql_query("SELECT * FROM books", conn)

if not books.empty:
    st.dataframe(books)
else:
    st.info("No books found! Start adding books from the sidebar.")

# ❌ **Delete a Book**
st.subheader("🗑 Remove a Book")
book_id = st.number_input("Enter Book ID to Delete", min_value=1, step=1)
if st.button("Delete Book"):
    cursor.execute("DELETE FROM books WHERE id=?", (book_id,))
    conn.commit()
    st.success("Book deleted successfully!")

# Close DB Connection
conn.close()
