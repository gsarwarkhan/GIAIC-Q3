import streamlit as st
import sqlite3
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import hashlib
from PIL import Image

# Database setup
conn = sqlite3.connect("spiritual_tracker.db", check_same_thread=False)
cursor = conn.cursor()

# Create users table
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        is_admin BOOLEAN DEFAULT 0
    )
''')

# Check if activities table exists and has the correct structure
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='activities'")
if cursor.fetchone():
    # Check if salah_completed column exists
    cursor.execute("PRAGMA table_info(activities)")
    columns = [column[1] for column in cursor.fetchall()]
    if 'salah_completed' not in columns:
        # Create temporary table with new structure
        cursor.execute('''
            CREATE TABLE activities_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                salah_completed BOOLEAN DEFAULT 0,
                al_asaas_count INTEGER DEFAULT 0,
                marboota_shareef_count INTEGER DEFAULT 0,
                fatiha_count INTEGER DEFAULT 0,
                zikr_mufrith_count INTEGER DEFAULT 0,
                notes TEXT,
                date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # Copy data from old table to new table
        cursor.execute('''
            INSERT INTO activities_new (username, al_asaas_count, marboota_shareef_count, 
                                      fatiha_count, zikr_mufrith_count, notes, date)
            SELECT username, al_asaas_count, marboota_shareef_count, 
                   fatiha_count, zikr_mufrith_count, notes, date
            FROM activities
        ''')
        # Drop old table and rename new table
        cursor.execute("DROP TABLE activities")
        cursor.execute("ALTER TABLE activities_new RENAME TO activities")
else:
    # Create activities table if it doesn't exist
    cursor.execute('''
        CREATE TABLE activities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            salah_completed BOOLEAN DEFAULT 0,
            al_asaas_count INTEGER DEFAULT 0,
            marboota_shareef_count INTEGER DEFAULT 0,
            fatiha_count INTEGER DEFAULT 0,
            zikr_mufrith_count INTEGER DEFAULT 0,
            notes TEXT,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

# Insert default admin user if not exists
cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
if cursor.fetchone()[0] == 0:
    hashed_password = hashlib.sha256('admin123'.encode()).hexdigest()
    cursor.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", 
                  ('admin', hashed_password, 1))
    conn.commit()

# Function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to verify password
def verify_password(password, hashed_password):
    return hash_password(password) == hashed_password

# Load and display logo
logo = Image.open('Al Burhaniya/logo.png')
st.image(logo, width=200)

# Sidebar login/signup
st.sidebar.title("Authentication")

# If logged in, show logout button
if "logged_in" in st.session_state and st.session_state["logged_in"]:
    if st.sidebar.button("Logout"):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.experimental_rerun()
    st.sidebar.write(f"Logged in as: {st.session_state['username']}")
else:
    # Toggle between login and signup
    auth_type = st.sidebar.radio("Choose", ["Login", "Sign Up"])

    if auth_type == "Sign Up":
        st.sidebar.subheader("Create New Account")
        new_username = st.sidebar.text_input("Choose Username")
        new_password = st.sidebar.text_input("Choose Password", type="password")
        confirm_password = st.sidebar.text_input("Confirm Password", type="password")
        
        if st.sidebar.button("Sign Up"):
            if new_password != confirm_password:
                st.sidebar.error("Passwords do not match!")
            else:
                try:
                    hashed_password = hash_password(new_password)
                    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                                 (new_username, hashed_password))
                    conn.commit()
                    st.sidebar.success("Account created successfully! Please log in.")
                except sqlite3.IntegrityError:
                    st.sidebar.error("Username already exists!")
    else:
        st.sidebar.subheader("Login")
        username = st.sidebar.text_input("Username")
        password = st.sidebar.text_input("Password", type="password")
        login_button = st.sidebar.button("Login")

        if login_button:
            cursor.execute("SELECT password, is_admin FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            
            if result and verify_password(password, result[0]):
                st.sidebar.success(f"Welcome, {username}!")
                st.session_state["logged_in"] = True
                st.session_state["username"] = username
                st.session_state["is_admin"] = bool(result[1])
            else:
                st.sidebar.error("Invalid username or password.")

# If logged in
if "logged_in" in st.session_state and st.session_state["logged_in"]:
    st.title("📿 Daily Spiritual Activity Tracker")

    if not st.session_state.get("is_admin", False):  # Normal User Dashboard
        st.subheader("Log Your Spiritual Activity")
        
        # Primary Activity - Salah Prayer
        st.markdown("### 🕌 Primary Activity")
        salah_completed = st.radio("Did you complete all Salah prayers today?", ["Yes", "No"])
        
        # Other Spiritual Activities
        st.markdown("### 📿 Other Spiritual Activities")
        col1, col2 = st.columns(2)
        
        with col1:
            al_asaas_count = st.number_input("Al-Asaas Count", min_value=0, step=1)
            marboota_shareef_count = st.number_input("Marboota Shareef Count", min_value=0, step=1)
        
        with col2:
            fatiha_count = st.number_input("Fatiha Count", min_value=0, step=1)
            zikr_mufrith_count = st.number_input("Zikr e Mufrith Count", min_value=0, step=1)
        
        notes = st.text_area("Additional Notes")

        if st.button("Submit"):
            cursor.execute('''
                INSERT INTO activities (username, salah_completed, al_asaas_count, marboota_shareef_count, 
                                      fatiha_count, zikr_mufrith_count, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (st.session_state["username"], salah_completed == "Yes", al_asaas_count, marboota_shareef_count, 
                 fatiha_count, zikr_mufrith_count, notes))
            conn.commit()
            st.success("Your activity has been logged!")

        # Show user's own activity
        st.subheader("📊 Your Activity History")
        df_user = pd.read_sql_query(f"SELECT * FROM activities WHERE username='{st.session_state['username']}'", conn)
        st.dataframe(df_user)

    else:  # Admin Panel
        st.subheader("📊 Admin Dashboard - All Users Activity")
        
        # Admin Password Change Section
        st.subheader("🔐 Change Admin Password")
        current_password = st.text_input("Current Password", type="password")
        new_password = st.text_input("New Password", type="password")
        confirm_new_password = st.text_input("Confirm New Password", type="password")
        
        if st.button("Change Password"):
            # Verify current password
            cursor.execute("SELECT password FROM users WHERE username = 'admin'")
            current_hashed_password = cursor.fetchone()[0]
            
            if not verify_password(current_password, current_hashed_password):
                st.error("Current password is incorrect!")
            elif new_password != confirm_new_password:
                st.error("New passwords do not match!")
            else:
                new_hashed_password = hash_password(new_password)
                cursor.execute("UPDATE users SET password = ? WHERE username = 'admin'", (new_hashed_password,))
                conn.commit()
                st.success("Password changed successfully!")
        
        # Activity Dashboard
        st.subheader("📊 All Users Activity")
        df = pd.read_sql_query("SELECT * FROM activities", conn)
        st.dataframe(df)

        # Visualization
        st.subheader("📈 Activity Analysis")
        
        # Salah Prayer Completion Rate
        st.markdown("### 🕌 Salah Prayer Completion Rate")
        if not df.empty:
            fig, ax = plt.subplots(figsize=(10, 5))
            salah_completion = df.groupby('username')['salah_completed'].mean() * 100
            sns.barplot(x=salah_completion.index, y=salah_completion.values, ax=ax)
            plt.xticks(rotation=45)
            plt.title("Salah Prayer Completion Rate by User (%)")
            plt.ylim(0, 100)
            st.pyplot(fig)
        else:
            st.info("No activity data available yet.")
        
        # Other Activities
        st.markdown("### 📿 Other Activities")
        activities = ['al_asaas_count', 'marboota_shareef_count', 'fatiha_count', 'zikr_mufrith_count']
        activity_names = ['Al-Asaas', 'Marboota Shareef', 'Fatiha', 'Zikr e Mufrith']
        
        if not df.empty:
            for activity, name in zip(activities, activity_names):
                fig, ax = plt.subplots(figsize=(10, 5))
                sns.barplot(x=df["username"], y=df[activity], ax=ax)
                plt.xticks(rotation=45)
                plt.title(f"{name} Count by User")
                st.pyplot(fig)
        else:
            st.info("No activity data available yet.")

else:
    st.warning("Please log in to continue.")
