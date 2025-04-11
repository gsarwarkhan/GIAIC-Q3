import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime, timedelta
import hashlib
from init_db import init_sample_data
import plotly.express as px
import plotly.graph_objects as go
from io import BytesIO
import re
import time
import os

# Custom CSS and JavaScript
def local_css(file_name):
    try:
        file_path = os.path.join(os.path.dirname(__file__), file_name)
        with open(file_path, 'r', encoding='utf-8') as f:
            st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)
    except FileNotFoundError:
        st.error(f"CSS file not found: {file_name}")
    except Exception as e:
        st.error(f"Error loading CSS: {str(e)}")

def local_js(file_name):
    try:
        file_path = os.path.join(os.path.dirname(__file__), file_name)
        with open(file_path, 'r', encoding='utf-8') as f:
            st.markdown(f'<script>{f.read()}</script>', unsafe_allow_html=True)
    except FileNotFoundError:
        st.error(f"JavaScript file not found: {file_name}")
    except Exception as e:
        st.error(f"Error loading JavaScript: {str(e)}")

# Mouse trail effect JavaScript
mouse_js = """
document.addEventListener('mousemove', function(e) {
    const trail = document.createElement('div');
    trail.className = 'mouse-trail';
    trail.style.left = e.pageX + 'px';
    trail.style.top = e.pageY + 'px';
    document.body.appendChild(trail);
    setTimeout(() => {
        trail.remove();
    }, 1000);
});
"""

# Initialize the app with custom styling
st.set_page_config(
    page_title="Task Management System",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply custom CSS
local_css("style.css")

# Add mouse trail effect
st.markdown(f'<script>{mouse_js}</script>', unsafe_allow_html=True)

# Add session timeout configuration
SESSION_TIMEOUT = 1800  # 30 minutes in seconds
LOGIN_ATTEMPTS_LIMIT = 5
LOGIN_ATTEMPTS_WINDOW = 300  # 5 minutes in seconds

# Database initialization
def init_db():
    conn = sqlite3.connect('task_management.db')
    c = conn.cursor()
    
    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE,
                  password TEXT,
                  role TEXT,
                  name TEXT)''')
    
    # Create tasks table
    c.execute('''CREATE TABLE IF NOT EXISTS tasks
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  task_description TEXT,
                  status TEXT,
                  date DATE,
                  category TEXT,
                  priority TEXT,
                  deadline DATE,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    # Create login attempts table
    c.execute('''CREATE TABLE IF NOT EXISTS login_attempts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT,
                  timestamp INTEGER,
                  successful INTEGER)''')
    
    conn.commit()
    conn.close()
    init_sample_data()

def check_login_attempts(username):
    conn = sqlite3.connect('task_management.db')
    c = conn.cursor()
    
    # Get recent failed attempts
    c.execute('''SELECT COUNT(*) FROM login_attempts 
                 WHERE username = ? 
                 AND timestamp > ? 
                 AND successful = 0''',
              (username, int(time.time()) - LOGIN_ATTEMPTS_WINDOW))
    attempts = c.fetchone()[0]
    
    conn.close()
    return attempts < LOGIN_ATTEMPTS_LIMIT

def record_login_attempt(username, successful):
    conn = sqlite3.connect('task_management.db')
    c = conn.cursor()
    
    c.execute('''INSERT INTO login_attempts (username, timestamp, successful)
                 VALUES (?, ?, ?)''',
              (username, int(time.time()), 1 if successful else 0))
    
    conn.commit()
    conn.close()

# User authentication
def authenticate(username, password):
    # Check login attempts
    if not check_login_attempts(username):
        st.error("Too many failed login attempts. Please try again later.")
        return None
    
    conn = sqlite3.connect('task_management.db')
    c = conn.cursor()
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    c.execute('SELECT * FROM users WHERE username = ? AND password = ?',
              (username, hashed_password))
    user = c.fetchone()
    
    if user:
        st.session_state.username = username
        st.session_state.last_activity = time.time()
        record_login_attempt(username, True)
    else:
        record_login_attempt(username, False)
    
    conn.close()
    return user

def validate_password(password):
    """
    Validate password complexity:
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    return True, "Password meets requirements"

# User registration
def register_user(username, password, role, name):
    conn = sqlite3.connect('task_management.db')
    c = conn.cursor()
    
    # Validate username
    if not username or len(username) < 3:
        return False, "Username must be at least 3 characters long"
    
    # Validate name
    if not name or len(name.strip()) < 2:
        return False, "Please enter a valid full name"
    
    # Validate password
    is_valid, message = validate_password(password)
    if not is_valid:
        return False, message
    
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    try:
        c.execute('''INSERT INTO users (username, password, role, name)
                    VALUES (?, ?, ?, ?)''',
                 (username, hashed_password, role, name))
        conn.commit()
        return True, "Registration successful"
    except sqlite3.IntegrityError:
        return False, "Username already exists"
    except Exception as e:
        return False, f"Registration failed: {str(e)}"
    finally:
        conn.close()

# Add new functions for account management
def remove_user(user_id):
    conn = sqlite3.connect('task_management.db')
    c = conn.cursor()
    try:
        # First delete all tasks associated with the user
        c.execute('DELETE FROM tasks WHERE user_id = ?', (user_id,))
        # Then delete the user
        c.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        return True
    except Exception as e:
        st.error(f"Error removing user: {str(e)}")
        return False
    finally:
        conn.close()

def reassign_deputy_secretary(new_deputy_id):
    conn = sqlite3.connect('task_management.db')
    c = conn.cursor()
    try:
        # Get current deputy's ID
        c.execute('SELECT id FROM users WHERE role = "deputy_secretary"')
        current_deputy = c.fetchone()
        
        # Check if trying to reassign to current deputy
        if current_deputy and current_deputy[0] == new_deputy_id:
            return False, "Cannot reassign to the current Deputy Secretary"
            
        # Check if the new deputy exists and is an assistant
        c.execute('SELECT role FROM users WHERE id = ?', (new_deputy_id,))
        user_role = c.fetchone()
        if not user_role or user_role[0] != "assistant_secretary":
            return False, "Selected user must be an Assistant Secretary"
            
        # First remove deputy role from current deputy
        if current_deputy:
            c.execute('UPDATE users SET role = "assistant_secretary" WHERE id = ?', (current_deputy[0],))
        
        # Then assign new deputy
        c.execute('UPDATE users SET role = "deputy_secretary" WHERE id = ?', (new_deputy_id,))
        conn.commit()
        return True, "Deputy Secretary reassigned successfully"
    except Exception as e:
        return False, f"Error reassigning deputy: {str(e)}"
    finally:
        conn.close()

def generate_assistant_report(start_date, end_date):
    conn = sqlite3.connect('task_management.db')
    c = conn.cursor()
    
    # Get all tasks within date range
    c.execute('''SELECT 
                u.name as assistant_name,
                t.date,
                t.task_description,
                t.status,
                COUNT(*) OVER (PARTITION BY u.id) as total_tasks,
                SUM(CASE WHEN t.status = 'Completed' THEN 1 ELSE 0 END) OVER (PARTITION BY u.id) as completed_tasks
                FROM tasks t
                JOIN users u ON t.user_id = u.id
                WHERE u.role = 'assistant_secretary'
                AND t.date BETWEEN ? AND ?
                ORDER BY u.name, t.date''', (start_date, end_date))
    
    tasks = c.fetchall()
    conn.close()
    
    if tasks:
        # Create DataFrame
        df = pd.DataFrame(tasks, columns=['Assistant Name', 'Date', 'Task', 'Status', 'Total Tasks', 'Completed Tasks'])
        
        # Create Excel writer
        output = BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            # Write task details
            df.to_excel(writer, sheet_name='Task Details', index=False)
            
            # Create summary sheet
            summary = df.groupby('Assistant Name').agg({
                'Total Tasks': 'first',
                'Completed Tasks': 'first'
            }).reset_index()
            summary['Completion Rate'] = (summary['Completed Tasks'] / summary['Total Tasks'] * 100).round(2)
            summary.to_excel(writer, sheet_name='Summary', index=False)
        
        output.seek(0)
        return output
    return None

def add_task(user_id, task_description, status="Pending", category="General", priority="Medium", deadline=None):
    conn = sqlite3.connect('task_management.db')
    c = conn.cursor()
    try:
        c.execute('''INSERT INTO tasks (user_id, task_description, status, date, category, priority, deadline)
                    VALUES (?, ?, ?, ?, ?, ?, ?)''',
                 (user_id, task_description, status, datetime.now().date(), category, priority, deadline))
        conn.commit()
        return True
    except Exception as e:
        st.error(f"Error adding task: {str(e)}")
        return False
    finally:
        conn.close()

def get_user_tasks(user_id):
    conn = sqlite3.connect('task_management.db')
    c = conn.cursor()
    c.execute('''SELECT id, task_description, status, date, category, priority, deadline 
                 FROM tasks 
                 WHERE user_id = ? 
                 ORDER BY 
                    CASE priority 
                        WHEN 'High' THEN 1 
                        WHEN 'Medium' THEN 2 
                        WHEN 'Low' THEN 3 
                    END,
                    deadline ASC,
                    date DESC''', (user_id,))
    tasks = c.fetchall()
    conn.close()
    return tasks

def update_task_status(task_id, new_status):
    conn = sqlite3.connect('task_management.db')
    c = conn.cursor()
    try:
        c.execute('''UPDATE tasks 
                    SET status = ? 
                    WHERE id = ?''', (new_status, task_id))
        conn.commit()
        return True
    except Exception as e:
        st.error(f"Error updating task: {str(e)}")
        return False
    finally:
        conn.close()

def update_password(username, new_password):
    conn = sqlite3.connect('task_management.db')
    c = conn.cursor()
    try:
        hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
        c.execute('''UPDATE users 
                    SET password = ? 
                    WHERE username = ?''', (hashed_password, username))
        conn.commit()
        return True
    except Exception as e:
        st.error(f"Error updating password: {str(e)}")
        return False
    finally:
        conn.close()

def verify_user(username, name):
    conn = sqlite3.connect('task_management.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ? AND name = ?',
              (username, name))
    user = c.fetchone()
    conn.close()
    return user is not None

def check_session_timeout():
    if 'last_activity' in st.session_state:
        if time.time() - st.session_state.last_activity > SESSION_TIMEOUT:
            st.session_state.authenticated = False
            st.session_state.user_role = None
            st.session_state.user_id = None
            st.session_state.username = None
            st.warning("Your session has expired. Please login again.")
            st.rerun()
    st.session_state.last_activity = time.time()

# Main application
def main():
    # Add floating animation to the title
    st.markdown('<div class="float">', unsafe_allow_html=True)
    st.title("Task Management System")
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Initialize session state
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'user_role' not in st.session_state:
        st.session_state.user_role = None
    if 'user_id' not in st.session_state:
        st.session_state.user_id = None
    if 'show_signup' not in st.session_state:
        st.session_state.show_signup = False
    if 'show_forgot_password' not in st.session_state:
        st.session_state.show_forgot_password = False
    if 'username' not in st.session_state:
        st.session_state.username = None
    if 'verified_user' not in st.session_state:
        st.session_state.verified_user = None
    if 'last_activity' not in st.session_state:
        st.session_state.last_activity = time.time()
    
    # Check session timeout
    if st.session_state.authenticated:
        check_session_timeout()
    
    # Login/Signup form with glow effect
    if not st.session_state.authenticated:
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown('<div class="glow-border">', unsafe_allow_html=True)
            st.subheader("Login")
            username = st.text_input("Username", key="login_username")
            password = st.text_input("Password", type="password", key="login_password")
            
            if st.button("Login", key="login_button"):
                user = authenticate(username, password)
                if user:
                    st.session_state.authenticated = True
                    st.session_state.user_role = user[3]
                    st.session_state.user_id = user[0]
                    st.session_state.username = username  # Store username in session state
                    st.success("Login successful!")
                    st.rerun()
                else:
                    st.error("Invalid credentials")
            
            # Add Forgot Password button
            if st.button("Forgot Password?", key="forgot_password"):
                st.session_state.show_forgot_password = True
                st.rerun()
            st.markdown('</div>', unsafe_allow_html=True)
        
        with col2:
            st.markdown('<div class="glow-border">', unsafe_allow_html=True)
            st.subheader("Sign Up")
            new_username = st.text_input("Username", key="signup_username")
            new_password = st.text_input("Password", type="password", key="signup_password")
            confirm_password = st.text_input("Confirm Password", type="password", key="confirm_password")
            new_name = st.text_input("Full Name", key="signup_name")
            new_role = st.selectbox("Role", ["Assistant Secretary", "Deputy Secretary"], key="signup_role")
            
            if st.button("Sign Up", key="signup_button"):
                if new_password != confirm_password:
                    st.error("Passwords do not match!")
                elif not new_username or not new_password or not new_name:
                    st.error("Please fill in all fields!")
                else:
                    success, message = register_user(new_username, new_password, new_role, new_name)
                    if success:
                        st.success(message + " Please login.")
                    else:
                        st.error(message)
            st.markdown('</div>', unsafe_allow_html=True)
    
    # Main application after login
    else:
        st.sidebar.title(f"Welcome, {st.session_state.user_role}")
        
        # Add Change Password option in sidebar
        with st.sidebar.expander("Change Password"):
            current_password = st.text_input("Current Password", type="password", key="current_password")
            new_password = st.text_input("New Password", type="password", key="new_password_sidebar")
            confirm_password = st.text_input("Confirm New Password", type="password", key="confirm_password_sidebar")
            
            if st.button("Update Password", key="update_password_sidebar"):
                if not current_password or not new_password or not confirm_password:
                    st.error("Please fill in all fields!")
                elif new_password != confirm_password:
                    st.error("New passwords do not match!")
                else:
                    # Verify current password
                    user = authenticate(st.session_state.username, current_password)
                    if user:
                        if update_password(st.session_state.username, new_password):
                            st.success("Password updated successfully!")
                            st.session_state.authenticated = False
                            st.session_state.user_role = None
                            st.session_state.user_id = None
                            st.session_state.username = None
                            st.rerun()
                        else:
                            st.error("Failed to update password. Please try again.")
                    else:
                        st.error("Current password is incorrect!")
        
        if st.sidebar.button("Logout"):
            st.session_state.authenticated = False
            st.session_state.user_role = None
            st.session_state.user_id = None
            st.session_state.username = None
            st.rerun()
        
        # Forgot Password Section (for non-authenticated users)
        if st.session_state.show_forgot_password:
            st.markdown('<div class="glow-border">', unsafe_allow_html=True)
            st.subheader("Reset Password")
            
            reset_username = st.text_input("Enter your Username", key="reset_username")
            reset_name = st.text_input("Enter your Full Name", key="reset_name")
            
            if st.button("Verify Identity", key="verify_button"):
                if verify_user(reset_username, reset_name):
                    st.session_state.verified_user = reset_username
                    st.success("Identity verified! Please set your new password.")
                else:
                    st.error("Invalid username or name. Please try again.")
            
            if st.session_state.verified_user:
                new_password = st.text_input("New Password", type="password", key="new_password")
                confirm_new_password = st.text_input("Confirm New Password", type="password", key="confirm_new_password")
                
                if st.button("Reset Password", key="reset_button"):
                    if new_password != confirm_new_password:
                        st.error("Passwords do not match!")
                    elif not new_password:
                        st.error("Please enter a new password!")
                    else:
                        if update_password(st.session_state.verified_user, new_password):
                            st.success("Password reset successful! Please login with your new password.")
                            st.session_state.show_forgot_password = False
                            st.session_state.verified_user = None
                            st.rerun()
                        else:
                            st.error("Failed to reset password. Please try again.")
            
            if st.button("Back to Login", key="back_to_login"):
                st.session_state.show_forgot_password = False
                st.session_state.verified_user = None
                st.rerun()
            
            st.markdown('</div>', unsafe_allow_html=True)
            return

        # Deputy Secretary View
        if st.session_state.user_role == "Deputy Secretary":
            st.header("Admin Dashboard")
            
            # Admin Tabs
            tab1, tab2, tab3, tab4 = st.tabs(["Performance Overview", "Assistant Management", "Reports", "Account Management"])
            
            with tab1:
                st.subheader("Performance Overview")
                
                # Date range selector
                col1, col2 = st.columns(2)
                with col1:
                    start_date = st.date_input("Start Date", datetime.now() - timedelta(days=30))
                with col2:
                    end_date = st.date_input("End Date", datetime.now())
                
                # Overall KPIs
                st.subheader("Overall Performance Metrics")
                kpi_col1, kpi_col2, kpi_col3, kpi_col4 = st.columns(4)
                
                # Calculate overall metrics
                conn = sqlite3.connect('task_management.db')
                c = conn.cursor()
                c.execute('''SELECT 
                            COUNT(*) as total_tasks,
                            SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) as completed_tasks,
                            COUNT(DISTINCT user_id) as active_assistants,
                            AVG(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) * 100 as completion_rate
                            FROM tasks
                            WHERE date BETWEEN ? AND ?''', (start_date, end_date))
                overall_metrics = c.fetchone()
                
                # Convert None values to 0
                total_tasks = overall_metrics[0] or 0
                completed_tasks = overall_metrics[1] or 0
                active_assistants = overall_metrics[2] or 0
                completion_rate = overall_metrics[3] or 0
                
                with kpi_col1:
                    st.metric("Total Tasks", total_tasks)
                with kpi_col2:
                    st.metric("Completed Tasks", completed_tasks)
                with kpi_col3:
                    st.metric("Active Assistants", active_assistants)
                with kpi_col4:
                    st.metric("Completion Rate", f"{completion_rate:.1f}%")
                
                # Performance Charts
                st.subheader("Performance Analysis")
                
                # Get all tasks data
                c.execute('''SELECT t.date, t.status, u.name as assistant_name
                           FROM tasks t
                           JOIN users u ON t.user_id = u.id
                           WHERE t.date BETWEEN ? AND ?
                           ORDER BY t.date''', (start_date, end_date))
                all_tasks = c.fetchall()
                
                if all_tasks:
                    df_all = pd.DataFrame(all_tasks, columns=['Date', 'Status', 'Assistant'])
                    
                    # Task Completion Trend by Assistant
                    # Reshape the data for plotting
                    trend_data = df_all.groupby(['Date', 'Assistant', 'Status']).size().reset_index(name='Count')
                    fig_trend = px.line(trend_data, 
                                      x='Date', 
                                      y='Count', 
                                      color='Assistant',
                                      line_group='Status',
                                      title="Task Completion Trend by Assistant",
                                      labels={'Count': 'Number of Tasks', 'Date': 'Date'})
                    st.plotly_chart(fig_trend, use_container_width=True)
                    
                    # Task Distribution by Assistant
                    dist_data = df_all.groupby(['Assistant', 'Status']).size().reset_index(name='Count')
                    fig_dist = px.bar(dist_data,
                                    x='Assistant',
                                    y='Count',
                                    color='Status',
                                    title="Task Distribution by Assistant",
                                    labels={'Count': 'Number of Tasks'})
                    st.plotly_chart(fig_dist, use_container_width=True)
                
                conn.close()
            
            with tab2:
                st.subheader("Assistant Management")
                
                # Get all assistant secretaries
                conn = sqlite3.connect('task_management.db')
                c = conn.cursor()
                c.execute('SELECT id, name, username FROM users WHERE role = "Assistant Secretary"')
                assistants = c.fetchall()
                
                # Display assistants table
                if assistants:
                    df_assistants = pd.DataFrame(assistants, columns=['ID', 'Name', 'Username'])
                    st.dataframe(df_assistants)
                    
                    # Assistant selection for detailed view
                    selected_assistant = st.selectbox(
                        "Select Assistant for Detailed View",
                        [f"{a[1]} (ID: {a[0]})" for a in assistants]
                    )
                    
                    if selected_assistant:
                        assistant_id = int(selected_assistant.split("(ID: ")[1].rstrip(")"))
                        
                        # Get tasks for selected assistant
                        c.execute('''SELECT date, task_description, status 
                                   FROM tasks 
                                   WHERE user_id = ? AND date BETWEEN ? AND ?
                                   ORDER BY date DESC''', (assistant_id, start_date, end_date))
                        tasks = c.fetchall()
                        
                        if tasks:
                            df = pd.DataFrame(tasks, columns=['Date', 'Task', 'Status'])
                            st.dataframe(df)
                        else:
                            st.info("No tasks found for this assistant secretary")
                else:
                    st.info("No assistant secretaries found")
                
                conn.close()
            
            with tab3:
                st.subheader("Reports")
                
                # Date range selector for reports
                col1, col2 = st.columns(2)
                with col1:
                    report_start_date = st.date_input("Report Start Date", datetime.now() - timedelta(days=30))
                with col2:
                    report_end_date = st.date_input("Report End Date", datetime.now())
                
                if st.button("Generate and Download Report"):
                    report = generate_assistant_report(report_start_date, report_end_date)
                    if report:
                        st.download_button(
                            label="Download Excel Report",
                            data=report,
                            file_name=f"assistant_report_{report_start_date}_{report_end_date}.xlsx",
                            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                        )
                    else:
                        st.warning("No data found for the selected date range")
            
            with tab4:
                st.subheader("Account Management")
                
                # Get all assistant secretaries
                conn = sqlite3.connect('task_management.db')
                c = conn.cursor()
                c.execute('SELECT id, name, username FROM users WHERE role = "Assistant Secretary"')
                assistants = c.fetchall()
                
                if assistants:
                    # Display assistants table with remove option
                    df_assistants = pd.DataFrame(assistants, columns=['ID', 'Name', 'Username'])
                    st.dataframe(df_assistants)
                    
                    # Remove assistant section
                    st.subheader("Remove Assistant")
                    assistant_to_remove = st.selectbox(
                        "Select Assistant to Remove",
                        [f"{a[1]} (ID: {a[0]})" for a in assistants]
                    )
                    
                    if st.button("Remove Assistant"):
                        assistant_id = int(assistant_to_remove.split("(ID: ")[1].rstrip(")"))
                        if remove_user(assistant_id):
                            st.success("Assistant removed successfully!")
                            st.rerun()
                    
                    # Reassign Deputy Secretary section
                    st.subheader("Reassign Deputy Secretary")
                    
                    # Get current deputy
                    c.execute('SELECT id, name FROM users WHERE role = "deputy_secretary"')
                    current_deputy = c.fetchone()
                    if current_deputy:
                        st.info(f"Current Deputy Secretary: {current_deputy[1]}")
                    
                    new_deputy = st.selectbox(
                        "Select New Deputy Secretary",
                        [f"{a[1]} (ID: {a[0]})" for a in assistants]
                    )
                    
                    if st.button("Reassign Deputy Secretary"):
                        new_deputy_id = int(new_deputy.split("(ID: ")[1].rstrip(")"))
                        
                        # Show confirmation dialog
                        if st.warning("Are you sure you want to reassign the Deputy Secretary role? This action cannot be undone."):
                            success, message = reassign_deputy_secretary(new_deputy_id)
                            if success:
                                st.success(message)
                                st.rerun()
                            else:
                                st.error(message)
                else:
                    st.info("No assistant secretaries found")
                
                conn.close()
        
        # Assistant Secretary View
        elif st.session_state.user_role == "Assistant Secretary":
            st.header("Assistant Dashboard")
            
            # Daily Work Report Section
            st.subheader("Daily Work Report")
            with st.form("daily_report_form"):
                task_description = st.text_area("Task Description", 
                                              placeholder="Enter your task details here...")
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    task_category = st.selectbox("Category", 
                                               ["General", "Administrative", "Technical", "Meeting", "Report"])
                with col2:
                    task_priority = st.selectbox("Priority", 
                                               ["High", "Medium", "Low"])
                with col3:
                    task_deadline = st.date_input("Deadline", 
                                                min_value=datetime.now().date())
                
                task_status = st.selectbox("Task Status", 
                                         ["Pending", "In Progress", "Completed"])
                
                submitted = st.form_submit_button("Submit Task")
                
                if submitted and task_description:
                    if add_task(st.session_state.user_id, task_description, task_status, 
                              task_category, task_priority, task_deadline):
                        st.success("Task added successfully!")
                    else:
                        st.error("Failed to add task. Please try again.")
            
            # View and Manage Tasks
            st.subheader("My Tasks")
            tasks = get_user_tasks(st.session_state.user_id)
            
            if tasks:
                # Create a DataFrame for better display
                df = pd.DataFrame(tasks, columns=['ID', 'Task', 'Status', 'Date', 'Category', 'Priority', 'Deadline'])
                
                # Add status update functionality
                for index, row in df.iterrows():
                    with st.expander(f"Task: {row['Task']}"):
                        col1, col2 = st.columns(2)
                        with col1:
                            st.write(f"**Category:** {row['Category']}")
                            st.write(f"**Priority:** {row['Priority']}")
                            st.write(f"**Deadline:** {row['Deadline']}")
                        with col2:
                            st.write(f"**Date Created:** {row['Date']}")
                            st.write(f"**Current Status:** {row['Status']}")
                            new_status = st.selectbox(
                                "Update Status",
                                ["Pending", "In Progress", "Completed"],
                                index=["Pending", "In Progress", "Completed"].index(row['Status']),
                                key=f"status_{row['ID']}"
                            )
                            if new_status != row['Status']:
                                if update_task_status(row['ID'], new_status):
                                    st.success("Status updated!")
                                    st.rerun()
                
                # Display tasks in a table
                st.dataframe(df[['Task', 'Status', 'Date', 'Category', 'Priority', 'Deadline']])
            else:
                st.info("No tasks found. Add your first task using the form above.")
            
            # Performance Overview
            st.subheader("Performance Overview")
            if tasks:
                # Calculate completion rate
                total_tasks = len(tasks)
                completed_tasks = sum(1 for task in tasks if task[2] == "Completed")
                completion_rate = (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0
                
                # Display metrics
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Total Tasks", total_tasks)
                with col2:
                    st.metric("Completion Rate", f"{completion_rate:.1f}%")
                
                # Task status distribution
                status_counts = pd.DataFrame(tasks, columns=['ID', 'Task', 'Status', 'Date'])['Status'].value_counts()
                fig = px.pie(values=status_counts.values, 
                           names=status_counts.index,
                           title="Task Status Distribution")
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No performance data available yet. Start by adding tasks.")

if __name__ == "__main__":
    init_db()
    main()
