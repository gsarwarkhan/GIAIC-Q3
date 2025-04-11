import sqlite3
import hashlib

def init_sample_data():
    conn = sqlite3.connect('task_management.db')
    c = conn.cursor()
    
    # Create sample users
    users = [
        ("deputy1", "deputy123", "deputy_secretary", "John Smith"),
        ("assistant1", "assistant123", "assistant_secretary", "Alice Johnson"),
        ("assistant2", "assistant123", "assistant_secretary", "Bob Wilson")
    ]
    
    for username, password, role, name in users:
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        try:
            c.execute('''INSERT INTO users (username, password, role, name)
                        VALUES (?, ?, ?, ?)''',
                     (username, hashed_password, role, name))
        except sqlite3.IntegrityError:
            print(f"User {username} already exists")
    
    conn.commit()
    conn.close()
    print("Sample data initialized successfully!")

if __name__ == "__main__":
    init_sample_data() 