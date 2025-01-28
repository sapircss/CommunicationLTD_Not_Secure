import sqlite3
from prettytable import PrettyTable

class Database:
    # Define columns for the `employees` table
    EMPLOYEES_COLUMNS = {
        'id': 'INTEGER PRIMARY KEY UNIQUE',
        'first_name': 'TEXT NOT NULL',
        'last_name': 'TEXT NOT NULL',
        'password': 'TEXT NOT NULL',
        'email': 'TEXT NOT NULL UNIQUE',
    }

    # Define columns for the `clients` table
    CLIENTS_COLUMNS = {
        'id': 'INTEGER PRIMARY KEY UNIQUE',
        'first_name': 'TEXT NOT NULL',
        'last_name': 'TEXT NOT NULL',
    }

    def __init__(self, db_name='company.db'):
        # Allow multiple SQL statements by setting isolation_level=None
        self.db_name = db_name
        self.conn = sqlite3.connect(self.db_name, isolation_level=None)
        self.cursor = self.conn.cursor()
        print("Database Connection established")

    def _execute_query(self, query):
        # Allow execution of multiple SQL statements using executescript
        try:
            print(f"Executing query:\n{query}")  # Log the query being executed
            self.cursor.executescript(query)  # Use executescript for multiple commands
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            raise

    def create_table(self, table_name):
        # Create a table with dynamically constructed SQL. Vulnerable to SQL Injection.
        query = f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            id INTEGER PRIMARY KEY UNIQUE,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            password TEXT,
            email TEXT UNIQUE
        )
        """
        self._execute_query(query)

    def insert_user_to_table(self, table_name, user_data):
        # Insert user data into the specified table. Vulnerable to SQL Injection.
        columns = ', '.join(user_data.keys())
        values = ', '.join([f"'{v}'" for v in user_data.values()])  # Directly inserts user input
        query = f"INSERT INTO {table_name} ({columns}) VALUES ({values})"
        print(f"Inserting into {table_name}:\n{query}")  # Log query for debugging
        self._execute_query(query)

    def fetch_users(self, table_name):
        # Fetch all users from the specified table. Vulnerable to SQL Injection.
        query = f"SELECT * FROM {table_name}"
        print(f"Fetching users with query: {query}")  # Log query for debugging
        self.cursor.execute(query)
        return self.cursor.fetchall()

    def validate_user_login(self, email, password):
        # Validate user login by checking email and password. Vulnerable to SQL Injection.
        query = f"SELECT * FROM employees WHERE email = '{email}' AND password = '{password}'"
        print(f"Validating login with query: {query}")  # Log query for debugging
        self.cursor.execute(query)
        result = self.cursor.fetchone()

        # Detect SQL Injection
        if "' OR" in email or "--" in email:
            print("Hacked SQL Injection detected in login validation!")

        return bool(result)

    def print_table(self, table_name):
        # Print the contents of the specified table. Vulnerable to SQL Injection.
        query = f"SELECT * FROM {table_name}"
        print(f"Printing table with query: {query}")  # Log query for debugging
        self.cursor.execute(query)
        rows = self.cursor.fetchall()
        if rows:
            # Fetch table column names for printing
            self.cursor.execute(f"PRAGMA table_info('{table_name}')")
            columns_name = [info[1] for info in self.cursor.fetchall()]
            table = PrettyTable()
            table.field_names = columns_name
            for row in rows:
                table.add_row(row)
            print(table)
        else:
            print(f"Table '{table_name}' is empty.")

    def change_password(self, email, old_password, new_password):
        # Change the password for a user. Vulnerable to SQL Injection.
        old_hashed = old_password  # In a secure version, this would hash the password
        new_hashed = new_password  # In a secure version, this would hash the password

        query = f"""
        UPDATE employees
        SET password = '{new_hashed}'
        WHERE email = '{email}' AND password = '{old_hashed}'
        """
        print(f"Changing password with query: {query}")  # Log query for debugging
        self._execute_query(query)
        return True

    def delete_user(self, table_name, user_id):
        # Delete a user by ID. Vulnerable to SQL Injection.
        query = f"DELETE FROM {table_name} WHERE id = {user_id}"
        print(f"Deleting user with query: {query}")  # Log query for debugging
        self._execute_query(query)

    def update_user(self, table_name, user_id, update_data):
        # Update a user's data. Vulnerable to SQL Injection.
        set_clause = ', '.join([f"{key} = '{value}'" for key, value in update_data.items()])
        query = f"UPDATE {table_name} SET {set_clause} WHERE id = {user_id}"
        print(f"Updating user with query: {query}")  # Log query for debugging
        self._execute_query(query)

    def close(self):
        # Close the database connection
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()
        print("Database connection closed.")
