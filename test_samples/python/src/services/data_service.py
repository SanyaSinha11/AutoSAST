import sqlite3
from security.validators import sanitize_sql_input, is_safe_identifier


class DataService:
    def __init__(self, db_path):
        self.db_path = db_path
    
    def get_connection(self):
        return sqlite3.connect(self.db_path)
    
    def search_records(self, table, column, value):
        if not is_safe_identifier(table):
            raise ValueError("Invalid table name")
        if not is_safe_identifier(column):
            raise ValueError("Invalid column name")
        
        safe_value = sanitize_sql_input(value)
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        query = f"SELECT * FROM {table} WHERE {column} = ?"
        cursor.execute(query, (safe_value,))
        
        results = cursor.fetchall()
        conn.close()
        return results
    
    def search_with_like(self, table, column, pattern):
        if not is_safe_identifier(table):
            raise ValueError("Invalid table name")
        if not is_safe_identifier(column):
            raise ValueError("Invalid column name")
        
        safe_pattern = sanitize_sql_input(pattern)
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        query = f"SELECT * FROM {table} WHERE {column} LIKE ?"
        cursor.execute(query, (f'%{safe_pattern}%',))
        
        results = cursor.fetchall()
        conn.close()
        return results
    
    def get_by_id(self, table, record_id):
        if not is_safe_identifier(table):
            raise ValueError("Invalid table name")
        
        safe_id = sanitize_sql_input(record_id)
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        query = f"SELECT * FROM {table} WHERE id = ?"
        cursor.execute(query, (safe_id,))
        
        result = cursor.fetchone()
        conn.close()
        return result

