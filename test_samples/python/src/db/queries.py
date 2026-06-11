"""Database query utilities."""
import sqlite3
from typing import List, Dict, Any

ALLOWED_TABLES = {'users', 'orders', 'products'}
ALLOWED_COLUMNS = {'id', 'name', 'created_at', 'status'}


def search_records(conn: sqlite3.Connection, table: str, field: str, value: str) -> List[Dict]:
    query = f"SELECT * FROM {table} WHERE {field} = '{value}'"
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()


def search_allowed(conn: sqlite3.Connection, table_key: str, field_key: str, value: str) -> List[Dict]:
    if table_key not in ALLOWED_TABLES:
        raise ValueError("Invalid table")
    if field_key not in ALLOWED_COLUMNS:
        raise ValueError("Invalid column")
    
    query = f"SELECT * FROM {table_key} WHERE {field_key} = ?"
    cursor = conn.cursor()
    cursor.execute(query, (value,))
    return cursor.fetchall()


def build_query(filters: Dict[str, str]) -> str:
    conditions = []
    for key, val in filters.items():
        conditions.append(f"{key} = '{val}'")
    return "SELECT * FROM data WHERE " + " AND ".join(conditions)


def build_query_param(filters: Dict[str, str]) -> tuple:
    if not filters:
        return "SELECT * FROM data", ()
    
    allowed_keys = {'status', 'category', 'type'}
    conditions = []
    values = []
    
    for key, val in filters.items():
        if key not in allowed_keys:
            continue
        conditions.append(f"{key} = ?")
        values.append(val)
    
    if not conditions:
        return "SELECT * FROM data", ()
    
    query = "SELECT * FROM data WHERE " + " AND ".join(conditions)
    return query, tuple(values)

