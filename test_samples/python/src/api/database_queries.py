"""
Database Query Examples - SQL Injection True Positive and False Positive
This file demonstrates both vulnerable and safe SQL query patterns.
"""

from fastapi import FastAPI, HTTPException, Query
import sqlite3
from typing import Optional, List
import re

app = FastAPI()


# ============================================================================
# TRUE POSITIVE: SQL Injection - Direct string formatting
# ============================================================================
@app.get("/users/search-vulnerable")
async def search_users_vulnerable(username: str):
    """
    VULNERABLE: SQL Injection via string formatting
    This is a TRUE POSITIVE - real vulnerability
    """
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    
    # VULNERABLE: Direct string formatting in SQL query
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    
    results = cursor.fetchall()
    conn.close()
    return {"users": results}


# ============================================================================
# FALSE POSITIVE 1: Parameterized query with user input
# ============================================================================
@app.get("/users/search-safe")
async def search_users_safe(username: str):
    """
    SAFE: Uses parameterized query
    This is a FALSE POSITIVE - SAST tools might flag any SQL with user input
    """
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    
    # SAFE: Parameterized query prevents SQL injection
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    
    results = cursor.fetchall()
    conn.close()
    return {"users": results}


# ============================================================================
# FALSE POSITIVE 2: Dynamic column name with whitelist validation
# ============================================================================
@app.get("/users/sort")
async def get_users_sorted(sort_by: str = "id"):
    """
    SAFE: Dynamic column name but validated against whitelist
    This is a FALSE POSITIVE - SAST might flag dynamic SQL construction
    """
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    
    # SAFE: Whitelist validation for column names
    allowed_columns = {"id", "username", "email", "created_at"}
    if sort_by not in allowed_columns:
        raise HTTPException(status_code=400, detail="Invalid sort column")
    
    # SAFE: Column name is validated, user input in WHERE is parameterized
    query = f"SELECT * FROM users ORDER BY {sort_by}"
    cursor.execute(query)
    
    results = cursor.fetchall()
    conn.close()
    return {"users": results}


# ============================================================================
# FALSE POSITIVE 3: SQL query with no user input at all
# ============================================================================
@app.get("/users/active")
async def get_active_users():
    """
    SAFE: Hardcoded query with no user input
    This is a FALSE POSITIVE - SAST might flag any SQL query
    """
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    
    # SAFE: No user input, completely static query
    query = "SELECT * FROM users WHERE status = 'active' AND deleted_at IS NULL"
    cursor.execute(query)
    
    results = cursor.fetchall()
    conn.close()
    return {"users": results}


# ============================================================================
# FALSE POSITIVE 4: Integer parameter with type validation
# ============================================================================
@app.get("/users/{user_id}")
async def get_user_by_id(user_id: int):
    """
    SAFE: Integer parameter with FastAPI type validation
    This is a FALSE POSITIVE - SAST might flag SQL with path parameters
    """
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    
    # SAFE: user_id is validated as int by FastAPI, then parameterized
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        raise HTTPException(status_code=404, detail="User not found")
    return {"user": result}


# ============================================================================
# FALSE POSITIVE 5: String input with strict regex validation
# ============================================================================
@app.get("/users/by-email")
async def get_user_by_email(email: str):
    """
    SAFE: Email validated with regex before use in parameterized query
    This is a FALSE POSITIVE - SAST might flag any string in SQL context
    """
    # SAFE: Strict email validation
    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if not re.match(email_pattern, email):
        raise HTTPException(status_code=400, detail="Invalid email format")
    
    # Additional length check
    if len(email) > 254:
        raise HTTPException(status_code=400, detail="Email too long")
    
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    
    # SAFE: Validated input + parameterized query
    query = "SELECT * FROM users WHERE email = ?"
    cursor.execute(query, (email,))
    
    result = cursor.fetchone()
    conn.close()
    
    if not result:
        raise HTTPException(status_code=404, detail="User not found")
    return {"user": result}


# ============================================================================
# FALSE POSITIVE 6: Using ORM-style query builder
# ============================================================================
@app.get("/users/filter")
async def filter_users(
    min_age: Optional[int] = None,
    max_age: Optional[int] = None,
    status: Optional[str] = None
):
    """
    SAFE: Building query with validated parameters
    This is a FALSE POSITIVE - SAST might flag dynamic query building
    """
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    
    # SAFE: Build query with parameterized conditions
    conditions = []
    params = []
    
    if min_age is not None:
        conditions.append("age >= ?")
        params.append(min_age)
    
    if max_age is not None:
        conditions.append("age <= ?")
        params.append(max_age)
    
    if status is not None:
        # SAFE: Whitelist validation
        allowed_statuses = {"active", "inactive", "pending"}
        if status not in allowed_statuses:
            raise HTTPException(status_code=400, detail="Invalid status")
        conditions.append("status = ?")
        params.append(status)
    
    # SAFE: Dynamic WHERE clause but all values are parameterized
    base_query = "SELECT * FROM users"
    if conditions:
        where_clause = " WHERE " + " AND ".join(conditions)
        query = base_query + where_clause
    else:
        query = base_query
    
    cursor.execute(query, tuple(params))
    results = cursor.fetchall()
    conn.close()
    
    return {"users": results, "filters_applied": len(conditions)}

