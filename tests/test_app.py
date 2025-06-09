
import sys
import os
import pytest
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import app

def test_home_route():
    tester = app.test_client()
    response = tester.get('/')
    assert response.status_code == 200
    assert b'LinkedIn' in response.data or b'Home' in response.data

def test_register_route_get():
    tester = app.test_client()
    response = tester.get('/register')
    assert response.status_code == 200
    assert b'Register' in response.data

def test_login_route_get():
    tester = app.test_client()
    response = tester.get('/login')
    assert response.status_code == 200
    assert b'Login' in response.data
