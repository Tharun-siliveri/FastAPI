import mysql.connector # mysql-connector-python
from mysql.connector import Error

from dotenv import load_dotenv
import os

load_dotenv()

def get_connection():
    try:
        connection = mysql.connector.connect(
            host=os.getenv('host'),
            database=os.getenv('database'),
            user=os.getenv('user'),
            password=os.getenv('password')
        )
        if connection.is_connected():
            print("Connected to MySQL database")
            return connection
    except Error as e:
        print("Error while connecting to MySQL", e)
    return None

def close_connection(connection):
    if connection.is_connected():
        connection.close()