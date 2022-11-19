import sqlite3
from sqlite3 import Error
import sys
import json

"""
This program loads and creates a database if none exists

Uncomment the "main_insert()" funciton if you want sample records

To install modules/windows
python -m pip install --upgrade pip
pip3 install tkinter
pip3 install base64
pip3 install hashlib
pip3 install pycrypttodome

To install on modules/Linux (Debian 10 at least):
sudo apt-get install python3-tk
pip3 install pybase64
pip3 isntall pycryptodomex
"""

# encryption stuff
from base64 import b64encode, b64decode
import hashlib
from Cryptodome.Cipher import AES
import os
from Cryptodome.Random import get_random_bytes

def show_error(e):
    print(e)
    sys.exit()


def run_query(query, parameters = ()):
    db_name = 'encrypteds.db'
    with sqlite3.connect(db_name) as conn:
        cursor = conn.cursor()
        result = cursor.execute(query, parameters)
        conn.commit()
    return result
    
def create_connection(db_file):
    """ create a database connection to the SQLite database
        specified by db_file
    :param db_file: database file
    :return: Connection object or None
    """
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except Error as e:
        show_error(e)
    return conn
    
def create_table(conn, create_table_sql):
    """ create a table from the create_table_sql statement
    :param conn: Connection object
    :param create_table_sql: a CREATE TABLE statement
    :return:
    """
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except Error as e:
        print(e)

def create_entry(conn,data):
    """
    Create a new Entry
    :param conn:
    :param data:
    :return:
    """
    
    sql = ''' INSERT INTO encrypts(username,password,login_uri,enc_key)
              VALUES(?,?,?,?) '''
    
    cur = conn.cursor()
    cur.execute(sql,data)
    conn.commit()
    return cur.lastrowid

def main_create():
    #database = r"C:\sqlite\db\pythonsqlite.db"
    database = r"encrypteds.db"

    sql_create_encrypts_table = """ CREATE TABLE IF NOT EXISTS `encrypts` (
                                        `id` integer PRIMARY KEY,
                                        `username` text NOT NULL,
                                        `password` text,
                                        `login_uri` text
                                    ); """
    # create a database connection
    conn = create_connection(database)

    # create tables
    if conn is not None:
        # create table
        create_table(conn, sql_create_encrypts_table)
    else:
        print("Error! cannot create the database connection.")


def main_insert():
    database = r"encrypteds.db"

    for r in range(0, 100, 1):
        user = 'someuser'+str(r)
        passw = 'somepass'+str(r)
        url = 'https://site'+str(r)+'.com'
        
        encrypted = encrypt_it(passw, '12345678')
        print(encrypted)
        serialized = json.dumps(encrypted)
        print(serialized)
        print()
        
        query = 'INSERT INTO encrypts VALUES(NULL, ?, ?, ?)'
        parameters = [user,serialized,url]
        run_query(query, parameters)

def encrypt_it(plain_text,password):
    """
    encrypts a string and returns a dictionary
    works with b64 encode/decode to make json happy
    so it's stored in b64, but that b64 data is encrypted with AES
    """
    # generate a random salt
    salt = get_random_bytes(AES.block_size)
    # use the Scrypt KDF to get a private key from the password
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

    # create cipher config
    cipher_config = AES.new(private_key, AES.MODE_GCM)

    # return a dictionary with the encrypted text
    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(plain_text, 'utf-8'))
    return {
        'cipher_text': b64encode(cipher_text).decode('utf-8'),
        'salt': b64encode(salt).decode('utf-8'),
        'nonce': b64encode(cipher_config.nonce).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8')
    }

    
if __name__ == '__main__':
    # will only create db if none exists
    main_create()
    
    # uncomment if you need 100 sample records created
    #main_insert()
