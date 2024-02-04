"""
This script imports a chrome password export (or any formatted CSV)

File structure should be first 3 columns as:
url, user, pass

install the requirements:
colorama==0.4.6
pybase64==1.2.3
pycryptodome==3.17
pycryptodomex==3.17

Suggested to use venv
python -m venv passwordkeeper

And then the requirements file:
python -m pip install -r requirements.txt


Run the script:
python encryptcsv.py -i input.csv -o chromedump.db

Warning
If you name the output file as an existing password database it will add duplicate entries.

Source & License:
https://github.com/rubysash/
"""


import gvars                    # global variable file
import getopt                   # for the -i and -o parameters
import csv                      # to read from csv
import getpass                  # to hide password variable when typing

import sqlite3                  # DB Stuff
from sqlite3 import Error       # for raising error

import json                     # file i/o stuff and json serialization/deserialization
import random                   # works with encryption libraries
import sys                      # for the graceful exit

# encryption stuff
from base64 import b64encode, b64decode
import hashlib
from Cryptodome.Cipher import AES
import os
from Cryptodome.Random import get_random_bytes

# for the screen clear
from os import system, name 

# for colors on CLI
from colorama import init
init()
# class ripped from geeks for geeks colorama tutorial
class colors: 
	reset='\033[0m'
	bold='\033[01m'
	disable='\033[02m'
	underline='\033[04m'
	reverse='\033[07m'
	strikethrough='\033[09m'
	invisible='\033[08m'
	class fg: 
		black='\033[30m'
		red='\033[31m'
		green='\033[32m'
		orange='\033[33m'
		blue='\033[34m'
		purple='\033[35m'
		cyan='\033[36m'
		lightgrey='\033[37m'
		darkgrey='\033[90m'
		lightred='\033[91m'
		lightgreen='\033[92m'
		yellow='\033[93m'
		lightblue='\033[94m'
		pink='\033[95m'
		lightcyan='\033[96m'
		white='\033[37m'
	class bg: 
		black='\033[40m'
		red='\033[41m'
		green='\033[42m'
		orange='\033[43m'
		blue='\033[44m'
		purple='\033[45m'
		cyan='\033[46m'
		lightgrey='\033[47m'

# simple error message
def show_error(e):
    print("\n",colors.fg.red,e)
    print(colors.fg.yellow,gvars.csv_help_msg)
    sys.exit()

# initial test for db connection
# fixme: duplicate code
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

# add a table to connected database
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

# create db if it doesn't exist
def touch_db(db_name):
    sql_create_encrypts_table = """ CREATE TABLE IF NOT EXISTS `encrypts` (
                                        `id` integer PRIMARY KEY,
                                        `username` text NOT NULL,
                                        `password` text,
                                        `login_uri` text
                                    ); """
    # create a database connection
    conn = create_connection(db_name)

    # create tables
    if conn is not None:
        # create table
        create_table(conn, sql_create_encrypts_table)
    else:
        msg = '764: Data Missing or Your Encryption Keys Do Not Match'
        show_error(msg)

# Function to Execute Database Querys
def run_query(db_name, query, parameters = ()):
    with sqlite3.connect(db_name) as conn:
        cursor = conn.cursor()
        result = cursor.execute(query, parameters)
        conn.commit()
    return result

# load a modified chrome password dump all at once
def load_csv(inputfile,db_name,password):
    '''
    requires file of 3 columns:
    url,user,pass
    '''
    # create a db file tables if they don't exist
    touch_db(db_name)

    # loop over input file
    with open(inputfile) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        print(colors.fg.yellow,"ENCRYPTING AND ADDING TO SQLITE DB...")
        # modify your csv if this isn't the order
        
        # encrypt each row and insert into db
        # will make duplicate entries, but will allow you to import into existing db
        # fixme:  do something with duplicates
        for row in csv_reader:
            (url,user,passw) = row[0],row[1],row[2]
            encrypted = encrypt_it(passw, password)
            serialized = json.dumps(encrypted)
            query = 'INSERT INTO encrypts VALUES(NULL, ?, ?, ?)'
            parameters = [user,serialized,url]
            run_query(db_name, query, parameters)
            
            print(colors.fg.yellow,"USER:",colors.fg.green,user)
            print(colors.fg.yellow,"URL:",colors.fg.green,url)
            print()

# create encrypted base64encoded json for sqlite
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

# verify read or write, defaults to check read
def is_accessible(path, mode='r'):
    """
    Check if the file or directory at `path` can
    be accessed by the program using `mode` open flags.
    """
    try:
        f = open(path, mode)
        f.close()
    except IOError:
        return False
    return True

# for screen clears independent of OS
def clear(): 
	# for windows 
	if name == 'nt': 
		_ = system('cls') 
  
	# for mac and linux(here, os.name is 'posix') 
	else: 
		_ = system('clear')

# main logic
def main():
    print(colors.fg.red,"\n\WARNING!!!!   This import will add duplicates if you specify an existing output database!")
    print(colors.fg.yellow,"(CTRL + C to cancel)\n")
    # basic opt verification
    try:
        opts, args = getopt.getopt(sys.argv[1:],"h?i:o:")
    except getopt.GetoptError as err:
        show_error(err)

    # loop over all opts and set flags, check R/W, etc
    (o,i,inputfile,outputfile) = (0,0,"","")
    for opt, arg in opts:
        if opt in ("-h", '-?'):
            show_error(str(183) + " INSTRUCTIONS")
        if opt in ("-i"):
            i = 1
            # because they could say -i but not give a command
            if len(sys.argv) < 4:
                show_error(str(191) + " ADDITIONAL ARGUMENTS REQUIRED")

            # verify exists and is readable
            if (is_accessible(arg, 'r')):
                inputfile = arg
            else: 
                show_error(str(205) + " CANNOT READ FILE, " + arg)

        if opt in ("-o"):
            o = 1
            # because they could say -i but not give a command
            if len(sys.argv) < 4:
                show_error(str(212) + " ADDITIONAL ARGUMENTS REQUIRED")
            else:
                # verify exists and is writable
                if (is_accessible(arg, 'w')):
                    outputfile = arg
                else: show_error(str(218) + " CANNOT WRITE FILE, " + inputfile)

    # they have specified both in and out, ok to proceed
    if ((i == 1) and (o == 1)):
        print(colors.fg.yellow)
        password1 = getpass.getpass(prompt="Enter the Master Encryption Password for all entries\n")
        password2 = getpass.getpass(prompt="VERIFY Master Encryption Password\n")
        
        if password1 == password2:
            load_csv(inputfile,outputfile,password1)
        else:
            show_error(str(240)+" PASSWORD MISMATCH ")
    else:
        show_error(str(241) + " MISSING PARAMETERS ")

    sys.exit()

if __name__ == '__main__':
    clear()
    try:
        if len(sys.argv) > 1:
            main()
        else:
            #url,user,passw
            show_error(str(230) + " NO PARAMETERS GIVEN")
    except KeyboardInterrupt:
        show_error(str(273)+ " CTRL+C Detected, Cancelling ")

