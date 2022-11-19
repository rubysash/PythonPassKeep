"""
Passkeep clone, written in python
Each record has it's own unlock key
You can share full database and only unlock keys of records you want to share


-------------
KNOWN ISSUE
-------------
It is not designed for multiple connections to database.
Use it as one thread via one script only.


-------------
BACKUP
-------------
Please backup your main file periodically.
This uses the sqlite module to write to "encrypteds.db" file
That is the file you will need to backup

-------------
INSTALLATION
-------------
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

-------------
ADD RECORD
-------------
Fill it out and click "save"

-------------
EDIT RECORD/VIEW PASSWORD
-------------
Type your unlock key in "KEY1" and click "edit"
"""


# GUI Stuff
import tkinter as tk
import tkinter.messagebox as mb 

from tkinter import *
from tkinter import Tk, Text, BOTH, W, N, E, S, DISABLED, font

from tkinter import ttk
from tkinter.ttk import Frame, Button, Label, Style, LabelFrame


import sqlite3                  # DB Stuff

import json                     # file i/o stuff and json serialization/deserialization
from datetime import datetime   # for date time filename
import time                     # for run timer
import random                   # for the inspiration randoms
import sys                      # for the graceful exit

# encryption stuff
from base64 import b64encode, b64decode
import hashlib
from Cryptodome.Cipher import AES
import os
from Cryptodome.Random import get_random_bytes

# some colors
grey = '#dcdad5'

bgcolor = '#ECECEC'
white  = '#FFFFFF'

dblack = '#000000'
lblack = '#444444'

dred   = '#FF0000'
lred   = '#f9dede'

dgreen = '#076d05'
lgreen = '#e0f9d9'

dblue  = '#4a6984'
lblue  = '#e2e6ff'

# Styles
opts1 = { 'ipadx': 2, 'ipady': 2 , 'sticky': 'nswe' } # centered
opts2 = { 'ipadx': 1, 'ipady': 1 , 'sticky': 'e' } # right justified
opts3 = { 'ipadx': 2, 'ipady': 1 , 'sticky': 'w' } # left justified


class ScrollableFrame:
    """
    # How to use class
    from tkinter import *
    obj = ScrollableFrame(master,height=300,width=400) # look at master for sizing
    objframe = obj.frame
    # use objframe as the main window to make widget
    """
    
    # fixme:  mousewheel is not working as expected
    def __init__ (self,master,width,height,mousescroll=0):
        self.mousescroll = mousescroll
        self.master = master
        self.height = height
        self.width = width
        self.main_frame = Frame(self.master)
        self.main_frame.pack(fill=BOTH,expand=1)

        self.scrollbar = Scrollbar(self.main_frame, orient=VERTICAL)
        self.scrollbar.pack(side=RIGHT,fill=Y)

        self.canvas = Canvas(self.main_frame,yscrollcommand=self.scrollbar.set)
        self.canvas.pack(expand=True,fill=BOTH)

        self.scrollbar.config(command=self.canvas.yview)

        self.canvas.bind('<Configure>', lambda e: self.canvas.configure(scrollregion = self.canvas.bbox("all")))

        self.frame = Frame(self.canvas,width=self.width,height=self.height)
        self.frame.pack(expand=True,fill=BOTH)
        self.canvas.create_window((0,0), window=self.frame, anchor="nw")

        self.frame.bind("<Enter>", self.entered)
        self.frame.bind("<Leave>", self.left)

    def _on_mouse_wheel(self,event):
        self.canvas.yview_scroll(-1 * int((event.delta / 120)), "units")

    def entered(self,event):
        if self.mousescroll:
            self.canvas.bind_all("<MouseWheel>", self._on_mouse_wheel)
        
    def left(self,event):
        if self.mousescroll:
            self.canvas.unbind_all("<MouseWheel>")


class Passwords:
    # connection dir property
    db_name = 'encrypteds.db'

    def __init__(self, window):
        self.warned = 0
        # Initializations 
        self.wind = window
        self.wind.title('Python PassKeep')

        # default theme for most styling
        self.s = ttk.Style()
        self.s.theme_use('clam')

        # my styling for labels
        self.s.configure('B.TLabelframe.Label', font=('courier', 18, 'bold'), 
            foreground=dblue, background=grey)

        # bastardized entry styling
        self.estyle = ttk.Style()
        self.estyle.element_create("plain.field", "from", "clam")
        self.estyle.layout("EntryStyle.TEntry",
                           [('Entry.plain.field', {'children': [(
                               'Entry.background', {'children': [(
                                   'Entry.padding', {'children': [(
                                       'Entry.textarea', {'sticky': 'nswe'})],
                              'sticky': 'nswe'})], 'sticky': 'nswe'})],
                              'border':'2', 'sticky': 'nswe'})])
        
        self.estyle.configure("EntryStyle.TEntry",
                         background=grey, 
                         foreground=lblack,
                         fieldbackground=white)
        
        # Treeview styles
        self.s.configure("mytv.Treeview", highlightthickness=0, bd=0, font=('courier', 12)) 
        self.s.configure('mytv.Treeview.Heading', background='gray', font=('courier', 14, 'bold'))
       
        # Creating a Frame Container 
        frame = LabelFrame(self.wind, text = 'ADD NEW RECORD', style="B.TLabelframe")
        frame.grid(row = 0, column = 0, columnspan=2, pady=20, padx=20, sticky=N)

        # Name Input
        Label(frame, text = ' USER: ', font=('courier', 14, 'bold'), 
            foreground=dblue).grid(row = 1, column = 0, **opts2)
        self.user = ttk.Entry(frame,style="EntryStyle.TEntry")
        self.user.focus()
        self.user.grid(row = 1, column = 1)

        # Pass Input
        Label(frame, text = ' PASS: ', font=('courier', 14, 'bold'),
            foreground=dblue).grid(row = 2, column = 0, **opts2)
        self.passw = ttk.Entry(frame,style="EntryStyle.TEntry")
        self.passw.grid(row = 2, column = 1)

        # URL
        Label(frame, text = '  URL: ', font=('courier', 14, 'bold'),
            foreground=dblue).grid(row = 3, column = 0, **opts2)
        self.url = ttk.Entry(frame,style="EntryStyle.TEntry")
        self.url.grid(row = 3, column = 1)

        frame4 = LabelFrame(self.wind, text = 'PROTECTION KEY', style="B.TLabelframe")
        frame4.grid(row = 0, column = 2, columnspan=2, pady=20, padx=20, sticky=N)

        # key
        Label(frame4, text = ' KEY1: ', font=('courier', 14, 'bold'),
            foreground=dblue).grid(row = 1, column = 0, **opts2)
        self.key1= ttk.Entry(frame4, show="*",style="EntryStyle.TEntry")
        self.key1.grid(row=1, column=1)

        # verify
        Label(frame4, text = ' KEY2: ', font=('courier', 14, 'bold'),
            foreground=dblue).grid(row=2, column = 0, **opts2)
        self.key2 = ttk.Entry(frame4, show="*",style="EntryStyle.TEntry")
        self.key2.grid(row=2, column=1)

        # Output Messages 
        self.message = Label(text = ' ', font=('courier', 14, 'bold'),foreground=dred)
        self.message.grid(row = 7, column = 0, columnspan = 4, sticky = W + E, padx=20)

        # Buttons
        ttk.Button(text = 'DELETE', command = self.delete_password).grid(row = 8, column = 0, sticky = W + E)
        ttk.Button(text = 'EDIT', command = self.show_edited).grid(row = 8, column = 1, sticky = W + E)
        ttk.Button(text = 'ADD', command = self.add_password).grid(row = 8, column = 2, sticky = W + E)
        ttk.Button(text = 'HELP', command = self.show_help).grid(row = 8, column = 3, sticky = W + E)

        # Table
        self.tree = ttk.Treeview(height = 20, columns = ('#0','#1'),style='mytv.Treeview')
        self.tree.grid(row = 9, column=0, columnspan=4)
        
        # Configure columns to preferred spacing
        self.tree.column('#0', anchor=CENTER, stretch=NO, width=75 )
        self.tree.heading('#0', text = 'ID')
        self.tree.column('#1', stretch=NO, width=200 )
        self.tree.heading('#1', text = 'USERNAME', anchor = W)
        self.tree.column('#2', stretch=NO, width=425 )
        self.tree.heading('#2', text = 'LOGIN/URL', anchor = W)


        # Filling the Rows
        self.get_records()

        # fixme:  can't get alt colors working
        #self.tree.tag_configure('odd', foreground='black')
        #self.tree.tag_configure('even', foreground='white')
 
    def show_help(self):
        mb.showinfo("Information", "PLEASE MAKE BACKUPS OF 'encrypteds.db' FILE!!")

        thiswin = tk.Toplevel(window)
        thiswin.geometry('750x750')
        thiswin.configure(bg=grey,  padx=20, pady=20)
        obj = ScrollableFrame(thiswin,height=300,width=900 )
        helpwin = obj.frame
        
        frame6 = LabelFrame(helpwin, text='What is this?', style="B.TLabelframe", border=0)
        frame6.grid(row=0,column=0, **opts1)
        msg = """
This python program saves passwords in an encrypted sqlite database. Every entry is protected with a different key, so you can share the database freely, and only give the password unlock for the record you want them to view.
"""
        tk.Message(frame6,text = msg, width=650).grid(row = 0, column = 0, sticky = W + E, padx=20)

        frame7 = LabelFrame(helpwin, text='What type of Encryption?', style="B.TLabelframe", border=0)
        frame7.grid(row=2,column=0, **opts1)
        msg = """
The python module Cryptodome.Cipher is using AES 128 with the GCM cipher. It is also salting the password and storing it base 64 so it is compatible with sqlite (stored as a json dictionary).

The base64 is decoded, then the string is decrypted when you enter the proper key. Galois/Counter Mode is defined in http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf  if you are interested in the stuff I am unable to accurately explain!

Here are the module docs:  https://pycryptodome.readthedocs.io/en/latest/src/cipher/modern.html#gcm-mode
"""
        tk.Message(frame7,text = msg, width=650).grid(row = 0, column = 0, sticky = W + E, padx=20)

        frame8 = LabelFrame(helpwin, text='How to Encrypt', style="B.TLabelframe", border=0)
        frame8.grid(row=3,column=0, **opts1)
        msg = """
Type information in the fields provided.    The "password" is the only field that is encrypted. KEY1 and KEY2 must match.   This is your unlock key when you want to view the password.

14 characters is sufficient to stop most brute force attacks, and that is the suggested (not forced), minimum key length.    

It does no good to use strong encryption if your unlock key is weak.   Use a good password that is not a dictionary word, or combination of dictionary words.   A sentence is good.  Here is an example of a good password:

ILikeCoffee!NotStarBuck$

Something like this is easy to remember, but hard to break.
"""
        tk.Message(frame8,text = msg, width=650).grid(row = 0, column = 0, sticky = W + E, padx=20)


        frame9 = LabelFrame(helpwin, text='How to Decrypt', style="B.TLabelframe", border=0)
        frame9.grid(row=4,column=0, **opts1)
        msg = """
To unlock the vault for your record, type the key in "KEY1" filed then click "edit". This is also the method to change anything such as the login, user, password or your unlock key.
"""
        tk.Message(frame9,text = msg, width=650).grid(row = 0, column = 0, sticky = W + E, padx=20)

        





    # serialize, encrypt, salt
    def encrypt_it(self,plain_text,password):
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

    # deserialize, decrypt, salt
    def decrypt_it(self,encrypted,password):
        """
        decrypts a specific string and returns it
        works with b64 encode/decode to make json happy
        so it's stored in b64, but that b64 data is encrypted with AES
        """
        
        # data placeholders
        decrypted = []
        d = json.loads(encrypted)

        # decode the dictionary entries from base64
        salt = b64decode(d['salt'])
        cipher_text = b64decode(d['cipher_text'])
        nonce = b64decode(d['nonce'])
        tag = b64decode(d['tag'])

        # generate the private key from the password and salt
        private_key = hashlib.scrypt(
            password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

        # create the cipher config
        cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)

        # decrypt the cipher text
        return cipher.decrypt_and_verify(cipher_text, tag)
        
    # Function to Execute Database Querys
    def run_query(self, query, parameters = ()):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            result = cursor.execute(query, parameters)
            conn.commit()
        return result

    # Get all records from DB
    def get_records(self):

        # cleaning Table 
        records = self.tree.get_children()
        for element in records:
            self.tree.delete(element)

        # getting data
        query = 'SELECT * FROM encrypts ORDER BY login_uri DESC'
        db_rows = self.run_query(query)
        
        self.tree.tag_configure('odd', foreground='black')
        self.tree.tag_configure('even', foreground='white')

        # filling data
        # fixme:  alternating colors not working
        x = 1
        for row in db_rows:
            if x % 2 == 0:
                self.tree.insert("",0,text = row[0], values=(row[1],row[3]), tags=('odd',))
            else:
                self.tree.insert("",0,text = row[0], values=(row[1],row[3]), tags=('even',))
            x = x + 1
        self.tree.tag_configure('odd', foreground='black')
        self.tree.tag_configure('even', foreground='white')

    # Get actual encrypted password dictionary
    def get_password(self,id):

        # cleaning Table from window
        records = self.tree.get_children()
        for element in records:
            self.tree.delete(element)

        # getting data from database
        query = 'SELECT * FROM encrypts WHERE id = ?'
        parameters = (id,)
        db_rows = self.run_query(query, parameters)

        # give us the id that matches, return the encrypted json string
        for row in db_rows:
            return row[2]

    # User Input Validation
    def validation(self):
        return len(self.user.get()) != 0 and \
               len(self.passw.get()) != 0 and \
               len(self.url.get()) != 0 and \
               len(self.key1.get()) != 0 and \
               len(self.key2.get()) != 0 and \
               self.key1.get() == self.key2.get()

    # validate the popup edit window
    def validation2(self,new_user, new_passw, new_url, key1,key2):
        return len(new_user) != 0 and \
               len(new_passw) != 0 and \
               len(new_url) != 0 and \
               len(key1) != 0 and \
               len(key2) != 0 and \
               key1 == key2
                
    # add new entry
    def add_password(self):
        if self.validation():
            
            # json doesn't like encrypted text, so we need to serialize it
            encrypted = self.encrypt_it(self.passw.get(), self.key1.get())
            serialized = json.dumps(encrypted)
  
            query = 'INSERT INTO encrypts VALUES(NULL, ?, ?, ?)'
            parameters =  (self.user.get(), serialized, self.url.get())
            self.run_query(query, parameters)
            self.message['text'] = 'RECORD SAVED'
        else:
            msg = '434: All Fields are Required to Save. Keys Must Match'
            self.message['text'] = msg
            mb.showinfo("Information", msg)
        self.get_records()

    # delete that entry
    # fixme:  add a prompt
    def delete_password(self):
        self.message['text'] = ''
        try:
           self.tree.item(self.tree.selection())['text']
        except IndexError as e:
            msg = 'Please select a Record'
            self.message['text'] = msg
            mb.showinfo("Information", msg)
            return

        # clear our message
        self.message['text'] = ''
        
        # get data we clicked on
        user = self.tree.item(self.tree.selection())['values'][0]
        login_uri = self.tree.item(self.tree.selection())['values'][1]
        id = self.tree.item(self.tree.selection())['text']

        # build query
        query = 'DELETE FROM encrypts WHERE id = ?'
        
        # run query
        self.run_query(query, (id, ))
        
        # notify user
        self.message['text'] = 'ID: {} DELETED'.format(id)
        
        # repopulate the table
        self.get_records()

    # edit an entry
    def show_edited(self):
        self.message['text'] = ''
        
        # did they select something?
        try:
            self.tree.item(self.tree.selection())['values'][1]
        except IndexError as e:
            msg = 'Please, select Record'
            self.message['text'] = msg
            mb.showinfo("Information",msg)
            return
            
        # guess they did.   Get what they clicked
        id = self.tree.item(self.tree.selection())['text']
        user = self.tree.item(self.tree.selection())['values'][0]
        url = self.tree.item(self.tree.selection())['values'][1]
        
        # make new window
        self.edit_wind = Toplevel()
        self.edit_wind.configure(bg='#dcdad5')
        self.edit_wind.title = 'Edit Password'
        
        # get encrypted pass from db for this id
        passw = self.get_password(str(id))
        
        # see if we can decrypt it
        try:
            decrypted = self.decrypt_it(passw,self.key1.get())
        except ValueError as e:
            msg = "497: Decrypt Error (type key in 'KEY1' to unlock)"
            self.message['text'] = msg
            mb.showinfo("Information", msg)
            self.edit_wind.destroy()
            self.get_records()
            return

        # fixme:  I think this code will never trigger as bug was fixed
        if len(self.decrypt_it(passw,self.key1.get())) == 0:
            msg = "506: Decrypt Error (type key in 'KEY1' to unlock)"
            self.message['text'] = msg
            mb.showinfo("Information", msg)
            self.edit_wind.destroy()
            self.get_records()
            return
        
        # build the layouts
        frame1 = LabelFrame(self.edit_wind, text = 'OLD INFO', style="B.TLabelframe")
        frame1.grid(row = 0, column = 0, columnspan = 2, pady=20, padx=20)
        
        frame2 = LabelFrame(self.edit_wind, text = 'NEW INFO', style="B.TLabelframe")
        frame2.grid(row = 0, column = 2, columnspan = 2, pady=20, padx=20)
        
        frame3 = LabelFrame(self.edit_wind, text = 'PROTECTION KEY', style="B.TLabelframe")
        frame3.grid(row = 1, column = 3, columnspan = 2, pady=20, padx=20)
        
        # Old Name
        Label(frame1, text = 'Old User:', font=('courier', 14, 'bold'),
            foreground=dblue).grid(row = 0, column = 1,**opts2)
        Entry(frame1, textvariable = StringVar(frame1, value = user), state = 'readonly'
            ).grid(row = 0, column = 2)
        # New Name
        Label(frame2, text = 'New User:', font=('courier', 14, 'bold'),
            foreground=dblue).grid(row = 0, column = 3,**opts2)
        new_user= ttk.Entry(frame2,style="EntryStyle.TEntry")
        new_user.grid(row = 0, column = 4)

        # Old Passw
        Label(frame1, text = 'Old Password:', font=('courier', 14, 'bold'),
            foreground=dblue).grid(row = 1, column = 1,**opts2)
        Entry(frame1, textvariable = StringVar(
            frame1, value=decrypted), state = 'readonly'
            ).grid(row = 1, column = 2)
        # New passw
        Label(frame2, text = 'New Password:', font=('courier', 14, 'bold'),
            foreground=dblue).grid(row = 1, column = 3,**opts2)
        new_passw = ttk.Entry(frame2,style="EntryStyle.TEntry")
        new_passw.grid(row = 1, column = 4)

        # Old URL
        Label(frame1, text = 'Old URL:', font=('courier', 14, 'bold'),
            foreground=dblue).grid(row = 2, column = 1,**opts2)
        Entry(frame1, textvariable = StringVar(
            frame1, value = url), state = 'readonly'
            ).grid(row = 2, column = 2)
        # New URL
        Label(frame2, text = 'New URL:', font=('courier', 14, 'bold'),
            foreground=dblue).grid(row = 2, column = 3,**opts2)
        new_url= ttk.Entry(frame2,style="EntryStyle.TEntry")
        new_url.grid(row = 2, column = 4)

        # key
        Label(frame3, text = 'KEY1:', font=('courier', 14, 'bold'),
            foreground=dblue).grid(row = 1, column = 1,**opts2)
        key1 = ttk.Entry(frame3,show="*",style="EntryStyle.TEntry")
        key1.grid(row=1, column = 2)
        # verify
        Label(frame3, text = 'KEY2:', font=('courier', 14, 'bold'),
            foreground=dblue).grid(row = 2, column = 1,**opts2)
        key2 = ttk.Entry(frame3,show="*",style="EntryStyle.TEntry")
        key2.grid(row = 2, column = 2)

        Button(
            self.edit_wind, text = 'Update', command = lambda: self.save_edited(
            id,
            new_user.get(),
            new_passw.get(),
            new_url.get(),
            key1.get(), key2.get())
            ).grid(row = 5, column = 3, sticky = W, padx=10, pady=10)
        
        # repopulate table
        self.get_records()
        
        # fixme:  what does this do again?
        self.edit_wind.mainloop()

    # save the edited data
    def save_edited(self, id, new_user, new_passw, new_url, key1, key2):
        
        # if they filled it out, of course
        if self.validation2(new_user, new_passw, new_url, key1, key2):
            
            # json doesn't like encrypted text, so we need to serialize it
            encrypted = self.encrypt_it(new_passw, key1)
            serialized = json.dumps(encrypted)

            # build parameterized query
            query = 'UPDATE encrypts SET username = ?, password = ?, login_uri = ? WHERE id = ?'
            parameters = (new_user, serialized, new_url, id)
            
            # run query with parameters
            self.run_query(query, parameters)
            
            # ok, all done, destroy the edit window
            self.edit_wind.destroy()
            
            # notify user
            self.message['text'] = 'Record Saved'
        else:
            # user didn't do something righ
            self.message['text'] = 'Data Missing or Your Encryption Keys Do Not Match'
            mb.showinfo("Information", "Data Missing or Your Encryption Keys Do Not Match")
        
        # repopulate main window table
        self.get_records()

if __name__ == '__main__':
    try:
        # create class instance of tk.Tk
        window = tk.Tk()
        
        # default configurations to override theme
        window.configure(bg=grey)
        window.option_add("*Font", "Helvitica 14")
        window.option_add("*Label.Font", "Helvitica 18 bold")
        window.option_add("*Background", grey)

        # create instance of class 
        application = Passwords(window)

        # fixme: lookup and document what mainloop exactly does
        window.mainloop()
    except KeyboardInterrupt:
        print("CTRL+C Detected, stopping")
        sys.exit()

# fixme:  delete doesn't force a click or verify
# todo:  add categories/folders instead of simple records
# todo:  give option to load file of their choice
# todo:  add simple backup button for file.datestamp.db
