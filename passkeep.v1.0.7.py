"""
Passkeep clone, written in python
Each record has it's own unlock key
You can share full database and only unlock keys of records you want to share

latest:  https://github.com/rubysash/PythonPassKeep

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


install the requirements:
colorama==0.4.6
pybase64==1.2.3
pycryptodome==3.17
pycryptodomex==3.17

Suggested to use venv
python -m venv passwordkeeper

And then the requirements file:
python -m pip install -r requirements.txt

You can create a bat file and then short cut to it for auto start of env:
start cmd /k "Scripts\activate && python passkeep.py"


To install on modules/Linux (Debian 10 at least):
sudo apt-get install python3-tk
colorama==0.4.6
pybase64==1.2.3
pycryptodomex==3.17

-------------
ADD RECORD
-------------
Fill it out and click "save"

-------------
EDIT RECORD/VIEW PASSWORD
-------------
Type your unlock key in "KEY1" and click "edit"

"""
import gvars

# GUI Stuff
import tkinter as tk
import tkinter.messagebox as mb 

from tkinter import *
from tkinter import Tk, Text, BOTH, W, N, E, S, DISABLED, font

from tkinter import ttk
from tkinter.ttk import Frame, Button, Label, Style, LabelFrame

import sqlite3                  # DB Stuff
from sqlite3 import Error       # for raising error

import json                     # file i/o stuff and json serialization/deserialization
from datetime import datetime   # for date time filename
#import datetime as objDateTime
import time                     # for run timer
import random                   # for the inspiration randoms
import sys                      # for the graceful exit


# for partial
from functools import partial

# encryption stuff
from base64 import b64encode, b64decode
import hashlib
from Cryptodome.Cipher import AES
import os
from Cryptodome.Random import get_random_bytes

# https://stackoverflow.com/questions/1966929/tk-treeview-column-sort#1967793
class MyTreeview(ttk.Treeview):
    """
    Rewrite of treeview to allow clickable/sortable by header
    """
    def heading(self, column, sort_by=None, **kwargs):
        if sort_by and not hasattr(kwargs, 'command'):
            func = getattr(self, f"_sort_by_{sort_by}", None)
            if func:
                kwargs['command'] = partial(func, column, False)
        return super().heading(column, **kwargs)

    def _sort(self, column, reverse, data_type, callback):
        l = [(self.set(k, column), k) for k in self.get_children('')]
        l.sort(key=lambda t: data_type(t[0]), reverse=reverse)
        for index, (_, k) in enumerate(l):
            self.move(k, '', index)
        self.heading(column, command=partial(callback, column, not reverse))

    def _sort_by_num(self, column, reverse):
        self._sort(column, reverse, int, self._sort_by_num)

    def _sort_by_name(self, column, reverse):
        self._sort(column, reverse, str, self._sort_by_name)

    def _sort_by_date(self, column, reverse):
        def _str_to_datetime(string):
            return datetime.datetime.strptime(string, "%Y-%m-%d")
        self._sort(column, reverse, _str_to_datetime, self._sort_by_date)
    
    def _sort_by_multidecimal(self, column, reverse):
        def _multidecimal_to_str(string):
            arrString = string.split(".")
            strNum = ""
            for iValue in arrString:
                strValue = f"{int(iValue):02}"
                strNum = "".join([strNum, str(strValue)])
            strNum = "".join([strNum, "0000000"])
            return int(strNum[:8])
        self._sort(column, reverse, _multidecimal_to_str, self._sort_by_multidecimal)

    def _sort_by_numcomma(self, column, reverse):
        def _numcomma_to_num(string):
            return int(string.replace(",", ""))
        self._sort(column, reverse, _numcomma_to_num, self._sort_by_numcomma)

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
    '''
    the main ui window is labeled as "wind"
    the help button opens a new window labeled "helpwin"
    edit opens "editwind"
    Structure is:
    window_root
        window_main
            frame_new
                Add New REcord
                User  <user>
                Pass  <passw>
                URL   <url>
            frame_keys
                Protection Key
                key1    <key1>
                key2    <key2>
            frame_search
                Search Records
                search  <search>
            message
            buttons,buttons,buttons,buttons
            Treeview
        window_help
            frame6
            frame7
            frame8
            frame9
            frame10
        window_edit
            frame1
                Old Info
                old user
                old pass
                old url
            frame2
                New Info
                new user <new_user>
                new pass <new_pass>
                new url <new_url
            frame3
                Protection key
                key1    <key1>
                key2    <key2>
    
    '''
    def __init__(self, window, db_name):
        self.db_name = db_name

        # Initializations 
        self.window_main = window
        self.window_main.title('Python PassKeep V' + gvars.ppk_version)

        # default theme for most styling
        self.s = ttk.Style()
        self.s.theme_use('clam')

        # my styling for labels
        self.s.configure('B.TLabelframe.Label', 
            font=('courier', 14, 'bold'), 
            foreground=gvars.dblue, background=gvars.grey)

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
                         background=gvars.grey, 
                         foreground=gvars.lblack,
                         fieldbackground=gvars.white)
        
        # Treeview styles
        self.s.configure("mytv.Treeview", highlightthickness=0, bd=0, 
            font=('courier', 12)) 
        self.s.configure('mytv.Treeview.Heading', background=gvars.grey, 
            font=('courier', 12, 'bold'))
       
        # frame container for new info
        frame_new = LabelFrame(self.window_main, 
            text='ADD NEW RECORD', 
            style="B.TLabelframe")
        frame_new.grid(row=0, column=0, columnspan=2, pady=10, padx=20, sticky=N)

        # Name Input
        Label(frame_new, text=' USER: ', font=('courier', 12, 'bold'), 
            foreground=gvars.dblue).grid(row=1, column=0, **gvars.opts2)
        self.user = ttk.Entry(frame_new,style="EntryStyle.TEntry")
        self.user.focus()
        self.user.grid(row=1, column=1)

        # Pass Input
        Label(frame_new, text=' PASS: ', font=('courier', 12, 'bold'),
            foreground=gvars.dblue).grid(row=2, column=0, **gvars.opts2)
        self.passw = ttk.Entry(frame_new,style="EntryStyle.TEntry")
        self.passw.grid(row=2, column=1)

        # URL
        Label(frame_new, text='  URL: ', font=('courier', 12, 'bold'),
            foreground=gvars.dblue).grid(row=3, column=0, **gvars.opts2)
        self.url = ttk.Entry(frame_new,style="EntryStyle.TEntry")
        self.url.grid(row=3, column=1)

        # frame container for the keys
        frame_keys = LabelFrame(self.window_main, 
            text='PROTECTION KEY', 
            style="B.TLabelframe")
        frame_keys.grid(row=0, column=2, columnspan=2, pady=10, padx=20, sticky=N)

        # key
        Label(frame_keys, text=' KEY1: ', font=('courier', 12, 'bold'),
            foreground=gvars.dblue).grid(row=1, column=0, **gvars.opts2)
        self.key1= ttk.Entry(frame_keys, show="*",style="EntryStyle.TEntry")
        self.key1.grid(row=1, column=1)

        # verify
        Label(frame_keys, text=' KEY2: ', font=('courier', 12, 'bold'),
            foreground=gvars.dblue).grid(row=2, column=0, **gvars.opts2)
        self.key2 = ttk.Entry(frame_keys, show="*",style="EntryStyle.TEntry")
        self.key2.grid(row=2, column=1)

        # frame container for search
        frame_search = LabelFrame(self.window_main, 
            text='SEARCH RECORDS', 
            style="B.TLabelframe")
        frame_search.grid(row=1, column=0, columnspan=2, pady=10, padx=20, sticky=N)

        self.search = ttk.Entry(frame_search, style="EntryStyle.TEntry")
        self.search.grid(row=2, column=1)
        
        ttk.Button(frame_search, text='FIND IT', command=self.get_records).grid(row=2, column=3)

        '''
        # frame container for search
        frame_info = LabelFrame(self.window_main, 
            text='TO UNLOCK: ', 
            style="B.TLabelframe")
        frame_info.grid(row=1, column=2, columnspan=2, pady=10, padx=20, sticky=N+W+E)

        Label(frame_info, text=' 1. Search for/Select an Entry', font=('courier', 12, 'bold'), 
            foreground=gvars.dblue).grid(row=2, column=1, **gvars.opts3)
        Label(frame_info, text=' 2. Type unlock key in KEY1', font=('courier', 12, 'bold'), 
            foreground=gvars.dblue).grid(row=3, column=1, **gvars.opts3)
        Label(frame_info, text=' 3. Click "EDIT"', font=('courier', 12, 'bold'), 
            foreground=gvars.dblue).grid(row=4, column=1, **gvars.opts3)
        '''

        # Output Messages 
        self.message = Label(text=' ', font=('courier', 12, 'bold'),foreground=gvars.dred)
        self.message.grid(row=7, column=0, columnspan=4, sticky=W+E, padx=20)

        # Buttons
        ttk.Button(text='DELETE', command=self.delete_password).grid(row=8, column=0, sticky=W+E)
        ttk.Button(text='EDIT', command=self.show_edited).grid(row=8, column=1, sticky=W+E)
        ttk.Button(text='ADD', command=self.add_password).grid(row=8, column=2, sticky=W+E)
        ttk.Button(text='HELP', command=self.show_help).grid(row=8, column=3, sticky=W+E)

        # Table
        self.tree = MyTreeview(columns=['ID','USERNAME','LOGIN/URL'], 
            show="headings", 
            style='mytv.Treeview')
        self.tree.grid(row=9, column=0, columnspan=4)
        
        # Configure columns to preferred spacing
        self.tree.heading('ID', text='ID', sort_by='num')
        self.tree.column('ID', anchor=CENTER, stretch=NO, width=75 )
        
        self.tree.column('USERNAME', stretch=NO, width=300 )
        self.tree.heading('USERNAME', text='USERNAME', anchor=W, sort_by='name')
        
        self.tree.column('LOGIN/URL', stretch=NO, width=325 )
        self.tree.heading('LOGIN/URL', text='LOGIN/URL', anchor=W, sort_by='name')

        # Filling the Rows
        self.get_records(1)

        # fixme:  tags not working with or without style
        self.tree.tag_configure('odd', background='#EEEEEE')
        self.tree.tag_configure('even', background='white')

    # Get all records from DB
    def get_records(self, recordz=0):

        # cleaning Table 
        records = self.tree.get_children()
        for element in records:
            self.tree.delete(element)

        # see if we are searching or returning default
        # getting data
        if recordz != 1:
            record = self.search.get() 
            query = "SELECT * FROM encrypts where username LIKE ? or login_uri LIKE ? ORDER BY login_uri DESC"
            record = '%' + record + '%'
            db_rows = self.run_query(query, (record, record, ))
            
        else:
            query = 'SELECT * FROM encrypts ORDER BY login_uri DESC'
            db_rows = self.run_query(query)
        
        # filling data, alternating background color
        x = 1
        for row in db_rows:
            if x % 2 == 0:
                # fixme, difference in 0, and 'end' controls sort order, why?
                self.tree.insert("",0,values=[row[0],row[1],row[3]], tags=('odd',))
            else:
                self.tree.insert("",0,values=[row[0],row[1],row[3]], tags=('even',))
            x = x + 1
        
    # show help/instructions
    def show_help(self):
        mb.showinfo("Information", "PLEASE MAKE BACKUPS OF 'encrypteds.db' FILE!!")

        window_help = tk.Toplevel(window_root)
        window_help.geometry('750x750')
        window_help.configure(bg=gvars.grey,  padx=20, pady=20)
        obj = ScrollableFrame(window_help,height=300,width=900 )
        window_help = obj.frame # fixme:  what does obj.frame do? 
        
        frame6 = LabelFrame(window_help, text='What is this?', style="B.TLabelframe", border=0)
        frame6.grid(row=0,column=0, **gvars.opts1)
        msg = gvars.f6
        tk.Message(frame6,text=msg, width=650).grid(row=0, column=0, sticky=W+E, padx=20)

        frame7 = LabelFrame(window_help, text='Encryption Type', style="B.TLabelframe", border=0)
        frame7.grid(row=2,column=0, **gvars.opts1)
        msg = gvars.f7
        tk.Message(frame7,text=msg, width=650).grid(row=0, column=0, sticky=W+E, padx=20)

        frame8 = LabelFrame(window_help, text='How to Encrypt', style="B.TLabelframe", border=0)
        frame8.grid(row=3,column=0, **gvars.opts1)
        msg = gvars.f8
        tk.Message(frame8,text=msg, width=650).grid(row=0, column=0, sticky=W+E, padx=20)

        frame9 = LabelFrame(window_help, text='How to Decrypt', style="B.TLabelframe", border=0)
        frame9.grid(row=4,column=0, **gvars.opts1)
        msg = gvars.f9
        tk.Message(frame9,text=msg, width=650).grid(row=0, column=0, sticky=W+E, padx=20)

        frame10 = LabelFrame(window_help, text='To Do/Fixme', style="B.TLabelframe", border=0)
        frame10.grid(row=4,column=0, **gvars.opts1)
        msg = gvars.f10
        tk.Message(frame10,text=msg, width=650).grid(row=0, column=0, sticky=W+E, padx=20)
    
    # load a modified chrome password dump all at once
    def load_csv(self,inputfile,password):
        import csv
        
        with open(inputfile) as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            
            # modify your csv if this isn't the order
            for row in csv_reader:
                (url,user,passw) = row[0],row[1],row[2]
                encrypted = encrypt_it(passw, password)
                print(encrypted)
                serialized = json.dumps(encrypted)
                query = 'INSERT INTO encrypts VALUES(NULL, ?, ?, ?)'
                parameters = [user,serialized,url]
                run_query(query, parameters)

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
        
        # convert json dictionary to serial string
        d = json.loads(encrypted)

        # decode the dictionary entries from base64
        salt = b64decode(d['salt'])
        cipher_text=b64decode(d['cipher_text'])
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
            msg = '552: All Fields are Required to Save. Keys Must Match'
            self.message['text'] = msg
            mb.showinfo("Information", msg)
        self.get_records(1)

    # delete that entry
    # fixme:  add a delete confirmation prompt
    def delete_password(self):
        self.message['text'] = ''

        # did they select something?
        try:
           self.tree.item(self.tree.selection())['values'][1]
        except IndexError as e:
            msg = '543: Please select a Record'
            self.message['text'] = msg
            mb.showinfo("Information", msg)
            return

        # verify before delete
        result = mb.askquestion("Delete", "Are You Sure?", icon='warning')
        if result == 'yes':
            # clear our message
            self.message['text'] = ''
            
            # guess they did.   Get what they clicked
            id = self.tree.item(self.tree.selection())['values'][0]

            # build query
            query = 'DELETE FROM encrypts WHERE id = ?'

            # run query
            self.run_query(query, (id, ))

            # notify user
            self.message['text'] = 'ID: {} DELETED'.format(id)
        else:
            msg = '588: Record Deletion CANCELLED'
            self.message['text'] = msg

       
        # repopulate the table
        self.get_records(1)

    # edit an entry
    def show_edited(self):
        self.message['text'] = ''
        
        # did they select something?
        try:
            self.tree.item(self.tree.selection())['values'][1]
        except IndexError as e:
            msg = '574: Please, select Record'
            self.message['text'] = msg
            mb.showinfo("Information",msg)
            return
            
        # guess they did.   Get what they clicked
        id = self.tree.item(self.tree.selection())['values'][0]
        user = self.tree.item(self.tree.selection())['values'][1]
        url = self.tree.item(self.tree.selection())['values'][2]
        
        # make new window
        self.window_edit=Toplevel()
        self.window_edit.configure(bg='#dcdad5')
        self.window_edit.title = 'Edit Password'
        
        # get encrypted pass from db for this id
        passw = self.get_password(str(id))
        
        # see if we can decrypt it
        try:
            decrypted = self.decrypt_it(passw,self.key1.get())
        except ValueError as e:
            msg = "596: Decrypt Error (type key in 'KEY1' to unlock)"
            self.message['text'] = msg
            mb.showinfo("Information", msg)
            self.window_edit.destroy()
            self.get_records(1)
            return


        # Old Info Frame
        frame_old = LabelFrame(self.window_edit, text='OLD INFO', style="B.TLabelframe")
        frame_old.grid(row=0, column=0, columnspan=2, pady=20, padx=20)

        # Old Name
        Label(frame_old, text='Old User:', font=('courier', 14, 'bold'),
            foreground=gvars.dblue).grid(row=0, column=1,**gvars.opts2)
        Entry(frame_old, textvariable = StringVar(frame_old, value = user), state = 'readonly'
            ).grid(row=0, column=2)

        # Old Passw
        Label(frame_old, text='Old Password:', font=('courier', 14, 'bold'),
            foreground=gvars.dblue).grid(row=1, column=1,**gvars.opts2)
        Entry(frame_old, textvariable = StringVar(
            frame_old, value=decrypted), state = 'readonly'
            ).grid(row=1, column=2)

        # Old URL
        Label(frame_old, text='Old URL:', font=('courier', 14, 'bold'),
            foreground=gvars.dblue).grid(row=2, column=1,**gvars.opts2)
        Entry(frame_old, textvariable = StringVar(
            frame_old, value = url), state = 'readonly'
            ).grid(row=2, column=2)


        
        # New Info Frame
        frame_new = LabelFrame(self.window_edit, text='NEW INFO', style="B.TLabelframe")
        frame_new.grid(row=0, column=2, columnspan=2, pady=20, padx=20)

        # New Name
        Label(frame_new, text='New User:', font=('courier', 14, 'bold'),
            foreground=gvars.dblue).grid(row=0, column=3,**gvars.opts2)
        new_user= ttk.Entry(frame_new,style="EntryStyle.TEntry")
        new_user.grid(row=0, column=4)

        # New passw
        Label(frame_new, text='New Password:', font=('courier', 14, 'bold'),
            foreground=gvars.dblue).grid(row=1, column=3,**gvars.opts2)
        new_passw = ttk.Entry(frame_new,style="EntryStyle.TEntry")
        new_passw.grid(row=1, column=4)

        # New URL
        Label(frame_new, text='New URL:', font=('courier', 14, 'bold'),
            foreground=gvars.dblue).grid(row=2, column=3,**gvars.opts2)
        new_url= ttk.Entry(frame_new,style="EntryStyle.TEntry")
        new_url.grid(row=2, column=4)



        # Keys Frame
        frame_keys = LabelFrame(self.window_edit, text='PROTECTION KEY', style="B.TLabelframe")
        frame_keys.grid(row=1, column=3, columnspan=2, pady=20, padx=20)
        
        # key1
        Label(frame_keys, text='KEY1:', font=('courier', 14, 'bold'),
            foreground=gvars.dblue).grid(row=1, column=1,**gvars.opts2)
        key1 = ttk.Entry(frame_keys,show="*",style="EntryStyle.TEntry")
        key1.grid(row=1, column=2)

        # key2 (verify)
        Label(frame_keys, text='KEY2:', font=('courier', 14, 'bold'),
            foreground=gvars.dblue).grid(row=2, column=1,**gvars.opts2)
        key2 = ttk.Entry(frame_keys,show="*",style="EntryStyle.TEntry")
        key2.grid(row=2, column=2)


        Button(
            self.window_edit, text='Update', command=lambda: self.save_edited(
            id,
            new_user.get(),
            new_passw.get(),
            new_url.get(),
            key1.get(), key2.get())
            ).grid(row=5, column=3, sticky = W, padx=10, pady=10)
        
        # repopulate table
        self.get_records(1)
        self.window_edit.mainloop()

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
            self.window_edit.destroy()
            
            # notify user
            self.message['text'] = 'Record Saved'
        else:
            # user didn't do something right
            msg = '708: Data Missing or Encryption Keys Do Not Match'
            self.message['text'] = msg
            mb.showinfo("Information", msg)
        
        # repopulate main window table
        self.get_records(1)

def show_error(e):
    print(e)
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
        print(msg)
        self.message['text'] = msg
        mb.showinfo("Information", msg)
        

if __name__ == '__main__':
    # create a db if none exist
    touch_db(gvars.db_name)
    
    # catch the ctrl c and break clean if we can
    try:
        # create class instance of tk.Tk
        window_root = tk.Tk()
        
        # default configurations to override theme
        window_root.configure(bg=gvars.grey)
        window_root.option_add("*Font", "Helvitica 14")
        window_root.option_add("*Label.Font", "Helvitica 18 bold")
        window_root.option_add("*Background", gvars.grey)

        # create instance of class 
        application = Passwords(window_root, gvars.db_name)

        window_root.mainloop()
    except KeyboardInterrupt:
        print("CTRL+C Detected, stopping")
        sys.exit()

