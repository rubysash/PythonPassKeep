# PythonPassKeep
PassKeep Clone written in Python.   AES  Encrypted SQLite tkinter UI

## gvars.py

My crude attempt at cleaning up code

## python_passkeep.py

Will create db file if table doesn't exist.    It is a basic version of a password vault.    

## Installation

To install modules/windows
```bash
python -m pip install --upgrade pip
pip3 install tkinter
pip3 install base64
pip3 install hashlib
pip3 install pycrypttodome
```
To install on modules/Linux (Debian 10 at least):
```bash
sudo apt-get install python3-tk
pip3 install pybase64
pip3 isntall pycryptodomex
```

![picture alt](https://github.com/rubysash/PythonPassKeep/blob/main/pythonpasskeep.png?raw=true)

## FIX
- fixme: add a delete confirmation prompt
- fixme: alternating colors not working
- fixme: verify precisely for documentation what mainloop does
- fixme: mousewheel is not working as expected
- fixme: move this to data module out of main code

## ADD FEATURE
- todo: add categories/folders instead of simple records
- todo: give option to load file of their choice
- todo: add simple backup button for file.datestamp.db
- todo: add option to encrypt spreadsheet/csv
- todo: search logins/urls
- todo: load default "old" into "new" as default when editing
- done: sort by column header choice

## VERSION HISTORY
### 1.0.0
- Put initial on Github
### 1.0.1
- fix no click on delete
- cosmetic code reformatting
### 1.0.2
- auto create db if not exist
- cosmetic code reformatting
- More help documentation
- grammar touch ups
- modify db name and title to have version name
### 1.0.3
- tested function and added bulk encrypt, not connected
### 1.0.4
- sort by column added
- minor code cosmetic reformatting
