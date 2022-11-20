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

ppk_version = '1.0.4'
db_name = "encrypteds."+ppk_version+".db"

f6 = """
This python script saves passwords in a sqlite database. The password portion of each entry is encrypted, but user name and login location is not.  Every entry is protected with a different key, so you can share the database freely, and only give the password unlock for the record you want them to view.
"""

f7 = """
The python module Cryptodome.Cipher is using AES 128 with the GCM cipher. It is also salting the password and storing it base 64 so it is compatible with sqlite (stored as a json dictionary).

The base64 is decoded, then the string is decrypted when you enter the proper key. Galois/Counter Mode is defined in http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf  if you are interested in the stuff I am unable to accurately explain!

Here are the module docs:  https://pycryptodome.readthedocs.io/en/latest/src/cipher/modern.html#gcm-mode
"""

f8 = """
Type information in the fields provided.    The "password" is the only field that is encrypted.  It is unlocked using the KEY1 decryption key. KEY1 and KEY2 must match.   This is your unlock key when you want to view the password.

14 characters is sufficient to stop most brute force attacks, and that is the suggested (not forced), minimum key length.    

It does no good to use strong encryption if your unlock key is weak.   Use a good password that is not a dictionary word, or combination of dictionary words.   Here is an example of a good password:

ILikeCoffee!NotStarBuck$

Something like this is easy to remember, but hard to break.
"""

f9 = """
To unlock the vault for your record, type the key in "KEY1" filed then click "edit". This is also the method to change anything such as the login, user, password or your unlock key.
"""

f10 = """
-------------
FIX
-------------
# fixme: add a delete confirmation prompt
# fixme: alternating colors not working
# fixme: verify precisely for documentation what mainloop does
# fixme: mousewheel is not working as expected
# fixme: move this to data module out of main code
-------------
ADD FEATURE
-------------
# todo:  add categories/folders instead of simple records
# todo:  give option to load file of their choice
# todo:  add simple backup button for file.datestamp.db
# todo:  add option to encrypt spreadsheet/csv
# todo:  search logins/urls
# done:  sort by column header choice
-------------
VERSION HISTORY
-------------
1.0.0
- Put initial on Github
1.0.1
- fix no click on delete
- cosmetic code reformatting
1.0.2
- auto create db if not exist
- cosmetic code reformatting
- More help documentation
- grammar touch ups
- modify db name and title to have version name
1.0.3
- tested function and added bulk encrypt, not connected
1.0.4
- sort by column added
- minor code cosmetic reformatting

"""