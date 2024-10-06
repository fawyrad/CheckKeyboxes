# **CheckKeyboxes**

A Python script to batch process a directory with keybox XML files.

**What it does:**
- checks if XML files are valid keybox XML files
- checks for duplicated keybox XML files
- checks if keybox has been revoked
- checks if keybox has expired
- checks if keybox is software signed
- renames valid XML files to _keybox_{checksum}.xml_
- takes one of valid XML files and renames it to _current_keybox_{checksum}.xml_
- puts _current_keybox_{checksum}.xml_ as _keybox.xml_ in a selected location (OneDrive for example) - only if _current_keybox_{checksum}.xml_ has been revoked, has expired or hasn't existed before running the script

**How to use:**
1. Place _check_keyboxes.py_ in selected directory.
2. Create a new _keyboxes_ directory in the same location as _check_keyboxes.py_.
3. Put all your keybox XML files to _keyboxes_ directory.
4. Edit _check_keyboxes.py_ and change _target_path_ variable on top of the file to the path you'd like to copy _current_keybox_{checksum}.xml_ to.
5. Run _check_keyboxes.py_.

**Credits:**
- badabing2005 for PixelFlasher - https://github.com/badabing2005/PixelFlasher
- hldr4 for checkKB.py - https://gist.github.com/hldr4/b933f584b2e2c3088bcd56eb056587f8
