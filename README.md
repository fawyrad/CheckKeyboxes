# **CheckKeyboxes**

A Python script to batch process a directory with keybox XML files.

**What it does:**
- checks for valid keybox XML files
- checks for duplicated keybox XML files
- checks if keybox has been revoked
- checks if keybox has expired
- checks if keybox is software signed
- renames valid XML files to keybox_<checksum>.xml
- takes one of valid XML files and renames it to current_keybox_<checksum>.xml
- puts current_keybox_<checksum>.xml as keybox.xml in selected location (OneDrive for example) - only if current_keybox_<checksum>.xml has been revoked, has expired or hasn't existed before running the script

**How to use:**
1. Place check_keyboxes.py in selected directory.
2. Create a new "keyboxes" directory in the same location as check_keyboxes.py.
3. Put all your keybox XML files to "keyboxes" directory.
4. Edit check_keyboxes.py and change target_path variable on top of the file to the path you'd like to copy current_keybox_<checksum>.xml to.
5. Run check_keyboxes.py.

**Credits:**
- badabing2005 for PixelFlasher - https://github.com/badabing2005/PixelFlasher
- hldr4 for checkKB.py - https://gist.github.com/hldr4/b933f584b2e2c3088bcd56eb056587f8
