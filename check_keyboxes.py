import os
import hashlib
import shutil
import requests
import sys
import pytz
from lxml import etree
from datetime import datetime
from cryptography import x509

target_path = 'E:\\Gleniu\\OneDrive\\Android\\keybox\\'

# Funtion to clean XML files and check if they are valid
def clean_xml_file(file_path):
    is_valid_xml = None
    parser = etree.XMLParser(recover=True)
    try:
        tree = etree.parse(file_path, parser)
        if tree.getroot() is not None:
            with open(file_path, 'wb') as cleaned_file:
                cleaned_file.write(etree.tostring(tree, pretty_print=True, encoding='UTF-8', xml_declaration=True))
            is_valid_xml = True
        else:
            is_valid_xml = False
    except:
        is_valid_xml = False
    return is_valid_xml

# Function to compute the MD5 hash of a file
def compute_file_hash(file_path):
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as f:
        for byte_block in f:
            md5_hash.update(byte_block)
    return md5_hash.hexdigest()

# Function to check a single keybox
def check_keybox(file_path):
    expiry_date = None
    is_sw_signed = None
    is_revoked = None
    parser = etree.XMLParser(recover=True)
    tree = etree.parse(file_path, parser)
    certs = [elem.text for elem in tree.getroot().iter() if elem.tag == 'Certificate']
    for cert in certs:
        cert = "\n".join(line.strip() for line in cert.strip().split("\n"))
        parsed = x509.load_pem_x509_certificate(cert.encode())
        certs_expiry_dates.append(parsed.not_valid_after_utc)
        if "Software Attestation" in str(parsed.issuer):
            is_sw_signed = True
        sn = f'{parsed.serial_number:x}'
        if sn in crl["entries"].keys():
            is_revoked = True
    expiry_date = min(certs_expiry_dates)
    keyboxes_expiry_dates.append(expiry_date)
    return expiry_date, is_sw_signed, is_revoked
    
def request_with_fallback(method, url, headers=None, data=None, stream=False):
    response = 'ERROR'
    try:
        response = requests.request(method, url, headers=headers, data=data, stream=stream)
        response.raise_for_status()
    except requests.exceptions.SSLError:
        # Retry with SSL certificate verification disabled
        print(f"WARNING! Encountered SSL certification error while connecting to: {url}.")
        print("Retrying with SSL certificate verification disabled.")
        print("For security, you should double check and make sure your system or communication is not compromised.")
        response = requests.request(method, url, headers=headers, data=data, verify=False, stream=stream)
    except requests.exceptions.HTTPError as err:
        print(f"HTTP error occurred: {err}")
    except requests.exceptions.Timeout:
        print("The request timed out")
    except requests.exceptions.TooManyRedirects:
        print("Too many redirects")
    except requests.exceptions.RequestException as err:
        print(f"An error occurred: {err}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    return response

url = "https://android.googleapis.com/attestation/status"
crl = request_with_fallback(method='GET', url=url, headers={'Cache-Control': 'max-age=0'})
if crl is not None and crl != 'ERROR':
    crl = crl.json()
else:
    print(f"\nERROR: Could not fetch CRL from {url}.")
    print("\nScript failed. Check your internet connection or try again later.")
    input("\nPress Enter to exit...")
    sys.exit()

utc = pytz.UTC
current_directory = os.path.dirname(os.path.realpath(__file__))
keyboxes_directory = os.path.join(current_directory, 'keyboxes')
invalid_directory = os.path.join(keyboxes_directory, 'invalid')
if not os.path.exists(invalid_directory):
    os.makedirs(invalid_directory)
valid_files = []
current_moved = False
current_hash = None
seen_hashes = set()
processed_files = 0
revoked_keyboxes = 0
expired_keyboxes = 0
sw_signed_keyboxes = 0
invalid_files = 0
duplicate_keyboxes = 0
keyboxes_expiry_dates = []
current_keybox = None

print("Checking XML files...")
for filename in os.listdir(keyboxes_directory):
    file_path = os.path.join(keyboxes_directory, filename)
    if filename.endswith(".xml"):
        is_valid_xml = clean_xml_file(file_path)
        if is_valid_xml == True:
            if filename.startswith("current_"): 
                file_hash = compute_file_hash(file_path)
                current_hash = file_hash
                new_filename = "current_keybox_"+file_hash[:6]+".xml"
                current_keybox = new_filename
                if filename != new_filename:
                    destination = os.path.join(keyboxes_directory, new_filename)
                    print(f"\n{filename} is a valid XML file. Renaming {filename} to {new_filename}...")
                    shutil.move(file_path, destination)
            else:
                file_hash = compute_file_hash(file_path)
                new_filename = "keybox_"+file_hash[:6]+".xml"
                if filename != new_filename:
                    destination = os.path.join(keyboxes_directory, new_filename)
                    counter = 1
                    while os.path.exists(destination):
                        new_filename = new_filename[:-4] + f"_0{counter}" + ".xml"
                        destination = os.path.join(keyboxes_directory, new_filename)
                        counter += 1
                    print(f"\n{filename} is a valid XML file. Renaming {filename} to {new_filename}...")
                    shutil.move(file_path, destination)
        else:
            new_filename = "invalid_" + filename
            destination = os.path.join(invalid_directory, new_filename)
            print(f"\n{filename} is not a valid XML file. Moving as {new_filename} to invalid directory.")
            shutil.move(file_path, destination)
            invalid_files += 1
        processed_files += 1

print('\nProcessing valid XML files...')
print('--------------------------------------')
for filename in os.listdir(keyboxes_directory):
    file_path = os.path.join(keyboxes_directory, filename)
    certs_expiry_dates = []
    is_sw_signed = False
    is_revoked = False
    if filename.endswith(".xml"):
        print(f"{filename}:")
        if filename == current_keybox:
            try:
                expiry_date, is_sw_signed, is_revoked = check_keybox(file_path)
                if is_revoked:
                    new_filename = 'revoked_' + filename[len("current_"):]
                    destination = os.path.join(invalid_directory, new_filename)
                    current_moved = True
                    print(f"Revoked: Yes\nKeybox is revoked. Moving as {new_filename} to invalid directory.")
                    shutil.move(file_path, destination)
                    revoked_keyboxes += 1
                elif expiry_date < utc.localize(datetime.now()):
                    new_filename = 'expired_' + filename
                    destination = os.path.join(invalid_directory, new_filename)
                    current_moved = True
                    print(f"Revoked: No\nExpired on: {expiry_date}\nKeybox is expired. Moving as {new_filename} to invalid directory.")
                    shutil.move(file_path, destination)
                    expired_keyboxes += 1
                elif is_sw_signed:
                    new_filename = 'sw_signed_' + filename
                    destination = os.path.join(invalid_directory, new_filename)
                    current_moved = True
                    print(f"Revoked: No\nExpires on: {expiry_date}\nKeybox is software signed and not hardware-backed. Moving as {new_filename} to invalid directory.")
                    shutil.move(file_path, destination)
                    sw_signed_keyboxes += 1
                else:
                    valid_files.append(file_path)
                    print(f"Revoked: No\nExpires on: {expiry_date}")
            except:
                new_filename = "invalid_" + filename
                destination = os.path.join(invalid_directory, new_filename)
                current_moved = True
                print(f"File is not a valid keybox. Moving as {new_filename} to invalid directory.")
                shutil.move(file_path, destination)
                invalid_files += 1
        else:
            file_hash = compute_file_hash(file_path)
            if file_hash in seen_hashes or file_hash == current_hash:
                new_filename = 'duplicate_' + filename
                destination = os.path.join(invalid_directory, new_filename)
                print(f"Keybox is duplicated. Moving as {new_filename} to invalid directory.")
                shutil.move(file_path, destination)
                duplicate_keyboxes += 1
            else:
                seen_hashes.add(file_hash)
                try:
                    expiry_date, is_sw_signed, is_revoked = check_keybox(file_path)
                    if is_revoked:
                        new_filename = 'revoked_' + filename
                        destination = os.path.join(invalid_directory, new_filename)
                        print(f"Revoked: Yes\nKeybox is revoked. Moving as {new_filename} to invalid directory.")
                        shutil.move(file_path, destination)
                        revoked_keyboxes += 1
                    elif expiry_date < utc.localize(datetime.now()):
                        new_filename = 'expired_' + filename
                        destination = os.path.join(invalid_directory, new_filename)
                        print(f"Revoked: No\nExpired on: {expiry_date}\nKeybox is expired. Moving as {new_filename} to invalid directory.")
                        shutil.move(file_path, destination)
                        expired_keyboxes += 1
                    elif is_sw_signed:
                        new_filename = 'sw_signed_' + filename
                        destination = os.path.join(invalid_directory, new_filename)
                        print(f"Revoked: No\nExpires on: {expiry_date}\nKeybox is software signed and not hardware-backed. Moving as {new_filename} to invalid directory.")
                        shutil.move(file_path, destination)
                        sw_signed_keyboxes += 1
                    else:
                        valid_files.append(file_path)
                        print(f"Revoked: No\nExpires on: {expiry_date}")
                except:
                    new_filename = "invalid_" + filename
                    destination = os.path.join(invalid_directory, new_filename)
                    print(f"File is not a valid keybox. Moving as {new_filename} to invalid directory.")
                    shutil.move(file_path, destination)
                    invalid_files += 1
        print('--------------------------------------')

print(f"""
Total XML files processed: {processed_files}
Invalid XML files:         {invalid_files}
Duplicated keyboxes:       {duplicate_keyboxes}
Revoked keyboxes:          {revoked_keyboxes}
Expired keyboxes:          {expired_keyboxes}
Software signed keyboxes:  {sw_signed_keyboxes}

Valid keyboxes left:       {len(valid_files)}""")

if valid_files:
    print(f"\nThe longest valid keybox will expire on {max(keyboxes_expiry_dates).date()}.")
    if current_keybox == None:
        valid_file = valid_files[0]
        valid_file_filename = os.path.basename(valid_file)
        current_copy_path = os.path.join(keyboxes_directory, f"current_{valid_file_filename}")
        shutil.move(valid_file, current_copy_path)
        print('\n--------------------------------------')
        print(f"\nRenaming {valid_file_filename} to current_{valid_file_filename}...")
        print(f"\nCopying current_{valid_file_filename} to {target_path} as keybox.xml...")
        if not os.path.exists(target_path):
            os.makedirs(target_path)
        shutil.copyfile(current_copy_path, target_path + 'keybox.xml')
        print("\nPlease copy keybox.xml to /data/adb/tricky_store.")
    elif current_moved:
        valid_file = valid_files[0]
        valid_file_filename = os.path.basename(valid_file)
        current_copy_path = os.path.join(keyboxes_directory, f"current_{valid_file_filename}")
        shutil.move(valid_file, current_copy_path)
        print('\n--------------------------------------')
        print(f"\nCurrent keybox was revoked or expired. Renaming {valid_file_filename} to current_{valid_file_filename}...")
        print(f"\nCopying current_{valid_file_filename} to {target_path} as keybox.xml...")
        if not os.path.exists(target_path):
            os.makedirs(target_path)
        shutil.copyfile(current_copy_path, target_path + 'keybox.xml')
        print("\nPlease copy new keybox.xml to /data/adb/tricky_store.")
else:
    print('\n--------------------------------------')
    print("\nNo valid keyboxes available at this time. Search for a new keybox.")

print('\n--------------------------------------')
input("\nDone. Press Enter to exit...")