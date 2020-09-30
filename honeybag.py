#!/usr/bin/env python

import os
import shutil
import zipfile
import string
import random
import sqlite3
import time
import logging
from configparser import ConfigParser

current_dir = os.path.dirname(__file__)

logging.basicConfig(format='[%(levelname)s] - %(message)s', level=logging.INFO)

def main():

    print("  _   _                        _                 ")
    print(" | | | | ___  _ __   ___ _   _| |__   __ _  __ _ ")
    print(" | |_| |/ _ \| '_ \ / _ \ | | | '_ \ / _` |/ _` |")
    print(" |  _  | (_) | | | |  __/ |_| | |_) | (_| | (_| |")
    print(" |_| |_|\___/|_| |_|\___|\__, |_.__/ \__,_|\__, |")
    print("                         |___/             |___/ ")
    print("                                                 ")

    logging.info('WELCOME TO HONEYBAG!');

    # reading configuration from ./conf/honeybag.conf
    logging.info('Reading configuration from honeybag.conf file: ');
    parser = ConfigParser()
    try:
        with open('./conf/honeybag.conf') as config:
            parser.read_file(config)
    except IOError:
        logging.error("Missing honeybag.conf file. Please make sure honeybag.conf is located in ./conf folder")
        return False

    domain = parser.get('honeybag-config','domain')
    ip_addr = parser.get('honeybag-config','ip_address')
    alert_mode_desktop_ini = parser.getboolean('honeybag-config','alert_mode_desktop_ini')
    alert_mode_url_shortcut = parser.getboolean('honeybag-config','alert_mode_url_shortcut')
    token_length = int(parser.get('honeybag-config','token_length'))
    token_value = parser.get('honeybag-config','token_value')
    token_description = parser.get('honeybag-config','token_description')
    url_shortcut_link = parser.get('honeybag-config','url_shortcut_link')
    url_shortcut_file_name = parser.get('honeybag-config','url_shortcut_file_name')
    folder_name_in_zip_file = parser.get('honeybag-config','folder_name_in_zip_file')
    file_name_final_zip_file = parser.get('honeybag-config','file_name_final_zip_file')

    logging.info('+ domain                       : ' + domain)
    logging.info('+ IP address                   : ' + ip_addr)
    logging.info('+ alert mode \'desktop.ini\'     : ' + str(alert_mode_desktop_ini))
    logging.info('+ alert mode \'url shortcut\'    : ' + str(alert_mode_url_shortcut))
    logging.info('+ token length                 : ' + str(token_length))
    logging.info('+ token value                  : ' + token_value)
    logging.info('+ token description            : ' + token_description)
    logging.info('+ url shortcut link            : ' + url_shortcut_link)
    logging.info('+ url shortcut file name       : ' + url_shortcut_file_name)
    logging.info('+ folder name in ZIP archive   : ' + folder_name_in_zip_file)
    logging.info('+ final ZIP archive name       : ' + file_name_final_zip_file)

    # for alert mode 'desktop.ini', we need a valid domain name to receive alerts
    if alert_mode_desktop_ini:
        if domain == "":
            logging.error('For alert mode \'desktop.ini\', please add a valid domain name in the honeybag.conf file')
            return False

    # for alert mode 'URL shortcut', we need a IP address with RESPONDER setup
    if alert_mode_url_shortcut:
        if ip_addr == "":
            logging.error('For alert type \'URL shortcut\', please add a valid IP address in the honeybag.conf file')
            return False

    yes = {'yes','y', 'ye', ''}
    no = {'no','n'}

    while True:
        choice = input("\nContinue to create a custom ZIP archive with the configuration ? [Y/n] [ENTER]").lower()
        if choice in yes:
           break
        elif choice in no:
           return False
        else:
            return False

    print(' ')

    # if no custom token_value in the honeybag.conf, generate a new token value
    if token_value == "" :
        if token_length is None:
            token_value = generate_token(6)
            logging.info('Generate new token value       : ' + token_value)
        elif token_length < 6 or token_length > 6:
            token_value = generate_token(token_length)
            logging.info('Generate new token value       : ' + token_value)
        else:
            token_value = generate_token(6)
            logging.info('Generate new token value       : ' + token_value)

    try:
        # For the first run of Honeybag, generate a new database - honeybag.sqlite
        if not os.path.isfile('./log/honeybag.sqlite'):
            create_sqlite_db()

        conn1 = sqlite3.connect('./log/honeybag.sqlite')
        ts = time.time()
        if alert_mode_desktop_ini:
            conn1.execute("INSERT INTO token \
                (timestamp_creation, alert_mode, token_value, token_description, domain) \
                VALUES (?, ?, ?, ?, ?);", (ts, 'ini', token_value, token_description, domain))
        if alert_mode_url_shortcut:
            conn1.execute('INSERT INTO token \
                (timestamp_creation, alert_mode, token_value, token_description, ip_address) \
                VALUES (?, ?, ?, ?, ?);', (ts, "url", token_value, token_description, ip_addr))

        conn1.commit()

    except sqlite3.Error as error:
        logging.error('SQL error', error)
    finally:
        if (conn1):
            conn1.close
            logging.info('New token details are stored in database successfully')

    generate_alert_file(alert_mode_desktop_ini, alert_mode_url_shortcut, token_value, domain, ip_addr, 
        url_shortcut_link, url_shortcut_file_name, folder_name_in_zip_file, file_name_final_zip_file)


def generate_token(size=6, chars=string.ascii_lowercase + string.digits):

    return ''.join(random.choice(chars) for _ in range(size))


def create_sqlite_db():

    conn = sqlite3.connect('./log/honeybag.sqlite')
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS token (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        timestamp_creation INTEGER, 
        alert_mode TEXT, 
        token_value TEXT, 
        token_description TEXT, 
        domain TEXT, 
        ip_address TEXT)''')

    c.execute('''CREATE TABLE IF NOT EXISTS hits_domain_not_matched (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        timestamp_hits INTEGER, 
        source_ip TEXT, 
        source_port INTEGER, 
        domain TEXT)''')

    c.execute('''CREATE TABLE IF NOT EXISTS hits_domain_matched (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        timestamp_hits INTEGER, 
        source_ip TEXT, 
        source_port INTEGER, 
        computer_domain TEXT, 
        computer_hostname TEXT, 
        computer_username TEXT, 
        token_value TEXT, 
        domain TEXT)''')

    conn.commit()
    conn.close()


def generate_alert_file (alert_mode_ini, alert_mode_url, token_value, domain, ip_addr, url_shortcut_link, 
    url_shortcut_file_name, folder_name_in_zip_file, file_name_final_zip_file):

    if alert_mode_ini:
        logging.info('Generating desktop.ini')
        content = "\\\\%USERNAME%.%COMPUTERNAME%.%USERDOMAIN%." + token_value + "."+ domain
        logging.debug(content)

        with open(current_dir + 'mainfolder/input/desktop.ini', 'w', newline='\r\n') as the_file:
            the_file.write('[.ShellClassInfo]\n')
            the_file.write('IconFile=' + content + '\\icon.ico' + '\n')

    if alert_mode_url:
        shortcut_filename_url = url_shortcut_file_name +".url"
        logging.info('Generating ' + shortcut_filename_url)

        with open(current_dir + 'mainfolder/input/' + shortcut_filename_url, 'w', newline="\r\n") as the_file:
            the_file.write('[InternetShortcut]\n')
            the_file.write('URL=' + url_shortcut_link + '\n')
            the_file.write('IconFile=\\\\' + ip_addr + '\\icon.ico'+'\n')
            the_file.write('IconIndex=0\n')

    # As an overview, each folder is designed to serve the following purposes:
    # 1. folder 'input': we can put any text files, PDF, documents, etc as decoy files in this folder
    # 2. folder 'temp' : during the ZIP archive creation process, Honeybag creates a new folder 
    #    (with the name which specified in honeybag.conf) under folder 'temp'. The folder 'temp' serves as an intermediate folder
    # 3. folder 'output-final': The final ZIP archive will be in here (with the name which specified in honeybag.conf)

    # if the 'temp' folder exists under parent folder 'mainfolder', delete it and its contents recursively 
    if os.path.exists(current_dir+'mainfolder/temp'):
        try:
            shutil.rmtree(current_dir+'mainfolder/temp')
        except OSError as e:
            logging.error("Error: %s - %s." % (e.filename, e.strerror))

    # copy all content from mainfolder/inputs to mainfolder/temp
    shutil.copytree(current_dir + 'mainfolder/input', current_dir + 'mainfolder/temp/' + folder_name_in_zip_file)

    # for files and folders in mainfolder/temp, set the file or folder access and modified times to current time
    for dirpath, _, filenames in os.walk(current_dir + 'mainfolder/temp/' + folder_name_in_zip_file):
        os.utime(dirpath,None)
        for file in filenames:
            os.utime(os.path.join(dirpath, file), None)

    generate_zip(folder_name_in_zip_file, file_name_final_zip_file)


def generate_zip(folder_name_in_zip_file, file_name_final_zip_file):

    old_path = os.getcwd()
    os.chdir(current_dir + 'mainfolder/output-final')

    relroot = os.path.abspath(os.path.join(current_dir + '../temp/' + folder_name_in_zip_file , os.pardir))
    logging.debug('relroot: ' + relroot)

    with zipfile.ZipFile(file_name_final_zip_file, "w", zipfile.ZIP_DEFLATED) as zip:
        for root, dirs, files in os.walk(current_dir + '../temp'):
            logging.debug('root: ' + root)
            logging.debug(dirs)
            logging.debug(files)
            for dir in dirs:
                info_dir=zipfile.ZipInfo(dir,date_time=time.localtime(time.time())[:6])
                info_dir.external_attr = 0x10
                info_dir.external_attr |= 0x04
                info_dir.filename = dir + '/'
                info_dir.compress_type = 0
                info_dir.create_system = 0
                info_dir.create_version = 20
                info_dir.extract_version = 20
                zip.writestr(info_dir,'')
            for file in files:
                filename = os.path.join(root, file)
                if os.path.isfile(filename): # regular files only
                    # 'filename' is the file path + file name on local machine
                    # 'arcname' is the designated file path + file name which will be appeared in the ZIP archive
                    arcname = os.path.join(os.path.relpath(root, relroot), file)
                    logging.debug('filename: ' + filename)
                    logging.debug('arcname: ' + arcname)
                    if  filename.endswith('.gitkeep'):
                        continue
                    logging.info('Adding file to new ZIP archive : ' + arcname)
                    if filename.endswith('.ini'):
                        logging.debug('filename .INI: ' + filename)
                        f = open(filename, 'r', newline='')
                        data = f.read()
                        f.close
                        info_file=zipfile.ZipInfo(arcname)
                        # https://docs.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants
                        # FILE_ATTRIBUTE_NORMAL 0x80
                        # FILE_ATTRIBUTE_HIDDEN 0x02
                        # FILE_ATTRIBUTE_SYSTEM 0x04
                        info_file.external_attr = 0x80
                        info_file.external_attr |= 0x02
                        info_file.external_attr |= 0x04
                        info_file.compress_type = 8
                        info_file.create_system = 0
                        info_file.create_version = 20
                        info_file.extract_version = 20
                        zip.writestr(info_file, data)
                    elif filename.endswith('.url'):
                        logging.debug('filename .URL: ' + filename)
                        f = open(filename, 'r', newline='')
                        data = f.read()
                        f.close
                        info_file1=zipfile.ZipInfo(arcname)
                        info_file1.external_attr = 0x80
                        info_file1.external_attr |= 0x02
                        info_file1.compress_type = 8
                        info_file1.create_system = 0
                        info_file1.create_version = 20
                        info_file1.extract_version = 20
                        zip.writestr(info_file1, data)
                    else:
                        zip.write(filename, arcname)

    logging.info('Done! You can find your custom generated ZIP archive in ' + 'mainfolder/output-final/' 
    	+ file_name_final_zip_file + '\n')


if __name__ == '__main__':
    main()
