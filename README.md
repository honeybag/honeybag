# Honeybag 
Honeybag is a tool that helps you to create a 'bait archive' with any folders and files, notify you if someone accesses it. This can be useful for data breach detection, deception defense mechanism, etc.

## How it works:
What if we can easily create a tailor-made secret.zip archive, with any embedded files (e.g. document.pdf, secret.doc), and we will be notified if someone unzip and accesses it? 

With Honeybag, we can easily create this ZIP archive, with highly customizable configurations. Honeybag will add custom desktop.ini and/or .url shortcut files into the ZIP archive. It leverages on the custom UNC path and sends alerts with DNS or SMB network protocol.

## Getting started
### Prerequisites (minimal setup)
- a domain name  
- a host (Ubuntu preferably) with public IP address for Honeybag / Honeybag Simple DNS Server / RESPONDER 


## Setup (10 easy steps)
#### Part 1 - Domain name
1. Make sure you have a domain name (e.g. yourdomain.abc) with configurable Nameserver
2. Point the Nameserver of the domain (e.g. yourdomain.abc) to a custom Nameserver (e.g. ns.yourdomain.abc)
3. Set the A record of the custom Nameserver (e.g. ns.yourdomain.abc) to the public IP address which you will use to setup Honeybag Simple DNS Server

#### Part 2 - On the host  
4. Clone this repo to the host using `git clone https://github.com/honeybag/honeybag.git`
5. Copy `conf/honeybag.conf.dist` to `conf/honeybag.conf`
6. Edit the `conf/honeybag.conf` with your domain name and/or IP address to receive alerts. You can choose to further customise honeybag.conf or leave it with the default setting
```
[honeybag-config]

domain                    = yourdomain.abc
ip_address                = 127.0.0.1
<leave others as default>
```
#### Part 3 - Honeybag - Create the custom ZIP archive
7. You can include any file in the ZIP archive. Place the file in the folder `./mainfolder/input/` 
8. Generate the custom ZIP archive with honeybag.py
```
$ python3 honeybag.py
  _   _                        _                 
 | | | | ___  _ __   ___ _   _| |__   __ _  __ _ 
 | |_| |/ _ \| '_ \ / _ \ | | | '_ \ / _` |/ _` |
 |  _  | (_) | | | |  __/ |_| | |_) | (_| | (_| |
 |_| |_|\___/|_| |_|\___|\__, |_.__/ \__,_|\__, |
                         |___/             |___/ 
                                                 
[INFO] - WELCOME TO HONEYBAG!
[INFO] - Reading configuration from honeybag.conf file: 
[INFO] - + domain                       : yourdomain.abc
[INFO] - + IP address                   : 127.0.0.1
[INFO] - + alert mode 'desktop.ini'     : True
[INFO] - + alert mode 'url shortcut'    : True
[INFO] - + token length                 : 6
[INFO] - + token value                  : 
[INFO] - + token description            : this is my first honeybag token
[INFO] - + url shortcut link            : http://placetherealshortcuturlhere.com
[INFO] - + url shortcut file name       : placetherealshortcuturlhere.com
[INFO] - + folder name in ZIP archive   : secretfolder
[INFO] - + final ZIP archive name       : secret.zip

Continue to create a custom ZIP archive with the configuration ? [Y/n] [ENTER]
 
[INFO] - Generate new token value       : drly5h
[INFO] - New token details are stored in database successfully
[INFO] - Generating desktop.ini
[INFO] - Generating placetherealshortcuturlhere.com.url
[INFO] - Adding file to new ZIP archive : secretfolder/placetherealshortcuturlhere.com.url
[INFO] - Adding file to new ZIP archive : secretfolder/anydocument.pdf
[INFO] - Adding file to new ZIP archive : secretfolder/desktop.ini
[INFO] - Done! You can find your custom generated ZIP archive in mainfolder/output-final/secret.zip
```
#### Part 4 - Honeybag Simple DNS Server
9. Start the Honeybag Simple DNS Server on the host with port UDP/53
```
$ sudo python3 honeybag-dnsserver.py --udp --port 53
  _   _                        _                   ____  _   _ ____  
 | | | | ___  _ __   ___ _   _| |__   __ _  __ _  |  _ \| \ | / ___| 
 | |_| |/ _ \| '_ \ / _ \ | | | '_ \ / _` |/ _` | | | | |  \| \___ \ 
 |  _  | (_) | | | |  __/ |_| | |_) | (_| | (_| | | |_| | |\  |___) |
 |_| |_|\___/|_| |_|\___|\__, |_.__/ \__,_|\__, | |____/|_| \_|____/ 
                         |___/             |___/                     
                                                                     
2020-09-30 19:25:48+0000 - [INFO] - Starting Honeybag simple DNS server...
2020-09-30 19:25:48+0000 - [INFO] - UDP server loop running in thread: Thread-1
```

#### Part 5 - Setup RESPONDER (Optional)
10. You may setup RESPONDER on the host from the official Github https://github.com/lgandx/Responder, and run it with
`python Responder.py -I eth0 -rv`

#### Here we go!
Place the custom generated ZIP archive somewhere. If someone unzip and access it in a Windows environment, we will have the alerts in Honeybag Simple DNS Server / RESPONDER. Bingo!

## Logging
Honeybag will store the generated token details and data collected from Simple DNS Server in:
- `log/honeybag.sqlite`
- `log/honeybag-dns.log`

## Limitation
As of current development, the alert mechanism with UNC path will only be applicable for Windows environment. In other words, if someone accesses the ZIP archive in Windows environment, this will trigger the alerts. We are looking for new alert mechanisms for *nix or OSX in future development.

## Acknowledgments
This project is inspired by Thinkst Applied Research Canarytokens open source project and others. Thank you!
