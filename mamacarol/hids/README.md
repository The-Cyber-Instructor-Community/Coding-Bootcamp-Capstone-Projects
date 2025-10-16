## HIDS
by Carol On
October 10, 2025

Host-based Intrusion Detection System (HIDS): Monitor system processes Data files integrity for signs of compromise Real-time Alerts, 
created OAuth2 for Google to email alerts, custom argument to set alert feature on/off (-a alerts_on) 
Customized patterns and security rules, with file rules.txt and packets.txt

Required packages
pip3 install psutil pip3 install python-dotenv pip3 uninstall oauth2client pip3 install oauth2client

RUN Script
python3 ids.py rules.txt packets.txt -a alerts_on
