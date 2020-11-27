# Defenz Timely Alerts
This script is used to generate and send block reports for a specific period of time. 
This script can be scheduled by a scheduler e.g. cron to be run at specific times.

`NOTE`: To run this script you need Python 3.6+

## How to install
Clone this repository:
```shell script
git clone https://github.com/InternetNZ/defenz-alerts.git
```
Install the dependencies:
```shell script
cd defenz-alerts
pip3 install -r requirements.txt
```

## Set the configs
Before running the script for the first time you need to configure the script. The config file
is located in ``DEFENZ_ALERTS_DIR/defenz_alerts/config.ini``. If the config file does not exist 
creat one from the sample one:

```shell script
cd DEFENZ_ALERTS_DIR/defenz_alerts/
cp config.sample.ini config.ini
```

The config file should look like below:

```ini
[DEFENZ]
USERNAME =
PASSWORD =
CLIENT_ID =
CLIENT_SECRET =
REPORT_EMAIL =
INTERVAL = 10
LOGIN_ENDPOINT = https://dnsfirewall-auth.defe.nz/auth/realms/D-ZoneFireWall/protocol/openid-connect/token
API_URL = https://dnsfirewall-api.defe.nz

[EMAIL]
SMTP_SERVER =
SMTP_PORT = 465
SMTP_USER =
SMTP_PASSWORD =
SENDER_EMAIL_ADDRESS =
SUBJECT = Defenz Block Report
```

All the attributes are self-descriptive. You don't need to change `LOGIN_ENDPOINT` and `API_URL` as
they are already set to a valid value. `USERNAME`, `PASSWORD`, `CLIENT_ID` and `CLIENT_SECRET` are 
the needed credentials to login to Defenz in order to call the APIs. These can 
be provided as command line parameters as well.

`NOTE`: The default `INTERVAL` is set to 10 minutes. Please don't set it to a lower value as there is
delay in API so data might not show up.

The `EMAIL` section is for setting up SMTP server configurations so the script will be able to email
the alerts to the recipients.

`NOTE`: If email settings are not configured or configured incorrectly, the script won't raise any errors.
It just log a warning in the log file/console. That's useful when you want to run the script for testing purpose
and you don't want send any emails out.

## Run the script
After installing dependencies and setting up the config file, the script should be ready to be run. Use below command to get help:

```shell script
cd DEFENZ_ALERTS_DIR
./defenz_alerts.py -h

usage: defenz_alerts.py [-h] [-u USERNAME] [-p PASSWORD] [-c CLIENT_ID] [-s CLIENT_SECRET] [-e REPORT_EMAIL] [-n [NETWORK_IDS [NETWORK_IDS ...]]] [-r [{MALWARE_PHISHING_BLOCKS,BOT_NET_BLOCK_DETAILS,WEB_FILTER_BLOCKS} [{MALWARE_PHISHING_BLOCKS,BOT_NET_BLOCK_DETAILS,WEB_FILTER_BLOCKS} ...]]] [-i INTERVAL] [-v]

This script is used to send scheduled Defenz alerts by using Defenz APIs.

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        Defenz portal username. Default: read from config file
  -p PASSWORD, --password PASSWORD
                        Defenz portal password. Default: read from config file
  -c CLIENT_ID, --client-id CLIENT_ID
                        Defenz client id (customer name). Default: read from config file
  -s CLIENT_SECRET, --client-secret CLIENT_SECRET
                        Defenz client secret. Default: read from config file
  -e REPORT_EMAIL, --report-email REPORT_EMAIL
                        The report will be sent to this email address if network report email is not set. Default: read from config file
  -n [NETWORK_IDS [NETWORK_IDS ...]], --network-ids [NETWORK_IDS [NETWORK_IDS ...]]
                        List of network ids. Default all networks
  -r [{MALWARE_PHISHING_BLOCKS,BOT_NET_BLOCK_DETAILS,WEB_FILTER_BLOCKS} [{MALWARE_PHISHING_BLOCKS,BOT_NET_BLOCK_DETAILS,WEB_FILTER_BLOCKS} ...]], --report-types [{MALWARE_PHISHING_BLOCKS,BOT_NET_BLOCK_DETAILS,WEB_FILTER_BLOCKS} [{MALWARE_PHISHING_BLOCKS,BOT_NET_BLOCK_DETAILS,WEB_FILTER_BLOCKS} ...]]
                        List of report types. Default MALWARE_PHISHING_BLOCKS and BOT_NET_BLOCK_DETAILS
  -i INTERVAL, --interval INTERVAL
                        Report interval in minute. Default: read from config file
  -v, --verbose         Writes the logs in console as well. Otherwise the logs only will be written in the log files. The log files are located in $HOME/defenz
```

`USERNAME`, `PASSWORD`, `CLIENT_ID`, `CLIENT_SECRET` and `REPORT_EMAIL` can be provided either 
as command line arguments or by [config file](#set-the-configs). Please note these are required and must be provided
in either way.

Assuming the credentials are being provided by command line, the script can be run like this:

```shell script
./defenz_alerts.py -u myusername -p mysecurepassword -c myclientid -s myclientsecret -e myemail@example.com -v
```

In this example the script search all the networks to find anomaly events in the last 10 
minutes. Then email the reports to report emails set on the networks. If 
report email is not set, the reports will be sent to `myemail@example.com`. The logs will be written in
standard output as well as log file.


As another example, below command runs the script only for two networks and search them for
any events in last 10 minutes. 

```shell script
./defenz_alerts.py -u myusername -p mysecurepassword -c myclientid -s myclientsecret -e myemail@example.com -i 10 -n 120 130 -v
```

## How to schedule the script
This script can be scheduled by a scheduler e.g. `cron` to be run periodically. For example, 
to run the script every 10 minutes put below command in your crontab file.
```shell script
*/10 * * * * PATH_TO_DEFENZ_ALERTS_DIR/defenz_alerts.py -u myusername -p mysecurepassword -c myclientid -s myclientsecret -e myemail@example.com -i 10
```
