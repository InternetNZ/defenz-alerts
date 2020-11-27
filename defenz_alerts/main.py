#!/usr/bin/env python3
"""
This script is used to send scheduled Defenz alerts by using Defenz APIs.
"""
import argparse
import logging
import smtplib
import traceback
from datetime import datetime, timedelta
from email.message import EmailMessage

import requests
from tabulate import tabulate

from defenz_alerts import CONFIG, LOGGER
from defenz_alerts.authentication import DefenzAuthentication

# Mapping a standard readable block report type to actual summary and details
# report type
WEB_FILTER_BLOCKS = 'WEB_FILTER_BLOCKS'
BOT_NET_BLOCKS = 'BOT_NET_BLOCK_DETAILS'
MALWARE_PHISHING_BLOCKS = 'MALWARE_PHISHING_BLOCKS'
REPORTS_MAPPING = {
    WEB_FILTER_BLOCKS: 'WEB_FILTER_BLOCK_DETAILS',
    BOT_NET_BLOCKS: 'BOT_NET_BLOCK_DETAILS',
    MALWARE_PHISHING_BLOCKS: 'PHISHING_MALWARE_BLOCK_DETAILS',
}

API_URL = CONFIG['DEFENZ']['API_URL']
AUTHENTICATOR = DefenzAuthentication()


def call_api(end_point, params=None, headers=None):
    """

    :param end_point: API end point
    :param params: API parameters
    :param headers: headers to call the API
    :return: Http response
    """
    access_token = AUTHENTICATOR.get_access_token()

    default_headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    if headers:
        default_headers.update(headers)

    LOGGER.debug("Calling API end point %s - Params: %s - Headers: %s",
                 end_point, str(params), str(default_headers))

    response = requests.get(
        end_point,
        headers=default_headers,
        params=params
    )

    LOGGER.debug("Response Status Code: %s - Response Content: %s",
                 response.status_code, response.json())

    # pylint: disable=no-member
    if response.status_code != requests.codes.ok:
        response.raise_for_status()

    return response


def get_networks():
    """
    Returns all the networks under current customer.

    :return: list of networks
    """
    LOGGER.info("Getting all the networks...")

    end_point = API_URL + '/networks'

    params = {
        'pageSize': 10,
        'page': 0
    }

    networks = []
    while True:
        response = call_api(end_point, params=params)

        result = response.json()
        networks.extend(result['items'])

        if not result.get('hasNext'):
            break

        params['page'] += 1

    return networks


def get_network(network_id):
    """
    Returns a specific network by given network id.

    :param network_id: network id
    :return: network details
    """
    LOGGER.info("Getting details of network %s", network_id)

    end_point = API_URL + f'/networks/{network_id}'

    response = call_api(end_point)

    return response.json()


def _get_email_recipients(network_id, default_report_email=None):
    """
    Returns report email recipients from network details.

    :param network_id: network id.
    :param default_report_email: list of email addresses. Will be return if no
        email addresses have been set on the network.
    :return: list of email addresses
    """
    LOGGER.info("Getting report email recipients for network %s", network_id)

    network = get_network(network_id)
    report_emails = network['reportEmails']

    recipients = []
    if report_emails:
        recipients.extend([e['address'] for e in report_emails])

    if not recipients and default_report_email:
        recipients.append(default_report_email)

    return recipients


def get_all_reports(network_id, ran_at, interval=None):
    """
    Returns all the summary reports for given network.

    :param network_id: Network id
    :param ran_at: A datetime object that shows start time of the script
    :param interval: Report interval
    :return: list of reports
    """
    LOGGER.info("Getting all the report for network id %s", network_id)

    end_point = CONFIG['DEFENZ'][
                    'API_URL'] + f'/reporting/alldata/{network_id}'

    params = {}

    if interval:
        params['rangeEnd'] = int(ran_at.timestamp())
        params['rangeStart'] = \
            int((ran_at - timedelta(minutes=int(interval))).timestamp())

    response = call_api(end_point, params=params)

    return response.json()


def get_report(network_id, report_type, ran_at, interval=None):
    """
    Returns a report in details for given network and network type.

    :param network_id: Network id
    :param report_type: Report type
    :param ran_at: A datetime object that shows start time of the script
    :param interval: Report interval
    :return: report details
    """
    LOGGER.info("Getting report %s for network id %s", report_type, network_id)

    end_point = API_URL + f'/reporting/{network_id}'

    params = {
        'type': report_type
    }

    if interval:
        params['rangeEnd'] = int(ran_at.timestamp())
        params['rangeStart'] = \
            int((ran_at - timedelta(minutes=int(interval))).timestamp())
        params['interval'] = f'{interval}%20mins'

    response = call_api(end_point, params=params)

    return response.json()


def generate_email_content(report_details, block_type, network, interval):
    """
    Generates email body content for the alert.

    :param report_details: Report detail object
    :param network: Network object
    :param block_type: Block report type
    :param interval: Report interval in minute
    :return: String as email content
    """
    LOGGER.info("Generating email content for block report %s and network %s",
                block_type, network['id'])

    email_body_template = """
Malicious events detected in past {interval} minutes in your network.

BLOCK TYPE: {block_type}
NETWORK: {network_id} - {network_name}

{blocks}

"""

    if block_type in (MALWARE_PHISHING_BLOCKS, WEB_FILTER_BLOCKS):
        blocks = \
            _generate_malware_phishing_email_content(report_details) \
            if report_details else "No data found!"
    elif block_type == BOT_NET_BLOCKS:
        blocks = str(report_details) if report_details else "No data found!"
    else:
        raise Exception("Invalid block report type!")

    email_body = email_body_template.format(
        interval=interval,
        block_type=block_type,
        network_id=network['id'],
        network_name=network['name'],
        blocks=blocks,
    )

    return email_body


def _generate_malware_phishing_email_content(report_details):
    """
    Generates email body content for Malware Phishing block report.

    :param report_details: Report details object
    :return:
    """
    rows = [v for r in report_details['results'] for v in r['value']]
    table = [
        ['Protocol', 'URL', 'Time', 'Reason', 'Count']
    ]
    for row in rows:
        # timestamp is in milliseconds
        time_stamp = row['timestamp'] / 1000
        table.append([
            row['protocol'],
            row['url'],
            datetime.fromtimestamp(time_stamp).strftime('%Y-%m-%d %H:%M:%S'),
            row['reason'],
            row['count'],
        ])
    return str(tabulate(table, headers='firstrow', tablefmt="simple"))


def send_alert(network, report_type, ran_at, interval, report_email):
    """
    Sends an alert to report recipients of the given network for found anomaly
    events.

    :param network: Network object
    :param report_type: Block report type
    :param ran_at: A datetime object that shows start time of the script
    :param interval: Report interval
    :param report_email: The email will be sent to this address if the report
        email is not set on the network
    """

    report_details = get_report(
        network['id'],
        REPORTS_MAPPING[report_type],
        ran_at,
        interval=interval
    )

    email_content = \
        generate_email_content(report_details, report_type, network, interval)

    recipients = _get_email_recipients(
        network['id'],
        default_report_email=report_email
    )

    send_email(email_content, recipients)


def send_email(email_content, recipients):
    """
    Sends an alert email for found anomaly events.

    :param email_content: Email content
    :param recipients: List of email addresses
    """

    if not CONFIG['EMAIL']['SMTP_SERVER'] or \
        not CONFIG['EMAIL']['SMTP_PORT'] or \
        not CONFIG['EMAIL']['SMTP_USER'] or \
        not CONFIG['EMAIL']['SMTP_PASSWORD'] or \
        not CONFIG['EMAIL']['SENDER_EMAIL_ADDRESS']:
        LOGGER.warning("Email configs have not been provided correctly. "
                       "The email can't be send. "
                       "Please check email configs in the config file.")
        return

    if not recipients:
        LOGGER.warning("No report email is set on this network or provided by"
                       "command line/config. So the alert won't be sent.")
        return

    LOGGER.info("Sending email to %s", ', '.join(recipients))

    msg = EmailMessage()
    msg.set_content(email_content)
    msg['Subject'] = CONFIG['EMAIL']['SUBJECT']
    msg['From'] = CONFIG['EMAIL']['SENDER_EMAIL_ADDRESS']
    msg['To'] = ', '.join(recipients)

    with smtplib.SMTP(CONFIG['EMAIL']['SMTP_SERVER'],
                      CONFIG['EMAIL']['SMTP_PORT']) as server:
        server.login(CONFIG['EMAIL']['SMTP_USER'],
                     CONFIG['EMAIL']['SMTP_PASSWORD'])
        server.send_message(msg)


def validate_arguments(args):
    """
    Check required arguments to be provided.

    :param args: Arguments
    """

    error_temp = \
        "{} is required and hasn't been provided. " \
        "Neither by arguments nor by config file!"

    if not args.username:
        raise Exception(error_temp.format('Username'))

    if not args.password:
        raise Exception(error_temp.format('Password'))

    if not args.client_id:
        raise Exception(error_temp.format('Client ID'))

    if not args.client_secret:
        raise Exception(error_temp.format('Client Secret'))

    if not args.interval:
        raise Exception(error_temp.format('Interval'))


def get_command_line_arguments():
    """
    Gets command line arguments.

    :return: arguments
    """
    args_parser = \
        argparse.ArgumentParser(
            description="""This script is used to send scheduled Defenz alerts
            by using Defenz APIs.""")

    args_parser.add_argument(
        '-u',
        '--username',
        default=CONFIG['DEFENZ']['USERNAME'],
        help='Defenz portal username. Default: read from config file'
    )

    args_parser.add_argument(
        '-p',
        '--password',
        default=CONFIG['DEFENZ']['PASSWORD'],
        help='Defenz portal password. Default: read from config file'
    )

    args_parser.add_argument(
        '-c',
        '--client-id',
        default=CONFIG['DEFENZ']['CLIENT_ID'],
        help='Defenz client id (customer name). Default: read from config file'
    )

    args_parser.add_argument(
        '-s',
        '--client-secret',
        default=CONFIG['DEFENZ']['CLIENT_SECRET'],
        help='Defenz client secret. Default: read from config file'
    )

    args_parser.add_argument(
        '-e',
        '--report-email',
        default=CONFIG['DEFENZ']['REPORT_EMAIL'],
        help='The report will be sent to this email address '
             'if network report email is not set. '
             'Default: read from config file'
    )

    args_parser.add_argument(
        '-n',
        '--network-ids',
        nargs='*',
        help='List of network ids. Default all networks'
    )

    args_parser.add_argument(
        '-r',
        '--report-types',
        nargs='*',
        default=[MALWARE_PHISHING_BLOCKS, BOT_NET_BLOCKS],
        choices=[MALWARE_PHISHING_BLOCKS, BOT_NET_BLOCKS, WEB_FILTER_BLOCKS],
        help='List of report types. Default {} and {}'.format(
            MALWARE_PHISHING_BLOCKS, BOT_NET_BLOCKS)
    )

    args_parser.add_argument(
        '-i',
        '--interval',
        default=CONFIG['DEFENZ']['INTERVAL'],
        help='Report interval in minute. Default: read from config file'
    )

    args_parser.add_argument(
        '-v',
        '--verbose',
        default=False,
        action='store_true',
        help='Write the logs in console as well. Otherwise the logs only will '
             'be written in the log files. The log files are located in '
             '$HOME/defenz'
    )

    return args_parser.parse_args()


def main():
    """
    The main function of the script.
    """

    try:
        args = get_command_line_arguments()

        if args.verbose:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.DEBUG)
            console_handler.setFormatter(
                logging.Formatter('%(asctime)s - %(levelname)s: %(message)s'))
            LOGGER.addHandler(console_handler)

        validate_arguments(args)

        AUTHENTICATOR.login(
            args.username, args.password,
            args.client_id, args.client_secret
        )

        networks = []
        if args.network_ids:
            for network_id in args.network_ids:
                networks.append(get_network(network_id))
        else:
            networks = get_networks()

        # We need to be consistent about report time throughout the script
        now = datetime.now()

        for net in networks:
            try:
                reports = get_all_reports(net['id'], now, args.interval)
                for report_type in args.report_types:
                    if reports[report_type]['results']:
                        send_alert(net, report_type, now,
                                   args.interval, args.report_email)
            except Exception as ex:  # pylint: disable=broad-except
                LOGGER.error("%s %s", str(ex), traceback.format_exc())
    except Exception as ex:  # pylint: disable=broad-except
        LOGGER.error("%s %s", str(ex), traceback.format_exc())


if __name__ == '__main__':
    main()
