"""
Defenz APIs authentication.
"""
from datetime import datetime, timedelta

import requests

from defenz_alerts import LOGGER, CONFIG


class DefenzAuthentication:
    """
    Defenz API authentication.
    """
    def __init__(self):
        self.__token = None
        self.__client_id = None
        self.__client_secret = None

    def get_access_token(self):
        """
        Returns a valid access token.

        :return: access token
        """

        self._validate_token()

        return self.__token['access_token']

    def login(self, username, password, client_id, client_secret):
        """
        Login to get access token. This method set global variable TOKEN with
        obtained credentials.

        :param username: Defenz username
        :param password: Defenz password
        :param client_id: Defenz client id or customer name
        :param client_secret: Defenz client secret
        """
        LOGGER.info("Logging in to get the access token.")

        data = f"client_id={client_id}&client_secret={client_secret}&" \
               f"grant_type=password&username={username}&" \
               f"password={password}"

        response = requests.post(
            CONFIG['DEFENZ']['LOGIN_ENDPOINT'],
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            data=data
        )

        result = response.json()

        # pylint: disable=no-member
        if response.status_code != requests.codes.ok:
            raise Exception(
                'Unsuccessful Login! Status Code: {} - '
                'Error: {} - Error Description: {}'.format(
                    response.status_code,
                    result.get('error'),
                    result.get('error_description')
                )
            )

        result['created_at'] = datetime.now()
        self.__client_id = client_id
        self.__client_secret = client_secret
        self.__token = result

        LOGGER.info('The token has been obtained successfully!')

    def _re_login(self):
        """
        Uses refresh token to refresh the access token. This method set global
        variable TOKEN with obtained credentials.
        """
        LOGGER.info('Refreshing the token...')

        refresh_token = self.__token['refresh_token']
        client_id = self.__client_id
        client_secret = self.__client_secret
        data = f"client_id={client_id}&client_secret={client_secret}&" \
               f"grant_type=re_login&re_login={refresh_token}"

        response = requests.post(
            CONFIG['DEFENZ']['LOGIN_ENDPOINT'],
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            data=data
        )

        result = response.json()

        # pylint: disable=no-member
        if response.status_code != requests.codes.ok:
            raise Exception(
                'Unsuccessful Re-Login! Status Code: {} '
                '- Error: {} - Error Description: {}'.format(
                    response.status_code,
                    result.get('error'),
                    result.get('error_description')
                )
            )

        self.__token.update(result)
        self.__token['created_at'] = datetime.now()

        LOGGER.info('The token has been refreshed successfully!')

    def _validate_token(self):
        """
        Validate the access token if it's expired. If expired, does a re-login to
        refresh the token.
        """
        LOGGER.info('Validating the token...')

        if not self.__token:
            raise Exception('Invalid token! Please try to login first.')

        if datetime.now() > self.__token['created_at'] + timedelta(
                seconds=self.__token['expires_in']):
            LOGGER.warning('The token is expired!')
            self._re_login()
