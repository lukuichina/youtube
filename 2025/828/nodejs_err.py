import time
import datetime
import requests
from requests.auth import HTTPBasicAuth

DA_HOST = 'https://server8.webhostmost.com:2222'
DA_LOGIN = 'username'
DA_PASS = 'password'

AUTH = HTTPBasicAuth(DA_LOGIN, DA_PASS)
HEADERS = {'Content-Type': 'application/x-www-form-urlencoded'}

DOMAIN = 'domain.com'
WAITING = 120

def rename():
    params = {}
    params['json'] = 'yes'
    params['action'] = 'rename'
    params['path'] = f'/nodevenv/domains'
    params['old'] = f'{DOMAIN}'
    params['filename'] = f'{DOMAIN}_bak'
    print(params)

    url_post = f"{DA_HOST}/CMD_API_FILE_MANAGER"
    response = requests.post(url_post, data=params, auth=AUTH, headers=HEADERS)
    response.raise_for_status()
    print(response.text)
    
def restore():
    params = {}
    params['json'] = 'yes'
    params['action'] = 'rename'
    params['path'] = f'/nodevenv/domains'
    params['old'] = f'{DOMAIN}_bak'
    params['filename'] = f'{DOMAIN}'
    print(params)

    url_post = f"{DA_HOST}/CMD_API_FILE_MANAGER"
    response = requests.post(url_post, data=params, auth=AUTH, headers=HEADERS)
    response.raise_for_status()
    print(response.text)

def main():
    rename()

    print(datetime.datetime.now())
    time.sleep(WAITING)
    print(datetime.datetime.now())

    restore()

main()
exit()