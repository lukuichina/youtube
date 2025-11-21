import requests
from requests.auth import HTTPBasicAuth

DA_HOST = 'https://server3.webhostmost.com:2222'
DA_LOGIN = 'username'
HEADERS = {'Content-Type': 'application/x-www-form-urlencoded'}

SESSION = 'session id'
CSRFTOKEN = 'csrf token'

DOMAIN = 'whm3.swings.ggff.net'
VERSION = '22'
TAR_GZ_LIB = '/lib.tar.gz'

def checkAppAlive():
    response = requests.get(f"https://{DOMAIN}/info", headers=HEADERS)
    #response.raise_for_status()
    print(response.text)

    if response.status_code == 404 :
        return False
    elif response.status_code == 503 :
        return True
    else :
        return True

def createApp():
    header = HEADERS
    header['Cookie'] = 'session={}; csrftoken={}'.format(SESSION, CSRFTOKEN)
    print(header)

    params = 'command=cloudlinux-selector&method=create&params[interpreter]=nodejs&params[app-root]=public_html&params[app-uri]=%2F&params[version]={}&params[startup-file]=app.js&params[env-vars]=%7B%7D&params[app-mode]=development&params[user]={}&csrftoken={}'.format(VERSION, DA_LOGIN, CSRFTOKEN)
    print(params)

    url_post = f"{DA_HOST}/CMD_PLUGINS/nodejs_selector/index.raw?c=send-request"
    response = requests.post(url_post, data=params, headers=header)
    response.raise_for_status()
    print(response.text)

def upload():
    header = HEADERS
    header['Cookie'] = 'session={}; csrftoken={}'.format(SESSION, CSRFTOKEN)
    print(header)

    params = {}
    params['json'] = 'yes'
    params['action'] = 'edit'
    params['path'] = f'/domains/{DOMAIN}/public_html/'

    params['filename'] = 'app.js'
    with open('app.js', "rb") as file:
        params['text'] = file.read()
    #print(params)

    url_post = f"{DA_HOST}/CMD_API_FILE_MANAGER"
    response = requests.post(url_post, data=params, headers=header)
    response.raise_for_status()
    print(response.text)

    params['filename'] = 'package.json'
    with open('package.json', "rb") as file:
        params['text'] = file.read()
    #print(params)

    response = requests.post(url_post, data=params, headers=header)
    response.raise_for_status()
    print(response.text)

def install():
    header = HEADERS
    header['Cookie'] = 'session={}; csrftoken={}'.format(SESSION, CSRFTOKEN)
    print(header)

    params = 'command=cloudlinux-selector&method=install-modules&params[interpreter]=nodejs&params[app-root]=public_html&params[user]={}&csrftoken={}'.format(DA_LOGIN, CSRFTOKEN)
    print(params)

    url_post = f"{DA_HOST}/CMD_PLUGINS/nodejs_selector/index.raw?c=send-request"
    response = requests.post(url_post, data=params, headers=header)
    response.raise_for_status()
    print(response.text)

def extract():
    header = HEADERS
    header['Cookie'] = 'session={}; csrftoken={}'.format(SESSION, CSRFTOKEN)
    print(header)

    params = {}
    params['json'] = 'yes'
    params['action'] = 'extract'
    params['path'] = TAR_GZ_LIB
    params['directory'] = f'/nodevenv/domains/{DOMAIN}/public_html/{VERSION}'
    print(params)

    url_post = f"{DA_HOST}/CMD_API_FILE_MANAGER"
    response = requests.post(url_post, data=params, headers=header)
    response.raise_for_status()
    print(response.text)

def main():
    if checkAppAlive() :
        exit()

    createApp()
    upload()
    extract()

main()
exit()