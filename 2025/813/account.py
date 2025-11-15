from http.server import HTTPServer
from http.server import BaseHTTPRequestHandler

from urllib.parse import parse_qs, urlparse,  unquote, quote
import json
import urllib

import requests
from requests.auth import HTTPBasicAuth

DA_HOST = 'https://server3.webhostmost.com:2222'
DA_LOGIN = 'hostmost3'
DA_PASS = 'aXRP_i7qL1YMx6ruB1R7GJqg5UUEE165'
AUTH = HTTPBasicAuth(DA_LOGIN, DA_PASS)
HEADERS = {'Content-Type': 'application/x-www-form-urlencoded'}

DEFAULT_EMAIL = 'email@test.com'
DEFAULT_PASSWD = '20251231'
DEFAULT_DOMAIN = 'test.com'
DEFAULT_PACKAGE = 'free-125mb'
DEFAULT_IP = '66.78.59.15'
DEFAULT_NOTIFY = 'no'


class CustomHTTPRequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        print('path = {}'.format(self.path))
      
        parsed_path = urlparse(self.path)
        pq = parse_qs(parsed_path.query)
        print('parsed: path = {}, query = {}'.format(parsed_path.path, pq))

        username = ''
        action = ''
        email = ''
        passwd = ''
        passwd2 = ''
        domain = ''
        package = ''
        ip = ''
        notify = ''
        
        if len(pq.get('username', [])) > 0 :
            username = pq.get('username', [])[0]

        if len(pq.get('action', [])) > 0 :
            action = pq.get('action', [])[0]

        if len(pq.get('email', [])) > 0 :
            email = pq.get('email', [])[0]

        if len(pq.get('passwd', [])) > 0 :
            passwd = pq.get('passwd', [])[0]

        if len(pq.get('passwd2', [])) > 0 :
            passwd2 = pq.get('passwd2', [])[0]

        if len(pq.get('domain', [])) > 0 :
            domain = pq.get('domain', [])[0]
            
        if len(pq.get('package', [])) > 0 :
            package = pq.get('package', [])[0]

        if len(pq.get('ip', [])) > 0 :
            ip = pq.get('ip', [])[0]

        if len(pq.get('notify', [])) > 0 :
            notify = pq.get('notify', [])[0]

        print('query: username = {}, action = {}, email = {}, passwd = {}, passwd2 = {}, domain = {}, package = {}, ip = {}, notify = {},'.format(username, action, email, passwd, passwd2, domain, package, ip, notify))
        
        if parsed_path.path == '/':
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'Hello, world')

        elif parsed_path.path == '/sub':
            try:
                if username == '' :
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'No username')
                    return

                elif action == "create" :
                    params = {}
                    params["action"] = "create"
                    params["add"] = "Submit"
                    params["username"] = username
                    params["email"] = email
                    params["passwd"] = "20251231"
                    params["passwd2"] = "20251231"
                    params["domain"] = "test.com"
                    params["package"] = "free-125mb"
                    params["ip"] = "66.78.59.15"
                    params["notify"] = "no"
                    
                    url_data = urllib.parse.urlencode(params)
                    
                    print(params)
                    print(url_data)
                    
                    url_post = f"{DA_HOST}/CMD_API_ACCOUNT_USER"
                    response = requests.post(url_post, data=params, auth=AUTH, headers=HEADERS)
                    #response = requests.post(url_post, data=url_data, auth=AUTH, headers=HEADERS)
                    params = dict(x.split('=') for x in unquote(response.text).strip().split('&') if '=' in x)
                    print(params)
                    
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(str(params).encode('utf-8'))
                    return

                else:
                    url = f"{DA_HOST}/CMD_API_SHOW_USER_CONFIG?user={username}"
                    response = requests.get(url, auth=AUTH)
                    response.raise_for_status()
                    params = dict(x.split('=') for x in unquote(response.text).strip().split('&') if '=' in x)
                    print(response.text)
                    print(params)
                    print(json.dumps(params).encode())
                    
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(json.dumps(params).encode())
                    return

            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write("error with build:{0}".format(str(e)).encode())
                return
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not found')

server_address = ('', 8080)
print("serving at port", 8080)
httpd = HTTPServer(server_address, CustomHTTPRequestHandler)
httpd.serve_forever()