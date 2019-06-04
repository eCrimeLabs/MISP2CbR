#!/usr/bin/env python3
"""
    This application will create a HTTPS webserver fetching data from MISP Threat Sharing Platform
    and expoxing it in a format that CarbonBlack Response understand and can import.

    MIT License

    Copyright (c) 2019 Dennis Rand (https://www.ecrimelabs.com)

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
"""

import argparse
import pprint
import json
from pymisp import PyMISP
import time
import hashlib
import socket
import re
from keys import misp_url, misp_key, misp_verifycert, misp_tag, proxies, flask_cert, flask_key, app_debug
from flask import Flask, Response
app = Flask(__name__)

__author__ = "Dennis Rand - eCrimeLabs"
__copyright__ = "Copyright (c) 2019, eCrimeLabs"
__version__ = "1.0.0"
__maintainer__ = "Dennis Rand"

def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True

def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True

def splash():
    print ("\r\n")
    print ('Expose MISP attributes to CarbonBlack Response')
    print ('(c)2019 eCrimeLabs')
    print ('https://www.ecrimelabs.com')
    print ("----------------------------------------\r\n")

def init(misp_url, misp_key):
    return PyMISP(misp_url, misp_key, misp_verifycert, 'json', debug=False, proxies=proxies)

def GetMISPData():
    reports = {}
    relative_path = 'attributes/restSearch'
    body = {
        "returnFormat":"json",
        "type":["ip-src","ip-dst","domain","hostname","md5","sha256"],
        "tags":misp_tag,
        "enforceWarninglist":"true",
        "to_ids":"true"
    }
    misp = PyMISP(misp_url, misp_key, misp_verifycert)
    data = misp.direct_call(relative_path, body)

    iocs_dns, iocs_ipv4, iocs_ipv6, iocs_md5, iocs_sha256 = [],[],[],[],[]

    for e in data['response']['Attribute']:
        if (e['type'] == 'domain' or e['type'] == 'hostname'):
            iocs_dns.append(e['value'])
        elif (e['type'] == 'ip-src' or e['type'] == 'ip-dst'):
            if (is_valid_ipv4_address(e['value'])):
                iocs_ipv4.append(e['value'])
            if (is_valid_ipv6_address(e['value'])):
                iocs_ipv6.append(e['value'])
        elif (e['type'] == 'md5'):
            if re.search("([a-f0-9][32,32])", e['value'], re.IGNORECASE | re.MULTILINE):
                iocs_md5.append(e['value'])
        elif (e['type'] == 'sha256'):
            if re.search("([a-f0-9][64,64])", e['value'], re.IGNORECASE | re.MULTILINE):
                iocs_sha256.append(e['value'])

    return(Build_CB_Feed(iocs_dns, iocs_ipv4, iocs_ipv6, iocs_md5, iocs_sha256))

def Build_CB_Feed(iocs_dns, iocs_ipv4, iocs_ipv6, iocs_md5, iocs_sha256):
    cbr_title = "MISP Threat Feed (" + misp_tag + ")"
    feed_id = hashlib.md5(cbr_title.encode('utf-8')).hexdigest()
    feed_timestamp = int(time.time())
    feed = {
            "feedinfo": {
                    "provider_url": "https://www.misp-project.org",
                    "display_name": "MISP Threat Feed",
                    "name": "MISP",
                    "tech_data": "There are no requirements to share any data to receive this feed.",
                    "summary": "MISP - Open Source Threat Intelligence Platform & Open Standards For Threat Information Sharing",
                    "icon": "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ykgbD/zRxj3ayo62cR+L9sxHOhJoVrGgZPXc8Go2gYXpx0abLQ20nKdZZ0RNQUmVvsiKGYtm6ntINQwF5qPZeKcJahnyeJ+2wcxEM/sNtDkvMKKi1sxKmxRTjZz7UZgC61N/dLx9LfKqx5uAFwOPG1nh/8Y1CKnRISg/XIPSrmPR/nY8WnF/QZm3a+1eFcqJzLe6J3Gwk9gmOusHuLR/w9/bbVAjUGZskN1rNuHMQ5moY4zEyWgP2WsdvgSpuY1IDQ02AdXY80uAZWknMN43AZ6O8sehvrzV+lRjxHkrH4TU5U3Wt/Coy+H2Xr09v8iI8JHLIettoRE7yd4bg1bJ7+z3jdkKMldHLJ2AZmTm+bTy0F4H6cjtJtBQMEeg1XQVMi2TaFmX02LF9EGzc0fVtOmbIm2cilTHcjTTr0SqJWy7iRbLyBuxU9CKu88IP5kWbZCi9Ybt0q6GSH0J6/c76AjM1WjlDiDLYGBnCdiPNuBdkXs70WxsipTvNkGH8RvQEp2NTk7MMtLWovj/8+h/Pplqzx+w8teAf6PZXYo83tCCKkdHWWaYcHeglVZnZO5Be0EtUhu11tZZ9s4eZEiEQt8Q+Z0CNlk9zchPCSfYx/ZsHfJnRqOY1fYISR3ikF1zW/Z9kMr4OEJCaFVsRvpymJHSaM/uipBQYveOss5usbr6ow1sj90vs7KU1T+IFuvIR+o6wuoqR5v2VhP6cBvjVjQrB9vvFFIVYUS3n73nrJ4P0YotQTO6yQQ7zNrdhiyew6x/RwKft7GejVbCTLTPZLSCii420tNgE/JEZEiEB9GeQ554XUeOW0/6QKOYsQ6p1L5IbdYSOa4ZI0aMGDFixIgRI0aMGDFixIgRI0aMGDFixIgRI0aMGDFixOgG/Be1A50tqJE6/gAAACV0RVh0ZGF0ZTpjcmVhdGUAMjAxNy0wNi0wMlQwNzozODoyMyswMDowMIFXcrIAAAAldEVYdGRhdGU6bW9kaWZ5ADIwMTctMDYtMDJUMDc6Mzg6MjMrMDA6MDDwCsoOAAAARnRFWHRzb2Z0d2FyZQBJbWFnZU1hZ2ljayA2LjcuOC05IDIwMTQtMDUtMTIgUTE2IGh0dHA6Ly93d3cuaW1hZ2VtYWdpY2sub3Jn3IbtAAAAABh0RVh0VGh1bWI6OkRvY3VtZW50OjpQYWdlcwAxp/+7LwAAABh0RVh0VGh1bWI6OkltYWdlOjpoZWlnaHQAMTkyDwByhQAAABd0RVh0VGh1bWI6OkltYWdlOjpXaWR0aAAxOTLTrCEIAAAAGXRFWHRUaHVtYjo6TWltZXR5cGUAaW1hZ2UvcG5nP7JWTgAAABd0RVh0VGh1bWI6Ok1UaW1lADE0OTYzODkxMDMDQTScAAAAD3RFWHRUaHVtYjo6U2l6ZQAwQkKUoj7sAAAAVnRFWHRUaHVtYjo6VVJJAGZpbGU6Ly8vbW50bG9nL2Zhdmljb25zLzIwMTctMDYtMDIvM2IxYjgxNGMwMzJkYTBkOTM4ODZlM2M5YTFiOTk1MjQuaWNvLnBuZw3tGoMAAAAASUVORK5CYII=",
                    "icon_small": "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ykgbD/zRxj3ayo62cR+L9sxHOhJoVrGgZPXc8Go2gYXpx0abLQ20nKdZZ0RNQUmVvsiKGYtm6ntINQwF5qPZeKcJahnyeJ+2wcxEM/sNtDkvMKKi1sxKmxRTjZz7UZgC61N/dLx9LfKqx5uAFwOPG1nh/8Y1CKnRISg/XIPSrmPR/nY8WnF/QZm3a+1eFcqJzLe6J3Gwk9gmOusHuLR/w9/bbVAjUGZskN1rNuHMQ5moY4zEyWgP2WsdvgSpuY1IDQ02AdXY80uAZWknMN43AZ6O8sehvrzV+lRjxHkrH4TU5U3Wt/Coy+H2Xr09v8iI8JHLIettoRE7yd4bg1bJ7+z3jdkKMldHLJ2AZmTm+bTy0F4H6cjtJtBQMEeg1XQVMi2TaFmX02LF9EGzc0fVtOmbIm2cilTHcjTTr0SqJWy7iRbLyBuxU9CKu88IP5kWbZCi9Ybt0q6GSH0J6/c76AjM1WjlDiDLYGBnCdiPNuBdkXs70WxsipTvNkGH8RvQEp2NTk7MMtLWovj/8+h/Pplqzx+w8teAf6PZXYo83tCCKkdHWWaYcHeglVZnZO5Be0EtUhu11tZZ9s4eZEiEQt8Q+Z0CNlk9zchPCSfYx/ZsHfJnRqOY1fYISR3ikF1zW/Z9kMr4OEJCaFVsRvpymJHSaM/uipBQYveOss5usbr6ow1sj90vs7KU1T+IFuvIR+o6wuoqR5v2VhP6cBvjVjQrB9vvFFIVYUS3n73nrJ4P0YotQTO6yQQ7zNrdhiyew6x/RwKft7GejVbCTLTPZLSCii420tNgE/JEZEiEB9GeQ554XUeOW0/6QKOYsQ6p1L5IbdYSOa4ZI0aMGDFixIgRI0aMGDFixIgRI0aMGDFixIgRI0aMGDFixOgG/Be1A50tqJE6/gAAACV0RVh0ZGF0ZTpjcmVhdGUAMjAxNy0wNi0wMlQwNzozODoyMyswMDowMIFXcrIAAAAldEVYdGRhdGU6bW9kaWZ5ADIwMTctMDYtMDJUMDc6Mzg6MjMrMDA6MDDwCsoOAAAARnRFWHRzb2Z0d2FyZQBJbWFnZU1hZ2ljayA2LjcuOC05IDIwMTQtMDUtMTIgUTE2IGh0dHA6Ly93d3cuaW1hZ2VtYWdpY2sub3Jn3IbtAAAAABh0RVh0VGh1bWI6OkRvY3VtZW50OjpQYWdlcwAxp/+7LwAAABh0RVh0VGh1bWI6OkltYWdlOjpoZWlnaHQAMTkyDwByhQAAABd0RVh0VGh1bWI6OkltYWdlOjpXaWR0aAAxOTLTrCEIAAAAGXRFWHRUaHVtYjo6TWltZXR5cGUAaW1hZ2UvcG5nP7JWTgAAABd0RVh0VGh1bWI6Ok1UaW1lADE0OTYzODkxMDMDQTScAAAAD3RFWHRUaHVtYjo6U2l6ZQAwQkKUoj7sAAAAVnRFWHRUaHVtYjo6VVJJAGZpbGU6Ly8vbW50bG9nL2Zhdmljb25zLzIwMTctMDYtMDIvM2IxYjgxNGMwMzJkYTBkOTM4ODZlM2M5YTFiOTk1MjQuaWNvLnBuZw3tGoMAAAAASUVORK5CYII="
                },
                "reports": [{
                    "title": cbr_title,
                    "timestamp": feed_timestamp,
                    "id": feed_id,
                    "link": misp_url,
                    "score": 100,
                    "iocs": {}
                }]
            }

    if not len(iocs_dns) == 0:
        feed['reports'][0]['iocs']['dns'] = iocs_dns
    if not len(iocs_ipv4) == 0:
        feed['reports'][0]['iocs']['ipv4'] = iocs_ipv4
    if not len(iocs_ipv6) == 0:
        feed['reports'][0]['iocs']['ipv6'] = iocs_ipv6
    if not len(iocs_md5) == 0:
        feed['reports'][0]['iocs']['md5'] = iocs_md5
    if not len(iocs_sha256) == 0:
        feed['reports'][0]['iocs']['sha256'] = iocs_sha256

    return(feed)

@app.route("/")
def fetch_and_deliver():
    feed = GetMISPData()
    return Response(json.dumps(feed), mimetype='application/json')



if __name__ == "__main__":
    splash()
    """Intake data from MISP and makes it avaliable in Carbon Black Response ."""
    desc = "Providing Threat Data from MISP to Cb Response EDR tool"
    parser = argparse.ArgumentParser(description=(desc))
    parser.add_argument("-i", "--ip", help="Hostname or IP of the service (default 127.0.0.1)", default="127.0.0.1")
    parser.add_argument("-p", "--port", help="Portname the service will listen on (default 8443)", default="8443")

    args = parser.parse_args()
    app.debug = app_debug
    if (len(flask_cert) == 0 or len(flask_key) == 0):
        app.run(ssl_context='adhoc', host=args.ip, port=args.port)
    else:
        app.run(ssl_context=(flask_cert, flask_key), host=args.ip, port=args.port)
