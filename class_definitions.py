import json
from datetime import datetime
import socket
import requests
from config import LogsManage


class CertManage:
    def __init__(self, cert):
        self.dns_records = []
        self.exp_date = cert.get("notAfter")
        self.days_left = (datetime.strptime(cert.get("notAfter"), '%b %d %H:%M:%S %Y %Z') - datetime.utcnow()).days

        if cert:
            for param_type, param_value in cert['subjectAltName']:
                if param_type == 'DNS':
                    self.dns_records.append(param_value)


class Alert:
    def __init__(self, domain, alert_type):
        self.domain = domain
        self.alert_type = alert_type
        self.level = "Error"
        self.message = ""
        self.timestamp = ""

        if self.alert_type == "connection error":
            self.message = f"Could not connect via ssl to {domain} after 3 tries"
        if self.alert_type == "soon expires":

            self.message = f"Less than 30 days left until the certificate for {domain} expires"
        if alert_type == "expired":
            self.message = f"The certificate for {domain} was expired"

    def form_alert(self):
        alert_descr = {
            "timestamp": datetime.utcnow(),
            "level": "Error",
            "type": self.alert_type,
            "domain": self.domain,
            "message": self.message
        }

        return alert_descr

    def form_and_send_alert(self):
        alert_descr = {
            "timestamp": datetime.utcnow(),
            "level": "Error",
            "type": self.alert_type,
            "domain": self.domain,
            "message": self.message
        }

        if LogsManage.api_on:
            uri = LogsManage.api_adress
            headers = {
                'Content-Type': 'application/json',
                LogsManage.api_auth_header_name: LogsManage.api_auth_header_value
            }
            requests.post(uri, headers= headers, data=json.dumps(alert_descr))

        if LogsManage.syslog_on:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(bytes(json.dumps(alert_descr), 'utf-8'), LogsManage.syslog_address)
