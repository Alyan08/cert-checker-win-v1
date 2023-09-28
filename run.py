import ssl
from datetime import datetime, timedelta
import socket
import sys
import time
from config import DomainsList
import config
from class_definitions import CertManage, Alert

while True:

    start_time = datetime.utcnow()


    def get_cert_info(domain_name):
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=domain_name) as sock:
            try:
                sock.connect((domain_name, 443))
                checked_cert = sock.getpeercert()
                return checked_cert
            except Exception as e:
                return e


    if not DomainsList.domains:
        print("Domains list not found or incorrect!!!")
        sys.exit()

    for domain in DomainsList.domains:
        alert = ""
        # 3 tries
        for i in range(3):
            if get_cert_info(domain):
                break
            time.sleep(2)

        if not get_cert_info(domain):
            alert = Alert(domain, "connection error").form_alert()
            print(alert)

        if get_cert_info(domain):
            print(f"Analyzed certificate name: {domain}:")
            cert = CertManage(get_cert_info(domain))
            print(f'DNS records: {cert.dns_records}')
            print(f'Expiration Date: {cert.exp_date}')
            print(f'Days before expiration: {cert.days_left}')
            print('----------------')

            if cert.days_left <= config.critical_days:
                alert = Alert(domain, "soon expires").form_alert()
                alert["Days before expiring"] = cert.days_left
                print(alert)

            if cert.days_left <= 0:
                alert = Alert(domain, "expired").form_alert()
                print(alert)

    end_time = datetime.utcnow()
    sleep_time = timedelta(hours=config.hours_between_checks) - (end_time - start_time)
    if sleep_time.total_seconds() > 0:
        print(f'i will sleep for {sleep_time}')
        time.sleep(sleep_time.total_seconds())
