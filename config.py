class DomainsList:
    domains = [
        "test1.com",
        "test2.com",
        "test3.com"
    ]


class LogsManage:

    syslog_on = False
    # add remote syslog server host, uri and port (f.e. udp://syslog.com:999)
    syslog_address = ""
    # api for logs
    api_on = False
    api_adress = ""
    api_auth_header_name = ""
    api_auth_header_value = ""


critical_days = 30

operation_system = ""

hours_between_checks = 24