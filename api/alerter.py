import hashlib
import logging
import smtplib
import StringIO
import sys
import time
import datetime

from elasticsearch import Elasticsearch
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


class StdOutAlertSender:

    def __init__(self, tabsep, console=sys.stdout):
        self.tab_separated_output = tabsep
        self.console = console

    def send_alerts(self, configuration, alerts):
        for alert in alerts:
            self.console.write(self.format_alert(alert[0], alert[1], alert[2]))
            self.console.write("\n")

    def format_alert(self, plugin_name, checked_id, details):
        if self.tab_separated_output:
            return ("%s\t%s\t%s\n" %
                    (plugin_name, checked_id, repr(details)))
        else:
            return ("Rule: %s\n"
                    "Subject: %s\n"
                    "Alert: %s\n\n" %
                    (plugin_name, checked_id, details))


class EmailAlertSender:

    def __init__(self, msg_type="plain"):
        self.msg_type = msg_type

    def send_alerts(self, configuration, alerts):
        output = StringIO.StringIO()
        ow = StdOutAlertSender(tabsep=False, console=output)
        ow.send_alerts(None, alerts)
        mail_content = output.getvalue()

        email_from = configuration.get("email_from", "reddalert@localhost")
        email_to = configuration.get("email_to", ['root@localhost'])
        email_subject = configuration.get("email_subject", "[reddalert] Report")
        email_txt = mail_content if self.msg_type == "plain" else mail_content.replace("\n", "<br />")

        self.send_email(email_from, email_to, email_subject, email_txt, self.msg_type, config=configuration)

    def send_email(self, email_from, email_to, subject, txt, msg_type="plain", config={}):
        recipients = ", ".join(email_to)

        msg = MIMEMultipart()
        msg["Subject"] = subject
        msg['From'] = email_from
        msg['To'] = recipients

        msg.attach(MIMEText(txt.encode("utf-8"), "plain"))

        print "msg: %s" % repr(msg.as_string())

        smtp = smtplib.SMTP(config.get("smtp_host", 'localhost'))
        smtp.sendmail(email_from, email_to, msg.as_string())
        smtp.quit()


class ESAlertSender:

    def __init__(self):
        self.es = None
        self.logger = logging.getLogger("ESAlertSender")

    def send_alerts(self, configuration, alerts):
        self.es = Elasticsearch([{"host": configuration["es_host"], "port": configuration["es_port"]}])
        for alert in self.flatten_alerts(alerts):
            self.insert_es(alert)

    def insert_es(self, alert):
        try:
            alert["@timestamp"] = datetime.datetime.utcnow().isoformat() + "Z"
            alert["type"] = "reddalert"
            self.es.create(body=alert, id=hashlib.sha1(str(alert)).hexdigest(), index='reddalert', doc_type='reddalert')
        except Exception as e:
            self.logger.error(e)

    def flatten_alerts(self, alerts):
        for alert in alerts:
            details = alert[2]
            if isinstance(details, dict):
                base = {"rule": alert[0], "id": alert[1]}
                base.update(details)
                yield base
            else:
                yield {"rule": alert[0], "id": alert[1], "details": details}


class Alerter:

    AVAILABLE_ALERTERS = {
        "stdout": StdOutAlertSender(tabsep=False),
        "stdout_tabsep": StdOutAlertSender(tabsep=True),
        "mail_txt": EmailAlertSender(msg_type='plain'),
        "mail_html": EmailAlertSender(msg_type='text/html'),
        "elasticsearch": ESAlertSender()
    }

    def __init__(self, enabled_alert_formats):
        formats = enabled_alert_formats.split(',')
        self.enabled_alerters = [self.AVAILABLE_ALERTERS[a] for a in formats if a in self.AVAILABLE_ALERTERS]
        self.recorded_alerts = []

    def send_alerts(self, configuration={}):
        if self.recorded_alerts:
            for alerter in self.enabled_alerters:
                alerter.send_alerts(configuration, self.recorded_alerts)

    def run(self, alert_obj):
        normalized_alerts = [(a['plugin_name'], a['id'], d) for a in alert_obj for d in a['details']]
        self.recorded_alerts.extend(normalized_alerts)
