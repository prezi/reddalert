import StringIO
import unittest
from mock import patch, Mock, call

from api.alerter import Alerter
from api.alerter import EmailAlertSender
from api.alerter import ESAlertSender
from api.alerter import StdOutAlertSender


class StdOutSenderTestCase(unittest.TestCase):

    def setUp(self):
        self.alerts = [
            ("simple", "_1_", "simple text"),
            ("simple", "_2_", "array1"),
            ("simple", "_2_", "array2"),
            ("complex", "_3_", {"foo": "bar"}),
            ("complex", "_3_", {"foo": "woo"})
        ]

    def test_normal_output(self):
        ow = StringIO.StringIO()
        StdOutAlertSender(False, ow).send_alerts({}, self.alerts)
        c = ow.getvalue()

        self.assertIn("Rule: simple", c)
        self.assertIn("Alert: simple text", c)
        self.assertIn("Alert: array2", c)
        self.assertIn("foo", c)


class EmailSenderTestCase(unittest.TestCase):

    def setUp(self):
        self.alerts = [
            ("simple", "_1_", "simple text"),
            ("simple", "_2_", "array1"),
            ("simple", "_2_", "array2"),
            ("complex", "_3_", {"foo": "bar"}),
            ("complex", "_3_", {"foo": "woo"})
        ]

    def test_defaults_applied(self):
        eas = EmailAlertSender()
        eas.send_email = Mock()

        eas.send_alerts({}, self.alerts)

        calls = eas.send_email.call_args
        self.assertEquals("reddalert@localhost", calls[0][0])

    def test_defaults_override(self):
        eas = EmailAlertSender()
        eas.send_email = Mock()

        eas.send_alerts({"email_from": "foobar"}, self.alerts)

        calls = eas.send_email.call_args
        self.assertEquals("foobar", calls[0][0])

    def test_email_text(self):
        eas = EmailAlertSender()
        eas.send_email = Mock()

        eas.send_alerts({}, self.alerts)

        calls = eas.send_email.call_args
        self.assertIn("Rule: simple", calls[0][3])
        self.assertIn("Alert: simple text", calls[0][3])
        self.assertIn("Alert: array2", calls[0][3])
        self.assertIn("foo", calls[0][3])


class AlerterTestCase(unittest.TestCase):

    def setUp(self):
        self.alerts = [
            {"plugin_name": "simple", "id": "_1_", "details": ["simple text"]},
            {"plugin_name": "simple", "id": "_2_", "details": ["array1", "array2"]},
            {"plugin_name": "complex", "id": "_3_", "details": [{"foo": "bar"}, {"foo": "woo"}]}
        ]

    def test_survive_nonexisting_senders(self):
        a = Alerter("foo,bar")

        a.run(self.alerts)
        a.send_alerts()

        self.assertTrue(a.recorded_alerts is not None)

    def test_flatten_details(self):
        a = Alerter("")

        a.run(self.alerts)

        self.assertEquals(5, len(a.recorded_alerts))
        self.assertTrue(any(x[0] == "complex" for x in a.recorded_alerts))
        self.assertTrue(any(x[1] == "_2_" for x in a.recorded_alerts))

    def test_multiple_run_keeps_details(self):
        a = Alerter("")

        a.run(self.alerts[0:2])
        a.run(self.alerts[2:])

        self.assertEquals(5, len(a.recorded_alerts))


class ElasticSearchWriterTestCase(unittest.TestCase):

    def setUp(self):
        pass

    def test_flatten_details(self):
        esa = ESAlertSender()

        flat_alerts = list(esa.flatten_alerts([("complex", "_3_", {"foo": "bar"})]))

        self.assertEquals(1, len(flat_alerts))
        self.assertIn("foo", flat_alerts[0])
        self.assertIn("rule", flat_alerts[0])
        self.assertEquals("_3_", flat_alerts[0]["id"])

    def test_leave_simple_details(self):
        esa = ESAlertSender()

        flat_alerts = list(esa.flatten_alerts([("complex", "_3_", "foobar")]))

        self.assertEquals(1, len(flat_alerts))
        self.assertIn("details", flat_alerts[0])
        self.assertEquals("foobar", flat_alerts[0]["details"])
        self.assertIn("rule", flat_alerts[0])
        self.assertEquals("_3_", flat_alerts[0]["id"])
