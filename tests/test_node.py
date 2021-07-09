import unittest

from saas.utilities.general_helpers import prompt
from tests.base_testcase import TestCaseBase


class NodeTestCase(unittest.TestCase, TestCaseBase):
    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)
        TestCaseBase.__init__(self)

    def setUp(self):
        self.initialise()

        self.node = self.get_node('node', enable_rest=False)

    def tearDown(self):
        self.cleanup()

    def test_send_simple_email(self):
        sender = prompt("from:")
        receiver = prompt("to:")
        account = prompt("SMTP account:")
        password = prompt("SMTP password:", hidden=True)

        self.node.enable_email_support(('mail.ethz.ch', 587), account, password)
        # service = EmailService(from_address, account, ('mail.ethz.ch', 587), password)
        # service = EmailService('aydt@arch.ethz.ch', ('smtp.gmail.com', 587), password)

        result = self.node.send_email(sender, receiver, "Test Email", "This is a test email.")
        assert(result is True)


if __name__ == '__main__':
    unittest.main()
