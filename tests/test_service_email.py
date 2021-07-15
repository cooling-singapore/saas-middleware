import unittest

from saas.helpers import prompt
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
        server_address = ('mail.ethz.ch', 587)
        account = "aydth@ethz.ch"
        password = prompt("SMTP password:", hidden=True)

        name = "Heiko Aydt"
        sender = "aydt@arch.ethz.ch"
        receiver = "aydt@arch.ethz.ch"

        self.node.start_email_service(server_address, account, password)
        self.node.update_identity(name=name, email=sender)
        result = self.node.email.send_test_email(receiver)
        assert(result is True)


if __name__ == '__main__':
    unittest.main()
