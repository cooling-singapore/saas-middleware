import unittest

from tests.base_testcase import TestCaseBase


class NodeTestCase(unittest.TestCase, TestCaseBase):
    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)
        TestCaseBase.__init__(self)

    def setUp(self):
        self.initialise()

        self.node = self.get_node('node', use_credentials=True, enable_rest=False)

    def tearDown(self):
        self.cleanup()

    def test_send_simple_email(self):
        receiver = self.node.identity().email()
        result = self.node.email.send_test_email(receiver)
        assert(result is True)


if __name__ == '__main__':
    unittest.main()
