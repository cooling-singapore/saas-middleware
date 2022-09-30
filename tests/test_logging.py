import os
import shutil
import tempfile
import unittest

from saas.log import Logging


class LoggingTestCase(unittest.TestCase):
    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)

    def setUp(self):
        self.wd_path = tempfile.mkdtemp()

    def tearDown(self):
        Logging.remove_all_handlers()
        shutil.rmtree(self.wd_path)

    def test_defaults(self):
        Logging.initialise()
        logger = Logging.get('test')

        logger.info("you can see me!")
        logger.debug("you should not be able to see me!")

    def test_log_to_separate_file(self):
        default_log_path = os.path.join(self.wd_path, 'log.default')
        custom_log_path = os.path.join(self.wd_path, 'log.custom')

        Logging.initialise(log_path=default_log_path)

        default = Logging.get('default_logger')
        custom = Logging.get('custom_logger', custom_log_path=custom_log_path)

        default.info("this should go into the default log file")
        custom.info("this should go into the default log file AND the custom log file")

        with open(default_log_path, 'r') as f:
            default_lines = f.readlines()
            print(default_lines)
        assert(len(default_lines) == 2)

        with open(custom_log_path, 'r') as f:
            custom_lines = f.readlines()
            print(custom_lines)
        assert(len(custom_lines) == 1)

    def test_rollover(self):
        log_path0 = os.path.join(self.wd_path, 'log')
        log_path1 = os.path.join(self.wd_path, 'log.1')
        log_path2 = os.path.join(self.wd_path, 'log.2')

        Logging.initialise(log_path=log_path0, max_bytes=80)

        logger = Logging.get('logger')
        assert(os.path.isfile(log_path0))
        assert(not os.path.isfile(log_path1))
        assert(not os.path.isfile(log_path2))

        logger.info('msg')
        assert(os.path.isfile(log_path0))
        assert(not os.path.isfile(log_path1))
        assert(not os.path.isfile(log_path2))

        logger.info('msg')
        assert(os.path.isfile(log_path0))
        assert(os.path.isfile(log_path1))
        assert(not os.path.isfile(log_path2))

        logger.info('msg')
        assert(os.path.isfile(log_path0))
        assert(os.path.isfile(log_path1))
        assert(os.path.isfile(log_path2))


if __name__ == '__main__':
    unittest.main()
