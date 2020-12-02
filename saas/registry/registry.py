"""
This module contains the code for the Registry component needed by a SaaS node.
"""

__author__ = "Heiko Aydt"
__email__ = "heiko.aydt@gmail.com"
__status__ = "development"

import logging
import copy

from threading import Lock

from saas.utilities.general_helpers import get_timestamp_now

logger = logging.getLogger('Registry.Registry')


class Registry:
    """
    Registry manages the node records and provides methods to access/manipulate them. A node record
    includes the iid and address of the node, a list of processors supported by that node, and a
    timestamp indicating when this node has been 'seen' the last time. This class is thread-safe.
    """

    def __init__(self):
        self.mutex = Lock()
        self.records = {}

    def size(self):
        """
        Returns the number of records in the registry.
        :return: number of records as integer
        """
        self.mutex.acquire()
        result = len(self.records)
        self.mutex.release()
        return result

    def get(self, node_iid=None):
        """
        Returns either a list of all records (may be empty in case the registry does not contain any records) OR a
        single record for a given node iid (None in case there is no record for that node iid).
        specified node_iid then the returned list is empty.
        :param node_iid: the iid of the node
        :return: a list of records (may be empty)
        """
        self.mutex.acquire()

        result = copy.deepcopy(self.records)

        self.mutex.release()
        return result[node_iid] if node_iid else result

    def update(self, node_iid, name, address, processors, last_seen=None):
        """
        Updates the information of a node in the records. Adds a new record in case there isn't already one for
        that node iid.
        :param node_iid: the iid of the node
        :param name: the name of the node
        :param address: the address (host, port) on which that node is listening
        :param processors: a list of strings, indicating the processor types supported by that node
        :param last_seen: a timestamp indicating when this node has been last seen (default: None - current time is
        used in case last_seen is not explicitly specified)
        :return: True if a record has been updated/added or False otherwise
        """
        self.mutex.acquire()
        result = False

        # use current time as default for last_seen
        if not last_seen:
            last_seen = get_timestamp_now()

        # we only need to update our records if (1) the information provided here is more recent than what's on
        # record OR (2) we don't have a a record for that node yet.
        if node_iid not in self.records or last_seen > self.records[node_iid]['last_seen']:
            self.records[node_iid] = {
                'name': name,
                'address': address,
                'processors': processors,
                'last_seen': last_seen
            }
            result = True

        self.mutex.release()
        return result

    def update_all(self, records):
        """
        Convenient method to update many records at once. Calls the update() method for each item.
        :param records: a dictionary containing the records for updating
        :return: the node iids of the records that have SUCCESSFULLY been updated
        """
        result = []
        for peer_iid, record in records.items():
            if self.update(peer_iid, record['address'], record['processors'], record['last_seen']):
                result.append(peer_iid)

        return result

    def touch(self, node_iid):
        """
        Updates the timestamp of a record identified by a given node iid. If there is no record for this node,
        this method does nothing.
        :param node_iid: the iid of the node whose record should be 'touched'
        :return: the new timestamp of the record or None if there is no record for the given node iid
        """
        self.mutex.acquire()

        t_now = None
        if node_iid in self.records:
            t_now = get_timestamp_now()
            self.records[node_iid]['last_seen'] = t_now

        self.mutex.release()
        return t_now

    def remove(self, node_iid_list):
        """
        Removes records identified by their node iid.
        :param node_iid_list: a list of node iid's
        :return: list with the removed records (if any)
        """
        self.mutex.acquire()

        removed = {}
        for node_iid in node_iid_list:
            if node_iid in self.records:
                removed[node_iid] = self.records.pop(node_iid)

        self.mutex.release()
        return removed
