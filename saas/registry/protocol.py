"""
This module contains the code for the Registry P2P protocol.
"""

__author__ = "Heiko Aydt"
__email__ = "heiko.aydt@gmail.com"
__status__ = "development"

import logging

from saas.utilities.general_helpers import get_timestamp_now
from saas.secure_messenger import SecureMessenger, MessengerProtocol

logger = logging.getLogger('Registry.Protocol')


class RegistryP2PProtocol(MessengerProtocol):
    """
    The RegistryP2PProtocol provides the necessary methods to synchronise registry records across a network of
    SaaS nodes within a domain. The protocol handles the following message types: 'join', 'leave', 'update', 'ping'
    and 'request_update'. It furthermore provides methods to send/broadcast messages. This class is IMPLICITLY
    thread-safe only.
    """
    id = "registry"

    def __init__(self, node):
        super().__init__(node, RegistryP2PProtocol.id, {
            'join': self.handle_join,
            'leave': self.handle_leave,
            'update': self.handle_update,
            'ping': self.handle_ping,
            'request_update': self.handle_request_update
        })

    def handle_join(self, message, messenger):
        """
        Upon receiving a 'join' message, a node MUST respond with an update contains its full state of records.
        :param message: the join message
        :param messenger: the messenger that facilitates communication between the node and the peer
        :return: None
        """
        if message['action'] == 'update':
            # update the node's records
            self.node.registry.update_all(message['content'])

            # then reply with an update message
            messenger.reply_ok(self.prepare_message("update", {
                'action': 'update',
                'content': self.node.registry.get(),
            }))

        else:
            logger.warning("encountered unsupported message action '{}:join:{}'".format(
                self.protocol_name, message['action']
            ))
            messenger.reply_error("action '{}' not supported by protocol '{}'".format(
                message['action'], self.protocol_name)
            )

    def handle_leave(self, message, messenger):
        """
        Upon receiving a 'leave' message, a node MUST remove the record of the peer.
        :param message: the leave message
        :param messenger: the messenger that facilitates communication between the node and the peer
        :return: None
        """
        self.node.registry.remove([messenger.peer.iid])

    def handle_update(self, message, messenger):
        """
        Upon receiving an 'update' message, a node SHOULD update its records.
        :param message: the update message
        :param messenger: the messenger that facilitates communication between the node and the peer
        :return: None
        """
        if message['action'] == 'update':
            self.node.registry.update_all(message['content'])

        else:
            logger.error("encountered unsupported message action '{}:update:{}'".format(
                self.protocol_name, message['action']
            ))

    def handle_ping(self, message, messenger):
        """
        Upon receiving a 'ping' message, the node MUST respond with a 'pong' message.
        :param message: the ping message
        :param messenger: the messenger that facilitates communication between the node and the peer
        :return: None
        """
        messenger.reply_ok(self.prepare_message('pong', {
            't_sent': get_timestamp_now()
        }))

    def handle_request_update(self, message, messenger):
        """
        Upon receiving a 'request_update' message, a node MUST respond with an update contains its full state
        of records.
        :param message: the request_update message
        :param messenger: the messenger that facilitates communication between the node and the peer
        :return: None
        """
        messenger.reply_ok(self.prepare_message('update', {
            'action': 'update',
            'content': self.node.registry.get(),
        }))

    def send_join(self, peer_address):
        """
        Sends a 'join' message to the peer at the specified address. Once we have received the update from the peer,
        the node MUST broadcast an update message to all other known peers.
        :param peer_address: the address (host, port) of the peer
        :return: None
        """
        logger.debug("send 'join' message to {}".format(peer_address))

        # connect to boot node
        peer, messenger = SecureMessenger.connect_to_peer(peer_address, self.node)
        logger.info("connected to peer (boot node) '{}'".format(peer.iid))

        # send 'join' message an receive an update from the peer
        response = messenger.request(self.prepare_message("join", {
            'action': 'update',
            'content': self.node.registry.get(),
        }))
        messenger.close()

        # update our own records
        self.node.registry.update_all(response['payload']['content'])

        # create the update message
        message = self.prepare_message("update", {
            'action': 'update',
            'content': self.node.registry.get()
        })

        # broadcast an update to all except the initial peer
        self.broadcast_message(message, [peer.iid])

    def broadcast_leave(self):
        """
        Broadcasts a 'leave' message to all known peers.
        :return: None
        """
        self.broadcast_message(self.prepare_message("leave"))

    def send_ping(self, peer_iid):
        """
        Sends a 'ping' message to the peer with the specified iid.
        :param peer_iid: the iid of the peer
        :return: None
        """
        # get the record for that peer iid
        record = self.node.registry.get(peer_iid)
        if not record:
            logger.warning("peer {} not found in registry".format(peer_iid))
            return

        # connect to peer
        peer, messenger = SecureMessenger.connect_to_peer(record['address'], self.node)
        logger.info("connected to peer '{}'".format(peer.iid))
        if not peer_iid == peer.iid:
            logger.warning("mismatching node iids for peer address {}: iid_on_record={} idd_as_per_peer={}".format(
                record['address'], peer_iid, peer.iid
            ))

        # send ping message and receive response
        t0 = get_timestamp_now()
        response = messenger.request(self.prepare_message("ping", {
            'from': self.node.key.iid,
            'to': peer_iid,
            't_sent': t0
        }))
        messenger.close()

        # if we have received a response, determine latency
        if response:
            # calculate latency
            t2 = get_timestamp_now()
            t1 = response['payload']['t_sent']
            dt0 = t1-t0
            dt1 = t2-t1
            logger.info("response latency: dt('{}'->'{}')={} and dt('{}'->'{}')={}".format(
                self.node.key.short_iid, peer.short_iid, dt0,
                peer.short_iid, self.node.key.short_iid, dt1
            ))

            # response received, touch the record
            self.node.registry.touch(peer_iid)

        else:
            # no response means we remove that peer
            self.node.registry.remove_all([peer_iid])
