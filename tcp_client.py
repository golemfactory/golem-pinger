#!/usr/bin/env python

import asyncio
import random
import shutil
import time
import struct

from golem.core.keysauth import EllipticalKeysAuth
from golem.network.p2p.node import Node
from golem.core.databuffer import DataBuffer
from golem.utils import decode_hex

from golem_messages import message, load, dump
message.init_messages()

name = 'node-'+str(time.time())+'.'+str(random.randint(0, 2147483647))


def prepare_hello(keys_auth, rand_val, config):
    node = Node(name, keys_auth.get_key_id(), config.prvaddr, config.prvport,
        config.pubaddr, None, 'Symmetric NAT', config.p2pprvport,
        config.p2pprvport)
    print("Proto id = ", config.protoid)
    challenge_kwargs = {}

    msg = message.Hello(
        proto_id=config.protoid,
        port=config.p2pprvport,
        node_name=name,
        client_key_id=keys_auth.get_key_id(),
        node_info=node,
        client_ver=config.cliver,
        rand_val=rand_val,
        metadata=[],
        solve_challenge=False,
        **challenge_kwargs
    )

    ser_msg = dump(
        msg,
        keys_auth.ecc.raw_privkey,
        None
    )

    db = DataBuffer()
    db.append_len_prefixed_bytes(ser_msg)
    return db.read_all()

def decode_msg(keys_auth, data):
    db = DataBuffer()
    db.append_bytes(data)
    messages = []
    for buf in db.get_len_prefixed_bytes():
        msg = load(
            buf,
            keys_auth.ecc.raw_privkey,
            None,
        )
        messages.append(msg)
    return messages

MSG_TYPES = {
    0: 'hello',
    1: 'randval',
    2: 'disconnect',
    1001: 'ping',
    1003: 'get_peers',
    1004: 'peers',
    1005: 'get_tasks',
    1010: 'degree',
    1014: 'find_node',
    1016: 'set_task_session',
}

class GolemHandshakeProtocol(asyncio.Protocol):
    def __init__(self, loop, config):
        self.loop = loop
        self.config = config
        keys_dir = config.datadir + name +'/keys'
        keys_auth = EllipticalKeysAuth(config.datadir + name)
        EllipticalKeysAuth._keys_dir = keys_dir
        self.keys_auth = keys_auth

    def connection_made(self, transport):
        print("[{}] Connection made".format(name))
        self.start = time.time()
        self.transport = transport

    def data_received(self, data):
        messages = None
        try:
            messages = decode_msg(self.keys_auth, data)
        except RuntimeError as e:
            print("[{}] Not for me".format(name))
            return

        if not messages:
            return

        print("[{}] Response after {}".format(name, time.time()-self.start))
        for i in messages:
            getattr(self, 'react_{}'.format(MSG_TYPES.get(i.TYPE, 'default')))(i)

    def react_default(self, msg):
        print ('[{}] DEFAULT {}: {}'.format(name, msg.TYPE, msg.__dict__))

    def react_hello(self, msg):
        print ('[{}] hello rnd: {}'.format(name, msg.rand_val))
        self.bootstrap_key_id = msg.client_key_id

        reply_hello = prepare_hello(self.keys_auth, msg.rand_val, self.config)
        print ('[{}] -> hello'.format(name))
        self.transport.write(reply_hello)

        self.other_pub_key = decode_hex(msg.client_key_id)

        reply = message.RandVal(rand_val=msg.rand_val)
        serialized = dump(
            reply,
            self.keys_auth.ecc.raw_privkey,
            self.other_pub_key
        )
        length = struct.pack("!L", len(serialized))
        length + serialized
        print ('[{}] -> rnd: {}'.format(name, reply.rand_val))
        self.transport.write(length + serialized)
        return

    def react_randval(self, msg):
        print('[{}] randval rnd: {}'.format(name, msg.rand_val))

    def react_disconnect(self, msg):
        print('[{}] disconnect: {}'.format(name, msg.reason))

    def react_get_tasks(self, msg):
        print('[{}] get_tasks'.format(name))

    def react_degree(self, msg):
        print('[{}] degree {}'.format(name, msg.degree))

    def react_ping(self, msg):
        print('[{}] ping'.format(name))
        reply = message.Pong()
        serialized = dump(
            reply,
            self.keys_auth.ecc.raw_privkey,
            self.other_pub_key
        )
        length = struct.pack("!L", len(serialized))
        length + serialized
        print ('[{}] -> Pong'.format(name))
        self.transport.write(length + serialized)

    def react_get_peers(self, msg):
        print('[{}] get_peers'.format(name))

    def react_peers(self, msg):
        print('[{}] peers cnt: {}'.format(name, len(msg.peers_array)))

    def react_find_node(self, msg):
        print('[{}] find_node'.format(name))

    def connection_lost(self, exc):
        print('[{}] The server closed the connection after {}'.format(name, time.time()-self.start))
        self.loop.stop()

def main(config):
    try:
        main_inner(config)
    finally:
        # Clean datadir
        shutil.rmtree(config.datadir+name, ignore_errors=True)

def main_inner(config):
    loop = asyncio.get_event_loop()
    echo_proto = GolemHandshakeProtocol(loop, config)
    coro = loop.create_connection(lambda: echo_proto,
                                  config.ip, config.p2pprvport)
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--prvaddr', required=True)
    parser.add_argument('--prvport', default=40103, type=int)
    parser.add_argument('--p2pprvport', default=40102, type=int)
    parser.add_argument('--pubaddr', required=True)
    parser.add_argument('--datadir', required=True)
    parser.add_argument('--ip', required=True)
    parser.add_argument('--protoid', type=int, default=1337)
    parser.add_argument('--cliver', default='0.11.0')
    config = parser.parse_args()
    main(config)
