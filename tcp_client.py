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

keys_auth = None
other_key = None

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

def prepare_task_hello(keys_auth, rand_val, config):
    msg = message.Hello(
        client_key_id=keys_auth.get_key_id(),
        rand_val=rand_val,
        proto_id=config.protoid
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

TASK_MSG_TYPES = {
    0: 'hello',
    1: 'randval',
    2: 'disconnect',
    2001: 'want_to_compute_task',
    2002: 'task_to_compute',
    2003: 'cannot_assign_task',
    2004: 'report_computed_task',
    2016: 'start_session_response',
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
        self.loop.call_later(20, self.send_set_task_session)

    def send_set_task_session(self):
        node = Node(
            node_name='super_node',
            key='0a28c92c28508266cb259c91005f7d1a481d9fc0ef631373808d9c4f857f105eb3c5a7beb3ad97c0675c3054d9dadf8c5ff497db3302ef9d44d31d39f3f93900',
            pub_addr='1.2.3.4',
            prv_addr='1.2.3.4',
            pub_port=10000,
            prv_port=10000)

        #counter = 0
        while True:
            #counter += 1
            msg = message.SetTaskSession(
                key_id='0a28c92c285082ffcb259c91005f7d1a481d9fc0ef631373808d9c4f857f105eb3c5a7beb3ad97c0675c3054d9dadf8c5ff497db3302ef9d44d31d39f3f93900',
                node_info=node,
                conn_id=None,
                super_node_info=None)

            serialized = dump(
                msg,
                keys_auth.ecc.raw_privkey,
                other_key
            )
            length = struct.pack("!L", len(serialized))
            length + serialized
            print('[{}] -> SetTaskSession'.format(name))
            self.transport.write(length + serialized)

    def react_set_task_session(self, msg):
        print('[{}]  SetTaskSession: {}'.format(name))
        #self.send_set_task_session()

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

        global keys_auth
        keys_auth = self.keys_auth
        global other_key
        other_key = self.other_pub_key

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
        return

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


class GolemTaskProtocol(asyncio.Protocol):
    def __init__(self, loop, config):
        self.loop = loop
        self.config = config

    def connection_made(self, transport):
        print("[{}] Connection made".format(name))
        self.start = time.time()
        self.transport = transport
        self.loop.call_later(10, self.send_task_hello)
        #self.loop.call_later(20, self.send_payment)

    def send_task_hello(self):
        reply_hello = prepare_task_hello(keys_auth, 42, self.config)
        print ('[{}] -> hello'.format(name))
        self.transport.write(reply_hello)

    def react_hello(self, msg):
        print ('[{}] hello rnd: {}'.format(name, msg.rand_val))
        self.bootstrap_key_id = msg.client_key_id

        reply_hello = prepare_task_hello(keys_auth, msg.rand_val, self.config)
        print ('[{}] -> hello'.format(name))
        self.transport.write(reply_hello)
        #
        # self.other_pub_key = decode_hex(msg.client_key_id)

        reply = message.RandVal(rand_val=msg.rand_val)
        serialized = dump(
            reply,
            keys_auth.ecc.raw_privkey,
            other_key
        )
        length = struct.pack("!L", len(serialized))
        length + serialized
        print ('[{}] -> rnd: {}'.format(name, reply.rand_val))
        self.transport.write(length + serialized)
        return

    def react_randval(self, msg):
        print('[{}] randval rnd: {}'.format(name, msg.rand_val))

    def send_payment(self):
        print("Start spamming")
        counter = 0
        while True:
            reply = message.SubtaskPayment(
                subtask_id=str(counter),
                reward="10",
                transaction_id=20,
                block_number=34
            )
            serialized = dump(
                reply,
                keys_auth.ecc.raw_privkey,
                other_key
            )
            length = struct.pack("!L", len(serialized))
            length + serialized
            print ('[{}] -> SubtaskPayment'.format(name))
            self.transport.write(length + serialized)
            counter += 1

    def data_received(self, data):
        print("Data received")
        if not keys_auth:
            return

        messages = None
        try:
            messages = decode_msg(keys_auth, data)
        except RuntimeError as e:
            print("[{}] Not for me".format(name))
            return

        if not messages:
            return

        print("[{}] TASK Response after {}".format(name, time.time()-self.start))
        for i in messages:
            getattr(self, 'react_{}'.format(TASK_MSG_TYPES.get(i.TYPE, 'default')))(i)

    def react_want_to_compute_task(self):
        print("react_want_to_compute_task")

    def react_task_to_compute(self):
        print("react_task_to_compute")

    def react_cannot_assign_task(self):
        print("react_cannot_assign_task")

    def react_report_computed_task(self):
        print("react_report_computed_task")

    def react_start_session_response(self):
        print("react_start_session_response")

    def connection_lost(self, exc):
        print('[{}] The server closed the Task connection after {}'.format(name,
                                                                      time.time() - self.start))
        self.loop.stop()

    def react_disconnect(self, msg):
        print('[{}] disconnect: {}'.format(name, msg.reason))

    def react_default(self, msg):
        print ('[{}] DEFAULT {}: {}'.format(name, msg.TYPE, msg))

def main(config):
    try:
        main_inner(config)
    finally:
        # Clean datadir
        shutil.rmtree(config.datadir+name, ignore_errors=True)

async def main_coro(conn, ip, port, loop):
    await loop.create_connection(lambda: conn, ip, port)

def call_in_background(target, *, loop=None, executor=None):
    """Schedules and starts target callable as a background task

    If not given, *loop* defaults to the current thread's event loop
    If not given, *executor* defaults to the loop's default executor

    Returns the scheduled task.
    """
    if loop is None:
        loop = asyncio.get_event_loop()
    if callable(target):
        return loop.run_in_executor(executor, target)
    raise TypeError("target must be a callable, "
                    "not {!r}".format(type(target)))

def run_in_foreground(task, *, loop=None):
    """Runs event loop in current thread until the given task completes

    Returns the result of the task.
    For more complex conditions, combine with asyncio.wait()
    To include a timeout, combine with asyncio.wait_for()
    """
    if loop is None:
        loop = asyncio.get_event_loop()
    return loop.run_until_complete(asyncio.ensure_future(task, loop=loop))

def schedule_coroutine(target, *, loop=None):
    """Schedules target coroutine in the given event loop

    If not given, *loop* defaults to the current thread's event loop

    Returns the scheduled task.
    """
    if asyncio.iscoroutine(target):
        return asyncio.ensure_future(target, loop=loop)
    raise TypeError("target must be a coroutine, "
                    "not {!r}".format(type(target)))

def main_inner(config):
    loop = asyncio.get_event_loop()
    echo_proto = GolemHandshakeProtocol(loop, config)
    task_proto = GolemTaskProtocol(loop, config)

    p2p = schedule_coroutine(main_coro(echo_proto, config.ip, config.p2pprvport, loop), loop=loop)
    task = schedule_coroutine(main_coro(task_proto, config.ip, config.prvport, loop), loop=loop)

    run_in_foreground(asyncio.wait([p2p, task]))
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
