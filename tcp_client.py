import asyncio
import random
import time

from golem.core.keysauth import EllipticalKeysAuth
from golem.network.p2p.node import Node
from golem.core.databuffer import DataBuffer

from golem.network.transport import message
message.init_messages()

name = 'node-'+str(time.time())+'.'+str(random.randint(0, 2147483647))
prv_addr = '10.30.8.12'
prv_port = 40103
p2p_prv_port = 40102
pub_addr = '194.181.80.91'
proto_id = 14
data_dir = "/home/dybi/var/bootstrap_stress/"
cli_ver = '0.8.1'

dir = data_dir + name +'/keys'
keys_auth = EllipticalKeysAuth(data_dir + name)
EllipticalKeysAuth._keys_dir = dir

def prepare_hello(keys_auth, rand_val):
    node = Node(name, keys_auth.get_key_id(), prv_addr, prv_port, pub_addr,
                None,
                'Symmetric NAT', pub_addr, p2p_prv_port)

    challenge_kwargs = {}
    msg = message.MessageHello(
        proto_id=proto_id,
        port=p2p_prv_port,
        node_name=name,
        client_key_id=keys_auth.get_key_id(),
        node_info=node,
        client_ver=cli_ver,
        rand_val=rand_val,
        metadata=[],
        solve_challenge=False,
        **challenge_kwargs
    )

    msg.sig = keys_auth.sign(msg.get_short_hash())
    ser_msg = msg.serialize()
    #enc_msg = keys_auth.encrypt(ser_msg, keys_auth.get_key_id())
    db = DataBuffer()
    db.append_len_prefixed_string(ser_msg)
    return db.read_all()

def decode_msg(keys_auth, data):
    db = DataBuffer()
    db.append_string(data)
    messages = []
    for msg in db.get_len_prefixed_string():
        m = message.Message.deserialize_message(msg)
        if m is None:
            m = message.Message.deserialize_message(keys_auth.decrypt(msg))
        messages.append(m)
    return messages

MSG_TYPES = {
    0: 'hello',
    1: 'randval',
    2: 'disconnect',
    1005: 'get_tasks',
}

class EchoClientProtocol(asyncio.Protocol):
    def __init__(self, message, loop):
        self.loop = loop

    def connection_made(self, transport):
        print("[{}] Connection made".format(name))
        self.start = time.time()
        self.transport = transport

    def data_received(self, data):
        messages = None
        try:
            messages = decode_msg(keys_auth, data)
        except (RuntimeError, KeyError) as e:
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

        reply_hello = prepare_hello(keys_auth, msg.rand_val)
        print ('[{}] -> hello'.format(name))
        self.transport.write(reply_hello)

        reply = message.MessageRandVal(rand_val=msg.rand_val)
        reply.sig = keys_auth.sign(reply.get_short_hash())
        ser_msg = reply.serialize()
        enc_msg = keys_auth.encrypt(ser_msg, self.bootstrap_key_id)
        db = DataBuffer()
        db.append_len_prefixed_string(enc_msg)
        print ('[{}] -> rnd: {}'.format(name, reply.rand_val))
        self.transport.write(db.read_all())
        return

    def react_randval(self, msg):
        print ('[{}] randval rnd: {}'.format(name, msg.rand_val))

    def react_disconnect(self, msg):
        print('[{}] disconnect: {}'.format(name, msg.reason))

    def react_get_tasks(self, msg):
        print('[{}] get_tasks'.format(name))

    def connection_lost(self, exc):
        print('[{}] The server closed the connection after {}'.format(name, time.time()-self.start))
        self.loop.stop()

loop = asyncio.get_event_loop()

coro = loop.create_connection(lambda: EchoClientProtocol(message, loop),
                              '54.221.50.79', 40102)
loop.run_until_complete(coro)
loop.run_forever()
loop.close()
