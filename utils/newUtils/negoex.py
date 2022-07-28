import ctypes
from enum import Enum

from asn1crypto import core
from minikerberos.protocol.asn1_structs import AS_REQ as AS_REQ1

from utils.newUtils.NegoExStructs import WST_EXCHANGE_MESSAGE, WST_BYTE_VECTOR, WST_MESSAGE_TYPE, WST_MESSAGE_HEADER, \
    WST_MESSAGE_SIGNATURE


class SPNEGO_PKINIT_REP(core.Sequence):
    class_ = 1
    tag = 0
    _fields = [
        ('kerberos-v5', core.ObjectIdentifier),
        ('null', core.Any),
        ('Kerberos', AS_REQ1),
    ]

class NegoExMessageType(Enum):
    MESSAGE_TYPE_INITIATOR_NEGO = 0
    MESSAGE_TYPE_ACCEPTOR_NEGO = 1
    MESSAGE_TYPE_INITIATOR_META_DATA = 2
    MESSAGE_TYPE_ACCEPTOR_META_DATA = 3
    MESSAGE_TYPE_CHALLENGE = 4
    MESSAGE_TYPE_AP_REQUEST = 5
    MESSAGE_TYPE_VERIFY = 6
    MESSAGE_TYPE_ALERT = 7


def parse_mechToken(hexData):
    headers = hexData.split("".join("{:02x}".format(ord(c)) for c in 'NEGOEXTS'))
    headers = [i[:8] for i in headers if i]

    # transform to big endian from little
    headers = [bytearray.fromhex(i) for i in headers]
    [i.reverse() for i in headers]
    headers = [int(i.hex(), 16) for i in headers]
    headers = [NegoExMessageType(i) for i in headers]
    return headers


toHex = lambda x: "".join([hex(c)[2:].zfill(2) for c in x])


def Pack(ctype_instance):
    buf = toHex(ctypes.string_at(ctypes.byref(ctype_instance), ctypes.sizeof(ctype_instance)))
    return buf


def generateAPRequest(data, oldMessage):
    signature = WST_MESSAGE_SIGNATURE(int.from_bytes(bytearray(oldMessage.Header.Signature), "big"))

    header2 = WST_MESSAGE_HEADER(signature,
                                 5,
                                 oldMessage.Header.SequenceNum,
                                 0,
                                 0,
                                 oldMessage.Header.ConversationId
                                 )

    exchange2 = WST_BYTE_VECTOR(64,  # should be ctypes.sizeof(header) + 8,
                                int(len(data) / 2),
                                0)

    exchangeMsg2 = WST_EXCHANGE_MESSAGE(header2,
                                        oldMessage.AuthScheme,
                                        exchange2)

    header = WST_MESSAGE_HEADER(signature,
                                WST_MESSAGE_TYPE.WST_MESSAGE_TYPE_AP_REQUEST.value,
                                oldMessage.Header.SequenceNum,
                                ctypes.sizeof(header2) + 24,
                                ctypes.sizeof(exchangeMsg2) + int(len(data) / 2),
                                oldMessage.Header.ConversationId
                                )

    exchange = WST_BYTE_VECTOR(ctypes.sizeof(header) + 24,
                               int(len(data) / 2),
                               0)

    ApRequestMsg = WST_EXCHANGE_MESSAGE(header,
                                        oldMessage.AuthScheme,
                                        exchange)
    return Pack(ApRequestMsg) + data
