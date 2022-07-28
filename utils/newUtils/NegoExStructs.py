import ctypes
import random
import string
from enum import Enum


class WST_MESSAGE_TYPE(Enum):
    WST_MESSAGE_TYPE_CLIENT_HELLO = 0
    WST_MESSAGE_TYPE_SERVER_HELLO = 1
    WST_MESSAGE_TYPE_CLIENT_META_DATA = 2
    WST_MESSAGE_TYPE_SERVER_META_DATA = 3
    WST_MESSAGE_TYPE_CHALLENGE = 4
    WST_MESSAGE_TYPE_AP_REQUEST = 5
    WST_MESSAGE_TYPE_VERIFY = 6
    WST_MESSAGE_TYPE_ALERT = 7


class MessageTypes(Enum):
    INITIATOR_NEGO = 0
    ACCEPTOR_NEGO = 1
    INITIATOR_META_DATA = 2
    ACCEPTOR_META_DATA = 3
    CHALLENGE = 4
    AP_REQUEST = 5
    VERIFY = 6


class _WST_AUTH_SCHEME_VECTOR(ctypes.Structure):
    _fields_ = [("AuthSchemeArrayOffset", ctypes.c_ulong),
                ("AuthSchemeCount", ctypes.c_ushort),
                ("AuthSchemePad", ctypes.c_ushort)
                ]


class _WST_EXTENSION_VECTOR(ctypes.Structure):
    _fields_ = [("ExtensionArrayOffset", ctypes.c_ulong),
                ("ExtensionCount", ctypes.c_ushort),
                ("ExtensionPad", ctypes.c_ushort)
                ]


class WST_MESSAGE_SIGNATURE(ctypes.BigEndianStructure):
    _fields_ = [("Signature", ctypes.c_ulonglong)
                ]


class WST_BYTE_VECTOR(ctypes.LittleEndianStructure):
    _fields_ = [("ExchangeOffset", ctypes.c_ulong),
                ("ExchangeByteCount", ctypes.c_ushort),
                ("ExchangePad", ctypes.c_ushort)
                ]


class _WST_CHECKSUM(ctypes.Structure):
    _fields_ = [("cbHeaderLength", ctypes.c_ulong),
                ("ChecksumScheme", ctypes.c_ulong),
                ("ChecksumType", ctypes.c_ulong),
                ("ChecksumValue", WST_BYTE_VECTOR)
                ]


class WST_MESSAGE_HEADER(ctypes.LittleEndianStructure):
    _fields_ = [("Signature", WST_MESSAGE_SIGNATURE),
                ("MessageType", ctypes.c_int),
                ("SequenceNum", ctypes.c_ulong),
                ("cbHeaderLength", ctypes.c_ulong),
                ("cbMessageLength", ctypes.c_ulong),
                ("ConversationId", ctypes.c_ubyte * 16)
                ]


class WST_EXCHANGE_MESSAGE(ctypes.BigEndianStructure):
    _fields_ = [("Header", WST_MESSAGE_HEADER),
                ("AuthScheme", ctypes.c_ubyte * 16),
                ("Exchange", WST_BYTE_VECTOR)
                ]


class _WST_HELLO_MESSAGE(ctypes.BigEndianStructure):
    _fields_ = [("Header", WST_MESSAGE_HEADER),
                ("Random", ctypes.c_ubyte * 32),
                ("ProtocolVersion", ctypes.c_ulonglong),
                ("AuthSchemes", _WST_AUTH_SCHEME_VECTOR),
                ("Extensions", _WST_EXTENSION_VECTOR),
                ("AuthScheme", ctypes.c_ubyte * 16)
                ]


class _WST_VERIFY_MESSAGE(ctypes.BigEndianStructure):
    _fields_ = [("Header", WST_MESSAGE_HEADER),
                ("AuthScheme", ctypes.c_ubyte * 16),
                ("Checksum", _WST_CHECKSUM)
                ]