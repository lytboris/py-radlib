#!/usr/local/bin/python3

'''
libradius(3) wrapper
'''

import socket
from ctypes import *
from ctypes import util
from collections import namedtuple
from enum import IntEnum, unique

RadiusAttribute = namedtuple('RadiusAttribute', ['type', 'data', 'datalen', 'vendor'])

class DirctionaryChapter(IntEnum):
    # allow unknown attributes as pure integers
    def _missing_(value):
        return value

@unique
class MessageTypes(DirctionaryChapter):
    ACCESS_REQUEST	= 1
    ACCESS_ACCEPT	= 2
    ACCESS_REJECT	= 3
    ACCOUNTING_REQUEST	= 4
    ACCOUNTING_RESPONSE	= 5
    ACCESS_CHALLENGE	= 11
    DISCONNECT_REQUEST	= 40
    DISCONNECT_ACK	= 41
    DISCONNECT_NAK	= 42
    COA_REQUEST		= 43
    COA_ACK		= 44
    COA_NAK		= 45

@unique
class Attributes(DirctionaryChapter):
    USER_NAME		= 1 # String
    USER_PASSWORD	= 2 # String
    CHAP_PASSWORD	= 3 # String
    NAS_IP_ADDRESS	= 4 # IP address
    NAS_PORT		= 5 # Integer
    SERVICE_TYPE	= 6 # Integer
    FRAMED_PROTOCOL	= 7 # Integer
    FRAMED_IP_ADDRESS	= 8 # IP address
    FRAMED_IP_NETMASK	= 9 # IP address
    FRAMED_ROUTING	= 10 # Integer
    FILTER_ID		= 11 # String
    FRAMED_MTU		= 12 # Integer
    FRAMED_COMPRESSION	= 13 # Integer
    LOGIN_IP_HOST	= 14 # IP address
    LOGIN_SERVICE	= 15 # Integer
    LOGIN_TCP_PORT	= 16 # Integer
    # unassiged #17
    REPLY_MESSAGE	= 18 # String
    CALLBACK_NUMBER	= 19 # String
    CALLBACK_ID		= 20 # String
    # unassiged #21
    FRAMED_ROUTE	= 22 # String
    FRAMED_IPX_NETWORK	= 23 # IP address
    STATE		= 24 # String
    CLASS		= 25 # Integer
    VENDOR_SPECIFIC	= 26 # Integer
    SESSION_TIMEOUT	= 27 # Integer
    IDLE_TIMEOUT	= 28 # Integer
    TERMINATION_ACTION	= 29 # Integer
    CALLED_STATION_ID	= 30 # String
    CALLING_STATION_ID	= 31 # String
    NAS_IDENTIFIER	= 32 # String
    PROXY_STATE		= 33 # Integer
    LOGIN_LAT_SERVICE	= 34 # Integer
    LOGIN_LAT_NODE	= 35 # Integer
    LOGIN_LAT_GROUP	= 36 # Integer
    FRAMED_APPLETALK_LINK= 37 # Integer
    FRAMED_APPLETALK_NETWORK= 38 # Integer
    FRAMED_APPLETALK_ZONE= 39 # Integer
    # reserved for accounting #40-59 (see below)
    ACCT_INPUT_GIGAWORDS= 52
    ACCT_OUTPUT_GIGAWORDS= 53
    CHAP_CHALLENGE	= 60 # String
    NAS_PORT_TYPE	= 61 # Integer
    PORT_LIMIT		= 62 # Integer
    LOGIN_LAT_PORT	= 63 # Integer
    CONNECT_INFO	= 77 # String
    EAP_MESSAGE		= 79 # Octets
    MESSAGE_AUTHENTIC	= 80 # Octets
    ACCT_INTERIM_INTERVAL= 85 # Integer
    NAS_IPV6_ADDRESS	= 95 # IPv6 address
    FRAMED_INTERFACE_ID	= 96 # 8 octets
    FRAMED_IPV6_PREFIX	= 97 # Octets
    LOGIN_IPV6_HOST	= 98 # IPv6 address
    FRAMED_IPV6_ROUTE	= 99 # String
    FRAMED_IPV6_POOL	= 100 # String

# Accounting attribute types and values
    STATUS_TYPE		= 40 # Integer
    DELAY_TIME		= 41 # Integer
    INPUT_OCTETS	= 42 # Integer
    OUTPUT_OCTETS	= 43 # Integer
    SESSION_ID		= 44 # String
    AUTHENTIC		= 45 # Integer
    SESSION_TIME	= 46 # Integer
    INPUT_PACKETS	= 47 # Integer
    OUTPUT_PACKETS	= 48 # Integer
    TERMINATE_CAUSE	= 49 # Integer
    MULTI_SESSION_ID	= 50 # String
    LINK_COUNT		= 51 # Integer

    ERROR_CAUSE		= 101 # Integer

@unique
class FramedProtocol(DirctionaryChapter):
    PPP			= 1
    SLIP		= 2
    ARAP		= 3 # Appletalk
    GANDALF		= 4
    XYLOGICS		= 5

@unique
class ServiceType(DirctionaryChapter):
    LOGIN		= 1
    FRAMED		= 2
    CALLBACK_LOGIN	= 3
    CALLBACK_FRAMED	= 4
    OUTBOUND		= 5
    ADMINISTRATIVE	= 6
    NAS_PROMPT		= 7
    AUTHENTICATE_ONLY	= 8
    CALLBACK_NAS_PROMPT	= 9

@unique
class FramedCompression(DirctionaryChapter):
    COMP_NONE		= 0
    COMP_VJ		= 1
    COMP_IPXHDR		= 2

@unique
class NASPortType(DirctionaryChapter):
    ASYNC		= 0
    SYNC		= 1
    ISDN_SYNC		= 2
    ISDN_ASYNC_V120	= 3
    ISDN_ASYNC_V110	= 4
    VIRTUAL		= 5
    PIAFS		= 6
    HDLC_CLEAR_CHANNEL	= 7
    X_25		= 8
    X_75		= 9
    G_3_FAX		= 10
    SDSL		= 11
    ADSL_CAP		= 12
    ADSL_DMT		= 13
    IDSL		= 14
    ETHERNET		= 15
    XDSL		= 16
    CABLE		= 17
    WIRELESS_OTHER	= 18
    WIRELESS_IEEE_802_11= 19

@unique
class AcctAuthentic(DirctionaryChapter):
    RADIUS		= 1
    LOCAL		= 2
    REMOTE		= 3

@unique
class AcctTerminateCause(DirctionaryChapter):
    USER_REQUEST	= 1
    LOST_CARRIER	= 2
    LOST_SERVICE	= 3
    IDLE_TIMEOUT	= 4
    SESSION_TIMEOUT	= 5
    ADMIN_RESET		= 6
    ADMIN_REBOOT	= 7
    PORT_ERROR		= 8
    NAS_ERROR		= 9
    NAS_REQUEST		= 10
    NAS_REBOOT		= 11
    PORT_UNNEEDED	= 12
    PORT_PREEMPTED	= 13
    PORT_SUSPENDED	= 14
    SERVICE_UNAVAILABLE	= 15
    CALLBACK		= 16
    USER_ERROR		= 17
    HOST_REQUEST	= 18

@unique
class AcctStatueType(DirctionaryChapter):
    START		= 1
    STOP		= 2
    UPDATE		= 3
    ACCOUNTING_ON	= 7
    ACCOUNTING_OFF	= 8


radlib = CDLL(util.find_library("radius"))
libc = CDLL(util.find_library("c"))

libc.free.argtypes = [c_void_p]

radlib.rad_acct_open.restype = c_void_p
def rad_acct_open():
    return radlib.rad_acct_open()

radlib.rad_auth_open.restype = c_void_p
def rad_auth_open():
    return radlib.rad_auth_open()

radlib.rad_close.argtypes = [ c_void_p ]
def rad_close(handle):
    return radlib.rad_close(handle)

radlib.rad_add_server.argtypes = [ c_void_p, c_char_p, c_int, c_char_p, c_int, c_int ]
def rad_add_server(handle, hostname, port, secret, timeout, max_tries):
    return radlib.rad_add_server(handle, hostname.encode(), port, secret.encode(), timeout, max_tries)
    
radlib.rad_add_server_ex.argtypes = [ c_void_p, c_char_p, c_int, c_char_p, c_int, c_int, c_int, c_void_p ]
def rad_add_server_ex(handle, hostname, port, secret, timeout, max_tries, deadtime, bindto):
    return radlib.rad_add_server_ex(  handle, hostname.encode(), port,
                                    secret.encode(), timeout, max_tries, deadtime, socket.inet_aton(bindto))

radlib.rad_config.argtypes = [ c_void_p, c_char_p ]
def rad_config(handle, config_file):
    return radlib.rad_config(handle, config_file.encode())

class timeval(Structure):
    _fields_ = [("tv_sec", c_long), ("tv_usec", c_long)]
    
radlib.rad_init_send_request.argtypes = [ c_void_p, POINTER(c_int), POINTER(timeval) ]
def rad_init_send_request(handle):
    tv = timeval()
    fd = c_int()
    retval = radlib.rad_init_send_request(handle, byref(fd), byref(tv))
    return (retval, fd, tv)

radlib.rad_continue_send_request.argtypes = [ c_void_p, c_int, POINTER(c_int), POINTER(timeval) ]
def rad_continue_send_request(handle, selected, fd, tv):
    retval = radlib.rad_continue_send_request(handle, selected, byref(fd), byref(tv))
    return (retval, fd, tv)

radlib.rad_create_request.argtypes = [ c_void_p, c_int ]
def rad_create_request(handle, code):
    return radlib.rad_create_request(handle, code)

radlib.rad_create_response.argtypes = [ c_void_p, c_int ]
def rad_create_response(handle, code):
    return radlib.rad_create_response(handle, code)

radlib.rad_cvt_addr.restype = c_uint
radlib.rad_cvt_addr.argtypes = [ c_void_p ]
def rad_cvt_addr(data):
    _data = c_char_p(data)
    packed = radlib.rad_cvt_addr(byref(_data))
    return inet_ntoa(packed)

radlib.rad_cvt_int.restype = c_uint
radlib.rad_cvt_int.argtypes = [ c_void_p ]
def rad_cvt_int(data):
    _data = c_char_p(data)
    return radlib.rad_cvt_int(byref(_data))

radlib.rad_cvt_string.restype = POINTER(c_char)
radlib.rad_cvt_string.argtypes = [ c_void_p, c_size_t ]
def rad_cvt_string(data, datalen):
    _data = c_char_p(data)
    retval = radlib.rad_cvt_string(byref(_data), datalen)
    if bool(retval) == False:
        return None
    retcopy = string_at(retval)
    libc.free(retval)
    return retcopy

radlib.rad_get_attr.argtypes = [ c_void_p, c_void_p, c_void_p ]
def rad_get_attr(handle):
    pvalue = c_char_p()
    len = c_size_t()
    retval = radlib.rad_get_attr(handle, cast(byref(pvalue), POINTER(c_void_p)), byref(len))
    if retval == -1:
        raise Exception("Malformed attribute found in dataset %s" % rad_strerror(handle))
    if retval == 0:
        return None
    if retval == int(Attributes.VENDOR_SPECIFIC):
        return rad_get_vendor_attr(string_at(pvalue, len.value), len.value)
    return RadiusAttribute(Attributes(retval), string_at(pvalue, len.value), len.value, None)

def rad_get_attrs(handle):
    attrs = []
    while True:
        attr = rad_get_attr(handle)
        if attr == None:
            break
        attrs.append(attr)
    return attrs

radlib.rad_get_vendor_attr.artgtypes = [ POINTER(c_uint), c_void_p, POINTER(c_size_t) ]
def rad_get_vendor_attr(data, datalen):
    mdata = create_string_buffer(data)
    pdata = cast(byref(mdata), POINTER(c_void_p))
    vendor = c_int()
    len = c_size_t(datalen)
    retval = radlib.rad_get_vendor_attr(byref(vendor), byref(pdata), byref(len))
    return RadiusAttribute(retval, string_at(pdata, len.value), len.value, vendor.value)

radlib.rad_put_addr.argtypes = [ c_void_p, c_int, c_uint ]
def rad_put_addr(handle, type, value, af = socket.AF_INET):
    packed = socket.inet_pton(af, value)
    return radlib.rad_put_attr(handle, type, packed, len(packed))

def rad_put_addr6(handle, type, value):
    return rad_put_addr(handle, type, value, socket.AF_INET6)

radlib.rad_put_attr.argtypes = [ c_void_p, c_int, c_void_p, c_size_t ]
def rad_put_attr(handle, type, data, datalen):
    cdata = c_char_p(data)
    return radlib.rad_put_attr(handle, type, cdata, datalen)

radlib.rad_put_int.argtypes = [ c_void_p, c_int, c_uint ]
def rad_put_int(handle, type, value):
    return radlib.rad_put_int(handle, type, value)

radlib.rad_put_string.argtypes = [ c_void_p, c_int, c_char_p ]
def rad_put_string(handle, type, value):
    return radlib.rad_put_string(handle, type, value.encode())

radlib.rad_put_message_authentic.argtypes = [ c_void_p ]
def rad_put_message_authentic(handle):
    return radlib.rad_put_message_authentic(handle)

radlib.rad_put_vendor_addr.argtypes = [ c_void_p, c_int, c_int, c_uint ]
def rad_put_vendor_addr(handle, vendor, type, value):
    return radlib.rad_put_vendor_addr(handle, vendor, type, socket.inet_aton(value))

radlib.rad_put_vendor_attr.argtypes = [ c_void_p, c_int, c_int, c_void_p, c_size_t ]
def rad_put_vendor_attr(handle, vendor, type, data, datalen):
    cdata = c_char_p(data)
    return radlib.rad_put_vendor_attr(handle, vendor, type, cdata, datalen)

radlib.rad_put_vendor_int.argtypes = [ c_void_p, c_int, c_int, c_uint ]
def rad_put_vendor_int(handle, vendor, type, value):
    return radlib.rad_put_vendor_int(handle, vendor, type, value)

radlib.rad_put_vendor_string.argtypes = [ c_void_p, c_int, c_int, c_char_p ]
def rad_put_vendor_string(handle, vendor, type, value):
    return radlib.rad_put_vendor_string(handle, vendor, type, value.encode())

radlib.rad_request_authenticator.restype = c_ssize_t
radlib.rad_request_authenticator.argtypes = [ c_void_p, POINTER(c_char), c_size_t ]
def rad_request_authenticator(handle):
    buflen = 32
    while buflen < 128:
        buf = create_string_buffer(buflen)
        written = radlib.rad_request_authenticator(handle, buf, buflen)
        if written > 0:
            break
        buflen = buflen * 2
    result = buf.raw[0:written]
    return "".join("{:02x}".format(ord(bytes([c]))) for c in result)

radlib.rad_receive_request.argtypes = [ c_void_p ]
def rad_receive_request(handle):
    return radlib.rad_receive_request(handle)

radlib.rad_send_request.argtypes = [ c_void_p ]
def rad_send_request(handle):
    return radlib.rad_send_request(handle)

radlib.rad_send_response.argtypes = [ c_void_p ]
def rad_send_response(handle):
    return radlib.rad_send_response(handle)

radlib.rad_server_open.restype = c_void_p
radlib.rad_server_open.argtypes = [ c_int ]
def rad_server_open(fd):
    return radlib.rad_server_open(fd)

radlib.rad_server_secret.restype = c_char_p
radlib.rad_server_secret.argtypes = [ c_void_p ]
def rad_server_secret(handle):
	return radlib.rad_server_secret(handle)

radlib.rad_bind_to.argtypes = [ c_void_p, c_uint ]
def rad_bind_to(handle, addr):
    return radlib.rad_bind_to(handle, socket.inet_aton(addr))

radlib.rad_demangle.restype = POINTER(c_char)
radlib.rad_demangle.argtypes = [ c_void_p, c_void_p, c_size_t ]
def rad_demangle(handle, mangled, mlen):
    _data = c_char_p(mangled)
    retval = radlib.rad_demangle(handle, byref(_data), mlen)
    if bool(retval) == False:
        return None
    retcopy = string_at(retval)
    libc.free(retval)
    return retcopy

radlib.rad_demangle_mppe_key.restype = POINTER(c_char)
radlib.rad_demangle_mppe_key.argtypes = [ c_void_p, c_void_p, c_size_t, c_void_p ]
def rad_demangle_mppe_key(handle, mangled, mlen):
    _data = c_char_p(mangled)
    len = c_size_t()
    retval = radlib.rad_demangle(handle, byref(_data), mlen, byref(len))
    if bool(retval) == False:
        return None
    retcopy = string_at(retval)
    libc.free(retval)
    return (retcopy, len)

radlib.rad_strerror.restype = c_char_p
radlib.rad_strerror.argtypes = [ c_void_p ]
def rad_strerror(handle):
    return radlib.rad_strerror(handle)
