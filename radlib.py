#!/usr/local/bin/python3

'''
libradius(3) wrapper
'''

import socket
from ctypes import *
from ctypes import util
from collections import namedtuple

RadiusAttribute = namedtuple('RadiusAttribute', ['type', 'data', 'datalen', 'vendor'])

# Message types
RAD_ACCESS_REQUEST	= 1
RAD_ACCESS_ACCEPT	= 2
RAD_ACCESS_REJECT	= 3
RAD_ACCOUNTING_REQUEST	= 4
RAD_ACCOUNTING_RESPONSE	= 5
RAD_ACCESS_CHALLENGE	= 11
RAD_DISCONNECT_REQUEST	= 40
RAD_DISCONNECT_ACK	= 41
RAD_DISCONNECT_NAK	= 42
RAD_COA_REQUEST		= 43
RAD_COA_ACK		= 44
RAD_COA_NAK		= 45

# Attribute types and values
RAD_USER_NAME		= 1 # String
RAD_USER_PASSWORD	= 2 # String
RAD_CHAP_PASSWORD	= 3 # String
RAD_NAS_IP_ADDRESS	= 4 # IP address
RAD_NAS_PORT		= 5 # Integer

RAD_SERVICE_TYPE	= 6 # Integer
RAD_LOGIN		= 1
RAD_FRAMED		= 2
RAD_CALLBACK_LOGIN	= 3
RAD_CALLBACK_FRAMED	= 4
RAD_OUTBOUND		= 5
RAD_ADMINISTRATIVE	= 6
RAD_NAS_PROMPT		= 7
RAD_AUTHENTICATE_ONLY	= 8
RAD_CALLBACK_NAS_PROMPT	= 9

RAD_FRAMED_PROTOCOL	= 7 # Integer
RAD_PPP			= 1
RAD_SLIP		= 2
RAD_ARAP		= 3 # Appletalk
RAD_GANDALF		= 4
RAD_XYLOGICS		= 5

RAD_FRAMED_IP_ADDRESS	= 8 # IP address
RAD_FRAMED_IP_NETMASK	= 9 # IP address
RAD_FRAMED_ROUTING	= 10 # Integer
RAD_FILTER_ID		= 11 # String
RAD_FRAMED_MTU		= 12 # Integer

RAD_FRAMED_COMPRESSION	= 13 # Integer
RAD_COMP_NONE		= 0
RAD_COMP_VJ		= 1
RAD_COMP_IPXHDR		= 2

RAD_LOGIN_IP_HOST	= 14 # IP address
RAD_LOGIN_SERVICE	= 15 # Integer
RAD_LOGIN_TCP_PORT	= 16 # Integer
# unassiged #17
RAD_REPLY_MESSAGE	= 18 # String
RAD_CALLBACK_NUMBER	= 19 # String
RAD_CALLBACK_ID		= 20 # String
# unassiged #21
RAD_FRAMED_ROUTE	= 22 # String
RAD_FRAMED_IPX_NETWORK	= 23 # IP address
RAD_STATE		= 24 # String
RAD_CLASS		= 25 # Integer
RAD_VENDOR_SPECIFIC	= 26 # Integer
RAD_SESSION_TIMEOUT	= 27 # Integer
RAD_IDLE_TIMEOUT	= 28 # Integer
RAD_TERMINATION_ACTION	= 29 # Integer
RAD_CALLED_STATION_ID	= 30 # String
RAD_CALLING_STATION_ID	= 31 # String
RAD_NAS_IDENTIFIER	= 32 # String
RAD_PROXY_STATE	= 33 # Integer
RAD_LOGIN_LAT_SERVICE	= 34 # Integer
RAD_LOGIN_LAT_NODE	= 35 # Integer
RAD_LOGIN_LAT_GROUP	= 36 # Integer
RAD_FRAMED_APPLETALK_LINK= 37 # Integer
RAD_FRAMED_APPLETALK_NETWORK= 38 # Integer
RAD_FRAMED_APPLETALK_ZONE= 39 # Integer
# reserved for accounting #40-59
RAD_ACCT_INPUT_GIGAWORDS= 52
RAD_ACCT_OUTPUT_GIGAWORDS= 53

RAD_CHAP_CHALLENGE	= 60 # String

RAD_NAS_PORT_TYPE	= 61 # Integer
RAD_ASYNC		= 0
RAD_SYNC		= 1
RAD_ISDN_SYNC		= 2
RAD_ISDN_ASYNC_V120	= 3
RAD_ISDN_ASYNC_V110	= 4
RAD_VIRTUAL		= 5
RAD_PIAFS		= 6
RAD_HDLC_CLEAR_CHANNEL	= 7
RAD_X_25		= 8
RAD_X_75		= 9
RAD_G_3_FAX		= 10
RAD_SDSL		= 11
RAD_ADSL_CAP		= 12
RAD_ADSL_DMT		= 13
RAD_IDSL		= 14
RAD_ETHERNET		= 15
RAD_XDSL		= 16
RAD_CABLE		= 17
RAD_WIRELESS_OTHER	= 18
RAD_WIRELESS_IEEE_802_11= 19

RAD_PORT_LIMIT		= 62 # Integer
RAD_LOGIN_LAT_PORT	= 63 # Integer
RAD_CONNECT_INFO	= 77 # String
RAD_EAP_MESSAGE		= 79 # Octets
RAD_MESSAGE_AUTHENTIC	= 80 # Octets
RAD_ACCT_INTERIM_INTERVAL= 85 # Integer
RAD_NAS_IPV6_ADDRESS	= 95 # IPv6 address
RAD_FRAMED_INTERFACE_ID	= 96 # 8 octets
RAD_FRAMED_IPV6_PREFIX	= 97 # Octets
RAD_LOGIN_IPV6_HOST	= 98 # IPv6 address
RAD_FRAMED_IPV6_ROUTE	= 99 # String
RAD_FRAMED_IPV6_POOL	= 100 # String

# Accounting attribute types and values
RAD_ACCT_STATUS_TYPE	= 40 # Integer
RAD_START		= 1
RAD_STOP		= 2
RAD_UPDATE		= 3
RAD_ACCOUNTING_ON	= 7
RAD_ACCOUNTING_OFF	= 8

RAD_ACCT_DELAY_TIME	= 41 # Integer
RAD_ACCT_INPUT_OCTETS	= 42 # Integer
RAD_ACCT_OUTPUT_OCTETS	= 43 # Integer
RAD_ACCT_SESSION_ID	= 44 # String

RAD_ACCT_AUTHENTIC	= 45 # Integer
RAD_AUTH_RADIUS		= 1
RAD_AUTH_LOCAL		= 2
RAD_AUTH_REMOTE		= 3

RAD_ACCT_SESSION_TIME	= 46 # Integer
RAD_ACCT_INPUT_PACKETS	= 47 # Integer
RAD_ACCT_OUTPUT_PACKETS	= 48 # Integer

RAD_ACCT_TERMINATE_CAUSE= 49 # Integer
RAD_TERM_USER_REQUEST	= 1
RAD_TERM_LOST_CARRIER	= 2
RAD_TERM_LOST_SERVICE	= 3
RAD_TERM_IDLE_TIMEOUT	= 4
RAD_TERM_SESSION_TIMEOUT= 5
RAD_TERM_ADMIN_RESET	= 6
RAD_TERM_ADMIN_REBOOT	= 7
RAD_TERM_PORT_ERROR	= 8
RAD_TERM_NAS_ERROR	= 9
RAD_TERM_NAS_REQUEST	= 10
RAD_TERM_NAS_REBOOT	= 11
RAD_TERM_PORT_UNNEEDED	= 12
RAD_TERM_PORT_PREEMPTED	= 13
RAD_TERM_PORT_SUSPENDED	= 14
RAD_TERM_SERVICE_UNAVAILABLE= 15
RAD_TERM_CALLBACK	= 16
RAD_TERM_USER_ERROR	= 17
RAD_TERM_HOST_REQUEST	= 18

RAD_ACCT_MULTI_SESSION_ID= 50 # String
RAD_ACCT_LINK_COUNT	= 51 # Integer

RAD_ERROR_CAUSE		= 101 # Integer

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
        raise Exception("Malformed attribute found in dataset %s" % rad_stderror(handle))
    if retval == 0:
        return None
    if retval == RAD_VENDOR_SPECIFIC:
        return rad_get_vendor_attr(string_at(pvalue, len.value), len.value)
    return RadiusAttribute(retval, string_at(pvalue, len.value), len.value, None)

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
