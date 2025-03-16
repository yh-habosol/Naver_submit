import usb.core
import usb.util
import time

dev = usb.core.find(idVendor=0x1782, idProduct=0x4d00)
dev.set_configuration()
cfg = dev.get_active_configuration()
intf = cfg[(0, 0)]


ep_out = usb.util.find_descriptor(
    intf,
    custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT)

ep_in = usb.util.find_descriptor(
    intf,
    custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN)


assert ep_out is not None
assert ep_in is not None


BSL_PING = b'\x00\x00'
BSL_CMD_START_DATA = b'\x00\x01'
BSL_CMD_MIDST_DATA = b'\x00\x02'
BSL_CMD_END_DATA = b'\x00\x03'
BSL_CMD_EXEC_DATA = b'\x00\x04'


fdl1_path = './fdl1-sign.bin'
with open(fdl1_path, 'rb') as f:
    fdl1_data = f.read()

file_size = len(fdl1_data)


def crc16_xmodem(data: bytes):
    crc = 0
    data = bytearray(data)
    msb = crc >> 8
    lsb = crc & 255
    for c in data:
        x = (0xFF & c) ^ msb
        x ^= (x >> 4)
        msb = (lsb ^ (x >> 3) ^ (x << 4)) & 255
        lsb = (x ^ (x << 5)) & 255
    return (msb << 8) + lsb

def crc16_fdl(data: bytes):
    crc = 0
    data = bytearray(data)
    l = len(data)
    for i in range(0, l, 2):
        if i + 1 == l:
            crc += data[i]
        else:
            crc += (data[i] << 8) | data[i + 1]
    crc = (crc >> 16) + (crc & 0xffff)
    crc += (crc >> 16)
    return ~crc & 0xffff


def create_hdlc_frame(data: bytes, crc_func):
    escaped_data = escape_data(data)
    if crc_func == None:
        crc_bytes = b""
    else:
        crc = crc_func(data).to_bytes(2, 'big')
        crc_bytes = escape_data(crc)
    return b'\x7e' + escaped_data + crc_bytes + b'\x7e'

def parse_hdlc_frame(frame: bytes, crc_func):
    if frame[0] != 0x7e or frame[-1] != 0x7e:
        raise ValueError("Invalid HDLC frame")
    unescaped_frame = unescape_data(frame[1:-1])
    data = unescaped_frame[:-2]
    return data

def escape_data(data: bytes):
    return data.replace(b'\x7d', b'\x7d\x5d').replace(b'\x7e', b'\x7d\x5e')

def unescape_data(data: bytes):
    return data.replace(b'\x7d\x5e', b'\x7e').replace(b'\x7d\x5d', b'\x7d')


def send_packet(data, crc_func):
    frame = create_hdlc_frame(data, crc_func)
    ep_out.write(frame)
    response = ep_in.read(ep_in.wMaxPacketSize).tobytes()
    return parse_hdlc_frame(response, crc_func)

def init_handshake():
    print("start handshake")
    res1 = send_packet(b'\x7e', crc16_xmodem)
    print("res1: ", res1)
    res2 = send_packet(b'\x00', crc16_xmodem)
    print("res2: ", res2)

def start_com(address, data):
    l = len(data)
    print("start start_com")
    addr = address.to_bytes(4, byteorder='big')
    f_size = (file_size + l).to_bytes(4, byteorder='big')
    packet = BSL_CMD_START_DATA + b'\x00\x08' + addr + f_size
    res = send_packet(packet, crc16_xmodem)
    print("res start: ", res)

def mid_com():
    print("start mid")
    chunk_size = 512
    for i in range(0, len(fdl1_data), chunk_size):
        chunk = fdl1_data[i:i+chunk_size]
        l = len(chunk)
        packet = BSL_CMD_MIDST_DATA + l.to_bytes(2, byteorder='big') + chunk
        res = send_packet(packet, crc16_xmodem)
        print("res mid: ", res)

def end_com():
    print("start end")
    packet = BSL_CMD_END_DATA + b'\x00\x00'
    res = send_packet(packet, crc16_xmodem)
    print("res end: ", res)

def exec_com(address):
    print("start exec")
    addr = address.to_bytes(4, byteorder='big')
    packet = BSL_CMD_EXEC_DATA + b'\x00\x04' + addr
    res = send_packet(packet, crc16_xmodem)
    print("res exec: ", res)

def final_handshake():
    print("final handshake")
    res = send_packet(b'\x7e', crc16_fdl)
    print("res final handshake: ", res)


def after(data, crc_func):
    print("after handshake")
    res = send_packet(data, crc_func)
    print("res after: ", res)
    return res
