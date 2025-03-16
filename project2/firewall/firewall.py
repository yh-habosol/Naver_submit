import os
from field import *


class BaseFirewall:
    def __init__(self, path):
        self.path = path
    
    def open(self):
        self.fs = open(os.path.join(self.path, 'whitelist_static.in'), 'a+')
        self.fd = open(os.path.join(self.path, 'debug.in'), 'a+')
    
    def close(self):
        self.fs.close()
        self.fd.close()
    
    def check(self, value):
        req_num = str(value[1])
        ip_ver = FVersion.get(value[2])
        proto = FProtocol.get(value[3])
        src_ip = FIP(value[4])
        src_port = FPort.get(value[5])
        dst_ip = FIP.get(value[6])
        dst_port = FPort.get(value[7])
        in_itf = FInterface.get(value[8])
        mac = FMAC.get(value[9])
        fmp = FProduction.get(str(value[10]))

        return (
            f'{req_num},{ip_ver},{proto},{src_ip},{src_port},'
            f'{dst_ip},{dst_port},{in_itf},{mac},{fmp}'
        )
    
    def set(self, in_or_out, value):
        self.req_num = value[0]
        self.ip_ver = f' -{value[1]}'
        self.proto = f' -p {value[2]}'
        self.src_ip = f' -s {value[3]}' if value[3] != 'None' else ''
        self.src_port = f' --sport {value[4]}' if value[4] != 'None' else ''
        self.dst_ip = f' -d {value[5]}' if value[5] != 'None' else ''
        self.dst_port = f' --dport {value[6]}' if value[6] != 'None' else ''
        self.in_itf = (
            f' -i {value[7]}' if in_or_out == 'IN' else f' -o {value[7]}'
        )
        self.mac = (
            f' -m mac --mac-source {value[8]}' if value[8] != 'None' else ''
        )
        self.fmp = 'WL_STATIC' if value[9] == 'o' else 'DEBUG'
    
    def error(self, file_path, value):
        _value = [x.replace('[Error]', '') for x in value if '[Error]' in x]
        _value = ', '.join(_value)
        self.fe = open(os.path.join(self.path, 'error.txt'), 'a+')
        self.fe.write(
            f'[File name]: {file_path}, [RN]: {value[0]} [Error]: {_value}\n'
        )
        self.fe.close()


class JLR(BaseFirewall):
    def __init__(self, path):
        self.log = {
            'Mistmatch_MAC_ADDR': 'UDP_SPOOFED_PACKET',
            'Mistmatch_IP_ADDR': 'TCPIP_SEV_DROP_INV_IP4_ADDR',
            'Mismatch_TCP_PORT': 'TCPIP_SEV_DROP_INV_PORT_TCP',
            'Mismatch_UDP_PORT': 'TCPIP_SEV_DROP_INV_PORT_UDP'
        }
        super().__init__(path)
    

    
    def write(self, in_or_out, value):
        super().set(in_or_out, value)
        file = self.fs if self.fmp == 'WL_STATIC' else self.fd

        if 'tcp' in self.proto:
            file.write(
                f"-A {self.fmp}_{in_or_out}{self.ip_ver}{self.in_itf}"
                f"{self.proto}{self.src_ip}{self.dst_ip} "
                f"-j RN{self.req_num}_PORT_TABLE\n"
            )
            file.write(self.prefix_log(self.log['Mistmatch_IP_ADDR']))
            file.write("\n\n")
            file.write(
                f"-A RN{self.req_num}_PORT_TABLE{self.src_port}"
                f"{self.dst_port} -j ACCEPT\n"
            )
            file.write(self.prefix_log(self.log['Mismatch_TCP_PORT']))
            file.write("\n\n")

        elif 'udp' in self.proto:
            file.write(
                f"-A {self.fmp}_{in_or_out}{self.ip_ver}{self.in_itf}"
                f"{self.proto}{self.src_ip}{self.mac} "
                f"-j RN{self.req_num}_PORT_TABLE\n"
            )
            file.write(self.prefix_log(self.log['Mistmatch_MAC_ADDR']))
            file.write("\n\n")
            file.write(
                f"-A RN{self.req_num}_PORT_TABLE{self.src_port}"
                f"{self.dst_port} -j ACCEPT\n"
            )
            file.write(self.prefix_log(self.log['Mismatch_UDP_PORT']))
            file.write("\n\n")

    @staticmethod
    def prefix_log(status):
        return (
            f'-A {status} -j NFLOG '
            f'--nflog-prefix "{status}" --nflog-group 5'
        )


