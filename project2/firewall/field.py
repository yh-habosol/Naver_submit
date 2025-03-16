import re
import math

class FMAC:
    __slots__ = 'mac'

    def __init__(self, mac=None):
        self.mac = self.error_check(mac) if mac else None

    def __str__(self):
        return str(self.mac)

    def __eq__(self, other):
        return self.mac == other

    @staticmethod
    def get(mac=None):
        return FMAC(mac) if mac else None

    def error_check(self, mac):
        pattern = r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
        try:
            if math.isnan(float(mac)):
                return None
        except:
            return mac if re.match(pattern, mac) else '[Error]MAC format'


class FIP:
    __slots__ = 'ip'

    def __init__(self, ip=None):
        self.ip = self.error_check(ip) if ip else None

    def __str__(self):
        return str(self.ip)

    def __eq__(self, other):
        return self.ip == other

    @staticmethod
    def get(ip=None):
        return FIP(ip) if ip else None

    def error_check(self, ip):
        error = None
        lines = str(ip).replace(' ', '').split(',')
        ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        subnet_pattern = r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$"

        try:
            if math.isnan(float(ip)):
                return None
        except:
            for line in lines:
                if not re.match(ip_pattern, line) and not re.match(subnet_pattern, line):
                    return '[Error]IP format'

                parts = line.split(".")
                for part in parts:
                    if "/" in part:
                        sub = part.split("/")
                        if not (0 <= int(sub[0]) <= 255 and 0 <= int(sub[1]) <= 32):
                            return '[Error]IP range'
                    elif not 0 <= int(part) <= 255:
                        return '[Error]IP range'
        return ip


class FVersion:
    __slots__ = 'version'

    def __init__(self, version=None):
        self.version = self.error_check(version) if version else None

    def __str__(self):
        return str(self.version)

    def __eq__(self, other):
        return self.version == other

    @staticmethod
    def get(version=None):
        return FVersion(version) if version else None

    def error_check(self, version):
        return version if str(version) in ['4', '6'] else '[Error]IP version'


class FPort:
    __slots__ = 'port'

    def __init__(self, port=None):
        self.port = self.error_check(port) if port else None

    def __str__(self):
        return str(self.port)

    def __eq__(self, other):
        return self.port == other

    @staticmethod
    def get(port=None):
        return FPort(port) if port else None

    def error_check(self, port):
        pattern = r"^\d+$|^\d+:\d+$"
        try:
            if math.isnan(float(port)):
                return None
        except:
            return port if re.match(pattern, str(port)) else '[Error]Port format'


class FProtocol:
    __slots__ = 'protocol'

    def __init__(self, protocol=None):
        self.protocol = self.error_check(protocol.lower()) if protocol else None

    def __str__(self):
        return str(self.protocol)

    def __eq__(self, other):
        return self.protocol == other

    @staticmethod
    def get(protocol=None):
        return FProtocol(protocol) if protocol else None

    def error_check(self, protocol):
        return protocol if protocol in ['udp', 'tcp'] else '[Error]Protocol format'


class FInterface:
    __slots__ = 'interface'

    def __init__(self, interface=None):
        self.interface = interface if interface else None

    def __str__(self):
        return str(self.interface)

    def __eq__(self, other):
        return self.interface == other

    @staticmethod
    def get(interface=None):
        return FInterface(interface) if interface else None


class FProduction:
    __slots__ = 'production'

    def __init__(self, production=None):
        self.production = self.error_check(production.lower()) if production else None

    def __str__(self):
        return str(self.production)

    def __eq__(self, other):
        return self.production == other

    @staticmethod
    def get(production=None):
        return FProduction(production) if production else None

    def error_check(self, production):
        return production if production in ['o', 'x'] else '[Error]Mass Production format'
