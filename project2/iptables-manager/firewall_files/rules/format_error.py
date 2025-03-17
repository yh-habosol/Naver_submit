import re

interface_list = ["eth0.1", "eth0.10", "eth0.13"]
mass_list = ["O", "X"]
protocol_list = ["UDP", "TCP"]


##정의된 interface가 아닌 다른 interface 사용 시 error
def check_interface_format(filename, req_num, interface):
    error_txt = ""
    if interface == "":
        return error_txt

    if interface not in interface_list:
        error_txt = "In {0}, RN{1} : interface format error\n".format(filename, req_num)

    return error_txt


## hex:hex:hex:hex:hex:hex 형식의 mac address가 아니면 error
def check_mac_format(filename, req_num, mac_addr):
    error_txt = ""

    if mac_addr == "":
        return error_txt

    pattern_mac = r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
    if re.match(pattern_mac, mac_addr) is None:
        error_txt = "In {0}, RN{1} : mac address format error\n".format(
            filename, req_num
        )

    return error_txt


##int.int.int.int or int.int.int.int/subnet 형식이 아니면 error
##이때, 각 int는 0<=int<=255, 0<=subnet<=32임
def check_ip_format(filename, req_num, ips):
    error_txt = ""
    if not ips:
        return error_txt

    ip_li = ips.split(",")
    pattern_ip = r"^(\d{1,3}\.){3}\d{1,3}$"
    pattern_subnet = r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$"

    for ip in ip_li:
        ## ip address 형식이 아니라면
        if not re.match(pattern_ip, ip) and not re.match(pattern_subnet, ip):
            error_txt = "In {0}, RN{1} : Ip address format error\n".format(
                filename, req_num
            )
            break

        components = ip.split(".")
        for component in components:
            ##subnet이 있을 경우
            if "/" in component:
                component_subnet = component.split("/")
                if not 0 <= int(component_subnet[0]) <= 255:
                    error_txt = "In {0}, RN{1} : IP address range error\n".format(
                        filename, req_num
                    )
                if not 0 <= int(component_subnet[1]) <= 32:
                    error_txt += (
                        "In {0}, RN{1} : IP address subnet range error\n".format(
                            filename, req_num
                        )
                    )
                break
            ##subnet이 없을 경우
            elif not 0 <= int(component) <= 255:
                error_txt = "In {0}, RN{1} : IP address range error\n".format(
                    filename, req_num
                )
                break
        break

    return error_txt


## int or int:int 형식의 port가 아니면 error
def check_port_format(filename, req_num, port):
    error_txt = ""

    if port == "":
        return error_txt

    port = str(port)
    pattern_port = r"^\d+$"
    pattern_port_range = r"^\d+:\d+$"

    if not re.match(pattern_port, port) and not re.match(pattern_port_range, port):
        error_txt = "In {0}, RN{1} : port format error\n".format(filename, req_num)

    return error_txt


## O or X가 아니면 error
## mass production은 빈칸이 되면 안됨
def check_mass_format(filename, req_num, mass):
    error_txt = ""

    mass = str(mass)

    if mass not in mass_list:
        error_txt = "In {0}, RN{1} : mass format error\n".format(filename, req_num)

    return error_txt


##정의된 protocol이 아니면 error
##protocol은 빈칸이 되면 안됨
def check_protocol_format(filename, req_num, protocol):
    error_txt = ""

    protocol = str(protocol)

    if protocol not in protocol_list:
        error_txt = "In {0}, RN{1} : protocol format error\n".format(filename, req_num)

    return error_txt
