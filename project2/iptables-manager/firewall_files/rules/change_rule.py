import pandas as pd
import math
import re
import os
import argparse

from config import *
from format_error import *

parser = argparse.ArgumentParser()
parser.add_argument("--oem", help="OEM argument")
args = parser.parse_args()

options_udp_line1 = {"-i": "", "-p": "", "-s": "", "-m mac --mac-source": ""}

options_udp_line3 = {"--sport": "", "--dport": ""}

options_tcp_line1 = {
    "-i": "",
    "-p": "",
    "-s": "",
    "-d": "",
}

options_tcp_line3 = {"--sport": "", "--dport": ""}


def get_current_dir():
    return os.getcwd()


def get_data_dir(current_dir):
    return current_dir + "/data"


def get_xlsx_list(data_dir):
    xlsx_file_lists = []

    for f in os.listdir(data_dir):
        if os.path.splitext(f)[1] == ".xlsx":
            xlsx_file_lists.append(f)

    return xlsx_file_lists


def get_rule_options(rule_options):
    for i in range(len(rule_options)):
        if "\n" in rule_options[i]:
            rule_options[i] = rule_options[i].replace("\n", " ")
    return rule_options


def get_policy(flow, mass):
    policies = {
        ("INPUT", "O"): "WL_STATIC_IN",
        ("INPUT", "X"): "DEBUG_IN",
        ("OUTPUT", "O"): "WL_STATIC_OUT",
        ("OUTPUT", "X"): "DEBUG_OUT",
    }

    return policies.get((flow, mass), None)


def make_rule(protocol, req_num, policy):
    rule = "##Request Number (RN) {0}\n".format(req_num)

    if protocol == "UDP":
        udp_rule_line1 = "-A {} ".format(policy)
        udp_rule_line1 += " ".join(
            ["{0} {1}".format(k, v) for k, v in options_udp_line1.items() if v]
        )
        udp_rule_line1 += "-j RN{}_PORT_TABLE\n".format(req_num)
        rule += udp_rule_line1

        rule += "-A -j NFLOG --nflog-prefix {0} --nflog-group 5\n\n".format(
            OEM_LOG[args.oem]["Mismatch_MAC_ADDR"]
        )

        udp_rule_line3 = "-A RN{}_PORT_TABLE ".format(req_num)
        udp_rule_line3 += " ".join(
            ["{0} {1}".format(k, v) for k, v in options_udp_line3.items() if v]
        )
        udp_rule_line3 += "-j ACCEPT\n"
        rule += udp_rule_line3

        rule += "-A -j NFLOG --nflog-prefix {0} --nflog-group 5\n\n\n".format(
            OEM_LOG[args.oem]["Mismatch_UDP_PORT"]
        )

    elif protocol == "TCP":
        tcp_rule_line1 = "-A {} ".format(policy)
        tcp_rule_line1 += " ".join(
            ["{0} {1}".format(k, v) for k, v in options_tcp_line1.items() if v]
        )
        tcp_rule_line1 += "-j RN{}_PORT_TABLE\n".format(req_num)
        rule += tcp_rule_line1

        rule += "-A -j NFLOG --nflog-prefix {0} --nflog-group 5\n\n".format(
            OEM_LOG[args.oem]["Mismatch_IP_ADDR"]
        )

        tcp_rule_line3 = "-A RN{}_PORT_TABLE ".format(req_num)
        tcp_rule_line3 += " ".join(
            ["{0} {1}".format(k, v) for k, v in options_tcp_line3.items() if v]
        )
        tcp_rule_line3 += "-j ACCEPT\n"
        rule += tcp_rule_line3

        rule += "-A -j NFLOG --nflog-prefix {0} --nflog-group 5\n\n\n".format(
            OEM_LOG[args.oem]["Mismatch_TCP_PORT"]
        )

    return rule


def main():
    current_dir = get_current_dir()
    data_dir = get_data_dir(current_dir)

    if not "output" in os.listdir(current_dir):
        os.mkdir("./output")

    xlsx_file_lists = get_xlsx_list(data_dir)

    for filename in xlsx_file_lists:
        try:
            df = pd.read_excel(
                data_dir + "/" + filename, engine="openpyxl", header=None
            )
        except FileNotFoundError as e:
            with open("./output/error.txt", "a") as f_error:
                f_error.write("File Not Found Error\n")
            print(e)
            exit(-1)

        ##data frame에서 중복 행 제거
        df = df.drop_duplicates(ignore_index=True)

        ##excel 파일을 읽은 후 결측치 포함 data frame의 row, col 크기
        ##row는 INPUT or OUTPUT이 있는 row 하나와, 최초 결측치 row, options row 제외
        ##col은 INPUT or OUTPUT이 있는 col 제외
        row_len = len(df.index) - 3

        ##data frame의 NaN 값을 "" 로 변경
        df = df.replace(float("NaN"), "")

        ##rule option을 따로 list로 추출
        rule_options = get_rule_options(list(df.loc[2])[1:])

        with open("./output/whitelist_static.in", "a") as f_static_in, open(
            "./output/whitelist_debug.in", "a"
        ) as f_debug_in:
            ##각각의 request number를 가지는 행에 대해서
            for ridx in range(3, 3 + row_len):
                row = list(df.loc[ridx])

                ## #Replaced to No가 존재하거나, Comment에 this request is sample 라고 적힌 row는
                ## rule을 적용하지 않음
                if (
                    row[0].startswith("#Replaced")
                    or row[rule_options.index("Comment") + 1]
                    == "this request is sample"
                ):
                    continue

                flow = df[0][1]
                req_num = row[1 + rule_options.index("#(Request Number)")]
                protocol = row[1 + rule_options.index("Protocol")]
                src_ip = row[1 + rule_options.index("SRC IP")]
                sport = row[1 + rule_options.index("SRC Port")]
                dst_ip = row[1 + rule_options.index("DST IP")]
                dport = row[1 + rule_options.index("DST Port")]
                interface = row[1 + rule_options.index("Incoming interface")]
                mac_addr = row[1 + rule_options.index("MAC")]
                mass = row[1 + rule_options.index("For mass production(O,X)")]
                policy = None

                error_txt = check_interface_format(filename, req_num, interface)
                error_txt += check_mac_format(filename, req_num, mac_addr)
                error_txt += check_ip_format(filename, req_num, src_ip)
                error_txt += check_ip_format(filename, req_num, dst_ip)
                error_txt += check_port_format(filename, req_num, sport)
                error_txt += check_port_format(filename, req_num, dport)
                error_txt += check_mass_format(filename, req_num, mass)
                error_txt += check_protocol_format(filename, req_num, protocol)

                if error_txt:
                    with open("./output/error.txt", "a") as f_error:
                        f_error.write(error_txt)
                    continue

                options_udp_line1["-i"] = interface
                options_udp_line1["-p"] = protocol
                options_udp_line1["-s"] = src_ip
                options_udp_line1["-m mac --mac-source"] = mac_addr

                options_udp_line3["--sport"] = sport
                options_udp_line3["--dport"] = dport

                options_tcp_line1["-i"] = interface
                options_tcp_line1["-p"] = protocol
                options_tcp_line1["-s"] = src_ip
                options_tcp_line1["-d"] = dst_ip

                options_tcp_line3["--sport"] = sport
                options_tcp_line3["--dport"] = dport

                policy = get_policy(flow, mass)
                rule = make_rule(protocol, req_num, policy)

                if policy and policy.startswith("WL"):
                    f_static_in.write(rule)
                elif policy and policy.startswith("DEBUG"):
                    f_debug_in.write(rule)


if __name__ == "__main__":
    main()
