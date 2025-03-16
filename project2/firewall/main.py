import os
import argparse
import pandas as pd
from pathlib import Path
from firewall import *

parser = argparse.ArgumentParser(description='Firewall Rule Generator')
parser.add_argument('--oem', required=True, type=str, default='JLR',
                    help='Enter the OEM type [default: JLR]')
args = parser.parse_args()
OEM = args.oem

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')

if "rule" not in os.listdir(BASE_DIR):
    os.mkdir("./rule")

RULE_DIR = os.path.join(BASE_DIR, 'rule')


def generate_rule(file_path, oem):
    df = pd.read_excel(file_path, engine='openpyxl')
    in_or_out = df[(df.iloc[:, 0] == 'INPUT') | (df.iloc[:, 0] == 'OUTPUT')]

    is_in_or_out = 'IN' if in_or_out.values[0][0] == 'INPUT' else 'OUT'
    _df = df.iloc[in_or_out.index[0] + 2:, :]

    if oem == 'JLR':
        firewall = JLR(RULE_DIR)
        firewall.open()

        for value in _df.values:
            if pd.isna(value).all() or not pd.isna(value[0]) or 'sample' in value[14]:
                continue

            result = firewall.check(value)
            if '[Error]' in result:
                firewall.error(file_path.stem, result.split(','))
            else:
                firewall.write(is_in_or_out, result.split(','))

        firewall.close()
    else:
        raise Exception('[Error] OEM ..')


def main():
    inputs = sorted([i for i in Path(DATA_DIR).glob('*.xlsx')])
    for i in inputs:
        generate_rule(i, OEM)


if __name__ == "__main__":
    main()

