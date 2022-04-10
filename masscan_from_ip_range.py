import dataset
from stuf import stuf
import argparse
import configparser
import os
config = configparser.ConfigParser()
config.read('mass_scan_config.conf')
parser = argparse.ArgumentParser(description='masscan_from_ip_range.py -input country.txt')
parser.add_argument('-input', action="store", type=str, dest='input')
parser.add_argument('-ports', action="store", type=str, dest='ports')

arguments = parser.parse_args()
if arguments.input == None and arguments.description == None and arguments.name == None:
    print("arguments not found")
    exit(1)
if arguments.ports != None:
    ports = arguments.ports
else:
    ports = config['masscan']['ports']
print("Finding targets... Please wait")
with open(arguments.input) as f:
    lines = [line[:-(line[-1] == '\n') or len(line)+1] for line in f]
    targetList = []
    for line in lines:
        lineList = line.split(" ")
        ipStart = lineList[0]
        ipEnd = lineList[1]
        lineList.pop(0)
        lineList.pop(0)
        description = ' '.join(map(str, lineList))
        targetList.append([ipStart, ipEnd, description])
print(len(targetList))
path = f"./{arguments.input}-output/"
try:
    os.mkdir(path)
except OSError:
    print ("Creation of the directory %s failed" % path)
else:
    print ("Successfully created the directory %s " % path)
listascr = open(f"{path}{arguments.input}.sh", "w")
for target in targetList:
    listascr.write(f"masscan -e {config['masscan']['interface']} {target[0]}-{target[1]} -p{ports} --rate {config['masscan']['max-rate']} -oL ./{target[0]}-{target[1]}.txt\n")
