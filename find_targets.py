from distutils.log import debug
from os import walk
import argparse
import configparser
import os
import socket 
import threading
from dns import resolver
from dns import reversename
import json
from stuf import stuf
import csv  

config = configparser.ConfigParser()
config.read('find_banner.conf')
parser = argparse.ArgumentParser(description='find_targets.py -search apache -oc ./output.txt')
parser.add_argument('inputfile', type=str, help='Document to parse')
parser.add_argument('-search', action="store", type=str, dest='search', default=None,  help='Search this string in all fields')
parser.add_argument('-hostname', action="store", type=str, dest='hostname', default=None, help="hostname or part of hostname eg:.com")
parser.add_argument('-port', action="store", type=str, dest='port', default=None, help= "Specify port")
parser.add_argument('-product', action="store", type=str, dest='product', default=None, help= "product")
parser.add_argument('-version', action="store", type=str, dest='version', default=None, help="Search for specific version eg: 2.0 will output also 2.0.1")
parser.add_argument('-ip', action="store", type=str, dest='ip', default=None, help= "Search for specific IP")
parser.add_argument('-oc', action="store", type=str, dest='oc', default=None, help="Output a file. Elements will be separated by commas")
parser.add_argument('-o', action="store", type=str, dest='o', default=None, help="Output a file. Elements will be separated by new line")
parser.add_argument('-http', action="store", type=bool, dest='http', default=None, help="Add http or https to url")
parser.add_argument('-resolved', action="store", type=bool, dest='resolved', default=None, help="Show only registered hostnames")
parser.add_argument('-hik', action="store", type=bool, dest='hik', default=None, help="")
arguments = parser.parse_args()

resultList = []
maxthreads = 10
sema = threading.Semaphore(value=maxthreads)
skipped = 0
totalResult = 0
targetsDic = {}
with open(f"{arguments.inputfile}") as f:
    lines = [line[:-(line[-1] == '\n') or len(line)+1] for line in f]
    for line in lines:
        try:
            tempSplit = line.split(',')
            first2Sections = len(tempSplit[0])+len(tempSplit[1])+4
            line = line[first2Sections:]
            ip_address = tempSplit[0]
            port = tempSplit[1]
            line = line.split(',{},')
            hostnameBlock = line[0]
            hostnameBlock = hostnameBlock.replace("'",'"')
            hostnameBlock.replace('""', '"')
            hostnameBlock = hostnameBlock[:-2]
            hostnameBlock = json.loads(hostnameBlock)
            line = line[1]
            line = line.replace("'",'"')
            line.replace('""', '"')
            line = line[1:]
            line = line[:-2]
            lineTemp = line.split(' ')
            charToCut = len(lineTemp[0])+1
            line = line[charToCut:]
            line = json.loads(line)
            totalResult += 1
            line["port"] = port
            line['name']= hostnameBlock['name']
            targetsDic[ip_address] = line
        except Exception as e:
            skipped += 1
            # print(e)
# print(targetsDic)

for ip_address in targetsDic:
    boolcheck = []
    skipOtherCheck = False
    ipInfo  = targetsDic[ip_address]
    if ipInfo['state'] == "open":
        if arguments.ip:
            if ip_address == arguments.ip:
                boolcheck.append(True)
            else:
                boolcheck.append(False)
        if arguments.search:
            if arguments.search.lower() in ipInfo['product'].lower() or arguments.search.lower() in ipInfo['cpe'].lower() or arguments.search.lower() in ipInfo['extrainfo'].lower():
                boolcheck.append(True)
            else:
                boolcheck.append(False)
        if arguments.port:
            if arguments.port == ipInfo['port']:
                boolcheck.append(True)
            else:
                boolcheck.append(False)
        if arguments.version:
            if arguments.version in ipInfo['version']:
                boolcheck.append(True)
            else:
                boolcheck.append(False)
        if arguments.product:
            if arguments.product.lower() in ipInfo['product'].lower():
                boolcheck.append(True)
            else:
                boolcheck.append(False)
        if False in boolcheck:
            pass
        else:
            resultList.append({ip_address:ipInfo})

# print (f"Skipped {skipped}")
# print (f"Total results {totalResult}")
print("")
print(f"Total Results {len(resultList)}")
print("Search results:")
print("")
for i in resultList:
    for k, v in i.items():
        product = v["product"]
        version = v["version"]
        extrainfo = v["extrainfo"]
        port = v['port']
        print(f"{k} {port} {product} {extrainfo} {version}")

outputString = ""

domainResults = [None] * len(resultList)
def resolverCheck(ip: str, hostName: str, index: int):
    sema.acquire()
    try:
        addrs = reversename.from_address(ip)
        sema.release()
        name = str(resolver.resolve(addrs,"PTR")[0])
        print(f"{ip} => {name}")
        if hostName ==name:
            domainResults[index]= {"name": hostName, "dynamic": False}
        else:
            domainResults[index]= {"name": name, "dynamic": True}
    except Exception as e:
        print(e)
        print(f"{ip} => NXDOMAIN not found")
        domainResults[index]={"name": None, "dynamic": True}


index = 0
if arguments.oc:
    with open(f"{arguments.oc}", 'w', encoding='UTF8') as f:
        index = -1
        for i in resultList:
            for k, v in i.items():
                index = index + 1
                if arguments.resolved == True:
                    thread = threading.Thread(target=resolverCheck, args=[k,v["name"], index])
                    thread.start()
                if arguments.http == True:
                    if v['port'] == "80":
                        outputString = outputString+"http://"+k+", "
                    if v['port'] == "443":
                        outputString =  outputString+"https://"+k+", "
                    else:
                        outputString =  outputString+f"http://{k}:{v[port]}, "
                else:
                    outputString = outputString+k+","
        f.write(str(outputString[:-1]))
if arguments.o:
    with open(f"{arguments.o}", 'w', encoding='UTF8') as f:
        index = -1
        for i in resultList:
            for k, v in i.items():
                index = index + 1
                if arguments.resolved == True:
                    thread = threading.Thread(target=resolverCheck, args=[k,v["name"], index])
                    thread.start()
                if arguments.http == True:
                    if v['port'] == "80":
                        outputString =  outputString+"http://"+k+"\n"
                    if v['port'] == "443":
                        outputString =  outputString+"https://"+k+"\n"
                    if v['port'] == "81":
                        outputString = outputString+"http://"+k+":"+v['port']+"\n"
                else:
                    outputString = outputString+k+", "
        f.write(str(outputString[:-1]))
pass