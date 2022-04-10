from os import walk
import argparse
import configparser
import threading
import nmap
from stuf import stuf
import csv  

config = configparser.ConfigParser()
parser = argparse.ArgumentParser(description='find_banner.py -inputdir mydir')
parser.add_argument('-inputdir', action="store", type=str, dest='inputdir')
parser.add_argument('-output', action="store", type=str, dest='output')
arguments = parser.parse_args()
maxthreads = 20
sema = threading.Semaphore(value=maxthreads)
if arguments.inputdir == None: 
    print ("inputdir needed")
    exit(1)
if arguments.output == None: 
    print ("output needed")
    exit(1)

header = ['Ip','Port','Banner']
def writeTofile(data):
    with open(f"{arguments.output}", 'a', encoding='UTF8') as f:
        writer = csv.writer(f)
        writer.writerow(data)

def port_scanner(ip,port ):
    sema.acquire()
    nm = nmap.PortScanner()
    sr =nm.scan(ip, str(port),"-sV" )
    print(sr)
    if ip in sr['scan']:
        data=[ip,port,sr['scan'][ip]['hostnames'],sr['scan'][ip]['vendor'],sr['scan'][ip]['tcp']]
        writeTofile(data)
    sema.release()

outDir = open(f"{arguments.inputdir}.sh", "w")
inDir = open(f"{arguments.inputdir}.sh", "w")
filenames = next(walk(f'{arguments.inputdir}'), (None, None, []))[2]  # [] if no file

for file in filenames:
    with open(f"{arguments.inputdir}/"+file, ) as f:
        lines = [line[:-(line[-1] == '\n') or len(line)+1] for line in f]
        for line in lines:
            if "open" in line:
                target = line.split(' ')
                thread = threading.Thread(target=port_scanner, args=[target[3],int(target[2])])
                thread.start()
