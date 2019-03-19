import socket
import random
import string
import argparse
import logging
import sys
from time import sleep
from random import randint
from select import select
from scapy.layers.llmnr import *
from scapy.layers.netbios import *
from scapy.layers.dns import DNSQR
from scapy.all import *
from binascii import b2a_hex
from smb.SMBConnection import SMBConnection
from smb.base import NotReadyError

NBNSBroadcast = "255.255.255.255"
NBNSBroadcastPort = 137
LLMNRBroadcast = "224.0.0.252"
LLMNRBroadcastPort = 5355
MULTICAST_TTL = 2

server_prefixes = ["srvdb","srvdb-","srvfile","srvfile-","corpfile-","srvweb","srvweb-","workstation-","reception-"]
bait_accounts = [["camerons","Password1"], ["srv-av-updater","antivirus"], ["SrvDefender","defending"]]

def listFromFile(filename):
    return open(filename).read().split("\n")

def loadHostnames(filename):
    logging.debug("Loading host prefixes from file [{}]".format(filename))
    server_prefixes = []
    lines = listFromFile(filename)
    for line in lines:
        if not line:
            continue
        server_prefixes.append(line)
    return server_prefixes

def loadUsernames(filename):
    logging.debug("Loading usernames:passwords from file [{}]".format(filename))
    bait_accounts = []
    lines = listFromFile(filename)
    for line in lines:
        if not line:
            continue
        user = line.split(":")
        bait_accounts.append(user)
    return bait_accounts

def genWonderingWorkstation():
    return "{}{}".format(server_prefixes[randint(0,len(server_prefixes)-1)],appendix_gen()).upper()

def appendix_gen(size=4, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def detectNBNSSpoof(name):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setblocking(0)
    request = NBNSQueryRequest(QUESTION_NAME=name)
    sock.sendto(bytes(request), (NBNSBroadcast, NBNSBroadcastPort))
    try:
        (ready, ar1, ar2) = select([sock], [], [], 5)
        if len(ready) > 0:
            p = sock.recv(10240)
            response = NBNSQueryResponse(p)
            return response.NB_ADDRESS
    except socket.error as sox:
        logging.error(sox)
    return None


def detectLLMNRSpoof(name):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MULTICAST_TTL)
    sock.setblocking(0)
    request = LLMNRQuery(id=RandShort(), qd=DNSQR(qname=name))
    sock.sendto(bytes(request), (LLMNRBroadcast, LLMNRBroadcastPort))
    try:
        (ready, ar1, ar2) = select([sock], [], [], 5)
        if len(ready) > 0:
            p = sock.recv(10240)
            response = LLMNRResponse(p)
            return response.an.rdata
    except socket.error as sox:
        logging.error(sox)
    return None

responder_ip = None

def sendSMBConnection(activeResponderIp, drive, directory, domain):
    global bait_accounts
    try:
        credidx = randint(0, len(bait_accounts)-1)
        logging.info("Seeding Responder {} with {}:{}".format(activeResponderIp, bait_accounts[credidx][0], bait_accounts[credidx][1]))
        conn = SMBConnection(bait_accounts[credidx][0], bait_accounts[credidx][1], 'connector', activeResponderIp, domain=domain, use_ntlm_v2=True, is_direct_tcp=True)
        conn.connect(activeResponderIp, 445)
        conn.listPath(drive, directory)
        conn.close()
    except NotReadyError as smbex:
        pass
    except Exception as ex:
        logging.error("Failed sending SMB creds: {}".format(ex))

def doDetection(detectionFunction):
    firstWorkstationName = genWonderingWorkstation()
    secondWorkstationName = genWonderingWorkstation()
    logging.debug("{}: Tesing with {} and {}".format(detectionFunction.__name__, firstWorkstationName, secondWorkstationName))
    activeResponderIp = detectionFunction(firstWorkstationName)
    if activeResponderIp:
        delay = randint(1,10)
        logging.info("{}: Got a response for {} from {}, sending verification using {} after {}s".format(detectionFunction.__name__,firstWorkstationName, activeResponderIp, secondWorkstationName, delay))
        sleep(delay)
        activeResponderIp = detectionFunction(secondWorkstationName)
        logging.info("{}: Got verification using {} from {}".format(detectionFunction.__name__,secondWorkstationName, activeResponderIp))
    return activeResponderIp

if __name__ == "__main__":
    banner = u"""\033[1;91m
  ______  _____    __         _____   ______  ______  _____  _____  ____   _  _____   ______  _____   
 |   ___|/     \ _|  |_  ___ |     | |   ___||   ___||     |/     \|    \ | ||     \ |   ___||     \  
 |   |  ||     ||_    _||___||     \ |   ___| `-.`-. |    _||     ||     \| ||      \|   ___||      \ 
 |______|\_____/  |__|       |__|\__\|______||______||___|  \_____/|__/\____||______/|______||______/ \033[1;m
                                                                                                      
 Author: @_w_m__                                                                                                     

"""
    print(banner)
    parser = argparse.ArgumentParser(description=u'Detects the use of LLMNR and NBT-NS spoofing')
    parser.add_argument(u'-L', dest=u'llmnronly', action=u'store_true', help=u'Only check for LLMRN spoofing')
    parser.add_argument(u'-N', dest=u'nbtnsonly', action=u'store_true', help=u'Only check for NBT-NS spoofing')
    parser.add_argument(u'-S', dest=u'seedresponder', action=u'store_true', help=u'Send fake SMB request with hash to "responder"')
    parser.add_argument(u'-H', dest=u'hostlist', help=u'List of hostnames to use as prefixes for random hostname generation')
    parser.add_argument(u'-u', dest=u'userlist', help=u'List of usernames and passwords to "seed" offending "responder"')
    parser.add_argument(u'-d', dest=u'delay',type=int, help=u'The delay in seconds between checks', default=10)
    parser.add_argument(u'-q', dest=u'staysilent',type=int, help=u'The delay in seconds to stop checking once a "responder" is detected', default=360)
    parser.add_argument(u'-f', dest=u'fakedrive',type=str, help=u'The fake share drive name', default="C$")
    parser.add_argument(u'-m', dest=u'fakedir',type=str, help=u'The fake directory name', default="/share/public")
    parser.add_argument(u'-V', dest=u'debug', action=u'store_true', help=u'Show debug output')
    parser.add_argument(u'-D', dest=u'domain', type=str, help=u'The fake domain to send with SMB "seeding"', default="CORP")
    args = parser.parse_args()
    level = logging.INFO
    if args.debug:
        level = logging.DEBUG
    logging.basicConfig(level=level,
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    datefmt='%m-%d %H:%M')

    
    if args.hostlist:
        server_prefixes = loadHostnames(args.hostlist)
    if args.userlist:
        bait_accounts = loadUsernames(args.userlist)
    if (len(server_prefixes) == 0) or (len(bait_accounts) == 0):
        logging.error("Hostlist or Userlist is empty, could be that your files were blank, please fix")
        sys.exit()
    logging.debug("Loaded {} hostname prefixes".format(len(server_prefixes)))
    logging.debug("Loaded {} usernames/passwords".format(len(bait_accounts)))
    logging.info("Detection started")
    while True:
        activeResponderIp = None
        if not args.llmnronly:
            activeResponderIp = doDetection(detectNBNSSpoof)
        if not args.nbtnsonly:
            if not activeResponderIp:
                activeResponderIp = doDetection(detectLLMNRSpoof)
        if activeResponderIp:
            logging.info("Spoofing detected by ip {}!, going dark for {}s".format(activeResponderIp, args.staysilent))
            if args.seedresponder:
                sendSMBConnection(activeResponderIp, args.fakedrive, args.fakedir, args.domain.upper())
            sleep(args.staysilent)
            logging.info("Going silent for {}s, don't want to spam the responder".format(args.staysilent))
        else:
            sleep(args.delay)