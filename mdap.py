# !/usr/bin/env python
# -*- coding:utf-8 -*-

##############################################################
# MDAP - Multicast ? ? Protocol
# For Speedtouch/Thomson/Technicolor MediaAccess router
#
# MDAP is a protocol used by CPE devices from these brands to issue commands to CPEs (called ants)
# using UDP multicast address 224.0.0.103 and port 3235 registered by IANA
#
#
# Copyright (C) 2017  Laurent MEIRLAEN - 0BuRner
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
##############################################################
import argparse
import logging
import platform
import pprint
import re
import socket
import struct
import sys
import threading
import time

MDAP_LIB_VERSION = '0.1.0'

MCAST_GROUP = '224.0.0.103'
MCAST_PORT = 3235
MCAST_TTL = 1
SEND_TIMEOUT = 0
DISCOVER_TIMEOUT = 1
SHELL_TIMEOUT = 0.5


class MDAP_Ant():
    id = ''             # ANT-ID
    ip = ''             # IPv4 address
    metadata = {}       # REPLY-ANT-SEARCH data
    info = {}           # REPLY-INFO data
    auth = False        # False or tuple(login, password) if logged successfully at least one time
    credentials = ()    # Contains last tried tuple(login, password)

    last_exec = None    # Last exec command used against this ant

    def __init__(self, id, ip):
        self.id = id
        self.ip = ip

    def __getitem__(self, key):
        return getattr(self, key)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __repr__(self):
        return pprint.pformat(vars(self))


class MDAP_Sender:

    __sock = None

    def __init__(self, ip=None):
        self.__sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.__sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, MCAST_TTL)
        self.__sock.bind((ip, 0)) if ip else None  # Send packet from this interface if multiple interfaces are up | Windows only

    def send_search(self, version='1.2'):
        self.send_raw("ANT-SEARCH", version)

    def send_info(self, ant, seq, username=None, password=None, version='1.2'):
        self.send_raw("INFO", version, seq, ant, None, username, password)

    def send_exec(self, cmd, ant, seq, username=None, password=None, version='1.2'):
        self.send_raw("EXEC-CLI", version, seq, ant, cmd, username, password)

    def send_raw(self, verb=None, version=None, seq=None, ant_id=None, cmd=None, username=None, password=None):
        raw = "{} MDAP/{}\r\n".format(verb, version) if verb and version else ''
        raw += "CLI-CMD:{}\r\n".format(cmd) if cmd else ''
        raw += "SEQ-NR:{}\r\n".format(seq) if seq else ''
        raw += "TO-ANT:{}\r\n".format(ant_id) if ant_id else ''
        raw += "USER-ID:{}\r\n".format(username) if username else ''
        raw += "USER-PWD:{}\r\n".format(password) if password else ''
        self.__send(raw)

    def __send(self, message):
        self.__sock.sendto(self.append_checksum(message), (MCAST_GROUP, MCAST_PORT))
        time.sleep(SEND_TIMEOUT)  # add timeout waiting for devices response

    @staticmethod
    def append_checksum(message):
        res = 0
        for c in message:
            res ^= ord(c)
        return '{}{:02X}'.format(message, res)


class MDAP_Listener:

    __sock = None
    __listening = False

    __analyzer = None

    def __init__(self, analyzer, ip=None):
        self.__sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.__sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if ip:
            group = socket.inet_aton(MCAST_GROUP)
            interface = socket.inet_aton(ip)  # listen for multicast packets on this interface
            self.__sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, group + interface)
            logging.info('Listening on {}'.format(ip))
        else:
            mreq = struct.pack("4sl", socket.inet_aton(MCAST_GROUP), socket.INADDR_ANY)
            self.__sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        self.__sock.bind(('', MCAST_PORT))
        self.__analyzer = analyzer

    def listen(self):
        self.__listening = True
        while self.__listening:
            data, address = self.__sock.recvfrom(10240)
            logging.info('Received {} bytes from {}'.format(len(data), address))
            logging.debug(data)
            self.__analyzer.process((data, address))

    def stop(self):
        self.__listening = False


class MDAP_Analyzer:

    __mdap = None
    __sender = None

    __errors = {
        '-1': 'Invalid credentials',
        '-2': 'Invalid SQ-NR sequence number',
        '-3': 'Invalid EXEC command',
        '-5': 'Malformed message',
    }

    def __init__(self, mdap, sender):
        self.__mdap = mdap
        self.__sender = sender

    def process(self, data):
        message, address = data

        if 'REPLY-' in message:
            ant_id = re.findall('ANT-ID:(.+)\r\n', message, flags=re.IGNORECASE)[0]
            ant = self.__mdap.find_ant('id', ant_id)

            if ant and ant.ip is None:
                ant.ip = address[0]

            if not ant:
                ant = MDAP_Ant(ant_id, address[0])
                self.__mdap.ants.append(ant)
                print('New ANT discovered: {}@{}'.format(ant.id, ant.ip))

            if 'REPLY-ANT-SEARCH' in message:
                ant.metadata = self.merge(ant.metadata, self.extract(message))
            else:
                seq = re.findall('SEQ-NR:(.+)\r\n', message, flags=re.IGNORECASE)[0].strip()
                if seq[0] == '-':
                    logging.error(self.__errors.get(seq, 'Unknown error'))
                else:
                    ant.auth = ant.credentials

                    if 'REPLY-INFO' in message:
                        ant.info = self.merge(ant.info, self.extract(message))
                        if 'DONE' not in seq:
                            # acknowledge response by resending packet with next sequence
                            self.__sender.send_info(ant.id, int(seq) + 1, ant.auth[0], ant.auth[1])
                            print("Reply data INFO received from {}@{}".format(ant.id, ant.ip))

                    if 'REPLY-EXEC-CLI' in message:
                        self.print_exec(message)
                        if 'DONE' not in seq:
                            # acknowledge response by resending packet with next sequence
                            self.__sender.send_exec(None, ant.id, int(seq) + 1, ant.auth[0], ant.auth[1])

    @staticmethod
    def extract(reply):
        """ Transform REPLY-* data to dict as KEY:VALUE """
        ant_data = {}
        for item in (item for (index, item) in enumerate(reply.split('\r\n')) if ':' in item):
            ar = item.split(':')
            ant_data[ar[0]] = ar[1]
        return ant_data

    @staticmethod
    def merge(dict_x, dict_y):
        """ Given two dicts, merge them into a new dict as a shallow copy. """
        z = dict_x.copy()
        z.update(dict_y)
        return z

    @staticmethod
    def print_exec(message):
        idx = message.index('\r\n\r\n')  # Split protocol headers
        response = message[idx:]  # Strip protocol headers
        if len(response) > 5:  # Avoid printing confirmation REPLY
            if 'DONE' in message:
                print response[:-4].strip('\r\n')  # Strip double checksum and print newline
            else:
                sys.stdout.write(response[:-2].strip('\r\n'))  # Strip checksum and NO newline
                sys.stdout.flush()


class MDAP:
    ants = []

    __target = None

    __sender = None
    __listener = None
    __analyzer = None

    thread_listener = None

    def __init__(self, ip=None):
        if not ip and 'Windows' in platform.system():
            logging.warning(
                "Random interface will be used to listen to MULTICAST_GROUP " + MCAST_GROUP + ".\r\n" +
                "This program might not work.\r\n" +
                "Use 'set interface interface_ip' in interactive mode or '-i interface_ip' in command-line arguments.\r\n"
            )
        self.__sender = MDAP_Sender(ip)
        self.__analyzer = MDAP_Analyzer(self, self.__sender)
        self.__listener = MDAP_Listener(self.__analyzer, ip)
        self.__start()

    def __start(self):
        try:
            # condition = threading.Condition()
            self.thread_listener = threading.Thread(name='ListenerThread', target=self.__listener.listen, args=())
            self.thread_listener.setDaemon(True)
            self.thread_listener.start()
        except Exception as e:
            logging.exception("Unable to start thread", e)

    def __find_or_create_ant(self, key, value):
        ant = self.find_ant(key, value)

        # Create new ant only if ANT-ID is known
        if not ant and key == 'id':
            ant = MDAP_Ant(value, None)
            self.ants.append(ant)

        return ant

    def find_ant(self, key, value):
        return next((ant for (index, ant) in enumerate(self.ants) if ant[key] == value), False)

    def discover(self, timeout=DISCOVER_TIMEOUT):  # Active discovery
        self.__sender.send_search()
        logging.debug(self.ants)
        time.sleep(timeout)

    def set_target(self, ant):
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ant):  # Find already discovered ANT by IP
            self.__target = self.find_ant('ip', ant)
        elif len(ant) == 9:  # As ANT-ID is the serial-number, it should always be 9 char long
            self.__target = self.__find_or_create_ant('id', ant)
        else:
            self.__target = None

        if self.__target:
            print("Set target to {}".format(ant))
        else:
            logging.error("Unknown target. Use 'discover' or 'load' first.")

    def get_target(self):
        return self.__target

    def login(self, username, password):
        self.info(username, password)

    def info(self, username=None, password=None):
        if self.__target:
            if self.__target.auth:
                username = self.__target.auth[0]
                password = self.__target.auth[1]
            self.__target.credentials = (username, password)
            self.__sender.send_info(self.__target['id'], 1, username, password)
        else:
            logging.error("Unknown target. Use 'set target ip|ant_id' first")

    def exec_cmd(self, cmd, username=None, password=None):
        if self.__target:
            if self.__target.auth:
                username = self.__target.auth[0]
                password = self.__target.auth[1]
            self.__target.credentials = (username, password)
            self.__target.last_cmd = cmd
            self.__sender.send_exec(cmd, self.__target['id'], 1, username, password)
        else:
            logging.error("Unknown target. Use 'set target ip|ant_id' first")

    def send_raw(self, verb, ver, ant_id, seq, cmd, username=None, password=None):
        ant = self.__find_or_create_ant('id', ant_id)
        ant.credentials = (username, password)
        ant.last_cmd = cmd

        self.__sender.send_raw(verb, ver, seq, ant_id, cmd, username, password)

##############################################################

__log_levels = {
    'off': logging.ERROR,
    '-v': logging.WARNING,
    '-vv': logging.INFO,
    '-vvv': logging.DEBUG,
    'on': logging.WARNING,
}


def interactive():

    mdap = MDAP()
    time.sleep(0.3)

    while True:
        cmd = raw_input("mdap > ")

        if cmd in ["quit", "exit"]:
            break

        if not len(cmd):
            continue

        c = cmd.split()
        method = c[0]

        if method == "set":
            if "interface" == c[1]:
                mdap = MDAP(c[2])
            elif "target" == c[1]:
                mdap.set_target(c[2])
            elif "logging" == c[1]:
                level = c[2]
                logging.getLogger().setLevel(__log_levels.get(level, logging.WARNING))
            else:
                logging.error("Unknown command")
        elif method == "discover":
            mdap.discover()
        elif method == "info":
            login = c[1] if len(c) >= 2 else None
            pwd = c[2] if len(c) >= 3 else None
            mdap.info(login, pwd)
        elif method == "exec":
            if len(c) == 2:
                mdap.exec_cmd(c[1])
            elif len(c) == 3:
                mdap.exec_cmd(c[1], c[2])
            elif len(c) == 4:
                mdap.exec_cmd(c[1], c[2], c[3])
            else:
                logging.error("Wrong parameters number")
        elif method == "shell":
            target = mdap.get_target()

            if not target.auth:
                login = c[1] if len(c) >= 2 else None
                pwd = c[2] if len(c) >= 3 else None
                target.credentials = (login, pwd)

                if login is None:
                    logging.error("Credentials are needed to enter interactive shell mode")
                    continue

            while True:
                cmd = raw_input("{}@{}: ".format(target['credentials'][0], target['ip']))
                if cmd in ["quit", "exit"]:
                    break
                if not len(cmd):
                    continue

                mdap.exec_cmd(cmd, target.credentials[0], target.credentials[1])
                time.sleep(SHELL_TIMEOUT)
        elif method == "save":
            logging.exception(NotImplementedError)
        elif method == "load":
            logging.exception(NotImplementedError)
        elif method == "help":
            logging.exception(NotImplementedError)
        elif method == "show":
            logging.exception(NotImplementedError)
        elif method == "print":
            print(mdap.ants)
        else:
            logging.error("Unknown command")

        time.sleep(SHELL_TIMEOUT)


def command_line(sys_args):
    parser = argparse.ArgumentParser(description='MDAP Protocol Helper')
    parser.add_argument('--version', action='version', version='%(prog)s ' + MDAP_LIB_VERSION)
    parser.add_argument('-d', action='store_true', help='send ANT-SEARCH discovery packet to multicast')
    parser.add_argument('-i', metavar='iface_ip', help='the interface used to listen and send MDAP packets')
    parser.add_argument('-t', metavar='target', help='the target device (ant_id, ip)')
    parser.add_argument('-m', metavar='method', choices=['info', 'exec'], help='the method to call (%(choices)s)')
    parser.add_argument('-c', metavar='command', help='the command to execute', nargs='*')
    parser.add_argument('-u', metavar='user')
    parser.add_argument('-p', metavar='password')
    parser.add_argument('-v', '--verbose', action='count', help="add more 'v' for more verbose (up to 3)")

    args = parser.parse_args(sys_args)

    print ''

    if args.verbose:
        logging.getLogger().setLevel(__log_levels.get('-' + ('v' * args.verbose), logging.WARNING))

    mdap = MDAP(args.i)
    if args.d:
        mdap.discover()
    mdap.set_target(args.t)
    if 'info' == args.m:
        mdap.info(args.u, args.p)
        time.sleep(1)
        print(mdap.ants)
    if 'exec' == args.m:
        mdap.exec_cmd(' '.join(args.c), args.u, args.p)
        time.sleep(1)

if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING, format='%(asctime)s:%(levelname)-8s (%(threadName)s) %(message)s')

    if len(sys.argv) == 1:
        interactive()
    else:
        command_line(sys.argv[1:])

    exit(0)
