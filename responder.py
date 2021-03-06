#!/usr/bin/env python

"""
Purpose: This script is meant to run on CentOS 7 template to configure SNMP responder using snmpsim.d
         This script can assign multiple IPs to an interface, create required files for snmpsim.d and launch multiple
         snmpsim.d instances in chunks of 255 IPs per snmpsim.d instance. For more details on snmpsim
         see http://snmpsim.sourceforge.net/

         For help on how to invoke this script see: print_usage()

Required: this script uses library IPy (see https://pypi.python.org/pypi/IPy/ ) in order to install it launch as root:
          yum install -y python-pip && pip install IPy

Author: Martin Pavlik
"""
from IN import AF_INET
import socket
import os
import sys
import getopt
import fnmatch
import struct
import fcntl

import IPy

FILE_PATH = "/etc/sysconfig/network-scripts"


def interface_check(interface="eth1"):
    """
    Check if network interface is UP from ifcfg point of view and check if wire is plugged into the interface
    :param interface: interface to check
    :type interface: str
    :return: exit code of the ifup command
    """
    # set some symbolic constants
    siocgifflags = 0x8913
    null256 = '\0'*256

    # create a socket so we have a handle to query
    from _socket import SOCK_DGRAM
    s = socket.socket(AF_INET, SOCK_DGRAM)

    # call ioctl() to get the flags for the given interface
    result = fcntl.ioctl(s.fileno(), siocgifflags, interface + null256)

    # extract the interface's flags from the return value
    flags, = struct.unpack('H', result[16:18])

    # check "UP" bit and print a message
    is_up = flags & 1

    if is_up != 1:
        print "Interface {} is DOWN".format(interface)
        sys.exit(2)
    if open("/sys/class/net/{0}/operstate".format(interface)).read().strip() != "up":
        print "Interface {0} has unplugged cable".format(interface)
        sys.exit(2)
    return True


def create_range_file(interface, ip, range_index):
    """
    function creates ifcfg-range files in order to assign IP ranges on the interface
    example of use: create_range_file(interface="eth1", ip="192.168.1.0", range_index=0)
    :param interface: interface for which the file is created, e.g. eth1
    :type interface: str
    :param ip: first ip in the range ending with zero
    :type ip: str
    :param range_index: index to determine clonenum for ifcfg file to avoid interface duplicity
    :type range_index int
    :return True if everything goes through
    """
    ip_prefix = ip + "/24"
    ip_range = IPy.IP(ip_prefix, make_net=True).strNormal(3)
    ip_range_split = ip_range.split("-")
    ip_start = ip_range_split[0]
    ip_end = ip_range_split[1]
    clonenum = 256*(range_index-1)

    filename = FILE_PATH + "/" + "ifcfg-" + interface + "-range" + str(range_index)
    print "Creating file: {0} for IP range {1}/24\n\n".format(filename, ip_start)

    with open(filename, "w+") as f:
        f.write("IPADDR_START={0}\n".format(ip_start))
        f.write("IPADDR_END={0}\n".format(ip_end))
        f.write("PREFIX=24\n")
        f.write("CLONENUM_START={0}\n".format(clonenum))
        f.write("ARPCHECK=no\n")

    return True


def create_ifcfg_file(interface="eth1"):
    """
    function creates ifcfg-XXXX file in order to configure interface to be used for IP ranges assignment
    :param interface: interface for which the file is created, e.g. eth1
    :type interface: str
    :return True if everything goes through
    """
    filename = FILE_PATH + "/" + "ifcfg-" + interface

    print "Creating ifcfg file for: {0}\n\n".format(interface)

    with open(filename, "w+") as f:
        f.write("DEVICE=\"{0}\"\n".format(interface))
        f.write("TYPE=\"Ethernet\"\n")
        f.write("BOOTPROTO=\"none\"\n")
        f.write("DEFROUTE=\"no\"\n")
        f.write("IPV6INIT=\"no\"\n")
        f.write("NAME=\"{0}\"\n".format(interface))
        f.write("ONBOOT=\"yes\"\n")
        f.write("NO_ALIASROUTING=\"yes\"\n")
        f.write("NM_CONTROLLED=\"no\"\n")
        f.write("ARPCHECK=\"no\"\n")
    return True


def create_route_file(ip, interface="eth1", netmask="255.255.0.0"):
    """
    function creates route-XXXX file in order to configure static route on network interface
    :param ip: IP from which will the network address derived based on netmask
    :type ip: str
    :param interface: interface for which the route file is created, e.g. eth1
    :type interface: str
    :param netmask: netmask for the route to be added
    :type netmask: str
    :return True if everything goes through
    """

    filename = FILE_PATH + "/" + "route-" + interface

    print "Creating route file {0} for interface: {1}".format(filename, interface)

    # convert ip to network address and remove /XX
    address = IPy.IP(ip).make_net(netmask).strNormal(0)

    with open(filename, "w+") as f:
        f.write("ADDRESS0=\"{0}\"\n".format(address))
        f.write("NETMASK0=\"{0}\"\n".format(netmask))
    return True


def create_responder_ip_file(first_ip, index):
    """
    This function creates file with list of IP addresses used as IPv4 end points for the responder
    :param first_ip: first IP which will be added to ip file for responder
    :type first_ip str
    :param index: index of the IP range file for the responder
    :type index int
    :return:
    """
    file_path = "/var/tmp/"
    file_name = "ips_" + str(index) + ".txt"
    ip_range = IPy.IP(first_ip + str("/24"), make_net=True)
    print "Creating responder config file {0}{1} for IP range {2}".format(file_path, file_name, ip_range)
    with open(file_path+file_name, "w+") as f:
        for ip in ip_range:
            f.write("--agent-udpv4-endpoint={0}\n".format(ip))
    return True


def restart_interface(interface="eth1"):
    """
    Put interface down and up in order to reload newly created config ifcfg files
    :param interface: interface which will be shut down and brought up
    :type interface: str
    :return: None
    """
    restart_cmd = "ifdown {0} && ifup {0}".format(interface)
    os.system(restart_cmd)


def start_responder_instance_screen(index=1):
    """
    Function will start snmpsimd in screen so user can attach and see output of the snmpsimd
    :param index: index of instance to be started
    :type index: int
    :return:start command
    """
    start_screen_cmd = "screen -S responder_range_{0} -d -m snmpsimd.py --args-from-file=/var/tmp/ips_{0}.txt " \
                       "--v2c-arch --process-user=nobody --process-group=nobody".format(index)
    print "Starting screen for responder_range_{0}\n".format(index)
    return os.system(start_screen_cmd)


def stop_responder_instance_screen(index=1):
    """
    Function will stop snmpsimd in screen
    :param index: index of instance to be stopped
    :type index: int
    :return:stop command
    """
    stop_screen_cmd = "screen -X -S responder_range_{0} quit".format(index)
    print "Stopping screen for responder_range_{0}\n".format(index)
    return os.system(stop_screen_cmd)


def print_usage():
    """
    Function to print how to use this script from command line
    :return: None
    """
    print "Usage: " + sys.argv[0] + " -a <action> -s <start IP> -e <end IP>"
    print "Example:" + sys.argv[0] + " -a configure -s 10.191.0.0 -e 10.191.20.255"
    print "Available actions: configure, start, stop, cleanup" \
          "\n\tconfigure: this will create ifcfg an ip files for responder" \
          "\n\tstart: will start responder instance in screen" \
          "\n\tstop: will stop responder instances" \
          "\n\tcleanup: will kill all responder instances and remove configuration files"


def get_increments(start_ip, end_ip):
    """
    Find how many increments by 255 are in between first and last IP in the range and the rest of the IPs after
    subtracting all the increments
    :param start_ip: first IP in the range
    :type start_ip str
    :param end_ip: last IP in the range
    :type end_ip str
    :return increments, rest
    """
    num_ips = (IPy.IPint(end_ip).int() - IPy.IPint(start_ip).int())
    increments, rest = divmod(num_ips, 255)
    # in case range is lower then 255 return 1
    increments += 1
    return increments, rest


def increment_range(start_ip, counter):
    """
    Increment IP address by 255 multiple times
    :param start_ip: base IP to be incremented
    :type start_ip: str
    :param counter: how many times do you want to increment the IP by 255
    :return:incremented IP
    """
    incremented_ip_int = IPy.IPint(start_ip).int() + counter * 255
    incremented_ip_str = IPy.intToIp(ip=incremented_ip_int, version=4)
    return incremented_ip_str


def kill_snmpsim():
    """
    Function to kill all snmpsimd.py process
    :return:
    """
    kill_cmd = "killall snmpsimd.py -s 9"
    print "Killing all snmpsimd instances..."
    os.system(kill_cmd)
    print "Done\n"


def kill_screen():
    """
    Function to kill and wipe all screen sessions
    :return:
    """
    kill_cmd = "killall screen -s 9"
    wipe_cmd = "screen -wipe"
    print "Killing all screen instances..."
    os.system(kill_cmd)
    print "Wiping dead screen instances..."
    os.system(wipe_cmd)
    print "Done\n"


def cleanup_files():
    """
    remove ifcfg, route configuration files and responder IP range files
    :return:
    """
    dir_ips = "/var/tmp/"
    pattern_ips = "ips_*.txt"
    pattern_ifcfg = "ifcfg-*-range*"
    pattern_route = "route-*"

    for f in os.listdir(dir_ips):
        if fnmatch.fnmatch(f, pattern_ips):
            print "Removing file {0}\n".format(os.path.join(dir_ips, f))
            os.remove(os.path.join(dir_ips, f))

    for f in os.listdir(FILE_PATH):
        if fnmatch.fnmatch(f, pattern_ifcfg) or fnmatch.fnmatch(f, pattern_route):
            print "Removing file {0}\n".format(os.path.join(FILE_PATH, f))
            os.remove(os.path.join(FILE_PATH, f))


def check_ip_ascending(start_ip, end_ip):
    # check that IPs are ascending
    if start_ip and end_ip and IPy.IPint(start_ip, 4).int() <= IPy.IPint(end_ip, 4).int():
        print "Start IP is: {0}\n".format(start_ip)
        print "End IP is: {0}\n\n".format(end_ip)

    else:
        print "Start IP has to be lower or equal to end IP, both IPs have to be filled"
        print_usage()
        sys.exit(2)


def main(argv):
    start_ip = ''
    end_ip = ''
    action = ''

    try:
        opts, args = getopt.getopt(argv, "ha:s:e:", ["action=", "start=", "end="])
    except getopt.GetoptError:
        print_usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help", "/h"):
            print_usage()
            sys.exit(2)
        elif opt in ("-s", "--start"):
            start_ip = arg
            # validate IP
            try:
                socket.inet_aton(start_ip)
            except socket.error:
                print "{0} is not valid IP address".format(start_ip)
                sys.exit(2)
        elif opt in ("-e", "--end"):
            end_ip = arg
            # validate IP
            try:
                socket.inet_aton(end_ip)
            except socket.error:
                print "{0} is not valid IP address".format(end_ip)
                sys.exit(2)
        elif opt in ("-a", "--action"):
            action = arg

    if action.lower() == "configure":
        check_ip_ascending(start_ip=start_ip, end_ip=end_ip)
        increments, rest = get_increments(start_ip=start_ip, end_ip=end_ip)
        cleanup_files()
        for counter in range(1, increments):
            incremented_ip = increment_range(start_ip, counter)
            create_range_file(ip=incremented_ip, interface="eth1", range_index=counter)
            create_responder_ip_file(first_ip=incremented_ip, index=counter)
            create_ifcfg_file()
            print ""
        create_route_file(ip=start_ip, netmask="255.255.0.0", interface="eth1")
        restart_interface()

    elif action.lower() == "start":
        check_ip_ascending(start_ip=start_ip, end_ip=end_ip)
        increments, rest = get_increments(start_ip=start_ip, end_ip=end_ip)
        if not interface_check():
            print "Network interface for SNMP responses is not UP !!!"
        for counter in range(1, increments):
            start_responder_instance_screen(index=counter)

    elif action.lower() == "stop":
        increments, rest = get_increments(start_ip=start_ip, end_ip=end_ip)
        for counter in range(1, increments):
            stop_responder_instance_screen(index=counter)

    elif action.lower() == "cleanup":
        kill_snmpsim()
        kill_screen()
        cleanup_files()
        restart_interface()

    else:
        print "Unknown action {0}".format(action)
        print "Known actions: configure, start, stop, cleanup"
        print_usage()
        sys.exit(2)

if __name__ == "__main__":
    main(sys.argv[1:])
