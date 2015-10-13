#!/usr/bin/env python

import socket
import struct
from os import system
import sys
import getopt

from IPy import IP


def ip2long(ip):
    """
    Convert an IP string to long
    """
    packed_ip = socket.inet_aton(ip)
    return struct.unpack("!L", packed_ip)[0]


def long2ip(long_int):
    """
    Convert an long to IP string
    """
    long_int = socket.inet_ntoa(long_int)
    return struct.unpack("!L", long_int)[0]


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
    # file_prefix = "/etc/sysconfig/network-scripts"
    # TODO: change path to correct one
    file_prefix = "/tmp"
    ip_prefix = ip + "/24"
    ip_range = IP(ip_prefix, make_net=True).strNormal(3)
    ip_range_split = ip_range.split("-")
    ip_start = ip_range_split[0]
    ip_end = ip_range_split[1]
    clonenum = 255*range_index

    filename = file_prefix + "/" + "ifcfg-" + interface + "-range" + str(range_index)
    print "Creating file: {0}".format(filename)

    with open(filename, "w+") as f:
        f.write("IPADDR_START={0}\n".format(ip_start))
        f.write("IPADDR_END={0}\n".format(ip_end))
        f.write("PREFIX=24\n")
        f.write("CLONENUM_START={0}\n".format(clonenum))
        f.write("ARPCHECK=no\n")

    with open(filename, 'r') as f:
        print "Printing content of {0}".format(filename)
        print f.read()

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
    ip_range = IP(first_ip + str("/24"), make_net=True)
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
    restart_cmd = "ifdown {0} && sudo ifup {0}".format(interface)
    system(restart_cmd)


def start_responder_instance_screen(index=0):
    """
    Function will start snmpsimd in screen so user can attach and see output of the snmpsimd
    :param index: index of instance to be started
    :type index: int
    :return:start command
    """
    start_screen_cmd = "screen -S responder_range_{0} -d -m snmpsimd.py --args-from-file=/var/tmp/ips_{0}.txt " \
                       "--v2c-arch --process-user=nobody --process-group=nobody".format(index)
    return system(start_screen_cmd)


def stop_responder_instance_screen(index=0):
    """
    Function will stop snmpsimd in screen
    :param index: index of instance to be stopped
    :type index: int
    :return:stop command
    """
    stop_screen_cmd = "do screen -X -S ${0}_responder quit".format(index)
    return system(stop_screen_cmd)


def print_usage():
    """
    Function to print how to use this script from command line
    :return: None
    """
    print "Usage: " + sys.argv[0] + " -a <action> -s <start IP> -e <end IP>"
    print "Example:" + sys.argv[0] + " -a configure -s 10.191.0.0 -e 10.191.20.255"


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
    num_ips = (ip2long(end_ip) - ip2long(start_ip))
    increments, rest = divmod(num_ips, 255)
    # in case range is lower then 255 return 1
    increments += 1
    return increments


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
        increments = get_increments(start_ip=start_ip, end_ip=end_ip)
        for counter in range(0, increments):
            ip = ((ip2long(str(start_ip))) + counter * 255)
            incremented_ip = long2ip(ip)
            create_range_file(ip=incremented_ip, interface="eth1", range_index=counter)
    else:
        print "Unknown action {0}".format(action)
        print "Known actions: configure, start, stop"
        print_usage()
        sys.exit(2)

    # check that IPs are ascending
    if start_ip and end_ip and ip2long(start_ip) <= ip2long(end_ip):
        print "Start IP is:", start_ip
        print "End IP is:", end_ip
        print "Action is:", action
    else:
        print "Start IP has to be lower or equal to end IP, both IPs have to be filled"
        print_usage()
        sys.exit(2)

if __name__ == "__main__":
    main(sys.argv[1:])
