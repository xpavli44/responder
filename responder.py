#!/usr/bin/env python

"""
Purpose: This script is meant to run on CentOS 7 template to configure SNMP responder using snmpsim.d
         This script can assign multiple IPs to an interface, create required files for snmpsim.d and launch multiple
         snmpsim.d instances in chunks of 255 IPs per snmpsim.d instance. For more details on snmpsim
         see http://snmpsim.sourceforge.net/

         For help on how to invoke this scipt see: print_usage()

Required: this script uses library IPy (see https://pypi.python.org/pypi/IPy/ ) in order to install it launch as root:
          yum install -y python-pip && pip install IPy

Author: Martin Pavlik
"""

import socket
import struct
import os
import sys
import getopt
import fnmatch

import IPy


def ip2long(ip):
    """
    Convert an IP string to longint
    """
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def long2ip(long_int):
    """
    Convert a longint to IP string
    """
    return socket.inet_ntoa(struct.pack("!I", long_int))


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
    file_prefix = "/etc/sysconfig/network-scripts"
    ip_prefix = ip + "/24"
    ip_range = IPy.IP(ip_prefix, make_net=True).strNormal(3)
    ip_range_split = ip_range.split("-")
    ip_start = ip_range_split[0]
    ip_end = ip_range_split[1]
    clonenum = 256*(range_index-1)

    filename = file_prefix + "/" + "ifcfg-" + interface + "-range" + str(range_index)
    print "Creating file: {0} for IP range {1}/24".format(filename, ip_start)

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
    file_prefix = "/etc/sysconfig/network-scripts"
    filename = file_prefix + "/" + "ifcfg-" + interface

    print "Creating ifcfg file for: {0}".format(interface)

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
    return increments


def increment_range(start_ip, counter):
    """
    Increment IP address by 255 multiple times
    :param start_ip: base IP to be incremented
    :type start_ip: str
    :param counter: how many times do you want to increment the IP by 255
    :return:incremented IP
    """
    ip = IPy.IPint(start_ip).int() + counter * 255
    incremented_ip = IPy.intToIp(ip=ip, version=4)
    return incremented_ip


def kill_snmpsim():
    """
    Function to kill all snmpsimd.py process
    :return:
    """
    kill_cmd = "killall snmpsimd.py -s 9"
    print "Killing all snmpsimd instances..."
    os.system(kill_cmd)
    print "Done"


def kill_screeen():
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
    print "Done"


def cleanup_files():
    """
    remove ifcfg configuration files and responder IP range files
    :return:
    """
    dir_ips = "/var/tmp/"
    pattern_ips = "ips_*.txt"
    dir_ifcfg = "/etc/sysconfig/network-scripts/"
    pattern_ifcg = "ifcfg-*-range*"

    for f in os.listdir(dir_ips):
        if fnmatch.fnmatch(f, pattern_ips):
            print "Removing file {0}".format(os.path.join(dir_ips, f))
            os.remove(os.path.join(dir_ips, f))

    for f in os.listdir(dir_ifcfg):
        if fnmatch.fnmatch(f, pattern_ifcg):
            print "Removing file {0}".format(os.path.join(dir_ifcfg, f))
            os.remove(os.path.join(dir_ifcfg, f))


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

    # check that IPs are ascending
    if start_ip and end_ip and ip2long(start_ip) <= ip2long(end_ip):
        print "Start IP is:", start_ip
        print "End IP is:", end_ip
        print "Action is:", action
        print ""

    else:
        print "Start IP has to be lower or equal to end IP, both IPs have to be filled"
        print_usage()
        sys.exit(2)

    increments = get_increments(start_ip=start_ip, end_ip=end_ip)

    if action.lower() == "configure":
        cleanup_files()
        for counter in range(1, increments):
            incremented_ip = increment_range(start_ip, counter)
            create_range_file(ip=incremented_ip, interface="eth1", range_index=counter)
            create_responder_ip_file(first_ip=incremented_ip, index=counter)
            create_ifcfg_file()
            print ""
        restart_interface()

    elif action.lower() == "start":
        for counter in range(1, increments):
            start_responder_instance_screen(index=counter)

    elif action.lower() == "stop":
        for counter in range(1, increments):
            stop_responder_instance_screen(index=counter)

    elif action.lower() == "cleanup":
        kill_snmpsim()
        kill_screeen()
        cleanup_files()
        restart_interface()

    else:
        print "Unknown action {0}".format(action)
        print "Known actions: configure, start, stop, cleanup"
        print_usage()
        sys.exit(2)

if __name__ == "__main__":
    main(sys.argv[1:])
