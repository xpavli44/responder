import socket
import struct
from os import system

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
    :param range_index: index to determine clonennum for ifcfg file to avoid interface duplicity
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

    with open(filename, "w+") as f:
        f.write("IPADDR_START={0}\n".format(ip_start))
        f.write("IPADDR_END={0}\n".format(ip_end))
        f.write("PREFIX=24\n")
        f.write("CLONENUM_START={0}\n".format(clonenum))
        f.write("ARPCHECK=no\n")

    return True


def create_responder_ip_file(first_ip, index):
    """
    This function creates file with list of IP addresses used as IPv4 endpoinds for the responder
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
    start_screen_cmd = "screen -S responder_range_{0} -d -m snmpsimd.py --args-from-file=/var/tmp/ips_{0}.txt " \
                       "--v2c-arch --process-user=nobody --process-group=nobody".format(index)
    system(start_screen_cmd)
    return True


def stop_responder_instance_screen(index=0):
    stop_screen_cmd = "do screen -X -S ${0}_responder quit".format(index)
    system(stop_screen_cmd)
    return True