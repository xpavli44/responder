Purpose: This script is meant to run on CentOS 7 template to configure SNMP responder using snmpsim.d
         This script can assign multiple IPs to an interface, create required files for snmpsim.d and launch multiple
         snmpsim.d instances in chunks of 255 IPs per snmpsim.d instance. For more details on snmpsim
         see http://snmpsim.sourceforge.net/

         For help on how to invoke this scipt see: print_usage()

Required: this script uses library IPy (see https://pypi.python.org/pypi/IPy/ ) in order to install it launch as root:
          yum install -y python-pip && pip install IPy

Author: Martin Pavlik