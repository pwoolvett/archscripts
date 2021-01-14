#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""

server_ip(){
    python3 -c "from socket import gethostbyname as g;print(g('$1'))"
}

vpn_addr() {
    ip add show ppp0 | egrep -o "inet\s+([0-9]+\.?){4}" | egrep -o "([0-9]+\.?){4}"
}
vpn_addr_srv() {
    ip add show ppp0 | egrep -o "peer\s+([0-9]+\.?){4}" | egrep -o "([0-9]+\.?){4}"
}

start(){

    systemctl start openswan
    #delay to ensure that IPsec is started before overlaying L2TP
    sleep 2
    systemctl start xl2tpd
    ipsec auto --up L2TP-PSK
    echo "c vpn-connection" > /var/run/xl2tpd/l2tp-control     
    #delay again to make that the PPP connection is up.
    sleep 2
    PPP_GW_ADD=$(vpn_addr)

    ip route add 10.100.10.0/24 via $(vpn_addr_srv) dev ppp0
    ip route add 10.200.10.0/24 via $(vpn_addr_srv) dev ppp0
}

start

#!/bin/bash
if [ $# != 1 ] ; then
    echo "Usage: (sudo) sh $0 {init|start|stop}" 
    exit 1;
fi

VPN_ADDR=XXX
IFACE=wlan0

function getIP(){
    ip addr show $1 | grep "inet " | awk '{print $2}' | sed 's:/.*::'       
}

function getGateWay(){
    ip route show default | awk '/default/ {print $3}'
}
function getVPNGateWay(){
    ip route | grep -m 1 "$VPN_ADDR" | awk '{print $3}'
}

GW_ADDR=$(getGateWay)  

function init(){
    cp ./options.l2tpd.client /etc/ppp/
    cp ./ipsec.conf /etc/
    cp ./ipsec.secrets /etc/
    cp ./xl2tpd.conf /etc/xl2tpd/
}

function start(){
    sed -i "s/^lns =.*/lns = $VPN_ADDR/g" /etc/xl2tpd/xl2tpd.conf
    sed -i "s/plutoopts=.*/plutoopts=\"--interface=$IFACE\"/g" /etc/ipsec.conf
    sed -i "s/left=.*$/left=$(getIP $IFACE)/g" /etc/ipsec.conf
    sed -i "s/right=.*$/right=$VPN_ADDR/g" /etc/ipsec.conf
    sed -i "s/^.*: PSK/$(getIP $IFACE) $VPN_ADDR : PSK/g" /etc/ipsec.secrets
    systemctl start openswan
    sleep 2    #delay to ensure that IPsec is started before overlaying L2TP

    systemctl start xl2tpd
    ipsec auto --up L2TP-PSK                        
    echo "c vpn-connection" > /var/run/xl2tpd/l2tp-control     
    sleep 2    #delay again to make that the PPP connection is up.

        ip route add $VPN_ADDR via $GW_ADDR dev $IFACE
        ip route add default via $(getIP ppp0)
        ip route del default via $GW_ADDR
}

function stop(){
    ipsec auto --down L2TP-PSK
    echo "d vpn-connection" > /var/run/xl2tpd/l2tp-control
    systemctl stop xl2tpd
    systemctl stop openswan
    
    VPN_GW=$(getVPNGateWay)
        ip route del $VPN_ADDR via $VPN_GW dev $IFACE
        ip route add default via $VPN_GW
}

$1
exit 0
"""

from datetime import datetime
import fcntl
import logging
import os
from pathlib import Path
import re
import shlex
import socket
from socket import gethostbyname
import struct
import subprocess as sp
import sys
from textwrap import dedent as _
from time import sleep

logging.basicConfig(
    level=logging.INFO,
    format='\x1b[6;30;42m' + "%(message)s" + '\x1b[0m'
)
logger = logging.getLogger("VPN")

def now():
    return datetime.now().isoformat().replace("-","_").replace(":", "_").replace(".", "_")

NOW = now()
IPSEC_CONF = _("""\
    config setup
         virtual_private=%v4:10.0.0.0/8,%v4:192.168.0.0/16,%v4:172.16.0.0/12
         nat_traversal=yes
         protostack=netkey
         plutoopts="--interface={interface}"

    conn L2TP-PSK
         authby=secret
         pfs=no
         auto=add
         keyingtries=3
         dpddelay=30
         dpdtimeout=120
         dpdaction=clear
         rekey=yes
         ikelifetime=8h
         keylife=1h
         type=transport
         left={local_ip}
         leftprotoport=17/1701
         right={server_ip}
         rightprotoport=17/1701
""")

IPSEC_SECRETS = '{local_ip} {server_ip} : PSK "{psk}"'

XL2TPD_CONF = _("""\
    [lac vpn-connection]
    lns = {server_ip}
    ppp debug = yes
    pppoptfile = /etc/ppp/options.l2tpd.client
    length bit = yes
""")

XL2TPD_CLIENT = _("""\
    ipcp-accept-local
    ipcp-accept-remote
    refuse-eap
    require-mschap-v2
    noccp
    noauth
    idle 1800
    mtu 1410
    mru 1410
    defaultroute
    usepeerdns
    debug
    connect-delay 5000
    name {username}
    password {password}
""")

def _local_ip(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fno = s.fileno()
    pack = struct.pack('256s', bytes(ifname[:15], encoding="utf8"))
    return socket.inet_ntoa(fcntl.ioctl(
        fno,
        0x8915,  # SIOCGIFADDR
        pack,
    )[20:24])

def vpn_ips(tunnel_device):
    stdout = _run(f"ip add show {tunnel_device}")
    match = re.match(
        r".*inet\s+(?P<own>([0-9]+\.?){4}).*peer\s+(?P<peer>([0-9]+\.?){4})(\/\d+)?",
        stdout,
        flags=re.MULTILINE|re.DOTALL
    )
    if match:
        result = match.groupdict()
        if all(result.get(name, "").count(".")==3 for name in ("own", "peer")):
            return result
    logger.error(f"Could not read ip using tunnel_device {tunnel_device}")
    sys.exit(3)

def _write(filepath:str, template:str, force=False, **template_kw):
    
    contents = template.format_map(template_kw)
    path = Path(filepath)
    if path.exists():
        msg = f"{path} already exists!"
        if force:
            np = path.with_name(f"{path.name}.{NOW}.bkp")
            logger.warning(f"{msg} Moving {path} to {np}")
            path.rename(np)
        else:
            logger.error(f"{msg} Not creating nor checking")
            return

    with open(path, "w") as fp:
        fp.write(contents)
    logger.info(f"Succesfully wrote into {path} the following contents:\n{contents}")


def _run(cmd):
    logger.info(f"Running command: {cmd}")
    try:
        stdout = sp.check_output(shlex.split(cmd), stderr=sp.PIPE)
    except (sp.CalledProcessError, sp.SubprocessError) as exc:
        logger.error(f"Failed running command {cmd}. Reason: {repr(exc)}")
        sys.exit(3)
    return stdout.decode("utf8")

def write_ipsec_conf(interface:str, local_ip:str, server_ip:str, force=False):

    """Configure basic information to establish IPsec tunnel to the VPN server.

    It enables NAT Traversal for if your machine is behind a NAT'ing
    router (most people are), and various other options that are
    necessary to connect correctly to the remote IPsec server.
    """

    _write(
        "/etc/ipsec.conf",
        template=IPSEC_CONF,
        interface=interface,
        local_ip=local_ip,
        server_ip=server_ip,
        force=force,
    )

def write_ipsec_secrets(local_ip:str, server_ip:str, psk:str, force=False):
    """Configure pre-shared key (PSK) for the server."""

    _write(
        "/etc/ipsec.secrets",
        IPSEC_SECRETS,
        local_ip=local_ip,
        server_ip=server_ip,
        psk=psk,
        force=force,
    )

def write_xl2tpd_conf(local_ip:str, server_ip:str, psk:str, force=False):
    """Configure xl2tpd connection params and optionspassed to pppd once the tunnel is set up."""
    _write(
        "/etc/xl2tpd/xl2tpd.conf",
        XL2TPD_CONF,
        server_ip=server_ip,
        force=force,
    )

def write_xl2tpd_client(username:str, password:str, force=False):
    """Configure xl2tpd client.

    Place your assigned username and password for the VPN server in this
    file. A lot of these options are for interoperability with Windows
    Server L2TP servers. If your VPN server uses PAP authentication,
    replace require-mschap-v2 with require-pap.
    """
    _write(
        "/etc/ppp/options.l2tpd.client",
        XL2TPD_CLIENT,
        username=username,
        password=password,
        force=force,
    )

def start_xl2tp_connection(num_attempts=10):
    _run("systemctl start openswan")
    _run("systemctl start xl2tpd")
    _run("ipsec auto --up L2TP-PSK")

    with open("/var/run/xl2tpd/l2tp-control", "w") as fp:
        fp.write("c vpn-connection")


    cmd = "ip link"

    pat = re.compile(r".*\d+:\s+(?P<tunnel_device>ppp\d+)\:\s+\<.*",flags=re.MULTILINE|re.DOTALL)
    
    for attempt in range(num_attempts):
        stdout = _run(cmd)
        match = pat.match(stdout)
        if match:
            result = match.groupdict()["tunnel_device"]
            if result:
                return result

        logger.warning(f"No tunnel device connected after {attempt} attempts",)
        sleep(1)

    logger.error(f"Command {cmd} output did not contain a 'pppX' interface after {num_attempts} attempts")
    sys.exit(2)

def enable_connection():
    """Enable lt2p connection via ipsec command."""
    _run("systemctl start openswan")
    _run("systemctl start xl2tpd")
    _run("ipsec auto --add L2TP-PSK")


def configure_openswan(
    interface:str,
    local_ip:str,
    server_ip:str,
    psk:str,
    force:bool=False,
):
    """Write openswan configuration files and enable connection."""

    write_ipsec_conf(interface=interface, local_ip=local_ip, server_ip=server_ip, force=force)
    write_ipsec_secrets(local_ip=local_ip, server_ip=server_ip, psk=psk, force=force)
    enable_connection()

def configure_xl2tpd(
    local_ip:str,
    server_ip:str,
    psk:str,
    username:str,
    password:str,
    force=False
):
    """Write xl2tpd configuration files and start the connection."""

    write_xl2tpd_conf(local_ip=local_ip, server_ip=server_ip, psk=psk, force=force)
    write_xl2tpd_client(username=username, password=password, force=force)
    return start_xl2tp_connection()

############################################################################################################
############################################################################################################
############################################################################################################
############################################################################################################
############################################################################################################

def install():
    """Install prerequisites.

    Install the xl2tpd and openswan (To use with NetworkManager:
    strongswan) packages.

    Now you can start openswan.service. If it's not running you may get
    an error message about a missing pluto_ctl connect(pluto_ctl)
    failed: No such file or directory.

    Run ipsec verify to check your configuration and resolve possible
    issues before continuing. 

    Note: The following versions are known to work
      xl2tpd   : 1.3.16-1
      openswan : 2.6.52.3-1
    """
    _run("yay -S xl2tpd openswan")
    _run("systemctl start openswan")
    _run("ipsec verify")

def configure(
    interface:str,
    local_ip:str,
    server_ip:str,
    psk:str,
    username:str,
    password:str,
    force:bool=False,
):
    """Configure openswan and xl2tpd."""
    configure_openswan(
        interface=interface,
        local_ip=local_ip,
        server_ip=server_ip,
        psk=psk,
        force=force,
    )
    return configure_xl2tpd(
        local_ip=local_ip,
        server_ip=server_ip,
        psk=psk,
        username=username,
        password=password,
    )

def route(
    vpn_add_or_subnet:str,
    peer_ip:str,
    tunnel_device:str,
):
    """Add a routing rule to your kernel table.

    # ip route add xxx.xxx.xxx.xxx via yyy.yyy.yyy.yyy dev pppX

    Note xxx.xxx.xxx.xxx is the specific ip address (e.g. 192.168.3.10)
    or subnet (e.g. 192.168.3.0/24) that you wish to communicate with
    through the tunnel device (e.g. ppp0).

    Note yyy.yyy.yyy.yyy is "peer ip" of your pppX device used to route
    traffic to tunnel destination xxx.xxx.xxx.xxx.


    See example below for command to identify tunnel device name and
    peer ip and then add route. :

    $ ip address

    4: ppp0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1400 qdisc fq_codel state UNKNOWN group default qlen 3
        link/ppp 
        inet 10.192.168.40 peer 192.0.2.1/32 scope global ppp0
           valid_lft forever preferred_lft forever

    # ip route add 192.168.3.0/24 via 192.0.2.1 dev ppp0

    Routing all traffic through the tunnel

    This is a lot more complex, but all your traffic will travel through
    the tunnel. Start by adding a special route for the actual VPN
    server through your current gateway:

    # ip route add 68.68.32.79 via 192.168.1.1 dev eth0

    This will ensure that once the default gateway is changed to the
    ppp interface that your network stack can still find the VPN server
    by routing around the tunnel. If you miss this step you will lose
    connectivity to the Internet and the tunnel will collapse. Now add a
    default route that routes to the PPP remote end:

    # ip route add default via yyy.yyy.yyy.yyy dev pppX

    The remote PPP end can be discovered by following the step in the
    previous section. Now to ensure that ALL traffic is routing through
    the tunnel, delete the original default route:

    # ip route delete default via 192.168.1.1 dev eth0

    To restore your system to the previous state, you can reboot or
    reverse all of the above steps.

    The route creation can also be automated by placing a script in
    /etc/ppp/ip-up.d.
    """

    _run(f"ip route add {vpn_add_or_subnet} via {peer_ip} dev {tunnel_device}")

def start(
    interface:str,
    server:str,
    vpn_add_or_subnet:str,
    psk:str="",
    username:str="",
    password:str="",
    force=False,
):
    if force:
        install()
    local_ip=_local_ip(interface)

    if server.count(".") != 3:
        server_ip = gethostbyname(server)
    else:
        server_ip = server

    tunnel_device = configure(
        interface=interface,
        local_ip=local_ip,
        server_ip=server_ip,
        psk=psk,
        username=username,
        password=password,
    )

    ips = vpn_ips(tunnel_device)
    peer_ip = ips["peer"]
    route(
        vpn_add_or_subnet=vpn_add_or_subnet,
        peer_ip=peer_ip,
        tunnel_device=tunnel_device
    )


def cli():

    if os.geteuid() != 0:
        logger.warning("Not runnign as sudo, attempting wrapping with sudo")
        return sp.run(shlex.split(f'sudo -k {sys.executable} ' + shlex.join(sys.argv)))

    allowed = [
        "help",
        "install",
        "configure",
        "route",
        "start"

        # "configure_openswan",
        # "configure_xl2tpd",

        # "start_xl2tp_connection",

        # "write_ipsec_conf",
        # "write_ipsec_secrets",
        # "write_xl2tpd_conf",
        # "add_connection",
    ]

    def __available(local):
        data = globals()
        data.update(local)
        return data

    def __summary(name):
        return (__available(locals())[name].__doc__ or "No help available").split('\n')[0].rstrip(".") + "."

    def help():
        """Show help"""
        logger.info("l2tp vpn setup based on wiki.archlinux.org/index.php/Openswan_L2TP/IPsec_VPN_client_setup")
        print("Available cmds:")
        for name in allowed:
            print(f"  {name:<20}: {__summary(name)}")

    if len(sys.argv) == 1:
        sys.argv = ["help"]
    else:
        sys.argv = list(sys.argv[1:])
    func = sys.argv.pop(0).lstrip("--")

    if func not in allowed:
        logger.error(f"Command {func} not available")
        help()

    __available(locals())[func](*sys.argv)

if __name__ == "__main__":
    cli()
