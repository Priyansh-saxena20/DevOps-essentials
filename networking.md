################# NETWORKING ##########################

**The main advantage of a token-passing protocol is a reduction in collisions.

**optical fiber: It has limits of up to around 200 km, which makes it ideal for linking many buildings in a city.

**Many national networks operated by Telecommunications companies support packet switching protocols.

**Since IP datagrams cannot simply be mapped onto X.25 (or vice versa),they are encapsulated in X.25 packets
and sent over the network

** A more recent protocol commonly offered by telecommunications companies is called Frame Relay.

** Frame Relay is ideal for carrying TCP/IP between sites. Linux provides drivers
that support some types of internal Frame Relay devices.

** X.25, AX.25, X.25. Amateur radio,

** AX.25, like X.25, requires serial hardware capable of synchronous operation, or an
external device called a "Terminal Node Controller" to convert packets transmitted via an asynchronous serial link into packets transmitted synchronously.

** This scheme of directing data to a remote host is called routing, and packets are often referred to as datagrams in this context.
(f you are at the Math department and want to access quark on the Physics department's LAN from your Linux box, the
networking software will not send packets to quark directly because it is not on the same Ethernet. Therefore, it has to rely on the gateway to act as a forwarder. The
gateway (named sophus) then forwards these packets to its peer gateway niels at the Physics department, using the backbone network, with niels delivering it to the
destination machine.)

** datagram exchange is governed by a single protocol that is independent of the hardware
used: IP, or Internet Protocol.

**  The main benefit of IP is that it turns physically dissimilar networks into one apparently homogeneous network. This is called internetworking, and the resulting
"meta-network" is called an internet.

** steps of finding addresses are called hostname resolution, for mapping
hostnames onto IP addresses, and address resolution, for mapping the latter to hardware addresses.

** Serial Line IP. A modification of SLIP known as CSLIP, or Compressed SLIP, performs
compression of IP headers to make better use of the relatively low bandwidth provided by most serial links.

** Point-to-Point Protocol. PPP is more modern than SLIP and includes a number of features that
make it more attractive. Its main advantage over SLIP is that it isn't limited to transporting IP datagrams, but is designed
to allow just about any protocol to be carried across it.

** It is therefore the responsibility of the communicating hosts to check the integrity
and completeness of the data and retransmit it in case of error.

** A TCP connection works essentially like a two-way pipe that both processes may write to and read from.

** TCP identifies the end points of such a connection by the IP addresses of the two
hosts involved and the number of a port on each host. Ports may be viewed as attachment points for network connections.

** UDP allows an application to contact a service on a certain port of the remote machine, but it doesn't establish a
connection for this. Instead, you use it to send single packets to the destination service -- hence its name.

** It takes at least three datagrams to establish a TCP connection, another three to send
and confirm a small amount of data each way, and another three to close the connection.

** UDP provides us with a means of using only two datagrams to achieve almost the same result.

** If an application wants to offer a certain service, it attaches itself to a port and waits for
clients (this is also called listening on the port).

** The same port may be open on many different machines, but on each machine only one process can open a port at any one time.

** Linux uses a file called /etc/services that maps service names to numbers.

** It is worth noting that although both TCP and UDP connections rely on ports,
these numbers do not conflict. This means that TCP port 513, for example, is different from UDP port 513.

** Berkeley Socket Library. Its name derives from a popular analogy that views ports as sockets and
connecting to a port as plugging in.

** In Linux, the socket library is part of the standard libc C library.
It supports the AF_INET and AF_INET6 sockets for TCP/IP and AF_UNIX for Unix domain sockets.

** Unix-to-Unix Copy (UUCP) started out as a package of programs that transferred
files over serial lines, scheduled those transfers, and initiated execution of programs on remote sites.

** One of the main disadvantages of UUCP networks is that they operate in batches.
Rather than having a permanent connection established between hosts, it uses temporary connections.

** While it is connected, it will transfer all of the news, email, and files that have been queued,
and then disconnect. It is this queuing that limits the sorts of applications that UUCP can be applied to.

** The latest stable Linux kernels can be found on ftp.kernel.org in /pub/linux/kernel/v2.x/, where x is an even number.

** The latest experimental Linux kernels can be found on ftp.kernel.org in /pub/linux/kernel/v2.y/, where y is an odd number.

** if you want to allow diskless hosts to boot from your machine, you must provide Trivial File Transfer Protocol (TFTP) so
that they can download basic configuration files from the /boot directory.

** there are tools like tripwire, written by Gene Kim and Gene Spafford, that allow you to check vital system files to see if
their contents or permissions have been changed.

** each peripheral networking device, a corresponding interface has to be present
in the kernel. For example, Ethernet interfaces in Linux are called by such names as eth0 and eth1;
PPP (discussed in Chapter 8, The Point-to-Point Protocol) interfaces are named ppp0 and ppp1; and FDDI
interfaces are given names like fddi0 and fddi1.

**  Before being used by TCP/IP networking, an interface must be assigned an IP
address that serves as its identification when communicating with the rest of the
world. This address is different from the interface name mentioned previously; if
you compare an interface to a door, the address is like the nameplate pinned on it.

** Other device parameters may be set, like the maximum size of datagrams that can
be processed by a particular piece of hardware, which is referred to as Maximum
Transfer Unit (MTU).

** A number of network addresses are reserved for special purposes. 0.0.0.0 and
127.0.0.0 are two such addresses. The first is called the default route, and the latter
is the loopback address.

** Network 127.0.0.0 is reserved for IP traffic local to your host. Usually, address
127.0.0.1 will be assigned to a special interface on your host, the loopback
interface, which acts like a closed circuit, The loopback network also allows you to use networking
software on a standalone host.

** A mechanism is needed to map IP addresses onto the addresses of the underlying
network. The mechanism used is the Address Resolution Protocol (ARP).

** Once a host has discovered an Ethernet address,
it stores it in its ARP cache so that it doesn't have to query for it again the next
time it wants to send a datagram to the host in question.

** Sometimes it is also necessary to find the IP address associated with a given
Ethernet address. This happens when a diskless machine wants to boot from a
server on the network, which is a common situation on Local Area Networks. A
diskless client, however, has virtually no information about itself -- except for its
Ethernet address! So it broadcasts a message containing a request asking a boot
server to provide it with an IP address. There's another protocol for this situation
named Reverse Address Resolution Protocol (RARP). Along with the BOOTP
protocol, it serves to define a procedure for bootstrapping diskless clients over the
network.

** we know that the default route matches every destination, but datagrams destined for
locally attached networks will match their local route, too. How does IP know
which route to use? It is here that the netmask plays an important role. While both
routes match the destination, one of the routes has a larger netmask than the other.
We previously mentioned that the netmask was used to break up our address space
into smaller networks.

** . For routing inside autonomous systems (such as the Groucho Marx
campus), the internal routing protocols are used. The most prominent one of these
is the Routing Information Protocol (RIP), which is implemented by the BSD
routed daemon. For routing between autonomous systems, external routing
protocols like External Gateway Protocol (EGP) or Border Gateway Protocol

** IP has a companion protocol that we haven't talked about yet. This is the Internet
Control Message Protocol (ICMP), used by the kernel networking code to
communicate error messages to other hosts.

** kernel accesses a piece of network hardware
through a software construct called an interface. Interfaces offer an abstract set of functions that are the same
across all types of hardware, such as sending or receiving a datagram.

** Unix-like operating systems, the network interface is
implemented as a special device file in the /dev/ directory. If you type the ls -las /dev/ command, you
will see what these device files look like

** SLIP interfaces are handled differently from others
because they are assigned dynamically. Whenever a SLIP connection is established, an interface is assigned to
the serial port.

** Gateway: You have to enable this option if your system acts as a gateway between two networks or between a LAN
and a SLIP link, etc. It doesn't hurt to enable this by default, but you may want to disable it to configure a
host as a so-called firewall.

** Firewall: Firewalls are hosts that are connected to two or more networks, but don't
route traffic between them. They're commonly used to provide users with Internet access at minimal risk
to the internal network. Users are allowed to log in to the firewall and use Internet services, but the
company's machines are protected from outside attacks because incoming connections can't cross the
firewall

** Virtual hosting: These options together allow to you configure more than one IP address onto an interface. This is
sometimes useful if you want to do "virtual hosting," through which a single machine can be configured
to look and act as though it were actually many separate machines, each with its own network
personality. We'll talk more about IP aliasing in a moment:
[*] Network aliasing
<*> IP: aliasing support

** Accounting
This option enables you to collect data on the volume of IP traffic leaving and arriving at your machine

** PC hug
This option works around an incompatibility with some versions of PC/TCP, a commercial TCP/IP
implementation for DOS-based PCs. If you enable this option, you will still be able to communicate with
normal Unix machines, but performance may be hurt over slow links:

** Diskless booting
This function enables Reverse Address Resolution Protocol (RARP). RARP is used by diskless clients
and X terminals to request their IP address when booting. You should enable RARP if you plan to serve
this sort of client. A small program called rarp, included with the standard networking utilities, is used to
add entries to the kernel RARP table:

** MTU
When sending data over TCP, the kernel has to break up the stream into blocks of data to pass to IP. The
size of the block is called the Maximum Transmission Unit, or MTU. For hosts that can be reached over a
local network such as an Ethernet, it is typical to use an MTU as large as the maximum length of an Ethernet packet -- 1,500
bytes. When routing IP over a Wide Area Network like the Internet, it is preferable to use smaller-sized datagrams to
ensure that they don't need to be further broken down along the route through a process called IP fragmentation.

** Security feature
The IP protocol supports a feature called Source Routing. Source routing allows you to specify the route a
datagram should follow by coding the route into the datagram itself. This was once probably useful
before routing protocols such as RIP and OSPF became commonplace.

** Novell support
This option enables support for IPX, the transport protocol Novell Networking uses. Linux will function
quite happily as an IPX router and this support is useful in environments where you have Novell
fileservers.

** lo: This is the local loopback interface. It is used for testing purposes, as well as a couple of network
applications. It works like a closed circuit in that any datagram written to it will immediately be returned
to the host's networking layer. There's always one loopback device present in the kernel, and there's little
sense in having more.

** eth0, eth1:  These are the Ethernet card interfaces. They are used for most Ethernet cards, including many of the
parallel port Ethernet cards.

** tr0, tr1:  These are the Token Ring card interfaces. They are used for most Token Ring cards, including non-IBM
manufactured cards.

** sl0, sl1: These are the SLIP interfaces. SLIP interfaces are associated with serial lines in the order in which they
are allocated for SLIP.

** ppp0, ppp1:  These are the PPP interfaces. Just like SLIP interfaces, a PPP interface is associated with a serial line
once it is converted to PPP mode.

** plip0, plip1:
These are the PLIP interfaces. PLIP transports IP datagrams over parallel lines. The interfaces are
allocated by the PLIP driver at system boot time and are mapped onto parallel ports. In the 2.0.x kernels
there is a direct relationship between the device name and the I/O port of the parallel port, but in later
kernels the device names are allocated sequentially, just as for SLIP and PPP devices.

** ax0, ax1: These are the AX.25 interfaces. AX.25 is the primary protocol used by amat

** If you use lilo to boot your system, you can pass parameters to the kernel by specifying them through the
append option in the lilo.conf file. To inform the kernel about an Ethernet device, you can pass the following
parameters:
ether=irq,base_addr,[param1,][param2,]name
The first four parameters are numeric, while the last is the device name. The irq, base_addr, and name
parameters are required, but the two param parameters are optional. Any of the numeric values may be set to
zero, which causes the kernel to determine the value by probing.

** For instance, to make
Linux install a second Ethernet card at 0x300 as eth1, you would pass the following parameters to the kernel:
reserve=0x300,32 ether=0,0x300,eth1

** enter the parameters into the /etc/lilo.conf using the
append= keyword. An example might look like this:
-------------------------------------------------
boot=/dev/hda
root=/dev/hda2
install=/boot/boot.b
map=/boot/map
vga=normal
delay=20
append="ether=10,300,eth0"
image=/boot/vmlinuz-2.2.14
label=2.2.14
read-only
-------------------------------------------------
After you've edited lilo.conf, you must rerun the lilo command to activate the change.

** Parallel Line IP (PLIP) is a cheap way to network when you want to connect only two machines. It uses a
parallel port and a special cable, achieving speeds of 10 kilobytes per second to 20 kilobytes per second.

** Parallel Line IP (PLIP) is a cheap way to network when you want to connect only two machines. It uses a
parallel port and a special cable, achieving speeds of 10 kilobytes per second to 20 kilobytes per second.

** The proc filesystem (or procfs, as it is also known) is usually mounted on /proc at system boot time. The best
method is to add the following line to /etc/fstab:
# procfs mount point:
none /proc   proc defaults
Then execute mount /proc from your /etc/rc script.

** To set the hostname to
name, enter:
# hostname <name>
Or:
# hostnamectl set-hostname <name>

** ifconfig is used to make an interface accessible to the kernel networking layer. This involves the assignment of
an IP address and other parameters, and activation of the interface, also known as "bringing up" the interface.
Being active here means that the kernel will send and receive IP datagrams through the interface. The simplest
way to invoke it is with:
# ifconfig interface ip-address
This command assigns ip-address to interface and activates it.

** route allows you to add or remove routes from the kernel routing table. It can be invoked as:
# route [add|del] [-net|-host] target [if]
The add and del arguments determine whether to add or delete the route to target. The -net and -host arguments
tell the route command whether the target is a network or a host (a host is assumed if you don't specify). The if
argument is again optional, and allows you to specify to which network interface the route should be directed

** The very first interface to be activated is the loopback interface:
# ifconfig lo 127.0.0.1

** Just as for the loopback interface, you now have to install a routing entry that informs the kernel about the
network that can be reached through eth0. For the Virtual Brewery, you might invoke route as:
# route add -net 172.16.1.0

** Therefore, route would think that
172.16.1.0 is a host address rather than a network number, because it cannot know that we use subnetting. We
have to tell route explicitly that it denotes a network, so we give it the -net flag.

# netstat -nr
Kernel IP routing table
Destination   Gateway     Genmask          Flags   MSS   Window   irtt  Iface
127.0.0.1       *         255.255.255.255   UH      0     0         0    lo
172.16.1.0      *         255.255.255.0     U       0     0         0    eth0
172.16.2.0    172.16.1.1  255.255.255.0     UG      0     0         0    eth0

The fourth column displays the following flags that describe the route:
G: The route uses a gateway.
U: The interface to be used is up.
H: Only a single host can be reached through the route. For example, this is the case for the loopback entry 127.0.0.1.
D: This route is dynamically created. It is set if the table entry has been
generated by a routing daemon like gated or by an ICMP redirect message
M: This route is set if the table entry was modified by an ICMP redirect message.
!: The route is a reject route and datagrams will be dropped.

** The next three columns show the MSS, Window and irtt that will be applied to TCP connections established via
this route. The MSS is the Maximum Segment Size and is the size of the largest datagram the kernel will
construct for transmission via this route. The Window is the maximum amount of data the system will accept in
a single burst from a remote host. The acronym irtt stands for "initial round trip time."


** Displaying Interface Statistics
# netstat -i
(RX-ERR/TX-ERR); how many were dropped (RX-DRP/TX-DRP); and how many were lost because of an
overrun (RX-OVR/TX-OVR).
The last column shows the flags that have been set for this interface. These characters are one-character
versions of the long flag names that are printed when you display the interface configuration with ifconfig:
B: A broadcast address has been set.
L: This interface is a loopback device.
M: All packets are received (promiscuous mode).
O: ARP is turned off for this interface.
P: This is a point-to-point connection.
R: Interface is running.
U: Interface is up.

**Displaying Connections
$ netstat -ta
The options -t, -u, -w, and -x show active TCP, UDP, RAW, or Unix socket connections.
If you provide the -a flag in addition, sockets that are waiting for a connection (i.e., listening) are displayed as well.


** Checking the ARP Tables
Its command-line options are:
arp [-v] [-t hwtype] -a [hostname]
arp [-v] [-t hwtype] -s hostname hwaddr
arp [-v] -d hostname [hostname...]
All hostname arguments may be either symbolic hostnames or IP addresses in dotted quad notation.
The -s option is used to permanently add hostname's Ethernet address to the ARP tables.
You may also set the hardware address for other types of hardware, using the -t option.
Invoking arp using the -d switch deletes all ARP entries relating to the given host.
The -s option may also be used to implement proxy ARP. This is a special technique through which a host, say
gate, acts as a gateway to another host named fnord by pretending that both addresses refer to the same host,
namely gate.

** displays the ARP entry for the IP address or host specified, or all hosts known if no
hostname is given. For example,
name is given. For example, invoking arp on vlager may yield:
# arp -a
IP address     HW type             HW address
172.16.1.3    10Mbps Ethernet     00:00:C0:5A:42:C1

** The proper invocation to provide proxy ARP for fnord is given below; of course, the given Ethernet address
must be that of gate:
# arp -s fnord 00:00:c0:a1:42:e0 pub
The proxy ARP entry may be removed again by invoking:
# arp -d fnord


** /etc/hosts file
order: This option determines the order in which the resolving services are tried. Valid options are bind for querying the
name server, hosts for lookups in /etc/hosts, and nis for NIS lookups. Any or all of them may be specified. The
order in which they appear on the line determines the order in which the respective services are tried.

multi: multi takes on or off as options. This determines if a host in /etc/hosts is allowed to have several IP addresses,
which is usually referred to as being "multi-homed." The default is off. This flag has no effect on DNS or NIS
queries.

nospoof: As we'll explain in the section "Reverse Lookups", DNS allows you to find the hostname belonging to an IP
address by using the in-addr.arpa domain. Attempts by name servers to supply a false hostname are called
spoofing. To guard against this, the resolver can be configured to check whether the original IP address is in fact
associated with the obtained hostname. If not, the name is rejected and an error is returned. This behavior is turned
on by setting nospoof on.

alert: This option takes on or off as arguments. If it is turned on, any spoof attempts will cause the resolver to log a
message to the syslog facility.

trim: This option takes an argument specifying a domain name that will be removed from hostnames before lookup.
This is useful for hosts entries, for which you might only want to specify hostnames without a local domain. If you
specify your local domain name here, it will be removed from a lookup of a host with the local domain name
appended, thus allowing the lookup in /etc/hosts to succeed. The domain name you add must end with the (.)
character (e.g., :linux.org.au.) if trim is to work correctly.

Sample host.conf File
# /etc/host.conf
# We have named running, but no NIS (yet)
order   bind,hosts
# Allow multiple addrs
multi  on
# Guard against spoof attempts
nospoof on
# Trim local domain (not really necessary).
trim  paytmbank.com.

RESOLV_HOST_CONF: This variable specifies a file to be read instead of /etc/host.conf.
RESOLV_SERV_ORDER: This variable overrides the order option given in host.conf. Services are given as hosts, bind, and nis, separated by
a space, comma, colon, or semicolon.
RESOLV_SPOOF_CHECK: This variable determines the measures taken against spoofing. It is completely disabled by off. The values warn
and warn off enable spoof checking by turning logging on and off, respectively. A value of * turns on spoof
checks, but leaves the logging facility as defined in host.conf.
RESOLV_MULTI: This variable uses a value of on or off to override the multi options from host.conf.
RESOLV_OVERRIDE_TRIM_DOMAINS: This variable specifies a list of trim domains that override those given in host.conf. Trim domains were explained
earlier when we discussed the trim keyword.
RESOLV_ADD_TRIM_DOMAINS: This variable specifies a list of trim domains that are added to those given in host.conf.

** A simple example of host and network database specification that would mimic our configuration using the older libc
standard library is
Sample nsswitch.conf File
# /etc/nsswitch.conf
#
# Example configuration of GNU Name Service Switch functionality.
# Information about this file is available in the `libc6-doc' package.
hosts:                 dns files
networks:              files


Methods of Attack

Unauthorized access: This simply means that people who shouldn't use your computer services are able to connect and use them. For
example, people outside your company might try to connect to your company accounting machine or to your NFS
server

Exploitation of known weaknesses in programs:
Some programs and network services were not originally designed with strong security in mind and are inherently
vulnerable to attack.
example: rlogin, rexec

Denial of service: Denial of service attacks cause the service or program to cease functioning or prevent others from making use of the
service or program. These may be performed at the network layer by sending carefully crafted and malicious
datagrams that cause network connections to fail.

Spoofing: This type of attack causes a host or application to mimic the actions of another. Typically the attacker pretends to be
an innocent host by following IP addresses in network packets.

Eavesdropping: A host is configured to "listen" to and capture data not belonging to it. Carefully
written eavesdropping programs can take usernames and passwords from user login network connections. Broadcast
networks like Ethernet are especially vulnerable to this type of attack

** A firewall is a secure and trusted machine that sits between a private network and a public network.[1] The firewall
machine is configured with a set of rules that determine which network traffic will be allowed to pass and which will be
blocked or refused. In some large organizations, you may even find a firewall located inside their corporate network to
segregate sensitive areas of the organization from other employees.

** What Is a Firewall?
A firewall is a secure and trusted machine that sits between a private network and a public network.[1] The firewall
machine is configured with a set of rules that determine which network traffic will be allowed to pass and which will be
blocked or refused. In some large organizations, you may even find a firewall located inside their corporate network to
segregate sensitive areas of the organization from other employees.

Firewalls can be constructed in quite a variety of ways. The most sophisticated arrangement involves a number of separate
machines and is known as a perimeter network. Two machines act as "filters" called chokes to allow only certain types of
network traffic to pass, and between these chokes reside network servers such as a mail gateway or a World Wide Web
proxy server.

** What Is IP Filtering?
IP filtering is simply a mechanism that decides which types of IP datagrams will be processed normally and which will be
discarded. By discarded we mean that the datagram is deleted and completely ignored, as if it had never been received.
● Protocol type: TCP, UDP, ICMP, etc.
● Socket number (for TCP/UPD)
● Datagram type: SYN/ACK, data, ICMP Echo Request, etc.
● Datagram source address: where it came from
● Datagram destination address: where it is going to

** It is important to understand at this point that IP filtering is a network layer facility. This means it doesn't understand
anything about the application using the network connections, only about the connections themselves. For example, you
may deny users access to your internal network on the default telnet port, but if you rely on IP filtering alone, you can't
stop them from using the telnet program with a port that you do allow to pass trhough your firewall.

** The netfilter code is the result of a large redesign of the packet handling flow in Linux. The netfilter is a multifaceted
creature, providing direct backward-compatible support for both ipfwadm and ipchains as well as a new alternative
command called iptables.

** The ipfwadm (IP Firewall Administration) utility is the tool used to build the firewall rules for all kernels prior to 2.2.0. Its
command syntax can be very confusing because it can do such a complicated range of things.

** Just as for the ipfwadm utility, the ipchains utility can be somewhat baffling to use at first. It provides all of the flexibility
of ipfwadm with a simplified command syntax, and additionally provides a "chaining" mechanism that allows you to
manage multiple rulesets and link them together.

** The syntax of the iptables utility is quite similar to that of the ipchains syntax. The changes are improvements and a result
of the tool being redesigned to be extensible through shared libraries

** Three Ways We Can Do Filtering
● The IP datagram is received. (1)
● The incoming IP datagram is examined to determine if it is destined for a process on this machine.
● If the datagram is for this machine, it is processed locally. (2)
● If it is not destined for this machine, a search is made of the routing table for an appropriate route and the datagram
is forwarded to the appropriate interface or dropped if no route can be found. (3)
● Datagrams from local processes are sent to the routing software for forwarding to the appropriate interface. (4)
● The outgoing IP datagram is examined to determine if there is a valid route for it to take, if not, it is dropped.
● The IP datagram is transmitted. (5)

** The Linux kernel IP firewall is capable of applying filtering at various stages in this process. That is, you can filter the IP
datagrams that come in to your machine, filter those datagrams being forwarded across your machine, and filter those
datagrams that are ready to be transmitted.

** The -F command-line argument tells ipfwadm that this is a forwarding rule. The first command instructs ipfwadm to
"flush" all of the forwarding rules. This ensures we are working from a known state before we begin adding specific rules.
# ipfwadm -F -f

** The second rule sets our default forwarding policy. We tell the kernel to deny or disallow forwarding of IP datagrams. It is
very important to set the default policy, because this describes what will happen to any datagrams that are not specifically
handled by any other rule.
# ipfwadm -F -p deny

** The third and fourth rules are the ones that implement our requirement. The third command allows our datagrams out, and
the fourth rule allows the responses back.
# ipfwadm -F -a accept -P tcp -S 172.16.1.0/24 -D 0/0 80
# ipfwadm -F -a accept -P tcp -S 0/0 80 -D 172.16.1.0/24

** The bidirectional flag allows us to collapse our two rules into one as follows:
# ipfwadm -F -a accept -P tcp -S 172.16.1.0/24 -D 0/0 80 -b

**Let's review each of the arguments:
-F: This is a Forwarding rule.
-a: accept: Append this rule with the policy set to "accept," meaning we will forward any datagrams that match this rule.
-P tcp: This rule applies to tcp datagrams (as opposed to UDP or ICMP).
-S: The Source address must have the first 24 bits matching those of the network address 172.16.1.0. example: 172.16.1.0/24
-D: 0/0 80 The destination address must have zero bits matching the address 0.0.0.0. This is really a shorthand notation for
"anything." The 80 is the destination port, in this case WWW. You may also use any entry that appears in the
/etc/services file to describe the port, so -D 0/0 www would have worked just as well.

**Subnet calculation
Netmask         Bit       Values        Notation
Netmask         Bits
255.0.0.0        8
255.255.0.0      16
255.255.255.0    24
255.255.255.128  25       128 ips       (32-25)=2^7
255.255.255.192  26       64 ips        (32-26)=2^6
255.255.255.224  27       32 ips        (32-27)=2^5
255.255.255.240  28       16 ips        (32-28)=2^4
255.255.255.248  29       8 ips         (32-29)=2^3
255.255.255.252  30       4 ips         (32-30)=2^2
255.255.255.254  31       2 ips         (32-31)=2^1
255.255.255.255  32       1 ip          (32-32)=2^0

** If a person on the outside had privileged access to a host, they could make a connection through our firewall to any of our hosts,
provided they use port 80 at their end. This is not what we intended.The ipfwadm command provides another flag that allows us to build rules
that will match datagrams with the SYN bit set.
# ipfwadm -F -a deny -P tcp -S 0/0 80 -D 172.16.10.0/24 -y
# ipfwadm -F -a accept -P tcp -S 172.16.1.0/24 -D 0/0 80 -b
The -y flag causes the rule to match only if the SYN flag is set in the datagram. So our new rule says: "Deny any TCP
datagrams destined for our network from anywhere with a source port of 80 and the SYN bit set," or "Deny any
connection requests from hosts using port 80."

** Listing our rules
# ipfwadm -F -l

** The ipfwadm command is able to produce a more detailed listing output if you specify the -e (extended output)
# ipfwadm -F -l -e

** We want our internal network users to be able to log into FTP servers on the Internet to read and write files. But we
don't want people on the Internet to be able to log into our FTP servers.
We know that FTP uses two TCP ports: port 20 (ftp-data) and port 21 (ftp), so:
# ipfwadm -a deny -P tcp -S 0/0 20 -D 172.16.1.0/24 -y
# ipfwadm -a accept -P tcp -S 172.16.1.0/24 -D 0/0 20 -b
#
# ipfwadm -a deny -P tcp -S 0/0 21 -D 172.16.1.0/24 -y
# ipfwadm -a accept -P tcp -S 172.16.1.0/24 -D 0/0 21 -b

** The ipfwadm has many different arguments that relate to IP firewall configuration. The general syntax is:
ipfwadm category command parameters [options]

Categories:
-I: Input rule
-O: Output rule
-F: Forwarding rule

Commands:
-a: Append a new rule
-i: Insert a new rule
-d: Delete an existing rule
-p: Set the default policy
-l: List all existing rules
-f: Flush all existing rules
accept: Allows matching datagrams to be received, forwarded, or transmitted
deny: Blocks matching datagrams from being received, forwarded, or transmitted
reject: Blocks matching datagrams from being received, forwarded, or transmitted, and sends the host that sent the
datagram and ICMP error message

Parameters:
-P: protocol Can be TCP, UDP, ICMP, or all. Example: -P tcp
-S: Source IP address that this rule will match. A netmask of "/32" will be assumed if you don't supply one. You may
optionally specify which ports this rule will apply to. You must also specify the protocol using the -P argument
described above for this to work. If you don't specify a port or port range, "all" ports will be assumed to match.
example: -S 172.29.16.1/24 ftp:ftp-data
-D: Specify the destination IP address that this rule will match. The destination address is coded with the same rules as
the source address described previously. Here is an example: -D 172.29.16.1/24 smtp
-V: Specify the address of the network interface on which the packet is received (-I) or is being sent (-O). This allows us
to create rules that apply only to certain network interfaces on our machine. Here is an example: -V 172.29.16.1
-W: Specify the name of the network interface. This argument works in the same way as the -V argument, except you
supply the device name instead of its address. Here is an example: -W ppp0

Options:
-b: This is used for bidirectional mode.
-o: This enables logging of matching datagrams to the kernel log. Any datagram that matches this rule will be logged as
      a kernel message. This is useful to enable you to detect unauthorized access.
-y; This is used to match TCP connect datagrams. The option causes the rule to match only datagrams that attempt to
      establish TCP connections. Only datagrams that have their SYN bit set, but their ACK bit unset, will match.
-k: This is used to match TCP acknowledgement datagrams. This option causes the rule to match only datagrams that
      are acknowledgements to packets attempting to establish TCP connections. Only datagrams that have their ACK bit
      set will match.

** ipchains Command Syntax
# ipchains command rule-specification options

Commands:
-A chain: Append one or more rules to the end of the nominated chain. If a hostname is supplied as either source or
destination and it resolves to more than one IP address, a rule will be added for each address.
-I chain rulenum: Insert one or more rules to the start of the nominated chain. Again, if a hostname is supplied in the rule
specification, a rule will be added for each of the addresses it resolves to.
-D chain: Delete one or more rules from the specified chain that matches the rule specification.
-D chain rulenum: Delete the rule residing at position rulenum in the specified chain. Rule positions start at one for the first rule in the chain.
-R chain rulenum: Replace the rule residing at position rulenum in the specific chain with the supplied rule specification.
-C chain: Check the datagram described by the rule specification against the specific chain. This command will return a
    message describing how the datagram was processed by the chain. This is very useful for testing your firewall
    configuration, and we look at it in detail a little later.
-L chain: List the rules of the specified chain, or for all chains if no chain is specified.
-F chain: Flush the rules of the specified chain, or for all chains if no chain is specified.
-Z chain: Zero the datagram and byte counters for all rules of the specified chain, or for all chains if no chain is specified.
-N chain: Create a new chain with the specified name. A chain of the same name must not already exist. This is how
          user-defined chains are created.
-X chain: Delete the specified user-defined chain, or all user-defined chains if no chain is specified. For this command to be
          successful, there must be no references to the specified chain from any other rules chain.
-P chain policy: Set the default policy of the specified chain to the specified policy. Valid firewalling policies are ACCEPT, DENY,
                REJECT, REDIR, or RETURN. ACCEPT, DENY, and REJECT have the same meanings as those for the tradition IP
                firewall implementation. REDIR specifies that the datagram should be transparently redirected to a port on the
                firewall host. The RETURN target causes the IP firewall code to return to the Firewall Chain that called the one
                containing this rule and continues starting at the rule after the calling rule.

Rule specification parameters:
A number of ipchains parameters create a rule specification by determining what types of packets match. If any of these
parameters is omitted from a rule specification, its default is assumed:
-p [!]protocol: Specifies the protocol of the datagram that will match this rule. Valid protocol names are tcp, udp, icmp, or all.
-s [!]address[/mask] [!] [port]: Specifies the source address and port of the datagram that will match this rule. The address may be supplied as a
          hostname, a network name, or an IP address. The optional mask is the netmask to use and may be supplied either in
          the traditional form (e.g., /255.255.255.0) or the modern form (e.g., /24). The optional port specifies the TCP or
          UDP port, or the ICMP datagram type that will match. You may supply a port specification only if you've supplied
          the -p parameter with one of the tcp, udp, or icmp protocols. Ports may be specified as a range by specifying the
          upper and lower limits of the range with a colon as a delimiter. For example, 20:25 described all of the ports
          numbered from 20 up to and including 25. Again, the ! character may be used to negate the values.
-d [!]address[/mask] [!] [port]: Specifies the destination address and port of the datagram that will match this rule. The coding of this parameter is
                                  the same as that of the -s parameter.
-j target: Specifies the action to take when this rule matches. You can think of this parameter as meaning "jump to." Valid
            targets are ACCEPT, DENY, REJECT, REDIR, and RETURN.
-i [!]interface-name: Specifies the interface on which the datagram was received or is to be transmitted. Again, the ! inverts the result of
                      the match.
[!] -f: Specifies that this rule applies to everything but the first fragment of a fragmented datagram.

Options:
-b: Causes the command to generate two rules. One rule matches the parameters supplied, and the other rule added
    matches the corresponding parameters in the reverse direction.
-v: Causes ipchains to be verbose in its output. It will supply more information.
-n: Causes ipchains to display IP address and ports as numbers without attempting to resolve them to their
    corresponding namCauses any numbers in the ipchains output to be expanded to their exact values with no rounding.es.
-l: Enables kernel logging of matching datagrams. Any datagram that matches the rule will be logged by the kernel
    using its printk() function, which is usually handled by the sysklogd program and written to a log file. This is useful
    for making unusual datagrams visible.
-o(maxsize): Causes the IP chains software to copy any datagrams matching the rule to the userspace "netlink" device. The
              maxsize argument limits the number of bytes from each datagram that are passed to the netlink device. This option
              is of most use to software developers, but may be exploited by software packages in the future.
-m(mark value): Causes matching datagrams to be marked with a value. Mark values are unsigned 32-bit numbers, If a markvalue begins with a + or -, the value is added or subtracted from
                the existing markvalue.
-t andmask xormask: The andmask and xormask represent bit masks that will be logically
                    ANDed and ORed with the type of service bits of the datagram respectively.
-x: Causes any numbers in the ipchains output to be expanded to their exact values with no rounding.
-y: Causes the rule to match any TCP datagram with the SYN bit set and the ACK and FIN bits clear. This is used to
    filter TCP connection requests.

Examples:
# ipchains -F forward
# ipchains -P forward DENY
# ipchains -A forward -s 0/0 80 -d 172.16.1.0/24 -p tcp -y -j DENY
# ipchains -A forward -s 172.16.1.0/24 -d 0/0 80 -p tcp -b -j ACCEPT
If we now wanted to add rules that allowed passive mode only access to FTP servers in the outside network, we'd add
these rules:
# ipchains -A forward -s 0/0 20 -d 172.16.1.0/24 -p tcp -y -j DENY
# ipchains -A forward -s 172.16.1.0/24 -d 0/0 20 -p tcp -b -j ACCEPT
# ipchains -A forward -s 0/0 21 -d 172.16.1.0/24 -p tcp -y -j DENY
# ipchains -A forward -s 172.16.1.0/24 -d 0/0 21 -p tcp -b -j ACCEPT

** Listing Our Rules with ipchains
# ipchains -L -n
A verbose form, invoked by the -u option, provides much more detail. Its output adds fields for the datagram and byte
counters, Type of Service AND and XOR flags, the interface name, the mark, and the outsize

** Datagram processing chain in IP chains:
1.checksum  2.sanity  3.input chain  4.demasq  5.routing decision  6.masq  7.forward chain  8.output chain

** netfilter mimics the ipchains interface with the following commands:
rmmod ip_tables
modprobe ipchains
ipchains ...

** Before you can use the iptables command, you must load the netfilter kernel module that provides support for it. The
easiest way to do this is to use the modprobe command as follows:
# modprobe ip_tables

** The iptables command is used to configure both IP filtering and Network Address Translation. To facilitate this, there are
    two tables of rules called filter and nat. The filter table is assumed if you do not specify the -t option to override it.

** The INPUT and FORWARD chains are available for the filter table, the
    PREROUTING and POSTROUTING chains are available for the nat table, and the OUTPUT chain is available for both
    tables.
The general syntax of most iptables commands is:
# iptables command rule-specification extensions

Commands:
-A chain: Append one or more rules to the end of the nominated chain. If a hostname is supplied as either a source or
          destination and it resolves to more than one IP address, a rule will be added for each address.
-I chain rulenum:  Insert one or more rules to the start of the nominated chain. Again, if a hostname is supplied in the rule
                    specification, a rule will be added for each of the addresses to which it resolves.
-D chain: Delete one or more rules from the specified chain matching the rule specification.
-D chain rulenum: Delete the rule residing at position rulenum in the specified chain. Rule positions start at 1 for the first rule in the chain.
-R chain rulenum: Replace the rule residing at position rulenum in the specific chain with the supplied rule specification.
-C chain: Check the datagram described by the rule specification against the specific chain. This command will return a
            message describing how the chain processed the datagram. This is very useful for testing your firewall
            configuration and we will look at it in detail later.
-L [chain]: List the rules of the specified chain, or for all chains if no chain is specified.
-F [chain]: Flush the rules of the specified chain, or for all chains if no chain is specified.
-Z [chain]: Zero the datagram and byte counters for all rules of the specified chain, or for all chains if no chain is specified.
-N chain: Create a new chain with the specified name. A chain of the same name must not already exist. This is how
          user-defined chains are created.
-X [chain}: Delete the specified user-defined chain, or all user-defined chains if no chain is specified. For this command to be
            successful, there must be no references to the specified chain from any other rules chain.
-P chain policy: Set the default policy of the specified chain to the specified policy. Valid firewalling policies are ACCEPT, DROP,
                QUEUE, and RETURN. ACCEPT allows the datagram to pass. DROP causes the datagram to be discarded. QUEUE
                causes the datagram to be passed to userspace for further processing. The RETURN target causes the IP firewall
                code to return to the Firewall Chain that called the one containing this rule, and continue starting at the rule after the
                calling rule.

Rule specification parameters:
-p [!]protocol: Specifies the protocol of the datagram that will match this rule. Valid protocol names are tcp, udp, icmp, or a
                number, if you know the IP protocol number.[6] For example, you might use 4 to match the ipip encapsulation
                protocol. If the ! character is supplied, the rule is negated and the datagram will match any protocol other than the
                specified protocol. If this parameter isn't supplied, it will default to match all protocols.
                [6] Take a look at /etc/protocols for protocol names and numbers.
-s [!]address[/mask]: Specifies the source address of the datagram that will match this rule. The address may be supplied as a hostname, a
                      network name, or an IP address. The optional mask is the netmask to use and may be supplied either in the
                      traditional form (e.g., /255.255.255.0) or in the modern form (e.g., /24).
-d [!]address[/mask]: Specifies the destination address and port of the datagram that will match this rule. The coding of this parameter is
                      the same as that of the -s parameter.
-j target: Specifies what action to take when this rule matches. You can think of this parameter as meaning "jump to." Valid
            targets are ACCEPT, DROP, QUEUE, and RETURN. We described the meanings of each of these previously in the
            "Commands" section. You may also specify the name of a user-defined chain where processing will continue. You
            may also supply the name of a target supplied by an extension. We'll talk about extensions shortly. If this parameter
            is omitted, no action is taken on matching datagrams at all, other than to update the datagram and byte counters of
            this rule.
-i [!]interface-name: Specifies the interface on which the datagram was received. Again, the ! inverts the result of the match. If the
                      interface name ends with "+" then any interface that begins with the supplied string will match. For example, -i
                      ppp+ would match any PPP network device and -i ! eth+ would match all interfaces except ethernet devices.
-o [!]interface-name: Specifies the interface on which the datagram is to be transmitted. This argument has the same coding as the -i
                      argument.

Options:
-v: causes iptables to be verbose in its output; it will supply more information.
-n: causes iptables to display IP address and ports as numbers without attempting to resolve them to their corresponding names.
-x: causes any numbers in the iptables output to be expanded to their exact values with no rounding.
--line-numbers: causes line numbers to be displayed when listing rulesets. The line number will correspond to the rule's position
within the chain.

Extensions:
--sport [!] [port[:port]] => Specifies the port that the datagram source must be using to match this rule. Ports may be specified as a range by
                specifying the upper and lower limits of the range using the colon as a delimiter. For example, 20:25 described all
                of the ports numbered 20 up to and including 25. Again, the ! character may be used to negate the values.
--dport [!] [port[:port]] => Specifies the port that the datagram destination must be using to match this rule. The argument is coded identically
                              to the --sport option.
--tcp-flags [!] mask comp => Specifies that this rule should match when the TCP flags in the datagram match those specified by mask and comp.
                              mask is a comma-separated list of flags that should be examined when making the test. comp is a comma-separated
                              list of flags that must be set for the rule to match. Valid flags are: SYN, ACK, FIN, RST, URG, PSH, ALL or NONE.
                              This is an advanced option: refer to a good description of the TCP protocol, such as RFC-793, for a description of
                              the meaning and implication of each of these flags. The ! character negates the rule.
[!] --syn => Specifies the rule to match only datagrams with the SYN bit set and the ACK and FIN bits cleared. Datagrams with these options are
              used to open TCP connections, and this option can therefore be used to manage connection requests. This option is shorthand for:
              --tcp-flags SYN,RST,ACK SYN
              When you use the negation operator, the rule will match all datagrams that do not have both the SYN and ACK bits set.

UDP Extensions: used with -m udp -p udp
--sport [!] [port[:port]] => Specifies the port that the datagram source must be using to match this rule. Ports may be specified as a range by
                              specifying the upper and lower limits of the range using the colon as a delimiter. For example, 20:25 describes all
                              of the ports numbered 20 up to and including 25. Again, the ! character may be used to negate the values.
--dport [!] [port[:port]] => Specifies the port that the datagram destination must be using to match this rule. The argument is coded identically
                              to the --sport option.

ICMP Extensions: used with -m icmp -p icmp
--icmp-type [!] typename => Specifies the ICMP message type that this rule will match. The type may be specified by number or name. Some
                              valid names are: echo-request, echo-reply, source-quench, time-exceeded,
                              destination-unreachable, network-unreachable, host-unreachable,protocol-unreachable, and port-unreachable.

Examples:
modprobe ip_tables
# iptables -F FORWARD
# iptables -P FORWARD DROP
# iptables -A FORWARD -m tcp -p tcp -s 0/0 --sport 80 -d 172.16.1.0/24 --syn -j DROP
# iptables -A FORWARD -m tcp -p tcp -s 172.16.1.0/24 --sport 80 -d 0/0 -j ACCEPT
# iptables -A FORWARD -m tcp -p tcp -d 172.16.1.0/24 --dport 80 -s 0/0 -j ACCEPT


** IPTables might contain multiple tables and tables might contain multiple chains and chains contain multiple rules where rules are defined for the incoming and outgoing packets.
    Therefore structure is IPTables -> Tables -> Chains -> Rules

** IPTables has the following 5 built-in tables:
1. Filter
2. Nat
3. Mangle
4. Raw
5. Security

** There are five built-in chains in which we can place our firewall policy rules:
INPUT CHAIN: It is used for rules which are applicable to the traffic/packets coming towards the server.
OUTPUT CHAIN: It is used for rules which need to be applied on outgoing traffic/packets from our server.
FORWARD CHAIN: It is used for adding rules related to forwarding an IP packet.
PRE-ROUTING CHAIN: It is used to add rules which define actions that need to be taken before a routing decision
                    is made by the kernel.
POST-ROUTING CHAIN: It is used for adding rules which will define actions that need to be taken after a routing decision
                    which is taken by the kernel.

** To list all rules from a table.
sudo iptables -t <table-name> -L
where,
-t   is used to specify the table name,
-v   for verbose and
-L   for listing the chains and rules

** To add a rule inside a chain of a table, we can type:
$ sudo iptables -t <table-name> -A <chain-name> -d <destination-address> -p <protocol> -j <action>
where,
-A   to append one or more rules to the end of the selected chain
-d   for specifying a destination
-p   protocol of the rule or of the packet to check
-j    specifies the target of the rule; i.e., what to do if the packet matches it.

** To flush all the rules:
$ sudo iptables -t <table-name> -F
where,
-F to flush the selected table rules

** To create a new chain:
$ sudo iptables -t <table-name> -N <chain-name>

** To Delete a chain
$ sudo iptables -t <table-name> -X <chain-name>

** Setting the rule:
$ sudo iptables -t filter -A INPUT -s 172.24.16.1 -p tcp -j DROP

**  delete the rule by line number:
$ sudo iptables -D INPUT 1

** Deleting the particular rule:
$ sudo iptables -D INPUT -s 172.24.16.1 -p tcp -j DROP

** Network Address Translation generally involves "re-writing the
    source and/or destination addresses of IP packets as they pass through a router or firewall"

** Once an IP packet is received the receiver has to assign the data to a process, which is the role
    of the transport layer, in our case TCP and UDP.

** The combination of IP-address and port number is called socket and is unique.
    Therefore connections are uniquely defined by their endpoints (=sockets),
    a connection sends data from the clients socket to the server socket and vice versa,
    for example from the socket with IP 123.123.123.123, port 65432 to the socket with IP 112.112.112.112, Port 80 as it
    may occur for a browser on 123.123.123.123 that connects to a http-server on 112.112.112.112. .

** The Linux kernel usually posesses a packet filter framework called netfilter, This framework enables a Linux machine with an
    appropriate number of network cards (interfaces) to become a router capable of NAT.This table has three predefinded chains:
    PREROUTING, OUTPUT und POSTROUTING.

**  packets arriving from the local net with a receipient's IP address somewhere in the internet have to be modified such that the
    sender's address is equal to the router's address. For further command examples let us assume that the first interface 'eth0'
    is connected to the local net and that the router is connected to the internet via the second interface 'eth1'.
    $> iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE

    iptables:	 	the command line utility for configuring the kernel
    -t nat	 	select table "nat" for configuration of NAT rules.
    -A POSTROUTING	 	Append a rule to the POSTROUTING chain (-A stands for "append").
    -o eth1	 	this rule is valid for packets that leave on the second network interface (-o stands for "output")
    -j MASQUERADE	 	the action that should take place is to 'masquerade' packets, i.e. replacing the sender's address by the router's address.

** # Abstract structure of an iptables instruction:
    $> iptables [-t table] command [match pattern] [action]

** For NAT we always have to choose the nat-table. A command might need further options, for example a pattern and an action to perform in case the pattern matches.
    # Choosing the nat-table
    # (further arguments abbreviated by [...])
    $> iptables -t nat [...]

**  # add a rule:
    $> iptables -t nat -A chain [...]

**  # list rules:
    $> iptables -t nat -L

**  # remove user-defined chain with index 'myindex':
    $> iptables -t nat -D chain myindex

**  # Remove all rules in chain 'chain':
    $> iptables -t nat -F chain

**  # TCP packets from 192.168.1.2:
    $> iptables -t nat -A POSTROUTING -p tcp -s 192.168.1.2 [...]

**   # UDP packets to 192.168.1.2:
    $> iptables -t nat -A POSTROUTING -p udp -d 192.168.1.2 [...]

**  # all packets from 192.168.x.x arriving at eth0:
    $> iptables -t nat -A PREROUTING -s 192.168.0.0/16 -i eth0 [...]

**  # all packets except TCP packets and except packets from 192.168.1.2:
    $> iptables -t nat -A PREROUTING -p ! tcp -s ! 192.168.1.2 [...]

**  # packets leaving at eth1:
    $> iptables -t nat -A POSTROUTING -o eth1 [...]

**  # TCP packets from 192.168.1.2, port 12345 to 12356
    # to 123.123.123.123, Port 22
    $> iptables -t nat -A POSTROUTING -p tcp -s 192.168.1.2 --sport 12345:12356 -d 123.123.123.123 --dport 22 [...]

******** Actions for matched packets ***************
**  # Source-NAT: Change sender to 123.123.123.123
    $> iptables [...] -j SNAT --to-source 123.123.123.123

** # Mask: Change sender to outgoing network interface
    $> iptables [...] -j MASQUERADE

** # Destination-NAT: Change receipient to 123.123.123.123, port 22
    $> iptables [...] -j DNAT --to-destination 123.123.123.123:22

**  # Redirect to local port 8080
    $> iptables [...] -j REDIRECT --to-ports 8080

** Source NAT (short: SNAT). As the name implies the sender's address is changed statically.The reason for choosing MASQUERADE in the previous example anyway has the following reason: For SNAT one has to specify the new source-IP explicitly. For routers with a static IP address SNAT is the best choice because it is faster than MASQUERADE which has to check the current IP address of the outgoing network interface at every packet. Since SNAT is only meaningful for packets leaving the router it   is  used within the POSTROUTING chain only.