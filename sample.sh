
echo "prct no : "
read p

if [ "$p" == "1" ]; then
	echo "
	# Practical1_SSH_NTP_SYSLOG.txt
	line vty 0 4
	password vtypa55
	login

	enable secret ciscoen55

	Part 2: Configure OSPF MD5 Authentication
	Test connectivity.
	PCA> ping 192.168.3.5
	PCB> ping 192.168.3.5

	router ospf 1
	network 192.168.1.0 0.0.0.255 area 0
	network 10.1.1.0 0.0.0.3 area 0

	router ospf 1
	network 10.1.1.0 0.0.0.3 area 0
	network 10.2.2.0 0.0.0.3 area 0

	router ospf 1
	network 192.168.3.0 0.0.0.255 area 0
	network 10.2.2.0 0.0.0.3 area 0

	Execute command on only serial interface of all routers
	router ospf 1
	area 0 authentication message-digest
	int se0/1/0
	ip ospf message-digest-key 1 md5 MD5pa55
	exit

	router ospf 1
	area 0 authentication message-digest
	int se0/1/0
	ip ospf message-digest-key 1 md5 MD5pa55
	exit
	int se0/1/1
	ip ospf message-digest-key 1 md5 MD5pa55
	exit

	router ospf 1
	area 0 authentication message-digest
	int se0/1/1
	ip ospf message-digest-key 1 md5 MD5pa55
	exit


	show ip ospf interface


	Configure NTP on all router
	ntp server 192.168.1.5
	ntp update-calendar

	show clock 

	ntp authenticate
	ntp trusted-key 1
	ntp authentication-key 1 md5 NTPpa55
	service timestamp log datetime msec

	Configure Routers to Log Messages to the Syslog Server 
	on all routers:
	logging host 192.168.1.6

	show logging

	on R3 this one
	ip domain-name ccnasecurity.com
	username SSHadmin privilege 15 secret ciscosshpa55
	line vty 0 4
	login local
	transport input ssh
	crypto key generate rsa
	show ip ssh

	ip ssh time-out 90
	ip ssh authentication-retries 2
	ip ssh version 2
	show ip ssh


	Open the Desktop of PC-C. Select the Command Prompt icon. From PC-C,
	enter the command to connect to R3 via Telnet
	telnet 192.168.3.1

	ssh -l SSHadmin 192.168.3.1
	password sshpa55

	ssh -v2 -l SSHadmin 10.2.2.1	
" > sic.txt
fi

if [ "$p" == "2" ]; then
	echo "
	# Practical2_AAA Authentication.txt
	line vty 0 4
	password vtypa55
	login

	enable secret enpa55

	router ospf 1
	network 192.168.1.0 0.0.0.255 area 0
	router ospf 1
	area 0 authentication message-digest
	int gig0/0
	ip ospf message-digest-key 1 md5 MD5pa55



	Part 1:Configure Local AAA Authentication for Console Access on R1
	Test connectivity
	PC0> ping 192.168.1.3
	PC1> ping 192.168.1.2

	show ip ospf interface
	username admin secret adminpa55
	aaa new-model
	aaa authentication login default
	end
	exit

	admin
	adminpa55

	ip domain-name ccnasecurity.com
	crypto key generate rsa
	aaa authentication login SSH-LOGIN local
	line vty 0 4
	login authentication SSH-LOGIN
	transport input ssh
	end

	Verify the AAA authentication method
	PC0> ssh -l admin 192.168.1.1
	adminpa55

	PC1> ssh -l admin 192.168.1.1
	adminpa55 
	" > sic.txt
fi

if [ "$p" == "3a" ]; then
	echo "
	# Practical3a_Extended ACLs.txt
	line vty 0 4
	password vtypa55
	login
	enable secret ciscoenpa55

	Configure, Apply and Verify an Extended Numbered ACL
	access-list 100 permit tcp 172.22.34.64 0.0.0.31 host 172.22.34.62 eq ftp
	access-list 100 permit icmp 172.22.34.64 0.0.0.31 host 172.22.34.62 
	int gig0/0
	ip access-group 100 in

	Verify the ACL implementation
	PC1> ping 172.22.34.62

	PC1> ftp 172.22.34.62
	ftp> quit

	PC1> ping 172.22.34.98

	Configure, Apply and Verify an Extended Named ACL
	ip access-list extended HTTP_ONLY
	permit tcp 172.22.34.96 0.0.0.15 host 172.22.34.62 eq www
	permit icmp 172.22.34.96 0.0.0.15 host 172.22.34.62 
	int gig0/1
	ip access-group HTTP_ONLY in

	Verify the ACL implementation
	PC2> ping 172.22.34.62

	PC2> ftp 172.22.34.62

	URL->  http://172.22.34.62

	PC2> ping 172.22.34.66

	" > sic.txt
fi

if [ "$p" == "3b" ]; then
	echo "
	# Practical3b_Extended ACLs.txt
	Configure the IP address on switch
	int vlan 1
	ip address 10.101.117.50 255.255.255.248
	no shut
	ip default-gateway 10.101.117.49

	int vlan 1
	ip address 10.101.117.34 255.255.255.240
	no shut
	ip default-gateway 10.101.117.33

	int vlan 1
	ip address 10.101.117.2 255.255.255.224
	no shut
	ip default-gateway 10.101.117.1

	Configure the secret on router and switch
	enable secret enpa55
	line console 0
	password conpa55
	login

	PCA> ping 10.101.117.35

	PCA> ping 10.101.117.2

	PCB> ping 10.101.117.2

	Configure domain name and crypto key for use with SSH
	ip domain-name ccnasecurity.com
	username admin secret adminpa55
	line vty 0 4
	login local
	exit
	crypto key generate rsa

	PCA> ssh -l admin 10.101.117.34

	PCA> ssh -l admin 10.101.117.2

	PCB> ssh -l admin 10.101.117.50

	PCB> ssh -l admin 10.101.117.2

	SWC> ssh -l admin 10.101.117.50

	SWC> ssh -l admin 10.101.117.34

	Configure the extended ACL router pe
	access-list 199 permit tcp 10.101.117.32 0.0.0.15 10.101.117.0 0.0.0.31 eq 22
	access-list 199 permit icmp any any
	int gig0/2
	ip access-group 199 out

	PCB> ping 10.101.117.51

	PCB> ping 10.101.117.2

	PCB> ssh -l admin 10.101.117.2

	PCA> ping 10.101.117.35

	PCA> ping 10.101.117.2

	PCA> ssh -l admin 10.101.117.2

	PCA> ssh -l admin 10.101.117.34

	SWB# ssh -l admin 10.101.117.2
	" > sic.txt
fi

if [ "$p" == "4a" ]; then
	echo "
	# Practical4a_IP ACLs to Mitigate Attacks.txt
	on all routers
	enable secret enpa55
	line console 0
	password conpa55
	login
	ip domain-name ccnasecurity.com
	username admin secret adminpa55
	line vty 0 4
	login local
	crypto key generate rsa

	for r2
	int loopback 0
	ip address 192.168.2.1 255.255.255.0
	no shut 

	on routers
	ip route 192.168.3.0 255.255.255.0 10.1.1.2
	ip route 10.2.2.0 255.255.255.252 10.1.1.2
	ip route 192.168.2.0 255.255.255.0 10.1.1.2

	ip route 192.168.1.0 255.255.255.0 10.1.1.1
	ip route 192.168.3.0 255.255.255.0 10.2.2.1

	ip route 192.168.1.0 255.255.255.0 10.2.2.2
	ip route 10.1.1.0 255.255.255.252 10.2.2.2
	ip route 192.168.2.0 255.255.255.0 10.2.2.2

	PCA> ping 192.168.3.3 
	PCA> ping 192.168.2.1 
	PCA> ssh –l admin 192.168.2.1

	PCC> ping 192.168.1.3 
	PCC> ping 192.168.2.1 
	PCC> ssh –l admin 192.168.2.1

	Execute command on all routers
	access-list 10 permit host 192.168.3.3
	line vty 0 4
	access-class 10 in

	Verify exclusive access from management station PC-C.
	PCC> ssh –l admin 192.168.2.1

	PCA> ssh –l admin 192.168.2.1

	Be sure to disable HTTP and enable HTTPS on server PC-A in Services tab.

	R1
	access-list 120 permit udp any host 192.168.1.3 eq domain
	access-list 120 permit tcp any host 192.168.1.3 eq smtp
	access-list 120 permit tcp any host 192.168.1.3 eq ftp
	access-list 120 permit tcp any host 192.168.1.3 eq 443
	access-list 120 permit tcp  host 192.168.3.3 host 10.1.1.1 eq 22
	int se0/1/0
	ip access-group 120 in

	Verify that PC-C cannot access PC-A via HTTPS using the web browser.
	Desktop->Web Browser->192.168.1.3 

	PCA> ping 192.168.2.1

	r1
	access-list 120 permit icmp any any echo-reply
	access-list 120 permit icmp any any unreachable
	access-list 120 deny icmp any any 
	access-list 120 permit ip any any

	Verify that PC-A can successfully ping the loopback interface on R2.
	PCA> ping 192.168.2.1 

	R3:
	access-list 110 permit ip 192.168.3.0 0.0.0.255 any
	int int gig0/0
	ip access-group 110 in
	access-list 100 permit tcp 10.0.0.0 0.255.255.255 host 192.168.3.3 eq 22
	access-list 100 deny ip 10.0.0.0 0.255.255.255 any
	access-list 100 deny ip 172.168.0.0 0.15.255.255 any
	access-list 100 deny ip 192.168.0.0 0.0.255.255 any
	access-list 100 deny ip 127.0.0.0 0.255.255.255 any
	access-list 100 deny ip 224.0.0.0 15.255.255.255 any
	access-list 100 permit ip any any
	int se0/1/0
	ip access-group 100 in


	Confirm that the specified traffic entering interface Serial 
	is handled correctly.
	PCC> ping 192.168.1.3 
	PCC> ssh –l admin 192.168.2.1
	" > sic.txt
fi

if [ "$p" == "4b" ]; then
	echo "
	# Practical4b_IPv6 ACLs to Mitigate Attacks.txt
	Execute command on all routers
	enable secret enpa55

	R1
	int gig0/0
	ipv6 address 2001:DB8:1:10::1/64
	ipv6 address FE80::1 link-local
	no shut
	exit
	int gig0/1
	ipv6 address 2001:DB8:1:11::1/64
	ipv6 address FE80::1 link-local
	no shut
	exit
	int se0/1/0
	ipv6 address 2001:DB8:1:1::1/64
	ipv6 address FE80::1 link-local
	no shut
	exit

	R2
	int se0/1/1
	ipv6 address 2001:DB8:1:2::2/64
	ipv6 address FE80::2 link-local
	no shut
	exit
	int se0/1/0
	ipv6 address 2001:DB8:1:1::2/64
	ipv6 address FE80::2 link-local
	no shut
	exit

	R3
	int gig0/0
	ipv6 address 2001:DB8:1:30::1/64
	ipv6 address FE80::3 link-local
	no shut
	exit
	int se0/1/1
	ipv6 address 2001:DB8:1:2::1/64
	ipv6 address FE80::3 link-local
	no shut
	exit


	Enable IPv6 routing
	R1
	ipv6 unicast-routing 
	ipv6 route 2001:DB8:1:2::0/64 2001:DB8:1:1::2
	ipv6 route 2001:DB8:1:30::0/64 2001:DB8:1:1::2

	R2
	ipv6 unicast-routing 
	ipv6 route 2001:DB8:1:10::0/64 2001:DB8:1:1::1
	ipv6 route 2001:DB8:1:11::0/64 2001:DB8:1:1::1
	ipv6 route 2001:DB8:1:30::0/64 2001:DB8:1:2::1

	R3
	ipv6 unicast-routing
	ipv6 route 2001:DB8:1:10::0/64 2001:DB8:1:2::2
	ipv6 route 2001:DB8:1:11::0/64 2001:DB8:1:2::2
	ipv6 route 2001:DB8:1:1::0/64 2001:DB8:1:2::2


	PC1> ping 2001:DB8:1:30::30

	PC2> ping 2001:DB8:1:30::30

	Configure an ACL that will block HTTP and HTTPS access
	ipv6 access-list BLOCK_HTTP
	deny tcp any host 2001:DB8:1:30::30 eq www
	deny tcp any host 2001:DB8:1:30::30 eq 443
	permit ipv6 any any
	exit
	int gig0/1
	ipv6 traffic-filter BLOCK_HTTP in

	Open a web browser to the PC1 to display the web page
	http://2001:DB8:1:30::30

	https://2001:DB8:1:30::30

	Open a web browser to the PC2 to display the web page.
	http://2001:DB8:1:30::30

	https://2001:DB8:1:30::30

	PC2> ping 2001:DB8:1:30::30

	Create an access list to block ICMP.
	R3:
	ipv6 access-list BLOCK_ICMP
	deny icmp any any
	permit ipv6 any any
	exit
	int gig0/0
	ipv6 traffic-filter BLOCK_ICMP OUT


	PC2> ping 2001:DB8:1:30::30
	PC1> ping 2001:DB8:1:30::30

	Open a web browser to the PC1 to display the web page.
	Desktop->Web Browser->http://2001:DB8:1:30::30
	Desktop->Web Browser->https://2001:DB8:1:30::30

	" > sic.txt
fi

if [ "$p" == "5" ]; then
	echo "
	# Practical5_ZoneBased Policy Firewall.txt
	Execute command on all routers
	line console 0
	password conpa55
	login
	line vty 0 4
	password vtypa55
	login
	exit
	enable secret enpa55
	ip domain-name ccnasecurity.com
	username admin secret adminpa55
	line vty 0 4
	login local
	crypto key generate rsa

	R1
	ip route 10.2.2.0 255.255.255.252 10.1.1.2
	ip route 192.168.3.0 255.255.255.0 10.1.1.2

	R2
	ip route 192.168.1.0 255.255.255.0 10.1.1.1
	ip route 192.168.3.0 255.255.255.0 10.2.2.1

	R3
	ip route 192.168.1.0 255.255.255.0 10.2.2.2
	ip route 10.1.1.0 255.255.255.252 10.2.2.2

	PCA> ping 192.168.3.3

	PCC> ssh -l admin 10.2.2.2

	Desktop -> Web Browser
	URL: http://192.168.1.3


	Create the Firewall Zones on R3 all comonda
	show version

	license boot module c1900 technology-package securityk9

	copy run start
	reload

	show version

	zone security IN-ZONE
	exit
	zone security OUT-ZONE
	exit

	access-list 101 permit ip 192.168.3.0 0.0.0.255 any

	class-map type inspect match-all IN-NET-CLASS-MAP
	match access-group 101
	exit

	policy-map type inspect IN-2-OUT-PMAP

	map IN-NET-CLASS-MAP

	class type inspect IN-NET-CLASS-MAP

	inspect
	exit
	exit

	Create a pair of zones
	zone-pair security IN-2-OUT-ZPAIR source IN-ZONE destination OUT-ZONE

	service-policy type inspect IN-2-OUT-PMAP
	exit

	int gig0/0
	zone-member security IN-ZONE
	exit
	int se0/1/1
	zone-member security OUT-ZONE
	exit

	copy run start
	reload


	PCC> ping 192.168.1.3

	PCC> ssh -l admin 10.2.2.2

	R3
	show policy-map type inspect zone-pair sessions 
	exit

	From internal PC-C, open a web browser to the PC-A server web page.
	URL: http://192.168.1.3

	R3
	show policy-map type inspect zone-pair sessions 

	Test Firewall Functionality from OUT-ZONE to IN-ZONE
	From internal PC-A, ping the external PC-C server.
	PCA>ping 192.168.3.3

	From R2, ping PC-C. 
	R2# ping 192.168.3.3

	" > sic.txt
fi


if [ "$p" == "6" ]; then
	echo "
	# Practical6_IOS Intrusion Prevention System.txt
	Execute command on all routers
	enable secret enpa55
	line console 0
	password conpa55
	login
	exit
	ip domain-name ccnasecurity.com
	username admin secret adminpa55
	line vty 0 4
	login local
	exit
	crypto key generate rsa

	R1
	router ospf 1
	network 10.1.1.0 0.0.0.3 area 0
	network 192.168.1.0 0.0.0.255 area 0

	R2
	router ospf 1
	network 10.1.1.0 0.0.0.3 area 0
	network 10.2.2.0 0.0.0.3 area 0

	R3
	router ospf 1
	network 10.2.2.0 0.0.0.3 area 0
	network 192.168.3.0 0.0.0.255 area 0

	R1
	show version
	conf t
	license boot module c1900 technology-package securityk9
	exit
	copy run start
	reload 
	show version


	PCA> ping 192.168.3.2

	PCC> ping 192.168.1.2

	R1
	mkdir ipsdir
	conf t
	ip ips config location flash:ipsdir
	ip ips name iosips
	ip ips notify log
	clock set 13:13:56 03 MAR 2021
	service timestamps log datetime msec
	logging host 192.168.1.50

	ip ips signature-category
	category all
	retired true
	exit
	category ios_ips basic
	retired false
	exit
	exit
	int gig0/0
	ip ips iosips out

	show ip ips all

	View the syslog messages.
	Click the Syslog server->Services tab-> SYSLOG

	Modify the Signature
	ip ips signature-definition 
	signature 2004 0 
	status
	retired false 
	enabled true 
	exit
	engine 
	event-action produce-alert
	event-action deny-packet-inline 
	exit 
	exit 
	exit 

	show ip ips all

	Verify that IPS is working properly
	PCC> ping 192.168.1.2

	PCA> ping 192.168.3.2

	View the syslog messages.
	Click the Syslog server->Services tab-> SYSLOG

	" > sic.txt
	
fi

if [ "$p" == "7" ]; then
	touch camera1.py
	echo "
	# Practical7_Layer 2 Security.txt
	Execute command on all switches and router
	enable secret ciscoenpa55
	line console 0
	password conpa55
	login
	ip domain-name ccnasecurity.com
	username admin secret adminpa55
	line vty 0 4
	login local
	crypto key generate rsa

	Determine the current root bridge
	Central
	show spanning-tree

	SW1
	show spanning-tree

	Central as the primary root bridge
	spanning-tree vlan 1 root primary
	show spanning-tree

	SW-1 as a secondary root bridge
	spanning-tree vlan 1 root secondary
	show spanning-tree

	Enable PortFast on all access ports 
	Commands on SWA-SWB
	int range fa0/1-4
	spanning-tree portfast
	exit
	int range fa0/1-4
	spanning-tree bpduguard enable

	int range fa0/23-24
	spanning-tree guard root

	int range fa0/1-22
	switchport mode access 
	switchport port-security
	switchport port-security maximum 2
	switchport port-security violation shutdown
	switchport port-security mac-address sticky

	show port-security interface fa0/1

	int range f0/5-22
	shutdown



	C1> ping 10.1.1.11

	C1> ping 10.1.1.14

	Commands on SWA-SWB
	show port-security int fa0/1

" > sic.txt

fi


if [ "$p" == "8" ]; then
	echo "
	# Practical8_Layer 2 VLAN Security.txt
	Execute command on all switches/router
	enable secret enpa55
	line console 0
	password conpa55
	login
	exit
	ip domain-name ccnasecurity.com
	username admin secret adminpa55
	line vty 0 4
	login local
	exit
	crypto key generate rsa

	Execute command on all switches
	show vlan brief
	vlan 5
	exit
	vlan 10
	exit
	vlan 15
	exit
	exit
	show vlan brief

	Execute command on switches 
	SWA:
	int fa0/2
	switchport mode access
	switchport access vlan 10
	exit
	int fa0/3
	switchport mode access
	switchport access vlan 10
	exit
	int fa0/4
	switchport mode access
	switchport access vlan 5

	SWB:
	int fa0/1
	switchport mode access
	switchport access vlan 5
	exit
	int fa0/2
	switchport mode access
	switchport access vlan 5
	exit
	int fa0/3
	switchport mode access
	switchport access vlan 5
	exit
	int fa0/4
	switchport mode access
	switchport access vlan 10

	Check the access mode allocations
	SWA:
	show vlan brief

	SWB:
	show vlan brief

	SWA:
	int fa0/24
	switchport mode trunk
	switchport trunk native vlan 15

	SWB:
	int fa0/24
	switchport mode trunk
	switchport trunk native vlan 15

	SW1
	int fa0/24
	switchport mode trunk
	switchport trunk native vlan 15

	SW1
	int gig0/1
	switchport mode trunk
	switchport trunk native vlan 15

	SW2
	int fa0/24
	switchport mode trunk
	switchport trunk native vlan 15

	SW2
	int gig0/1
	switchport mode trunk
	switchport trunk native vlan 15

	Central
	int range gig0/1-2
	switchport mode trunk
	switchport trunk native vlan 15
	exit
	int fa0/1
	switchport mode trunk
	switchport trunk native vlan 15
	exit
	show int trunk

	SW1 and SW2
	show int trunk

	SWA and SWB
	show int trunk

	R1:
	int gig0/0.1
	encapsulation dot1q 5
	ip address 192.168.5.100 255.255.255.0
	exit
	int gig0/0.2
	encapsulation dot1q 10
	ip address 192.168.10.100 255.255.255.0
	exit
	int gig0/0.15
	encapsulation dot1q 15
	ip address 192.168.15.100 255.255.255.0


	PC2> ping 192.168.10.2

	PC2> ping 192.168.5.2

	Connect SW-1 and SW-2.
	Using a crossover cable, connect port Fa0/23 on SW-1 to port Fa0/23
	on SW-2.

	(Execute command on SW- 1 and SW-2)
	int fa0/23
	switchport mode trunk
	switchport trunk native vlan 15
	switchport nonegotiate

	SWA
	vlan 20
	exit
	int vlan 20
	ip address 192.168.20.1 255.255.255.0

	(Execute command on SW-B, SW-1, SW-2, and Central)
	vlan 20
	exit

	SWB
	int vlan 20
	ip address 192.168.20.2 255.255.255.0

	SW1
	int vlan 20
	ip address 192.168.20.3 255.255.255.0

	SW2
	int vlan 20
	ip address 192.168.20.4 255.255.255.0

	Central
	int vlan 20
	ip address 192.168.20.5 255.255.255.0


	Connect the management PC using copper straight-through to SW-A port Fa0/1 and
	ensure that it is assigned an available IP address 192.168.20.50
	SWA:
	int fa0/1
	switchport mode access
	switchport acess vlan 20

	C1> ping 192.168.20.1 

	C1> ping 192.168.20.2 

	C1> ping 192.168.20.3 

	C1> ping 192.168.20.4 

	C1> ping 192.168.20.5 


	R1
	int gig0/0.3
	encapsulation dot1q 20
	ip address 192.168.20.100 255.255.255.0

	Set default gateway in management PC.
	C1 – 192.168.20.100

	C1> ping 192.168.20.100


	Enable security on R1
	access-list 101 deny ip any 192.168.20.0 0.0.0.255
	access-list 101 permit ip any any
	access-list 102 permit ip host 192.168.20.50 any
	int gig0/0.1
	ip access-group 101 in
	int gig0/0.2
	ip access-group 101 in
	line vty 0 4
	access-class 102 in 


	C1> ssh -l admin 192.168.20.100

	C1> ping 192.168.20.1 

	C1> ping 192.168.20.2 

	C1> ping 192.168.20.100 

	D1> ping 192.168.20.50
		" > sic.txt
fi


if [ "$p" == "9" ]; then
	echo "
	# Practical9_Verify a Site-to-Site IPsec.txt
	Execute command on all routers
	enable secret enpa55
	line console 0
	password conpa55
	login
	exit
	ip domain-name ccnasecurity.com
	username admin secret adminpa55
	line vty 0 4
	login local
	exit
	crypto key generate rsa

	R1
	router ospf 1
	network 192.168.1.0 0.0.0.255 area 0
	network 10.1.1.0 0.0.0.3 area 0

	R2
	router ospf 1
	network 192.168.2.0 0.0.0.255 area 0
	network 10.2.2.0 0.0.0.3 area 0
	network 10.1.1.0 0.0.0.3 area 0

	R3
	router ospf 1
	network 192.168.3.0 0.0.0.255 area 0
	network 10.2.2.0 0.0.0.3 area 0


	verify connectivity to PC-C and PC-B.
	PCA> ping 192.168.3.3

	PCA> ping 192.168.2.3

	PCB> ping 192.168.3.3


	R1
	show version
	conf t
	license boot module c1900 technology-package securityk9
	exit
	copy run start
	reload

	show version

	Identify interesting traffic on R1
	access-list 110 permit ip 192.168.1.0 0.0.0.255 192.168.3.0 0.0.0.255
	crypto isakmp policy 10
	encryption aes 256
	authentication pre-share
	group 5
	exit
	crypto isakmp key vpnpa55 address 10.2.2.2
	crypto ipsec transform-set VPN-SET esp-aes esp-sha-hmac
	crypto map VPN-MAP 10 ipsec-isakmp
	description VPN connection to R3
	set peer 10.2.2.2
	set transform-set VPN-SET
	match address 110
	exit
	int se0/1/0
	crypto map VPN-SET

	R3
	show version
	conf t
	license boot module c1900 technology-package securityk9
	copy run start
	reload
	show version
	conf t
	access-list 110 permit ip 192.168.3.0 0.0.0.255 192.168.1.0 0.0.0.255

	crypto isakmp policy 10
	encryption aes 256 
	authentication pre-share 
	group 5 
	exit 
	crypto isakmp key vpnpa55 address 10.1.1.2
	crypto ipsec transform-set VPN-SET esp-aes esp-sha-hmac
	crypto map VPN-MAP 10 ipsec-isakmp
	description VPN connection to R1
	set peer 10.1.1.2 
	set transform-set VPN-SET
	match address 110 
	exit
	int se0/1/1
	crypto map VPN-SET

	R1
	show crypto ipsec sa

	PCC> ping 192.168.1.3

	R1
	show crypto ipsec sa

	Create uninteresting traffic
	PCB>ping 192.168.1.3

	R1#ping 192.168.3.3

	R3#ping 192.168.1.3

	Verify the tunnel.
	R1# show crypto ipsec sa

	" > sic.txt
fi

if [ "$p" == "10" ]; then
	echo "
	# Practical10_ASA Basic Settings and Firewall.txt
	Execute command on all routers
	enable secret enpa55
	line console 0
	password conpa55
	login
	exit
	ip domain-name ccnasecurity.com
	username admin secret pa55
	line vty 0 4
	login local
	exit
	crypto key generate rsa

	R1
	router ospf 1
	network 209.165.200.0 0.0.0.7 area 0
	network 10.1.1.0 0.0.0.3 area 0  

	R2
	router ospf 1
	network 10.1.1.0 0.0.0.3 area 0
	network 10.2.2.0 0.0.0.3 area 0

	R3
	router ospf 1
	network 172.16.3.0 0.0.0.255 area 0
	network 10.2.2.0 0.0.0.3 area 0

	Verify connectivity.
	PCC -> R1, R2, R3 
	PCC -> ASA, PC-B, DMZ server

	ASA:
	show version
	show file system
	show flash:
	conf t
	hostname CCNAS-ASA
	domain-name ccnasecurity.com
	enable password enpa55
	clock set abhi ka time

	int vlan 1
	nameif inside
	ip address 192.168.1.1 255.255.255.0 
	security-level 100
	int vlan 2
	nameif outside
	ip address 209.165.200.226 255.255.255.248
	security-level 0
	exit
	show int ip brief

	show ip address

	show switch vlan

	Test connectivity to the ASA.
	PCB -> ASA 
	PCB -> R1 

	ASA waale main
	show route
	conf t
	route outside 0.0.0.0 0.0.0.0 209.165.200.225
	show route

	Test connectivity.
	ASA -> R1

	ASA waale main
	object network inside-net
	subnet 192.168.1.0 255.255.255.0
	nat (inside,outside) dynamic interface
	end
	exit
	show run

	PCB -> R1 

	show nat

	Modify the default MPF application inspection global service policy
	class-map inspection_default
	match default-inspection-traffic
	exit
	policy-map global_policy
	class inspection_default
	inspect icmp
	exit
	service-policy global_policy global

	PCB -> R1 


	Configure DHCP, AAA, and SSH
	dhcpd address 192.168.1.5-192.168.1.36 inside
	dhcpd dns 209.165.201.2 interface inside
	dhcpd enable inside

	Change PC-B from a static IP address to a DHCP client, and verify that it
	receives IP addressing information

	username admin password adminpa55
	aaa authentication ssh console LOCAL
	crypto key generate rsa modulus 1024
	ssh 192.168.1.0 255.255.255.0 inside
	ssh 172.16.3.3 255.255.255.255 outside
	ssh timeout 10


	PCC> ssh -l admin 209.165.200.226

	PCB> ssh -l admin 192.168.1.1


	Configure a DMZ, Static NAT, and ACLs
	int vlan 3
	ip address 192.168.2.1 255.255.255.0 
	no forward interface vlan 1  
	nameif dmz
	security-level 70
	int et0/2
	switchport access vlan 3
	exit
	exit

	show int ip brief

	show ip address

	show switch vlan

	object network dmz-server
	host 192.168.2.3 
	nat (dmz,outside) static 209.165.200.227 
	exit

	access-list OUTSIDE-DMZ permit icmp any host 192.168.2.3
	access-list OUTSIDE-DMZ permit tcp any host 192.168.2.3 eq 80
	access-group OUTSIDE-DMZ in interface outside

	Test access to the DMZ server.
	The ability to successfully test outside access to the DMZ web server was not
	in place; therefore, successful testing is not required.

	" > sic.txt

fi
