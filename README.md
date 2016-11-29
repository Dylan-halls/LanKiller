# LanKiller

LanKiller is a proof of concept showing how an attacker could completly mess up a network by simply siting
there and then every time a arp request comes along sending out a arp reply but with a fake addres meaning that
some of the packets will never reach the original ip.

- Coded in python using scapy

What happens is that when you start it running the killer will start collecting a database of all of its possable victims(IPs)
then once it has collected all of them it will passivly sit and wait until it re
