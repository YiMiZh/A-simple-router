1. Overview of Code Structure
The simple router implemented in this assignment consists of two main functionalities:
handling IP packets and handling ARP packets.
When received an IP packet, first apply sanity checks on the packet to ensure integrity
and correctness then determine whether the packet is for the router. If so then only send
back an ICMP echo response when it is an echo request or ICMP port unreachable is replied;
otherwise, since packet is not for the router we have to forward it. So we decrease TTL
to see if ICMP time exceeded is needed then modify ethernet header and try to fill in
the next hop mac address. This is done by first searching through routing table to find
longest prefix match, if not found then send back net unreachable; then use the found
next hop ip to search for next hop mac address in ARP cache. If no matching entry then
submit a new request and broadcast ARP request until sent five time and report ICMP host
unreachable, otherwise using the existing mapping to fill in next hop mac address and
send the packet away.
When received an ARP packet, if it is reply to me then cache the IP->MAC mapping and send
all pending packets; otherwise if it is request for me then construct an according
ARP reply and send it back.

2. Design Decisions
 - ICMP message sending function
   During implementation we found out multiple usage of sending ICMP message back, and
   found it having decent amount of repeated procedures, so we extracted the function
   out to tedious ICMP packet construction.
 - ARP and IP handling functions
   Initially we put all handling inside sr_handlepacket() and it became lengthy and
   difficult for debugging, so we extracted functionalities for cleaner code.
 - Routing table longest prefix match look up function
   This is an essential function required for routing table look up, hence implemented
   in sr_rt.c as utility function.