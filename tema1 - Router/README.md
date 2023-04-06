Ilie Dana Maria, 324CA

# About
I have solved everything except the efficient LPM using binary search or trie. Instead, I implemented LPM using a linear search. I have also solved the bonus.

# Implementation

First of all, I read the route table using the "read_rtable" function.

## While loop
When a packet is received, the ethernet header is extracted in order to
determine the packet's type.

### ARP packet
If the packet is an ARP, the ARP opcode is checked to see if the operation
is a request or a reply.

-> If the operation is a request, it is checked if the request is for the router
    -> If the request is not for the router, the packet is dropped
    -> Otherwise, the router sends back an ARP reply with its MAC address
       When replying, the router uses the same packet but changes the
       destination and source and ARP opcode
-> If the operation is a reply
    -> The router creates a new entry in the ARP table and saves the packet 
    sender's MAC address.
    -> Then, the packets are dequeued and sent forward

### IP packet
If the packet is an IP packet, the ip header is extracted, then it is checked
if the destination of the packet is the router

-> If the destination is the router
    -> It is checked if the packet is an icmp echo request
        -> If it is an icmp echo request, the router responds with an echo 
        reply

-> Otherwise
    -> The checksum is verified. If the checksum is wrong, then the packet it's
    dropped

    -> The TTL is verified. If the TTL is exceeded, the router sends and icmp
    time exceeded error and drops the packet

    -> If there's no route to the destination of the packet, the router sends
    a destination unreachable icmp error and drops the packet.

    -> The MAC address of the next hop is searched in the ARP table
        -> If the MAC address is not in the ARP table, the router sends
        and ARP request in order to find the MAC and queues the packet
        -> If the MAC address is in the ARP table, the router updates the TTL
        and checksum and sends the packet directly.
