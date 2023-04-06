#include "queue.h"
#include "skel.h"

void send_icmp(struct ether_header *eh, struct iphdr *ip, struct icmphdr *icmp, uint8_t icmp_type, int interface, size_t size_m){
	packet new_packet;
	new_packet.interface = interface;
	void *payload;

	struct ether_header eth_hdr;
	eth_hdr.ether_type = htons(ETH_P_IP);
	memcpy(eth_hdr.ether_dhost, eh->ether_shost, ETH_ALEN);
	memcpy(eth_hdr.ether_shost, eh->ether_dhost, ETH_ALEN);

	struct icmphdr icmp_hdr = {
		.type = icmp_type,
		.code = 0,
		.checksum = 0,
	};

	struct iphdr ip_hdr;
	ip_hdr.saddr = ip->daddr;
	ip_hdr.daddr = ip->saddr;
	ip_hdr.version = 4;
	ip_hdr.ihl = 5;
	ip_hdr.tos = 0;
	ip_hdr.protocol = IPPROTO_ICMP;
	ip_hdr.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr.id = htons(1);
	ip_hdr.frag_off = 0;
	ip_hdr.ttl = 64;
	ip_hdr.check = 0;
	ip_hdr.check = ip_checksum((uint8_t *)&ip_hdr, sizeof(struct iphdr));

	icmp_hdr.checksum = icmp_checksum((uint16_t *)&icmp_hdr, size_m - sizeof(struct ether_header) - sizeof(struct iphdr));

	payload = new_packet.payload;
	memcpy(payload, &eth_hdr, sizeof(struct ether_header));
	memcpy(payload + sizeof(struct ether_header), &ip_hdr, sizeof(struct iphdr));
	memcpy(payload + sizeof(struct ether_header) + sizeof(struct iphdr), &icmp_hdr, sizeof(struct icmphdr));

	new_packet.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	send_packet(&new_packet);

}

struct arp_entry* get_arp_entry(uint32_t ip, struct arp_entry* arp_table, int arp_table_size) {
	for (int i = 0; i < arp_table_size; i++) {
		if (arp_table[i].ip == ip) {
			return &arp_table[i];
		}
	}
	return NULL;
}

struct route_table_entry *get_best_route(uint32_t daddr, int rtable_size, struct route_table_entry *rtable)
{
	int idx = 0;
	struct route_table_entry vector[100000];

	for(int i = 0; i < rtable_size; i++) {
		if((daddr & rtable[i].mask) == rtable[i].prefix) {
			idx++;
			vector[idx - 1] = rtable[i];
		}
	}

	struct route_table_entry *result = NULL;
	uint32_t aux_mask = vector[0].mask;

	for(int i = 0; i < idx; i++) {
		if(vector[i].mask >= aux_mask) {
			aux_mask = vector[i].mask;
			result = &(vector[i]);
		}
	}

	return result;
}


int verify_checksum(packet m)
{	
	struct iphdr *iph = (struct iphdr *)(m.payload + sizeof(struct ether_header));
	uint16_t iph_check = iph->check;
	iph->check = 0;
	uint16_t checksum_result = ip_checksum((uint8_t *)iph, sizeof(struct iphdr));
	
	if (iph_check != checksum_result) {
		return 0;
	}

	return iph_check;
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);

	struct route_table_entry *rtable = (struct route_table_entry *)malloc(sizeof(struct route_table_entry) * 1000000);
	DIE(rtable == NULL, "Failed to allocate memory for rtable");

	struct arp_entry *arp_table = (struct arp_entry *)malloc(sizeof(struct arp_entry) * 1000000);
	DIE(arp_table == NULL, "Failed to allocate memory for arp_table");

	int rtable_size = read_rtable(argv[1], rtable);
	DIE(rtable_size < 0, "Failed to read rtable");

	int arp_table_index = 0;

	// Create a queue to store the packets
	queue q = queue_create();
	DIE(q == NULL, "Failed to create queue");

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");

		// Extract the ethernet header
		struct ether_header *eth = (struct ether_header *)m.payload;
		uint16_t eth_type = eth->ether_type;

		// Check the ether header type
		//ARP
		if (htons(eth_type) == ETHERTYPE_ARP) {
			// Extract the arp header
			struct arp_header *arp = (struct arp_header *)(m.payload + sizeof(struct ether_header));
			uint16_t arp_opcode = arp->op;

			// Check if the received operation is ARP_REQUEST
			if (htons(arp_opcode) == ARPOP_REQUEST) {
				// Check if the request is for the router
				char *ip = get_interface_ip(m.interface);
				uint32_t ip_target = inet_addr(ip);
				if (arp->tpa == ip_target) {
					// Send ARP_REPLY with the router's MAC address
					memcpy(eth->ether_dhost, eth->ether_shost, ETH_ALEN);
					get_interface_mac(m.interface, eth->ether_shost);
					
					memcpy(arp->tha, eth->ether_dhost, ETH_ALEN);
					memcpy(arp->sha, eth->ether_shost, ETH_ALEN);

					uint32_t tmp_ip = arp->tpa;
					arp->tpa = arp->spa;
					arp->spa = tmp_ip;

					arp->op = htons(ARPOP_REPLY);
					send_packet(&m);

				} else {
					// If the request is not for the router, drop the packet
					continue;
				}
			}
			// Check if the received operation is ARP_REPLY
			else if (htons(arp->op) == ARPOP_REPLY) {
				// Add the ARP entry to the ARP table
				arp_table[arp_table_index].ip = arp->spa;
				memcpy(arp_table[arp_table_index].mac, arp->sha, sizeof(arp->sha));
				arp_table_index++;

				queue aux_q = queue_create();
				
				while (!queue_empty(q)) {
					// Dequeue the packet
					packet *p = (packet *)queue_deq(q);
					struct iphdr *iph = (struct iphdr *)(p->payload + sizeof(struct ether_header));
					struct route_table_entry *rte = get_best_route(iph->daddr, rtable_size, rtable);
				
					if (rte->next_hop == arp->spa) {
						// Send the packet
						iph->ttl = iph->ttl - 1;

						uint16_t check = iph->check;
						uint16_t m1, m2;
						
						m1 = (iph->ttl + 1) | (iph->protocol << 8);
						check = check - (~m1);

						m2 = iph->ttl | (iph->protocol << 8);
						check = check - m2 - 1;

						iph->check = check;
						
						get_interface_mac(rte->interface, ((struct ether_header *)p->payload)->ether_shost);
						memcpy(((struct ether_header *)p->payload)->ether_dhost, arp->sha, ETH_ALEN);
						p->interface = rte->interface;
						
						send_packet(p);
					} else {
						queue_enq(aux_q, p);
					}
				}

				while (!queue_empty(aux_q)) {
					packet *p = (packet *)queue_deq(aux_q);
					queue_enq(q, p);
				}

				continue;
			}

		}
		//IP
		else if (htons(eth->ether_type) == ETHERTYPE_IP) {
			struct iphdr *iph = (struct iphdr *)(m.payload + sizeof(struct ether_header));

			// Check if the destination of the packet is the router
			char *ip = get_interface_ip(m.interface);
			uint32_t ip_router = inet_addr(ip);

			if (iph->daddr == ip_router) {
				if (iph->protocol == IPPROTO_ICMP) {
					struct icmphdr *icmph = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
					// Check if we have echo request
					if (icmph->type == ICMP_ECHO) {
						// Respond with echo reply
						icmph->type = ICMP_ECHOREPLY;
						icmph->code = 0;

						uint8_t dest_mac[ETH_ALEN];
						memcpy(dest_mac, eth->ether_dhost, ETH_ALEN);
						memcpy(eth->ether_dhost, eth->ether_shost, ETH_ALEN);
						memcpy(eth->ether_shost, dest_mac, ETH_ALEN);

						uint32_t tmp_ip = iph->daddr;
						iph->daddr = iph->saddr;
						iph->saddr = tmp_ip;

						iph->check = 0;
						iph->check = ip_checksum((uint8_t *)iph, sizeof(struct iphdr));
						send_packet(&m);
					}
				}

				continue;
			}

			// Verify the checksum
			int check = verify_checksum(m);
			if (check == 0) {
				// Drop the packet
				continue;
			} else {
				iph->check = check;
			}

			// Check the TTL
			if (iph->ttl <= 1) {
				// Send ICMP_TIME_EXCEEDED error and drop the packet
				struct ether_header *old_eth = (struct ether_header *)m.payload;
				struct icmphdr *old_icmph = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
				struct iphdr *old_iph = (struct iphdr *)(m.payload + sizeof(struct ether_header));
				send_icmp(old_eth, old_iph, old_icmph, ICMP_TIME_EXCEEDED, m.interface, sizeof(m.payload));

				continue;
			}

			// Search in the routing table
			struct route_table_entry *rte = get_best_route(iph->daddr, rtable_size, rtable);
			if (rte == NULL) {
				// Send HOST UNREACHABLE icmp error and drop the packet
				struct ether_header *old_eth = (struct ether_header *)m.payload;
				struct icmphdr *old_icmph = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
				struct iphdr *old_iph = (struct iphdr *)(m.payload + sizeof(struct ether_header));
				send_icmp(old_eth, old_iph, old_icmph, ICMP_DEST_UNREACH, m.interface, sizeof(m.payload));	

				continue;
			}

			// Search in the arp table for the MAC address of the next hop
			struct arp_entry *arp_entry = get_arp_entry(rte->next_hop, arp_table, arp_table_index);

			// If the MAC address is not in the arp table, send ARP request
			if (arp_entry == NULL) {
				// Add the packet to the queue
				packet *buff = malloc(sizeof(m));
				DIE(buff == NULL, "Malloc failed");

				memcpy(buff, &m, sizeof(m));
				buff->interface = rte->interface;
				queue_enq(q, buff);

				// Create a new packet for the ARP request
				packet arp_request;
				memset(arp_request.payload, 0, 1600);

				// Set the ethernet header
				struct ether_header arp_req_eth;
				uint8_t *broadcast_mac = malloc(6 * sizeof(uint8_t));
				DIE(broadcast_mac == NULL, "Malloc failed");
				memset(broadcast_mac, 0xff, 6);

				uint8_t *router_mac = malloc(6 * sizeof(uint8_t));
				DIE(router_mac == NULL, "Malloc failed");
				get_interface_mac(rte->interface, router_mac);

				arp_req_eth.ether_type = htons(ETHERTYPE_ARP);
				memcpy(arp_req_eth.ether_dhost, broadcast_mac, ETH_ALEN);
				memcpy(arp_req_eth.ether_shost, router_mac, ETH_ALEN);

				// Set the arp header
				struct arp_header arp_hdr;

				arp_hdr.htype = htons(1);
				arp_hdr.ptype = htons(2048);
				arp_hdr.hlen = 6;
				arp_hdr.plen = 4;
				arp_hdr.op = htons(ARPOP_REQUEST);
				
				memcpy(arp_hdr.sha, router_mac, ETH_ALEN);
				char *ip = get_interface_ip(rte->interface);
				struct in_addr router_ip;
				inet_aton(ip, &router_ip);
				arp_hdr.spa = router_ip.s_addr;

				memcpy(arp_hdr.tha, broadcast_mac, ETH_ALEN);
				arp_hdr.tpa = rte->next_hop;

				memcpy(arp_request.payload, &arp_req_eth, sizeof(struct ether_header));
				memcpy(arp_request.payload + sizeof(struct ether_header), &arp_hdr, sizeof(struct arp_header));
				arp_request.len = sizeof(struct ether_header) + sizeof(struct arp_header);
				arp_request.interface = rte->interface;

				send_packet(&arp_request);
			} else {
				// Send the packet directly
				iph->ttl--;
				uint16_t check = iph->check;
				uint16_t m1, m2;
				
				m1 = (iph->ttl + 1) | (iph->protocol << 8);
				check = check - (~m1);

				m2 = iph->ttl | (iph->protocol << 8);
				check = check - m2 - 1;

				iph->check = check;

				get_interface_mac(rte->interface, ((struct ether_header *)m.payload)->ether_shost);
				memcpy(((struct ether_header *)m.payload)->ether_dhost, arp_entry->mac, ETH_ALEN);
				m.interface = rte->interface;
				send_packet(&m);
			}
		}
	}
}
