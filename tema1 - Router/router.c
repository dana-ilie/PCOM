#include <queue.h>
#include "skel.h"

#define R_TABLE_SIZE 10000000

struct route_table_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} __attribute__((packed));

struct arp_entry {
	uint32_t ip;
	uint8_t mac[6];
};

struct route_table_entry *rtable;
int rtable_size;

struct arp_entry *arp_table;
int arp_table_len;

struct arp_entry *get_arp_entry(__u32 ip) {
    for(int i = 0; i < arp_table_len; i++){
    	if(ip == arp_table[i].ip)
    		return &arp_table[i];
    }
    return NULL;
}

// binary search for get_best_route - O(logn)
struct route_table_entry *get_best_route(__u32 dest_ip) {
	struct route_table_entry *aux = NULL;

    int left = 0;
	int right = rtable_size;

    while (left <= right) {
        int mid = (left + right) / 2;

        // matching prefixes
        if ((dest_ip & rtable[mid].mask) == rtable[mid].prefix) {
            aux = &(rtable[mid]);
            mid--;
            // looking for the the greatest mask
            while (rtable[mid].mask > aux->mask && (dest_ip & rtable[mid].mask) == rtable[mid].prefix) {
                aux = &(rtable[mid]);
                mid--;
            }
            break;
        }

        if (rtable[mid].prefix < (dest_ip & rtable[mid].mask)) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }
    return aux;
}

// compare function in order to use in qsort
int compare(const void *rtable1, const void *rtable2) {
	if(((struct  route_table_entry *) rtable1)->prefix  == ((struct  route_table_entry *) rtable2)->prefix) {
		return ((struct route_table_entry *)rtable2)->mask - ((struct route_table_entry *)rtable1)->mask;
	} 

	return ((struct route_table_entry *)rtable1)->prefix - ((struct route_table_entry *)rtable2)->prefix;
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	init(argc - 2, argv + 2);

	rtable = malloc(R_TABLE_SIZE * sizeof(struct route_table_entry));
	FILE *f = fopen(argv[1], "r");
	char *s1 = malloc(50);
	char *s2 = malloc(50);
	char *s3 = malloc(50);
	int interface;
	int index = 0;
	int idx = 0;
	rtable_size = 0;
	arp_table_len = 0;

	// parsing rtabel using inet_pton and checking for errors
	while(!feof(f)) {
		fscanf(f, "%s %s %s %d", s1, s2, s3, &interface);
		int n1 = inet_pton(AF_INET, s1, &rtable[index].prefix);
		int n2 = inet_pton(AF_INET, s2, &rtable[index].next_hop);
		int n3 = inet_pton(AF_INET, s3, &rtable[index].mask);

		if(n1 != 1 || n2 != 1 || n3 != 1) {
			printf("Error while parsing...\n");
		}

		rtable[index].interface = interface;
		index++;
		rtable_size++;
	}

	fclose(f);

	rtable_size = rtable_size - 1;
	// sorting rtable
	qsort(rtable, rtable_size, sizeof(struct route_table_entry), compare);
	// arp_table
	arp_table = malloc(sizeof(struct arp_entry) * R_TABLE_SIZE);
	// queue for directing the packages which don't have arp_entry
	queue q = queue_create();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		// extracting ethernet header
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;

		// ARP PACKET
		if(htons(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			// extracting ARP header
			struct arp_header *arp_hdr = parse_arp(m.payload);

			// ARP REQUEST
			if(htons(arp_hdr->op) == ARPOP_REQUEST) {
				
				// extracting the mac addr from the received interface
				uint8_t *my_mac = malloc(6 * sizeof(uint8_t));
				get_interface_mac(m.interface, my_mac);

				// checking if it is for the router
				char* source = get_interface_ip(m.interface);
				struct in_addr source_ip;
				inet_aton(source, &source_ip);
				if(arp_hdr->tpa == source_ip.s_addr) {
					// sending ARP reply
					struct ether_header *eth_hdr_reply = malloc(sizeof(struct ether_header));
					build_ethhdr(eth_hdr_reply, my_mac, arp_hdr->sha, htons(ETHERTYPE_ARP));
					send_arp(arp_hdr->spa, arp_hdr->tpa, eth_hdr_reply, m.interface, htons(ARPOP_REPLY));
				}
				// if it is not for the router => drop the packet
				else {
					continue;
				}
			}

			// ARP REPLY
			else if(htons(arp_hdr->op) == ARPOP_REPLY) { 				
				// adding the new entry in arp_table
				struct arp_entry new_entry;
				memcpy(new_entry.mac, arp_hdr->sha, sizeof(arp_hdr->sha));
				memcpy(&new_entry.ip, &arp_hdr->spa, sizeof(arp_hdr->spa));

				arp_table[idx] = new_entry;
				arp_table_len++;
				idx++;

				// directing the packages from queue
				if(!queue_empty(q)) {
					packet *temp = (packet *)queue_deq(q);
					packet my_pack = *temp;

					struct ether_header *p_eth = (struct ether_header *)my_pack.payload;
					struct iphdr *ip_h = (struct iphdr *)(my_pack.payload + sizeof(struct ether_header));
					struct route_table_entry *rentry = get_best_route(ip_h->daddr);
					
					get_interface_mac(rentry->interface, p_eth->ether_shost);
					memcpy(p_eth->ether_dhost, arp_hdr->sha, sizeof(arp_hdr->sha));
					send_packet(rentry->interface, &my_pack);	
				}
				continue;
			}
		}

		// IP PACKET
		else if(htons(eth_hdr->ether_type) == ETHERTYPE_IP) {

			// extracting both ip and icmp headers
			struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
			struct icmphdr *icmp_hdr = parse_icmp(m.payload);

			struct route_table_entry *rentry = get_best_route(ip_hdr->daddr); 

			char *ipchar = get_interface_ip(m.interface);
			uint32_t ip_router = inet_addr(ipchar);

			// checking if it is for the router
			if(ip_hdr->daddr == ip_router) {
				// checking if ICMP request
				if(icmp_hdr->type == ICMP_ECHO) { 
					// sending icmp reply
					send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost, 0, 0, m.interface, icmp_hdr->un.echo.id, icmp_hdr->un.echo.sequence);
				}
				continue;
			}

			uint16_t checks = ip_hdr->check;
			ip_hdr->check = 0;

			// wrong checksum => drop the packet
			if(checks != ip_checksum(ip_hdr, sizeof(struct iphdr))) {
				continue;
			}	

			// wrong ttl => TIME_EXCEEDED
			if(ip_hdr->ttl <= 1) {
				// sending icmp error 
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
				get_interface_mac(m.interface, eth_hdr->ether_shost);
				send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_shost, eth_hdr->ether_dhost, 11, 0, m.interface);
				continue;
			}

			// no destination => HOST_UNREACHABLE
			if(rentry == NULL) {
				// sending icmp error
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
				get_interface_mac(m.interface, eth_hdr->ether_shost);
				send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_shost, eth_hdr->ether_dhost, 3, 0, m.interface);
				continue;
			}

			// update TTL & checksum
			ip_hdr->ttl--; 
			ip_hdr->check = 0;
			ip_hdr->check= ip_checksum(ip_hdr, sizeof(struct iphdr));

			// looking in arp_table for next_hop's entry
			// if it doesn't exist => send broadcasted ARP request 
			if(get_arp_entry(rentry->next_hop) == NULL) {
				// adding the packet in queue
				packet *pointer = malloc(sizeof(packet));
				memcpy(pointer, &m, sizeof(packet));
				pointer->interface = rentry->interface;
				queue_enq(q, pointer);

				struct ether_header eth_req;
				// setting broadcast addr
				uint8_t *mac = malloc(6 * sizeof(uint8_t));
				get_interface_mac(pointer->interface, mac);
				uint8_t *broadcast = malloc(6 * sizeof(uint8_t));
				memset(broadcast, 0xff, 6);

				memcpy(&eth_req.ether_shost, mac, 6);
				memcpy(&eth_req.ether_dhost, broadcast, 6);
				eth_req.ether_type = htons(ETHERTYPE_ARP);

				char* ip_of_request = get_interface_ip(pointer->interface);
				struct in_addr s_ip;
				inet_aton(ip_of_request, &s_ip);

				// sending ARP request
				send_arp(rentry->next_hop, s_ip.s_addr, &eth_req, pointer->interface, htons(ARPOP_REQUEST));
			} else {
				// sending normally the packet 
				struct arp_entry *arp= get_arp_entry(rentry->next_hop);
				memcpy(eth_hdr->ether_dhost, arp->mac, sizeof(arp->mac));
				get_interface_mac(rentry->interface, eth_hdr->ether_shost);
				send_packet(rentry->interface, &m);
			}
		}
	}
}

