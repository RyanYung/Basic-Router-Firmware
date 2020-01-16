#include "sr_router.h"
#include "sr_utils.h"
#include "sr_ip.h"
#include "sr_arp.h"
#include <string.h>
#include <stdlib.h>
#include "sr_rt.h"
#include "sr_if.h"

#define ICMP_TYPE0 0x00
#define ICMP_TYPE11 0x0b
#define ICMP_TYPE3 0x03
#define ICMP_TYPE8 0x08

/* Send out ICMP echo request, can reuse the given packet and send it back out.
 	 This packet has no data section so it uses sr_icmp_hdr_t */
void sr_send_icmp_type0(struct sr_instance* sr,
		uint8_t * packet,
		unsigned int len,
		char* interface)
{
	struct sr_if * input_interface = sr_get_interface(sr, interface);
	struct sr_rt * routing_table_list = sr->routing_table;
	sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *) packet;
	sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
	sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

	struct sr_if * output_interface = NULL;
	while(routing_table_list != NULL) {
			uint32_t longest_prefix_match = routing_table_list->mask.s_addr & ip_hdr->ip_src;
			if(longest_prefix_match == routing_table_list->dest.s_addr) {
				output_interface = sr_get_interface(sr, routing_table_list->interface);
			}
			routing_table_list = routing_table_list->next;
	}
	/* Fill icmp header */
	icmp_hdr->icmp_type = ICMP_TYPE0;
	icmp_hdr->icmp_code = ICMP_TYPE0;
	icmp_hdr->icmp_sum = 0;
	icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_hdr_t));
	/* Swap src and dest in ip header */
	uint32_t temp_ip = ip_hdr->ip_src;
	ip_hdr->ip_src = input_interface->ip;
	ip_hdr->ip_dst = temp_ip;
	/* Set eth header */
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
	memcpy(eth_hdr->ether_shost, output_interface->addr, ETHER_ADDR_LEN);

	sr_send_packet(sr, packet, len, output_interface->name);
}

/* Send out ICMP error message by creating a new packet.
	This packet does carry data, so it uses sr_icmp_t3_hdr_t */
void sr_send_icmp_type3(struct sr_instance* sr,
			uint8_t * packet,
			unsigned int len,
			char* interface,
			uint8_t icmp_type,
			uint8_t icmp_code)
{
	int PACKET_LENGTH = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);

	struct sr_if * input_interface = sr_get_interface(sr, interface);
	struct sr_rt * routing_table_list = sr->routing_table;
	sr_ethernet_hdr_t * in_eth_hdr = (sr_ethernet_hdr_t *) packet;
	sr_ip_hdr_t * in_ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
	/* Create new packet and get pointers to headers */
	uint8_t * out_packet = (uint8_t *)malloc(PACKET_LENGTH);
	memset(out_packet, 0, PACKET_LENGTH);
	sr_ethernet_hdr_t * out_eth_hdr = (sr_ethernet_hdr_t *) out_packet;
	sr_ip_hdr_t * out_ip_hdr = (sr_ip_hdr_t *) (out_packet + sizeof(sr_ethernet_hdr_t));
	sr_icmp_t3_hdr_t * out_icmp_hdr = (sr_icmp_t3_hdr_t *) (out_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

	struct sr_if * output_interface = NULL;
	/* Do longest prefix match */
	while(routing_table_list != NULL) {
		uint32_t longest_prefix_match = routing_table_list->mask.s_addr & in_ip_hdr->ip_src;
		if(longest_prefix_match == routing_table_list->dest.s_addr) {
			output_interface = sr_get_interface(sr, routing_table_list->interface);
		}
		routing_table_list = routing_table_list->next;
	}
	/* Set icmp header */
	out_icmp_hdr->icmp_sum = 0;
	out_icmp_hdr->icmp_type = icmp_type;
	out_icmp_hdr->icmp_code = icmp_code;
	memcpy(out_icmp_hdr->data, in_ip_hdr, ICMP_DATA_SIZE);
	out_icmp_hdr->icmp_sum = cksum(out_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
	/* Set ip header */
	out_ip_hdr->ip_sum = 0;
	out_ip_hdr->ip_hl = in_ip_hdr->ip_hl;
	out_ip_hdr->ip_v = in_ip_hdr->ip_v;
	out_ip_hdr->ip_tos = in_ip_hdr->ip_tos;
	out_ip_hdr->ip_len = htons(len - sizeof(sr_ethernet_hdr_t));
	out_ip_hdr->ip_id = in_ip_hdr->ip_id;
	out_ip_hdr->ip_off = htons(IP_DF);
	out_ip_hdr->ip_ttl = INIT_TTL;
	out_ip_hdr->ip_p = ip_protocol_icmp;
	out_ip_hdr->ip_src = input_interface->ip;
	out_ip_hdr->ip_dst = in_ip_hdr->ip_src;
	out_ip_hdr->ip_sum = cksum(out_ip_hdr, sizeof(sr_ip_hdr_t));
	/* Set ethernet header */
	out_eth_hdr->ether_type = htons(ethertype_ip);
	memcpy(out_eth_hdr->ether_dhost, in_eth_hdr->ether_shost, ETHER_ADDR_LEN);
	memcpy(out_eth_hdr->ether_shost, output_interface->addr, ETHER_ADDR_LEN);

	sr_send_packet(sr, out_packet, len, output_interface->name);
}

/* Helper method used to abstract sending a type11 by using the method for sending a type 3 with code type 11 */
void sr_send_icmp_type11(struct sr_instance* sr,
			uint8_t * packet,
			unsigned int len,
			char* interface)
{
	sr_send_icmp_type3(sr, packet, len, interface, ICMP_TYPE11, ICMP_TYPE0);
}
