#include "sr_router.h"
#include "sr_utils.h"
#include "sr_ip.h"
#include "sr_icmp.h"
#include <string.h>
#include <stdlib.h>
#include "sr_rt.h"

#define ICMP_TYPE0 0x00
#define ICMP_TYPE11 0x0b
#define ICMP_TYPE3 0x03
#define ICMP_TYPE8 0x08

void sr_handle_ip(struct sr_instance* sr,
  uint8_t * packet,
  unsigned int len,
  char* interface)
  {
    /*print_hdrs(packet, len);*/
    /*Check length of ip packet*/
    if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))) {
      fprintf(stderr, "sr_handle_ip: IP packet was too short\n");
      return;
    }
    sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
    if (ip_hdr->ip_v != 4) {
      fprintf(stderr, "sr_handle_ip: ip packet was not version 4\n");
      return;
    }
    if (ip_hdr->ip_hl * 4 != sizeof(sr_ip_hdr_t)) {
      fprintf(stderr, "sr_handle_ip: ip packet header length was wrong\n");
      return;
    }
    /*Check checksum of ip packet*/
    uint16_t curr_ip_cksum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    uint16_t new_ip_cksum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    /*Checksum valid*/
    if (new_ip_cksum == curr_ip_cksum) {
      fprintf(stderr, "sr_handle_ip: packet checksum valid, processing\n");
      ip_hdr->ip_sum  = curr_ip_cksum;
      struct sr_if * interface_list = sr->if_list;
      /*Is packet for this router*/
      while(interface_list != NULL) {
        if (interface_list->ip == ip_hdr->ip_dst) {
          fprintf(stderr, "sr_handle_ip: packet destined for this router at interface %s\n", interface_list->name);
          /*If packet is not ICMP packet*/
          if (ip_hdr->ip_p != ip_protocol_icmp) {
            fprintf(stderr, "sr_handle_ip: received non icmp packet, sending icmp type 3\n");
            sr_send_icmp_type3(sr, packet, len, interface, ICMP_TYPE3, ICMP_TYPE3);
            return;
          }
          /* If packet is an ICMP packet */
          else if (ip_hdr->ip_p == ip_protocol_icmp) {
            sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            /*Check length of icmp packet*/
            if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t))) {
              fprintf(stderr, "sr_handle_ip: ICMP packet was too short\n");
              return;
            }
            /*If icmp echo request, send echo reply*/
            if(icmp_hdr->icmp_type == ICMP_TYPE8) {
              fprintf(stderr, "sr_handle_ip: icmp echo request received, sending icmp type 0\n");
              sr_send_icmp_type0(sr, packet, len, interface);
              return;
            }
            else {
              fprintf(stderr, "sr_handle_ip: unknown icmp type\n");
              return;
            }
          }
          else {
            return;
          }
        }
        interface_list = interface_list->next;
      }

      /*Packet not destined for this router*/
      /*Packet timed out, sending icmp type 11 code 0*/
      if (ip_hdr->ip_ttl <= 1) {
        fprintf(stderr, "sr_handle_ip: packet timed out, sending icmp type 11\n");
        ip_hdr->ip_ttl--;
        sr_send_icmp_type11(sr, packet, len, interface);
        return;
      }
      /*Do ip forwarding*/
      sr_ip_forwarding(sr, packet, len, interface);
    }

    /*Checksum failed return*/
    else if(new_ip_cksum != curr_ip_cksum) {
      fprintf(stderr, "sr_handle_ip: incoming packet checksum invalid\n");
      ip_hdr->ip_sum = curr_ip_cksum;
      return;
    }
  }

void sr_ip_forwarding(struct sr_instance* sr,
    uint8_t * packet,
    unsigned int len,
    char* interface)
{
  sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *) packet;
  sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
  struct sr_rt * routing_list = sr->routing_table;
  struct sr_if * output_interface = NULL;
  /* Do LPM to find next hop address */
  while(routing_list != NULL) {
    uint32_t longest_prefix_match = routing_list->mask.s_addr & ip_hdr->ip_dst;
    if (longest_prefix_match == routing_list->dest.s_addr) {
      fprintf(stderr, "sr_ip_forwarding: calling sr_get_interface on %s\n", routing_list->interface);
      output_interface = sr_get_interface(sr, routing_list->interface);
    }
    routing_list = routing_list->next;
  }
  /*Did not find the output interface*/
  if (output_interface == NULL) {
    fprintf(stderr, "sr_ip_forwarding: did not find output interface, sending icmp net unreachable\n");
    sr_send_icmp_type3(sr, packet, len, interface, ICMP_TYPE3, ICMP_TYPE0);
    return;
  }
  /*Found the output interface*/
  else if (output_interface != NULL) {
    struct sr_arpentry * arp_entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);
    /*Did not find the receiver based on IP*/
    if (arp_entry == NULL) {
      fprintf(stderr, "sr_ip_forwarding: did not find receiver, sending arp request\n");
      struct sr_arpreq * arp_request = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, packet, len, output_interface->name);
      sr_handle_arpreq(sr, arp_request);
      return;
    }
    /*Did find the receiver based on IP*/
    else if (arp_entry != NULL) {
      fprintf(stderr, "sr_ip_forwarding: found receiver, sending packet\n");
      memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
      memcpy(eth_hdr->ether_shost, output_interface->addr, ETHER_ADDR_LEN);
      ip_hdr->ip_ttl--;
      ip_hdr->ip_sum = 0;
      ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
      sr_send_packet(sr, packet, len, output_interface->name);
      free(arp_entry);
      return;
    }
  }
  else {
    return;
  }
}
