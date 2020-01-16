#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_router.h"
#include "sr_utils.h"
#include "sr_arp.h"
#include "sr_protocol.h"
#include "sr_rt.h"

void sr_handle_arp(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface)
{
  if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))) {
    fprintf(stderr, "sr_handle_arp: packet was too short\n");
    return;
  }
  /*Get this interface */
  struct sr_if * sr_interface = sr_get_interface(sr, interface);
  /*fprintf(stderr, "Printing sr_interface below\n");
  sr_print_if(sr_interface);*/

  /*Get the headers of this packet*/
  sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *) packet;
  sr_arp_hdr_t * arp_hdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

  /*If this packet is an arp request*/
  if (ntohs(arp_hdr -> ar_op) == arp_op_request) {
    fprintf(stderr, "sr_handle_arp: ARP request received\n");
    /*Add it to the cache*/
    sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

    int PACKET_LENGTH = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    /*Create new packet and clear the memory*/
    uint8_t * out_packet = (uint8_t *)malloc(PACKET_LENGTH);
    memset(out_packet, 0, PACKET_LENGTH);
    /*Get pointers to the header positions*/
    sr_ethernet_hdr_t * out_eth_hdr = (sr_ethernet_hdr_t *) out_packet;
    sr_arp_hdr_t * out_arp_hdr = (sr_arp_hdr_t *) (out_packet + sizeof(sr_ethernet_hdr_t));
    /*Fill in the ethernet header*/
    memcpy(out_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(out_eth_hdr->ether_shost, sr_interface->addr, ETHER_ADDR_LEN);
    out_eth_hdr->ether_type = ntohs(ethertype_arp);
    /*Fill in the arp header*/
    out_arp_hdr->ar_hrd = arp_hdr->ar_hrd;
    out_arp_hdr->ar_pro = arp_hdr->ar_pro;
    out_arp_hdr->ar_hln = arp_hdr->ar_hln;
    out_arp_hdr->ar_pln = arp_hdr->ar_pln;
    out_arp_hdr->ar_op = htons(arp_op_reply);
    memcpy(out_arp_hdr->ar_sha, sr_interface->addr, ETHER_ADDR_LEN);
    out_arp_hdr->ar_sip = sr_interface->ip;
    memcpy(out_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    out_arp_hdr->ar_tip = arp_hdr->ar_sip;
    /*Send the packet*/
    sr_send_packet(sr, out_packet, PACKET_LENGTH, sr_interface->name);
  }
  /*If this packet is an arp reply*/
  else if (ntohs(arp_hdr -> ar_op) == arp_op_reply) {
    /*If we are the destination for this packet*/
    if (arp_hdr->ar_tip == sr_interface->ip) {
      fprintf(stderr, "sr_handle_arp: ARP reply received\n");
      /* Lock cache while accessing it */
      pthread_mutex_lock(&sr->cache.lock);
      /*Get the request from the cache*/
      struct sr_arpreq * output_req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
      /*If the request exists, process*/
      if (output_req != NULL) {
        struct sr_packet * packet_list = output_req->packets;
        /*Iterate through list of packets waiting on this request and send them out*/
        while (packet_list != NULL) {
          uint8_t * out_packet = (uint8_t *) packet_list->buf;
          sr_ethernet_hdr_t * out_eth_hdr = (sr_ethernet_hdr_t *) out_packet;
          sr_ip_hdr_t * out_ip_hdr = (sr_ip_hdr_t *) (out_packet + sizeof(sr_ethernet_hdr_t));
          out_ip_hdr->ip_sum = 0;
          out_ip_hdr->ip_sum = cksum((const void *) out_ip_hdr, sizeof(sr_ip_hdr_t));
          memcpy(out_eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
          memcpy(out_eth_hdr->ether_shost, sr_interface->addr, ETHER_ADDR_LEN);
          sr_send_packet(sr, out_packet, packet_list->len, sr_interface->name);
          packet_list = packet_list->next;
        }
        sr_arpreq_destroy(&sr->cache, output_req);
      }
      /* Unlock cache when finished */
      pthread_mutex_unlock(&sr->cache.lock);
    }
  }
}
