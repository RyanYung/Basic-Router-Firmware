#ifndef SR_ARP_H
#define SR_ARP_H

void sr_handle_arp(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);


#endif
