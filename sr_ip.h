#ifndef SR_IP_H
#define SR_IP_H

void sr_handle_ip(struct sr_instance * sr, uint8_t * packet, unsigned int len, char* interface);
void sr_ip_forwarding(struct sr_instance* sr,  uint8_t * packet,  unsigned int len,  char* interface);
#endif
