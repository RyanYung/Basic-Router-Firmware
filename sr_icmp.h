#ifndef SR_ICMP_H
#define SR_ICMP_H

void sr_send_icmp_type0(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
void sr_send_icmp_type3(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, uint8_t imcp_type, uint8_t icmp_code);
void sr_send_icmp_type8(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
void sr_send_icmp_type11(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
#endif
