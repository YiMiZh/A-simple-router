/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);

    /* fill in code here */
    print_hdrs(packet, len);
    sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t *)packet;
    
    if (ntohs(eth_header->ether_type) == ethertype_ip) {
        printf("Received IP packet\n");
        handle_ip(sr, packet, len, interface);
    } else if (ntohs(eth_header->ether_type) == ethertype_arp) {
        printf("Received ARP packet\n");
        handle_arp(sr, packet, len, interface);
    }
}/* end sr_ForwardPacket */

/* This method handle an incoming ARP packet */
void handle_arp(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface) {
    /* this is an ARP packet */
    struct sr_if *receiver_interface = sr_get_interface(sr, interface);
    sr_arp_hdr_t *sender_arp_header = (sr_arp_hdr_t *)(packet + 14);
    fprintf(stderr, "before\n");
    print_hdr_eth(packet);
    print_hdr_arp(packet + 14);
    /* received a request */
    if (ntohs(sender_arp_header->ar_op) == arp_op_request) {
        if (receiver_interface->ip == sender_arp_header->ar_tip) {
            uint8_t *reply = (uint8_t *) malloc(len);
            if (!reply) {
                perror("handle_arp():malloc");
                return;
            }
            /* ethernet header */
            memcpy(reply, (packet + 6), 6);
            memcpy(reply + 6, receiver_interface->addr, 6);
            memcpy(reply + 12, packet + 12, 2);
            /* ARP packet */
            enum sr_arp_opcode reply_op_code;
            reply_op_code = htons(arp_op_reply);
            memcpy(reply + 14, packet + 14, 6);
            memcpy(reply + 20, &reply_op_code, 2);
            memcpy(reply + 22, receiver_interface->addr, 6);
            memcpy(reply + 28, packet + 38, 4);
            memcpy(reply + 32, packet + 6, 6);
            memcpy(reply + 38, packet + 28, 4);
            fprintf(stderr, "after\n");
            print_hdr_eth(reply);
            print_hdr_arp(reply + 14);
            sr_send_packet(sr, reply, len, interface);
            free(reply);
        } else {
            fprintf(stderr, "no target found");
            return;
        }
    }
    /* received a reply */
    else if (ntohs(((sr_arp_hdr_t *)(packet + 14))->ar_op) == arp_op_reply){
        struct sr_arpreq *arp_cache = sr_arpcache_insert(&(sr->cache), sender_arp_header->ar_sha, sender_arp_header->ar_sip);
        fprintf(stderr, "in arpreply(before)\n");
        print_addr_ip_int(sender_arp_header->ar_sip);
        print_addr_ip_int(htonl(sender_arp_header->ar_sip));
        if (arp_cache) {
            struct sr_packet *received_packet = arp_cache->packets;
            sr_ethernet_hdr_t *packet_to_cache = (sr_ethernet_hdr_t*)received_packet->buf;
            while (received_packet) {
                fprintf(stderr, "in loop arpreply\n");
                print_hdr_eth(received_packet->buf);
                print_hdr_ip(received_packet->buf + 14);
                memcpy(packet_to_cache->ether_shost, receiver_interface->addr, ETHER_ADDR_LEN);
                memcpy(packet_to_cache->ether_dhost, sender_arp_header->ar_sha, ETHER_ADDR_LEN);
                sr_send_packet(sr, received_packet->buf, received_packet->len, interface);
                fprintf(stderr, "after loop arpreply\n");
                print_hdr_eth(received_packet->buf);
                print_hdr_ip(received_packet->buf + 14);
                received_packet = received_packet->next;
            }
            sr_arpreq_destroy(&(sr->cache), arp_cache);
        }else {
            fprintf(stderr, "no packet for the reply");
            return;
        }
    }
}

/* This method handles an incoming IP packet */
void handle_ip(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface) {
    /* this is an IP packet */
    printf("Handling IP packet\n");
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    /* check checksum and minimum length */
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
        fprintf(stderr, "Packet too short\n");
        return;
    }
    if (!cksum(ip_header, ip_header->ip_hl)) {
        fprintf(stderr, "Packet invalid checksum\n");
        return;
    }

    if (sr_get_interface_from_ip(sr, ip_header->ip_dst)) {
        /* packet for us */
        printf("Packet for us\n");
        if (ntohs(ip_header->ip_p) == ip_protocol_icmp) {
            /* check echo request */
            sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            if (icmp_header->icmp_type == 8 && icmp_header->icmp_code == 0) {
                send_icmp_message(sr, 0, 0, packet, interface);
            }
        } else {
            send_icmp_message(sr, 3, 3, packet, interface);
        }
    } else {
        /* packet not for us */
        printf("Packet not for us\n");
        /* decrease TTL */
        if (ip_header->ip_ttl > 1) {
            ip_header->ip_ttl--;
        } else {
            send_icmp_message(sr, 11, 0, packet, interface);
            return;
        }

        sr_find_next_mac(sr, packet, len, interface);
    }
}

/* 
Helper for sending icmp message back to the sending host.
Echo Reply (type = 0)
Destination net unreachable (type = 3, code = 0)
Destination host unreachable (type = 3, code = 1)
Port unreachable (type = 3, code = 3)
Time exceeded (type = 11, code = 0)
*/
void send_icmp_message(struct sr_instance* sr, uint8_t type, uint8_t code, uint8_t *packet, char *interface) {
    printf("calling send_icmp_message, packet in is:\n");
    int len_icmp = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    print_hdrs((uint8_t *)packet, (uint32_t)len_icmp);
    /* Get the interface record */
    struct sr_if *interf = sr_get_interface(sr, interface);
    /* icmp_packet we need to send */
    uint8_t *icmp_packet = (uint8_t *)malloc(len_icmp);
    /* faild to malloc */
    if (icmp_packet == NULL) {
        printf("Malloc failed when creating icmp message\n");
        return;
    }
    /* prepare the fields of the package.
     ethernet part (it will be set up later) */
    printf("start filling ethernet field\n");
    sr_ethernet_hdr_t *eth_hdr_icmp = (sr_ethernet_hdr_t *)icmp_packet;
    sr_ethernet_hdr_t *eth_hdr_org = (sr_ethernet_hdr_t *)packet;
    eth_hdr_org -> ether_type = htons(ethertype_ip);
    /* ip part
     consturct the ip header */
    printf("start filling ip field\n");
    sr_ip_hdr_t *ip_hdr_icmp = (sr_ip_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t));
    sr_ip_hdr_t *ip_hdr_org = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    /* uint32_t ipSrc = ip_hdr_org -> ip_src; */
    ip_hdr_icmp -> ip_hl = 5;
    ip_hdr_icmp -> ip_v = 4;
    ip_hdr_icmp -> ip_tos = 0;
    ip_hdr_icmp -> ip_id = ip_hdr_org->ip_id;
    ip_hdr_icmp -> ip_off = htons(IP_DF);
    ip_hdr_icmp -> ip_ttl = INIT_TTL;
    ip_hdr_icmp -> ip_p = 1;
    ip_hdr_icmp -> ip_sum = 0;
    ip_hdr_icmp -> ip_dst = ip_hdr_org->ip_src;
    ip_hdr_icmp -> ip_src = interf->ip;
    ip_hdr_icmp -> ip_sum = cksum(ip_hdr_icmp, sizeof(sr_ip_hdr_t));
    printf("ip field finished filling\n");
    /* deal with different conditions.
     we use same structure for both type 3 and 11 */
    if (type == 3 || type == 11) {
        printf("Type3 or Type11 condition\n");
		/* construct the icmp field */
        printf("start filling icmp field\n");
        sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		icmp_hdr -> icmp_type = type;
		icmp_hdr -> icmp_code = code;
		icmp_hdr -> unused = 0;
        icmp_hdr -> next_mtu = 0;
		icmp_hdr -> icmp_sum = 0;
        memcpy(icmp_hdr->data, ip_hdr_org, ICMP_DATA_SIZE);
        icmp_hdr -> icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
        printf("icmp field finished filling\n");
        /* ethernet part
         check if the host's mac address in the arp cache */
        struct sr_arpentry *arp_inCache = sr_arpcache_lookup(&sr->cache, ip_hdr_org->ip_src);
        /* if we can find IP -> MAC in the cache, update the packet use current location's info */
        if (arp_inCache) {
            printf("We found target in our arp cache\n");
            memcpy(eth_hdr_icmp->ether_shost, interf->addr, ETHER_ADDR_LEN);
            memcpy(eth_hdr_icmp->ether_dhost, arp_inCache->mac, ETHER_ADDR_LEN);
            /* Prints out all ICMP message fields */
            printf("ethernet field finished filling\n");
            printf("icmp packet we need to send is:\n");
            print_hdrs((uint8_t *)icmp_packet, (uint32_t)len_icmp);
            sr_send_packet(sr, icmp_packet, (unsigned int)len_icmp, interface);
            printf("sent icmp packet succeed\n");
            free(arp_inCache);
            free(icmp_packet);
        }
        /* if we can't find IP -> MAC in the cache, sent a arp request */
        else {
            printf("We didn't find target in our arp cache\n");
            printf("now sending arp request\n");
            struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, ip_hdr_org->ip_src, icmp_packet, (unsigned int)len_icmp, interface);
            sr_handle_arpreq(sr, req);
        }
    }
    /* send response to Echo request*/
    else if (type == 0) {
        printf("Type0(echo reply) condition\n");
        memcpy(eth_hdr_icmp -> ether_dhost, eth_hdr_org -> ether_shost, ETHER_ADDR_LEN);
        memcpy(eth_hdr_icmp -> ether_shost, eth_hdr_org -> ether_dhost, ETHER_ADDR_LEN);
        printf("ethernet field finished filling\n");
        printf("start filling icmp field\n");
        sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        icmp_hdr -> icmp_type = 0;
		icmp_hdr -> icmp_code = 0;
        icmp_hdr -> icmp_sum = 0;
        icmp_hdr -> icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_hdr_t));
        printf("icmp field finished filling\n");
        /* Prints out all ICMP message fields */
        printf("icmp packet we need to send is:\n");
        print_hdrs((uint8_t *)icmp_packet, (uint32_t)len_icmp);
        sr_send_packet(sr, icmp_packet, len_icmp, interface);
        printf("sent icmp packet succeed\n");
        free(icmp_packet);
    }
}


/* This function fill in next hop mac address and send packet. */
void sr_find_next_mac(struct sr_instance *sr, uint8_t * packet, unsigned int len, char *interface) {
    printf("Finding next hop mac\n");
    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t *)packet;

    /* find routing table entry */
    struct sr_rt *rt_entry = sr_rt_lookup(sr->routing_table, ip_header->ip_dst);
    sr_print_routing_entry(rt_entry);
    if (!rt_entry) {
        printf("No matching routing table entry\n");
        send_icmp_message(sr, 3, 0, packet, interface);
        return;
    }
    struct sr_if *out_if = sr_get_interface(sr, rt_entry->interface);
    memcpy(eth_header->ether_shost, out_if->addr, ETHER_ADDR_LEN);
    uint32_t next_hop_ip = rt_entry->gw.s_addr;

    /* check ARP cache */
    struct sr_arpcache *cache = &(sr->cache);
    struct sr_arpentry *arp_entry = sr_arpcache_lookup(cache, next_hop_ip);

    if (arp_entry) {
        printf("Found next hop mac\n");
        /* recompute checksum */
        ip_header->ip_sum = 0;
        ip_header->ip_sum = cksum(packet, ip_header->ip_hl * 4);
        /* fill in next hop mac address */
        unsigned char *next_hop_mac = arp_entry->mac;
        memcpy(eth_header->ether_dhost, next_hop_mac, ETHER_ADDR_LEN);
        sr_send_packet(sr, packet, len, rt_entry->interface);
        free(arp_entry);
    } else {
        printf("No next hop mac\n");
        struct sr_arpreq *req = sr_arpcache_queuereq(cache, next_hop_ip, packet, len, interface);
        sr_handle_arpreq(sr, req);
    }
}
