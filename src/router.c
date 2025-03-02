#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806

struct route_table_entry *route_table;
int rt_len;

struct arp_table_entry *arp_table;
int arp_len;

// Definim o funcție de comparare pentru structura de intrare a tabelei de rutare
int compare_route_entries(const void *a, const void *b)
{
	const struct route_table_entry *entry_a = (const struct route_table_entry *)a;
	const struct route_table_entry *entry_b = (const struct route_table_entry *)b;

	// Daca prefixele sunt egale, sortam descrescator in functie de masca
	if (entry_a->prefix == entry_b->prefix)
	{
		if (entry_b->mask > entry_a->mask)
			return 1;
		else if (entry_b->mask < entry_a->mask)
			return -1;
		else
			return 0;
	}
	else
	{
		// Sortam descrescator dupa prefix
		if (entry_b->prefix > entry_a->prefix)
			return 1;
		else
			return -1;
	}
}

// Cautarea binara in tabela de rutare
struct route_table_entry *best_route(struct route_table_entry *route_table, int rt_len, uint32_t ip)
{
	int left = 0, right = rt_len - 1;
	struct route_table_entry *best = NULL;
	while (left <= right)
	{
		int mid = (left + right) / 2;
		struct route_table_entry *rt = &route_table[mid];
		if ((rt->mask & ip) == rt->prefix)
		{
			best = rt;
			right = mid - 1;
		}
		else if (rt->prefix > (ip & rt->mask))
		{
			left = mid + 1;
		}
		else
		{
			right = mid - 1;
		}
	}
	return best;
}

struct arp_table_entry *arp_lookup(struct arp_table_entry *arp_table, int arp_len, uint32_t ip)
{
	for (int i = 0; i < arp_len; i++)
	{
		if (ip == arp_table[i].ip)
		{
			return &arp_table[i];
		}
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	route_table = malloc(100000 * sizeof(struct route_table_entry));
	rt_len = read_rtable(argv[1], route_table);

	arp_table = malloc((100000) * sizeof(struct arp_table_entry));
	arp_len = parse_arp_table("arp_table.txt", arp_table);

	qsort(route_table, rt_len, sizeof(struct route_table_entry), compare_route_entries);

	while (1)
	{

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *)buf;

		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP)
		{
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
			uint32_t destination_ip = ip_hdr->daddr;
			uint16_t old_checksum = ip_hdr->check;
			ip_hdr->check = 0;
			uint16_t new_checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
			if (new_checksum != old_checksum)
			{
				// Checksum gresit, aruncam pachetul
				continue;
			}
			ip_hdr->check = old_checksum;

			if (ip_hdr->ttl <= 1)
			{

				// // Copierea a 8 bytes din pachetul IP original
				char bytes[8];
				memcpy(bytes, buf + sizeof(struct ether_header) + sizeof(struct iphdr), 8);
				struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

				// Setarea campurilor (type, code) pentru pachetul ICMP
				icmp_hdr->type = 11;
				icmp_hdr->code = 0;

				// Extragerea header-ului IP original din buffer-ul de intrare
				struct iphdr *ip_hdr_pack = (struct iphdr *)(buf + sizeof(struct ether_header));

				// Calcularea adresei la care incep datele ICMP în pachetul ICMP
				uint8_t *icmp_data = (uint8_t *)icmp_hdr + sizeof(struct icmphdr);

				// Copierea header-ului IP original în pachetul ICMP
				memcpy(icmp_data, ip_hdr_pack, sizeof(struct iphdr));

				// Copierea datelor suplimentare din pachetul IP original in pachetul ICMP
				memcpy(icmp_data + sizeof(struct iphdr), bytes, 8);

				icmp_hdr->checksum = 0;
				icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, len - sizeof(struct ether_header) - sizeof(struct iphdr)));

				// Schimbarea campurilor IP
				ip_hdr->daddr = ip_hdr->saddr;
				ip_hdr->saddr = destination_ip;
				ip_hdr->ttl = 64;
				ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
				ip_hdr->protocol = IPPROTO_ICMP;
				ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);
				ip_hdr->check = 0;
				ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

				// Schimbarea campurilor Ethernet
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));

				get_interface_mac(interface, eth_hdr->ether_shost);

				size_t new_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8;

				send_to_link(interface, buf, new_len);

				continue;
			}

			uint32_t dst_ip = ip_hdr->daddr;
			uint32_t router_ip = inet_addr(get_interface_ip(interface));

			if (dst_ip == router_ip)
			{

				struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

				// Daca pachetul este de tip echo request, trimitem echo reply
				if (icmp_hdr->type == 8)
				{
					icmp_hdr->type = 0;
					icmp_hdr->code = 0;
					icmp_hdr->checksum = 0;
					icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, len - sizeof(struct ether_header) - sizeof(struct iphdr)));

					ip_hdr->daddr = ip_hdr->saddr;
					ip_hdr->saddr = dst_ip;
					ip_hdr->ttl = 64;
					ip_hdr->check = 0;
					ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

					memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
					get_interface_mac(interface, eth_hdr->ether_shost);

					send_to_link(interface, buf, len);
					continue;
				}
			}

			ip_hdr->ttl--;
			ip_hdr->check = 0;
			uint16_t new_check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
			ip_hdr->check = new_check;

			struct route_table_entry *best_rt = best_route(route_table, rt_len, ip_hdr->daddr);

			// Daca nu exista o ruta valida, trimitem un mesaj ICMP destination unreachable
			if (best_rt == NULL)
			{
				// Copierea a 8 bytes din pachetul IP original
				char bytes[8];
				memcpy(bytes, buf + sizeof(struct ether_header) + sizeof(struct iphdr), 8);
				struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

				// Setarea campurilor (type, code) pentru pachetul ICMP
				icmp_hdr->type = 3;
				icmp_hdr->code = 0;

				// Extragerea header-ului IP original din buffer-ul de intrare
				struct iphdr *ip_hdr_pack = (struct iphdr *)(buf + sizeof(struct ether_header));
				uint8_t *icmp_data = (uint8_t *)icmp_hdr + sizeof(struct icmphdr);
				memcpy(icmp_data, ip_hdr_pack, sizeof(struct iphdr));
				memcpy(icmp_data + sizeof(struct iphdr), bytes, 8);

				// Recalcularea checksum-ului pentru pachetul ICMP
				icmp_hdr->checksum = 0;
				icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, len - sizeof(struct ether_header) - sizeof(struct iphdr)));

				// Schimbare campurilor IP
				ip_hdr->daddr = ip_hdr->saddr;
				ip_hdr->saddr = destination_ip;
				ip_hdr->ttl = 64;
				ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
				ip_hdr->protocol = IPPROTO_ICMP;
				ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);
				ip_hdr->check = 0;
				ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

				// Schimbarea campurilor Ethernet
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
				get_interface_mac(interface, eth_hdr->ether_shost);

				size_t new_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8;

				send_to_link(interface, buf, new_len);
				continue;
			}

			struct arp_table_entry *arp_entry = arp_lookup(arp_table, arp_len, best_rt->next_hop);

			// Adresa sursa va fi adresa interfetei pe care am primit pachetul
			get_interface_mac(best_rt->interface, eth_hdr->ether_shost);

			// Adresa destinatie va fi adresa MAC a urmatorului hop
			if (arp_entry->mac == NULL && arp_entry != NULL)
			{
				continue;
			}
			memcpy(eth_hdr->ether_dhost, arp_entry->mac, sizeof(arp_entry->mac));
			send_to_link(best_rt->interface, buf, len);
		}
		else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP)
		{
			continue;
		}
	}
	/* Note that packets received are in network order,
	any header field which has more than 1 byte will need to be conerted to
	host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
	sending a packet on the link, */
}
