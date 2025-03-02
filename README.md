# Router Implementation

This project implements the dataplane of a router, handling packet processing, routing decisions, and basic network protocols.

## Overview

The router implementation includes:
- IPv4 packet processing
- Routing table lookup with binary search
- ARP table management
- ICMP error handling
- TTL processing
- Checksum validation

## Features

- **IPv4 Packet Handling**: Processes IPv4 packets, validates checksums, decrements TTL, and forwards packets
- **Routing**: Uses a binary search algorithm to find the best route for a packet
- **ARP Table Management**: Maintains a table of MAC addresses for IP addresses
- **ICMP Support**: Generates appropriate ICMP messages for TTL exceeded, destination unreachable, and echo reply
- **Checksum Validation**: Validates and recalculates checksums for modified headers

## Project Structure

```
.
├── router.c                  # Main router implementation
├── lib.c / lib.h             # Helper functions for networking
├── protocols.h               # Protocol definitions (IP, ARP, ICMP, Ethernet)
├── queue.c / queue.h         # Queue implementation
├── list.c / list.h           # Linked list implementation
├── Makefile                  # Build instructions
├── README.md                 # Project documentation
└── arp_table.txt             # Static ARP table
```

## Key Components

### Routing Table

The router maintains a routing table sorted by prefix and mask for efficient lookup. Binary search is used to find the best route for a packet based on the destination IP address.

```c
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
```

### ARP Table Lookup

The router performs ARP table lookups to find the MAC address for a given IP address.

```c
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
```

### Packet Processing

The main loop receives packets, determines their type, and processes them accordingly:

- For IPv4 packets:
  - Validates the checksum
  - Processes TTL (generates ICMP message if TTL ≤ 1)
  - Checks if the router is the destination
  - Finds the best route for the packet
  - Forwards the packet to the next hop

- For ICMP Echo requests:
  - Generates Echo replies

## Building and Running

### Prerequisites

- GCC compiler
- Make
- Linux environment with network capabilities

### Compilation

```bash
make all
```

### Running the Router

To run the router with a specific routing table and interfaces:

```bash
./router rtable0.txt rr-0-1 r-0 r-1
```

or

```bash
make run_router0
```

## Implementation Details

### IPv4 Forwarding

When a router receives an IPv4 packet:
1. Validates the checksum
2. Checks if the TTL is greater than 1
3. Decrements the TTL by 1
4. Recalculates the header checksum
5. Looks up the best route for the packet
6. Looks up the MAC address of the next hop
7. Updates the Ethernet header
8. Forwards the packet

### ICMP Message Generation

The router generates ICMP messages in the following scenarios:
- TTL exceeded (Type 11, Code 0)
- Destination network unreachable (Type 3, Code 0)
- Echo reply (Type 0, Code 0) in response to Echo request
