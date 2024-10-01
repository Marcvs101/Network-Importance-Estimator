from scapy.all import *

cap = rdpcap('input/input.pcapng')

ip_addresses_set = set()
ip_src_set = set()
ip_dst_set = set()

ip_src_count = dict()
ip_dst_count = dict()
ip_src_dst_route_count = dict()

ip_src_count_weighted = dict()
ip_dst_count_weighted = dict()
ip_src_dst_route_count_weighted = dict()

for pkt in cap:
    # Only "purposeful" traffic is considered
    # TCP, UDP
    if ("TCP" in pkt) or ("UDP" in pkt):

        ip_src = ""
        ip_dst = ""
        pkt_size = len(pkt)

        # IPv4 handler
        if "IP" in pkt:
            ip_src = pkt["IP"].src
            ip_dst = pkt["IP"].dst
        
        # IPv6 handler
        elif "IPv6" in pkt:
            ip_src = pkt["IPv6"].src
            ip_dst = pkt["IPv6"].dst

        # No IP layer, possibly MAC only
        else:
            #print("WARN no IP layer found for packet",pkt,"Is this a MAC only packet?")
            pass

        ip_addresses_set.add(ip_src)
        ip_addresses_set.add(ip_dst)
        ip_src_set.add(ip_src)
        ip_dst_set.add(ip_dst)

        # Count
        if ip_src not in ip_src_count:
            ip_src_count[ip_src] = 0
        ip_src_count[ip_src] += 1

        if ip_dst not in ip_dst_count:
            ip_dst_count[ip_dst] = 0
        ip_dst_count[ip_dst] += 1

        if ip_src not in ip_src_dst_route_count:
            ip_src_dst_route_count[ip_src] = dict()
        if ip_dst not in ip_src_dst_route_count[ip_src]:
            ip_src_dst_route_count[ip_src][ip_dst] = 0
        ip_src_dst_route_count[ip_src][ip_dst] += 1

        # Weight == size
        if ip_src not in ip_src_count_weighted:
            ip_src_count_weighted[ip_src] = 0
        ip_src_count_weighted[ip_src] += pkt_size

        if ip_dst not in ip_dst_count_weighted:
            ip_dst_count_weighted[ip_dst] = 0
        ip_dst_count_weighted[ip_dst] += pkt_size

        if ip_src not in ip_src_dst_route_count_weighted:
            ip_src_dst_route_count_weighted[ip_src] = dict()
        if ip_dst not in ip_src_dst_route_count_weighted[ip_src]:
            ip_src_dst_route_count_weighted[ip_src][ip_dst] = 0
        ip_src_dst_route_count_weighted[ip_src][ip_dst] += pkt_size


print(ip_addresses_set)
print("----")
print(ip_src_count_weighted)
print("----")
print(ip_dst_count_weighted)