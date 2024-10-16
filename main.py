import json
from scapy.all import *

import networkx as nx
import plotly.graph_objects as go



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


#print(ip_addresses_set)
#print("----")
#print(ip_src_count_weighted)
#print("----")
#print(ip_dst_count_weighted)


f=open(file="output/ip_count.json",mode="w",encoding="utf-8")
f.write(json.dumps({"src_to_count":ip_src_count,"dst_to_count":ip_dst_count,"src_to_dst_to_count":ip_src_dst_route_count}))
f.close()

f=open(file="output/ip_count_weighted.json",mode="w",encoding="utf-8")
f.write(json.dumps({"src_to_count":ip_src_count_weighted,"dst_to_count":ip_dst_count_weighted,"src_to_dst_to_count":ip_src_dst_route_count_weighted}))
f.close()



# NETWORKX
network_graph = nx.DiGraph()
max_weight = 0

for src in ip_src_dst_route_count_weighted:
    network_graph.add_node(src)
    for dst in ip_src_dst_route_count_weighted[src]:
        network_graph.add_node(dst)
        network_graph.add_edge(src,dst,weight=ip_src_dst_route_count_weighted[src][dst])
        max_weight = max(max_weight,ip_src_dst_route_count_weighted[src][dst])


centrality_metric = nx.degree_centrality(network_graph)


# Draw graphs
def color_centrality(node):
    return "rgb("+str((1-centrality_metric[node])*255)+","+str((centrality_metric[node])*255)+",0)"



def print_graph(title,node_color_function,debug_data):
    pos = nx.spring_layout(network_graph)

    fig = go.Figure()
    for u, v, data in network_graph.edges(data=True):
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        fig.add_trace(go.Scatter(x=[x0, x1], y=[y0, y1], mode='lines',line=dict(width=.1+(data["weight"]/max_weight)*2, color='rgba(127,127,127,255)')))
    for node in network_graph.nodes():
        x, y = pos[node]
        fig.add_trace(go.Scatter(
            x=[x], y=[y], 
            name=node, 
            text=node+"\n"+str(debug_data[node]), 
            mode='markers',
            marker=dict(
                size=6,
                color=node_color_function(node),
                line=dict(
                    color='black',
                    width=1))))
    fig.update_layout(go.Layout(
        title="Network graph "+title,
        showlegend=False,
        hovermode='closest',
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)'
    ))
    fig.show()




print_graph("",color_centrality,centrality_metric)