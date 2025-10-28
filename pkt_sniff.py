from scapy.all import *
from scapy.layers.inet import *


def packet_cap(pkt):

    # print(pkt.show())

        
    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        src_port = pkt[IP].sport
        dst_port = pkt[IP].dport
        print("===== IP Layer =====")
        print("source IP & Port:-",src_ip,"/",src_port)
        print("destination IP & Port:-",dst_ip,'/',dst_port)
        print()
        if pkt.haslayer(Raw):
                data = pkt[Raw].load
                print("===== Raw Layer =====")
                print("Raw Payload:-\n",data.decode())
                print()
        else:
            print("No Raw layer found in the packet.")        
        

        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            print("===== TCP Layer =====")
            print("source IP & Port:-",src_ip,"/",src_port)
            print("destination IP & Port:-",dst_ip,'/',dst_port)
            print()
            
            if pkt.haslayer(Raw):
                data = pkt[Raw].load
                print("===== Raw Layer =====")
                print("Raw Payload:-",data.decode())
                print()
            else:
                print("No Raw layer found in the packet.")    
                
        elif pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            print("===== UDP Layer =====")
            print("source IP & Port:-",src_ip,"/",src_port)
            print("destination IP & Port:-",dst_ip,'/',dst_port)
            print()

            if pkt.haslayer(Raw):
                data = pkt[Raw].load
                print("===== Raw Layer =====")
                print("Raw Data:-",data.decode())
            else:
                print("No Raw layer found in the packet.")    
           
    else:
        print("No IP layer found in the packet.")
        print()

num_of_pkt = 3

print("Starting the packets capturing...")
print("="*100)
print()
sniff(filter="tcp port 80", prn=packet_cap, store=False, count=num_of_pkt)
print("Total packets captured:",num_of_pkt)
print("Packet capturing completed.")
