from scapy.all import *

client_ip_table=["10.1.64.120"]
target_ip="192.168.108.1"

def transmit_icmp(pktx):
    '''
        转发报文
    '''
    try:
        proto=pktx[IP].proto
    except:
		print("[log] not icmp packet") # TODO:
    else:
        src_ip=pktx[IP].src
		dst_ip=pktx[IP].dst
        #proto为1 表示icmp
		if proto==1:
			pkt_id=pktx[ICMP].id
			pkt_seq=pktx[ICMP].seq
			print("[log] catch an icmp paclet : ip.src",src_ip," ip.dst",dst_ip," icmp.seq",pkt_seq," icmp.id",pkt_id)
			if src_ip in client_ip_table:
                send(IP(dst=target_ip)/ICMP(seq=pkt_seq,id=pkt_id)/pktx[ICMP].payload)

def sniff_packet():
	'''
		抓取本机发送的数据包
	'''
	# sniff(filter,iface,prn,count)
	sniff(filter="icmp",prn=transmit_icmp)

def main():
    '''
        主函数
    '''
    sniff_packet()

main()
