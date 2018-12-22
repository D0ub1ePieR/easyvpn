from scapy.all import *

pkt_data=[]
ip_table=["10.1.64.120"]
server_ip="192.168.108.131"

def fix_icmp(pktx):
	'''
		sniff回调处理函数
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
			#目标ip在虚拟局域网内将报文发送给服务器
			if dst_ip in ip_table:
				send(IP(dst=server_ip)/ICMP(seq=pkt_seq,id=pkt_id)/pktx[ICMP].payload)

def sniff_packet():
	'''
		抓取本机发送的数据包
	'''
	# sniff(filter,iface,prn,count)
	sniff(filter="icmp",prn=fix_icmp)


def main():
    '''
        主函数
    '''
    sniff_packet()

main()