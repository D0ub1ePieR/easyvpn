from scapy.all import *

pkt_data=[]
ip_table=["192.168.108.137"]
server_ip_out="192.168.160.129"
server_ip_in="192.168.108.128"

def fix_icmp(pktx):
	'''
		sniff回调处理函数
	'''
	try:
		proto=pktx[IP].proto
	except:
		print("[log] not icmp packet") # TODO
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
				send(IP(dst=server_ip_out)/ICMP(seq=pkt_seq+50,id=pkt_id+50)/Raw(pktx[ICMP].payload.load+Raw(dst_ip).load))

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
