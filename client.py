from scapy.all import *

pkt_data=[]
ip_table=["192.168.108.137","192.168.108.1"]
server_ip_out="192.168.160.129"
server_ip_in="192.168.108.128"

def two_length_str(pstr):
	'''
		param : string
		return : length of string (length 2)
	'''
	tstr=str(len(pstr))
	if len(tstr)<2:
		tstr='0'+tstr
	return tstr

def fix_icmp(pktx):
	'''
		sniff回调处理函数
	'''
	try:
		proto=pktx[IP].proto
	except:
		print("[log] not icmp packet") #TODO
	else:
		src_ip=pktx[IP].src
		dst_ip=pktx[IP].dst
		#proto为1 表示icmp
		if proto==1:
			pkt_id=pktx[ICMP].id
			pkt_seq=pktx[ICMP].seq
			pkt_icmp_data=pktx[ICMP].payload.load
			print("[log] catch an icmp paclet : ip.src",src_ip," ip.dst",dst_ip," icmp.seq",pkt_seq," icmp.id",pkt_id)
			#目标ip在虚拟局域网内将报文发送给服务器
			if dst_ip in ip_table:
				#拼接数据段 记录目标ip
				send_payload=pkt_icmp_data+Raw(dst_ip).load+Raw(two_length_str(dst_ip)).load
				send(IP(dst=server_ip_out)/ICMP(seq=pkt_seq+50,id=pkt_id+50)/Raw(send_payload))

def sniff_packet():
	'''
		抓取本机发送的数据包
	'''
	# sniff(filter,iface,prn,count)
	sniff(iface="ens38",prn=fix_icmp)


def main():
    '''
        主函数
    '''
    sniff_packet()

main()
