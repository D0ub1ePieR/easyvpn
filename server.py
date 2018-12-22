from scapy.all import *

client_ip_table=["192.168.160.128"]
target_ip_table=["192.168.108.137","192.168.108.1"]
server_ip_out="192.168.160.129"
server_ip_in="192.168.108.128"
request_stack=[]

def transmit_icmp(pktx):
    '''
        转发报文
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
            pkt_icmp_data=pktx[ICMP].payload.load
			print("[log] catch an icmp paclet : ip.src",src_ip," ip.dst",dst_ip," icmp.seq",pkt_seq," icmp.id",pkt_id)
            if src_ip in client_ip_table and dst_ip==server_ip_out:
                #ICMP type为8 表示request请求报文
                if pktx[ICMP].type==8:
                    ip_length=int(pkt_icmp_data[-2:])
                    request_ip=pkt_icmp_data[-2-ip_length:-2]
                    request_stack.append([src_ip,request_ip])
                    send(IP(src=server_ip_in,dst=request_ip)/ICMP(seq=pkt_seq,id=pkt_id)/pktx[ICMP].payload)
            elif src_ip in target_ip_table and dst_ip not in client_ip_table:
                #ICMP type为0 表示reply回复报文
                if pktx[ICMP].type==0:
                    for pair in request_stack:
                        index=-1
                        if pair[1]==Raw(src_ip).load:
                            index=request_stack.index(pair)
                            send(IP(src=pair[1],dst=pair[0])/ICMP(seq=pkt_seq-50,type=0,id=pkt_id-50)/pktx[ICMP].payload);
                        if index!=-1:
                            request_stack.remove(request_stack[index])
                            break

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
