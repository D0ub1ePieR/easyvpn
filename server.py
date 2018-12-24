from scapy.all import *

client_ip_table=["192.168.160.128"]
target_ip_table=["192.168.108.137","192.168.108.1"]
server_ip_out="192.168.160.129"
server_ip_in="192.168.108.128"
server_port=20000
request_stack=[]

def transmit_icmp(pktx):
    '''
        转发icmp报文
    '''
    try:
        proto=pktx[IP].proto
    except:
        print("[log] not ip packet") # TODO
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

def transmit_tcp(pktx):
    '''
        实现客户端与目标主机的tcp连接
    '''
    src_ip=pktx[IP].src
    dst_ip=pktx[IP].dst
    try:
        pkt_ack=pktx[TCP].ack
        pkt_seq=pktx[TCP].seq
        pkt_flags=pktx[TCP].flags
        pkt_sport=pktx[TCP].sport
        pkt_dport=pktx[TCP].dport
    except:
        print("[log] tcp pakcet fix failed")
    else:
        #TCP flags FIN-1 SYN-2 RST-4 ACK-16
        if src_ip in client_ip_table and dst_ip==server_ip_out:
            # SYN
            if pkt_flags==2:
                data=pktx.payload.load
                if [src_ip,data,pkt_sport,pkt_dport] not in [t[:4] for t in request_stack]:
                    # 记录每一个tcp连接
                    request_stack.append([src_ip,data,pkt_sport,pkt_dport,server_port,pkt_seq,pkt_ack])
                    server_port=server_port+1
                    # 转发syn请求
                    send(IP(src=src_ip,dst=data)/TCP(flags=2,sport=pkt_sport,dport=pkt_dport,seq=pkt_seq,ack=pkt_ack))
            # ACK
            if pkt_flags==16:
                for i in len(request_stack):
                    if request_stack[i][4]==[src_ip,dst_ip,pkt_sport,pkt_dport]:
                        if pkt_ack==request_stack[i][5]+1 and pkt_seq==request_stack[i][6]:
                            send(IP(src=src_ip,dst=pktx.payload.load)/TCP(flags=16,sport=pkt_sport,dport=pkt_dport,seq=pkt_seq,ack=pkt_ack))
        if dst_ip in client_ip_table and src_ip!=server_ip_out:
            if pkt_flags==18:
                for i in len(request_stack):
                    if request_stack[i][:4]==[dst_ip,src_ip,pkt_dport,pkt_sport]:
                        if pkt_ack=request_stack[i][5]+1:
                            send(IP(src=src_ip,dst=dst_ip)/TCP(flags=18,sport=pkt_sport,dport=pkt_dport,seq=pkt_seq,ack=pkt_ack))
                            request_stack[i][5]=pkt_seq
                            request_stack[i][6]=pkt_ack

def sniff_packet():
    '''
        抓取本机发送的数据包
    '''
    def classify(pktx):
        '''
            sniff回调处理函数,分类包
        '''
        try:
            proto=pktx[IP].proto
        except:
            print("[log] not ip packet")
        else:
            #proto为6 表示tcp
            if proto==6:
                transmit_tcp(pktx)
            #proto为1 表示icmp
            if proto==1:
                transmit_icmp(pktx)
    # sniff(filter,iface,prn,count)
    sniff(filter="icmp",prn=classify)

def main():
    '''
        主函数
    '''
    sniff_packet()

main()
