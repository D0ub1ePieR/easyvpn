from scapy.all import *

pkt_data=[]
ip_table=["192.168.108.137","192.168.108.1"]
server_ip_out="192.168.160.129"
#server_ip_in="192.168.108.128"

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
        处理icmp
    '''
    try:
        proto=pktx[IP].proto
    except:
        print("[log] not ip packet") #TODO
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

def fix_tcp(pktx):
    '''
        处理tcp包
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
        if dst_ip in ip_table:
            if pkt_flags==2:
                send(IP(dst=server_ip_out)/TCP(flags=2,sport=pkt_sport,dport=pkt_dport,seq=pkt_seq,ack=pkt_ack)/Raw(dst_ip))
            # 提供服务器转发的syn包会使服务器回复一个rst
            if pkt_flags==4:
                print("[log] recieve a server RST")
            if pkt_flags==16:
                send(IP(dst=server_ip_out)/TCP(flags=16,sport=pkt_sport,dport=pkt_dport,seq=pkt_seq,ack=pkt_ack)/Raw(dst_ip))
            # 理论上不会进这个分支
            if pkt_flags==18:
                send(IP(dst=server_ip_out)/TCP(flags=18,sport=pkt_sport,dport=pkt_dport,seq=pkt_seq))

def sniff_packet():
    '''
        抓取本机发送的数据包
    '''
    # sniff(filter,iface,prn,count)
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
                fix_tcp(pktx)
            #proto为1 表示icmp
            if proto==1:
                fix_icmp(pktx)
    sniff(iface="ens38",prn=classify)


def main():
    '''
        主函数
    '''
    sniff_packet()

main()
