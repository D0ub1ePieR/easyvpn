from scapy.all import *
import wx,multiprocessing
import sys,hashlib

pkt_data=[]
ip_table=["192.168.108.137","192.168.108.1"]
server_ip_out="192.168.160.129"
#server_ip_in="192.168.108.128"
user_name="double_pier"
user_passwd="123456"
login_flag=0
key="B1ueBa11"

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
        #TCP flags FIN-1 SYN-2 RST-4 PSH-8 ACK-16
        # 使用浏览器 端口+50 向服务器发送
        if dst_ip in ip_table:
            if pkt_flags==2:
                send(IP(dst=server_ip_out)/TCP(flags=2,sport=pkt_sport+50,dport=pkt_dport,seq=pkt_seq,ack=pkt_ack)/Raw(dst_ip))
            # 提供服务器转发的syn包会使服务器回复一个rst
            if pkt_flags==4:
                print("[log] recieve a server RST")
            if pkt_flags==16:
                print("[send ack]")
                send(IP(dst=server_ip_out)/TCP(flags=16,sport=pkt_sport+50,dport=pkt_dport,seq=pkt_seq,ack=pkt_ack)/Raw(dst_ip))
            # 理论上不会进这个分支
            if pkt_flags==18:
                send(IP(dst=server_ip_out)/TCP(flags=18,sport=pkt_sport,dport=pkt_dport,seq=pkt_seq))
            # PSH ACK
            if pkt_flags==24:
                pkt_load=pktx[TCP].payload.load
                send_load=pkt_load+Raw(dst_ip).load+Raw(two_length_str(dst_ip)).load
                send(IP(dst=server_ip_out)/TCP(flags=24,sport=pkt_sport+50,dport=pkt_dport,seq=pkt_seq,ack=pkt_ack)/Raw(send_load))

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
            # 包括HTTP
            if proto==6:
                fix_tcp(pktx)
            #proto为1 表示icmp
            if proto==1:
                fix_icmp(pktx)
    sniff(iface="ens38",prn=classify)

def login(evt):
    '''
        登陆模块
    '''
    def check_login(pktx):
        text_content.write(name.GetValue()," login ",pktx.payload.load," \n")
        if pktx.payload.load==Raw("success"):
            global login_flag
            login_flag=1
    global user_name
    global user_passwd
    user_name=name.GetValue()
    user_passwd=passwd.GetValue()
    text_content.write(name.GetValue(),"try to login\n")

    encode=hashlib.sha256()
    encode.update(passwd.encode("utf-8"))
    mid=encode.hexdigest()
    encode.update((mid+key).encode('utf-8'))
    final=encode.hexdigest()
    
    send(IP(dst=server_ip_out)/UDP()/Raw("usr,",user_name,",pwd,",final))
    sniff(filter="icmp",count=1)
    sniff(filter="udp",count=1,prn=check_login)
    if login_flag==1:
        p=multiprocessing.Process(target=sniff_packet)
        p.start()

def save(evt):
    print("save")

def main():
    '''
        主函数
    '''
    global user_name
    global user_passwd
    # 命令行获取初始用户名和密码
    try:
        if sys.argv[1]!="-d":
            user_name=sys.argv[1]
    except:
        user_name=""
        user_passwd=""
    else:
        try:
            if sys.argv[-1]!="-d":
                user_passwd=sys.argv[2]
        except:
            user_passwd=""
    finally:
        app=wx.App()
        # 确认标题和窗口大小
        frame=wx.Frame(None,title="EasyVpn",size=(800,800))
        panel=wx.Panel(frame)
        # 用户名密码输入框
        text1=wx.StaticText(panel,label="username:",pos=(10,10),size=(100,30))
        global name
        name = wx.TextCtrl(panel,-1,user_name,pos=(110,10),size=(200,20))
        text2=wx.StaticText(panel,label="passwd:",pos=(10,40),size=(100,30))
        global passwd
        passwd = wx.TextCtrl(panel,-1,user_passwd,pos=(110,40),size=(200,20),style=wx.TE_PASSWORD)
        # 登录按钮
        bt_login=wx.Button(panel,label='Login',pos=(350,20),size=(60,30))
        bt_login.Bind(wx.EVT_BUTTON,login)
        # 日志记录文本框
        global text_content
        text_content= wx.TextCtrl(panel,pos=(10,100),size=(700,600),style=wx.TE_MULTILINE|wx.HSCROLL)
        # 导出日志按钮
        bt_save=wx.Button(panel,label='Save',pos=(10,720),size=(60,30))
        bt_save.Bind(wx.EVT_BUTTON,save)

        frame.Show()
        app.MainLoop()

main()
