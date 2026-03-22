//#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>

#ifdef WIN32
	#include <Packet32.h>
    #include <winsock.h>
#elif _POSIX_C_SOURCE >= 199309L
	#include <time.h>   // for nanosleep
#else
	#include <unistd.h> // for usleep
    #include <sys/socket.h>
    #include <netinet/in.h>
	//gcc pktsender.c -o pktsender -lpcap
#endif

#define USAGE_STRING "pktsender by pcap & chenqiang 00483624\nUsage: pktsender [adapter-name] [speed] [packet-hex-data]\nParameter:\n  [adapter-name] from Adapters of this PC below;\n  [speed] must between 0 to 1000 pps, send 1 packet when 0;\n  [packet-hex-data]'s length can not be odd;\n"
#define MAC_LEN 6
void ifprint(pcap_if_t *d);
char *iptos(u_long in);
char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);
void print_devs(void);
char* hex2char(u_char *buff, u_long buff_len);
int error_process(char* error, u_char *buff, pcap_t *fp);
void print_mac_by_adapter_name(char* adapter_name);
char g_errbuf[PCAP_ERRBUF_SIZE];

void sleep_ms(int milliseconds){ // cross-platform sleep function
#ifdef WIN32
    Sleep(milliseconds);
#elif _POSIX_C_SOURCE >= 199309L
    struct timespec ts;
    ts.tv_sec = milliseconds / 1000;
    ts.tv_nsec = (milliseconds % 1000) * 1000000;
    nanosleep(&ts, NULL);
#else
    if (milliseconds >= 1000)
      sleep(milliseconds / 1000);
    usleep((milliseconds % 1000) * 1000);
#endif
}


int main(int argc, char **argv)
{
    pcap_t *fp   = NULL;
    u_char *buff = NULL;
    int i, speed, buff_len, success=0, total=0;

    if (argc != 4)
        return error_process("The count of program parameter is wrong!", buff, fp);

    speed = atoi(argv[2]);
    if (speed<0 || speed>1000)
        return error_process("The speed is not between 0 to 1000 pps!", buff, fp);
    if (strlen(argv[3])%2 == 1)
        return error_process("The length of packet-hex-data is odd!", buff, fp);
    buff_len = strlen(argv[3])/2;
    buff = hex2char(argv[3], buff_len);
    if (buff == NULL)
        return error_process(NULL, buff, fp);

    if ((fp = pcap_open_live(argv[1],65536,1,1000,g_errbuf)) == NULL)
    {
        printf("Error: Unable to open adapter %s!\n", argv[1]);
        return error_process(NULL, buff, fp);
    }

    if (speed == 0)
    {
    	if (pcap_sendpacket(fp, buff, buff_len) == 0)
		{
			printf(".");
			success++;
		}
		else
		{
			printf("!");
		}
		total++;
    }
    else
	{
		printf("send speed: %d pps (send 1 packet then sleep %d ms).\n", speed, 1000/speed);
        while(1)
        {
	    	if (pcap_sendpacket(fp, buff, buff_len) == 0)
			{
				printf(".");
				success++;
			}
			else
			{
				printf("!");
			}
			total++;
			sleep_ms(1000/speed);
        }
    }
    free(buff);
    pcap_close(fp);
	printf("\n%d/%d packets sent!\n", success, total);
}

int error_process(char* error, u_char *buff, pcap_t *fp)
{
    if (buff != NULL) free(buff);
    if (fp != NULL) pcap_close(fp);
    if (error != NULL) printf("Error: %s\n",error);
    printf(USAGE_STRING);
    print_devs();
    return error;
}

char* hex2char(u_char *hex, u_long buff_len)
{
    u_long u;
    char *buff, *dst, *end;
    buff = malloc(buff_len);
    if (buff == NULL)
    {
        printf("Error: Allocate memory failed!\n");
        return NULL;
    }
    dst = buff;
    end = buff + buff_len;
    while ((dst <= end) && (sscanf(hex, "%2x", &u) == 1))
    {
        *dst++ = u;
        hex += 2;
    }
    if (dst < end)
    {
        free(buff);
        printf("Error: The packet-hex-data include invalid character!\n");
        return NULL;
    }
    return buff;
}

void print_devs()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;

    if(pcap_findalldevs(&alldevs, g_errbuf) == -1)
    {
        printf("Error: %s when pcap_findalldevs", g_errbuf);
        exit(1);
    }
    
    printf("Adapters of this PC:\n==============================================================\n");
    printf("Adapter-Name MAC-Address IPv4-Address IPv6-Address Description\n");
    printf("--------------------------------------------------------------\n");
    for(d=alldevs;d && !(d->flags & PCAP_IF_LOOPBACK);d=d->next)
    {    
        ifprint(d);
    }
    printf("==============================================================\n");

    pcap_freealldevs(alldevs);
}

void ifprint(pcap_if_t *d)
{
    pcap_addr_t *a;
    char ip6str[128];
    char mac[MAC_LEN];
    printf("%s ",d->name);
    print_mac_by_adapter_name(d->name);
    
    for(a=d->addresses;a;a=a->next) {
        if (a->addr && (a->addr->sa_family==AF_INET))
        {
            printf("%-15s ",iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
            break;
        }
    }
    for(a=d->addresses;a;a=a->next) {
        if (a->addr && (a->addr->sa_family==AF_INET6))
        {
            printf("%-28s ", ip6tos(a->addr, ip6str, sizeof(ip6str)));
            break;
        }
    }
    if (d->description)
        printf("%s",d->description);
    printf("\n");
}

void print_mac_by_adapter_name(char* adapter_name)
{
	
#ifdef WIN32
    LPADAPTER lpAdapter = 0;
    PPACKET_OID_DATA  OidData;
    
    lpAdapter = PacketOpenAdapter(adapter_name);
    if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE))
    {
        return;
    }

    OidData = malloc(MAC_LEN + sizeof(PACKET_OID_DATA));
    if (OidData == NULL) 
    {
        PacketCloseAdapter(lpAdapter);
        return;
    }
    OidData->Oid = 0x01010102;
    OidData->Length = MAC_LEN;
    ZeroMemory(OidData->Data, MAC_LEN);
    
    if(PacketRequest(lpAdapter, FALSE, OidData))
    {
        printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x ",
            (PCHAR)(OidData->Data)[0],
            (PCHAR)(OidData->Data)[1],
            (PCHAR)(OidData->Data)[2],
            (PCHAR)(OidData->Data)[3],
            (PCHAR)(OidData->Data)[4],
            (PCHAR)(OidData->Data)[5]);
    }

    free(OidData);
    PacketCloseAdapter(lpAdapter);
#else
#endif
    return;
}

/* From tcptraceroute, convert a numeric IP address to a string */
#define IPTOSBUFFERS    12
char *iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;
    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

#ifndef __MINGW32__ /* Cygnus doesn't have IPv6 */
char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
    socklen_t sockaddrlen;

    #ifdef WIN32
    sockaddrlen = sizeof(struct sockaddr_in6);
    #else
    sockaddrlen = sizeof(struct sockaddr_storage);
    #endif

    if(getnameinfo(sockaddr,sockaddrlen, address, addrlen, NULL, 0, NI_NUMERICHOST) != 0) 
        address = NULL;
    return address;
}
#endif /* __MINGW32__ */

