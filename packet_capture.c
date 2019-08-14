#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <linux/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdbool.h>
#include <ctype.h>
#include <pcre.h>

#define MAX_LEN     65536

#if 0
struct tcphdr {
    __be16  source;
    __be16  dest;
    __be32  seq;
    __be32  ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u16   res1:4,
        doff:4,
        fin:1,
        syn:1,
        rst:1,
        psh:1,
        ack:1,
        urg:1,
        ece:1,
        cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u16   doff:4,
        res1:4,
        cwr:1,
        ece:1,
        urg:1,
        ack:1,
        psh:1,
        rst:1,
        syn:1,
        fin:1;
#else
#error  "Adjust your <asm/byteorder.h> defines"
#endif
    __be16  window;
    __sum16 check;
    __be16  urg_ptr;
};

struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8    ihl:4,
        version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8    version:4,
        ihl:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
    __u8    tos;
    __be16  tot_len;
    __be16  id;
    __be16  frag_off;
    __u8    ttl;
    __u8    protocol;
    __sum16 check;
    __be32  saddr;
    __be32  daddr;
    /*The options start here. */
};

struct udphdr {
    __be16  source;
    __be16  dest;
    __be16  len;
    __sum16 check;
};

struct udphdr {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	short	uh_ulen;		/* udp length */
	u_short	uh_sum;			/* udp checksum */
};

#endif


void process_packet(pcre *re, unsigned char *buf, size_t plen);

static void inline
print_substring_match(char *str, int *ovector, int rc)
{
    int     i;

    /* As before, show substrings stored in the output vector by number,
    and then also any named substrings. */
    for (i = 0; i < rc; i++) {
        char *substring_start = str + ovector[2*i];
        int substring_length = ovector[2*i+1] - ovector[2*i];

        printf("%2d: %.*s\n", i, substring_length, substring_start);
    }
}

pcre *regex_compile_pattern(char *regex)
{
    const char  *error;
    int         erroffset;
    pcre        *re;

    re = pcre_compile (regex,   /* the pattern */
            PCRE_MULTILINE,
            &error,             /* for error message */
            &erroffset,         /* for error offset */
            0);                 /* use default character tables */
    if (NULL == re) {
        printf("pcre_compile failed (offset: %d), %s\n", erroffset, error);
        return NULL;
    }

    return re;
}

bool pcre_scan_exec_stream(pcre *re, char *str, size_t len)
{
#define OVECCOUNT   30

    int             rc, found = 0; (void) found;
    int             __ovector[OVECCOUNT], *ovector = __ovector;
    unsigned int    offset = 0;

    while (offset < len &&
        (rc = pcre_exec(re, NULL, str, len, offset, 0,
            ovector, sizeof(ovector))) >= 0) {
        printf("Match succeeded at "
            "offset:      %d\n",
            ovector[0]);
        print_substring_match(str, ovector, rc);
        offset = ovector[1];
        found++;

    }

    if(0 == found) {
        return false;
    }

    printf("total match found : %d\n", found);
    return true;
}


void print_ethr_hdr(struct ethhdr *eth, size_t len)
{
    printf("Ethernet Header:    %ld\n", len);
    printf("   |-Source Address      : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
            eth->h_source[0], eth->h_source[1], eth->h_source[2],
            eth->h_source[3], eth->h_source[4], eth->h_source[5] );
    printf("   |-Destination Address : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
            eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
            eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    printf("   |-Protocol            : %u\n",
            (unsigned short)eth->h_proto);
}

void print_ip_hdr(struct iphdr *iph, size_t len)
{
    struct sockaddr_in  src, dst;

    memset(&src, 0, sizeof(src));
    src.sin_addr.s_addr = iph->saddr;

    memset(&dst, 0, sizeof(dst));
    dst.sin_addr.s_addr = iph->daddr;

    printf("\n");
    printf("IP Header:  %ld\n", len);
    printf("   |-IP Version        : %d\n",
           (unsigned int)iph->version);
    printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n",
           (unsigned int)iph->ihl, ((unsigned int)(iph->ihl))*4);
    printf("   |-Type Of Service   : %d\n",
           (unsigned int)iph->tos);
    printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n",
           ntohs(iph->tot_len));
    printf("   |-Identification    : %d\n",
           ntohs(iph->id));
    printf("   |-TTL      : %d\n",
           (unsigned int)iph->ttl);
    printf("   |-Protocol : %d\n",
           (unsigned int)iph->protocol);
    printf("   |-Checksum : %d\n",
           ntohs(iph->check));
    printf("   |-Source IP        : %s\n",
           inet_ntoa(src.sin_addr));
    printf("   |-Destination IP   : %s\n",
            inet_ntoa(dst.sin_addr));
}

void print_tcp_hdr(struct tcphdr *tcp, size_t len)
{
    printf("\n");
    printf("TCP Header:     %ld\n", len);
    printf("   |-Source Port        : %d\n",
           (unsigned int) ntohs(tcp->source));
    printf("   |-Destination Port   : %d\n",
           (unsigned int) ntohs(tcp->dest));
    printf("   |-Sequence Number    : %d\n",
           (unsigned int) ntohs(tcp->seq));
    printf("   |-Acknowledge Number : %d\n",
           (unsigned int) ntohs(tcp->ack_seq));
#if 0
    printf("   |----------flags--------\n");
    printf("         |-Urgent Flags             : %d\n");
    printf("         |-Acknowledgement Flags    : %d\n");
    printf("         |-Push Flags               : %d\n");
    printf("         |-Reset Flags              : %d\n");
    printf("         |-Synchronise Flags        : %d\n");
    printf("         |-Finish Flags             : %d\n");
#endif
    printf("   |-Window Size        : %d\n",
           (unsigned int) ntohs(tcp->window));
    printf("   |-Checksum : %d\n",
           (unsigned int) ntohs(tcp->check));
    printf("   |-Urgent Pointer     : %d\n",
           (unsigned int) ntohs(tcp->urg_ptr));

}

void print_udp_hdr(struct udphdr *udph, size_t len)
{
    printf("\n");
    printf("UDP Header: %ld\n", len);
    printf("   |-Source Port        : %d\n",
           ntohs(udph->uh_sport));
    printf("   |-Destination Port   : %d\n",
           ntohs(udph->uh_dport));
    printf("   |-Length             : %d\n",
           ntohs(udph->uh_ulen));
    printf("   |-Checksum           : %d\n",
           ntohs(udph->uh_sum));

}

int main()
{
    int             fd, i;
    size_t          slen, dlen;
    struct sockaddr saddr;
    unsigned char   *buf = (unsigned char *)malloc(MAX_LEN);
    pcre            *re = NULL;
    char            *regex = "http";

    slen = sizeof(saddr);

    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) ;
    if(fd < 0) {
        perror("Socket Error");
        return -1;
    }

    if((re = regex_compile_pattern(regex)) == NULL) {
        printf("regex compile failed\n");
        return -1;
    }

    while(1) {
        dlen = recvfrom(fd, buf, MAX_LEN, 0, &saddr, (socklen_t *)&slen);
        if(dlen < 0) {
            printf("Recvfrom error , failed to get packets\n");
            goto bailout;
        }

        process_packet(re, buf, dlen);
    }

bailout:
    if(fd)
        close(fd);
    return 0;
}

#if 0
/* 16 byte print of the data */
static void inline hex_dump(unsigned char *data, size_t len)
{
    int     i;

    for(i=0; i<len; i++) {
        if(i!=0 && i%16 == 0) printf("\n");
        printf("%.2x ", data[i]);
    }
    printf("   ");

	/* ascii (if printable) */
    const u_char *ch;
	ch = data;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

    printf("\n");
}
#endif

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
static void inline
print_hex_ascii_line(const u_char *payload, int len, int offset)
{
    int             i;
    int             gap;
    const u_char    *ch;

    /* offset */
    printf("%05d   ", offset);

    /* hex */
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf("   ");

    /* ascii (if printable) */
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }

    printf("\n");

    return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
static void inline
print_payload(const u_char *payload, int len)
{
    int     len_rem = len;
    int     line_width = 16;			/* number of bytes per line */
    int     line_len;
    int     offset = 0;					/* zero-based offset counter */
    const u_char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for ( ;; ) {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }

    return;
}

bool process_payload(pcre *re, char *data, size_t len)
{
    if(pcre_scan_exec_stream(re, data, len)) {
        printf("found http\n");
        return true;
    }
    return false;
}

void process_packet(pcre *re, unsigned char *buf, size_t plen)
{
    int             i;
    struct udphdr   *udp;
    struct tcphdr   *tcp;
    struct iphdr    *iph;
    struct ethhdr   *eth;
    size_t          tl_data_len, iphdrlen, rdata_len;
    unsigned char   *tl_data, *user_data;
    bool            is_tcp = false, is_udp = false;

    eth = (struct ethhdr *) buf;
    iph = (struct iphdr *) (buf  + sizeof(struct ethhdr));
    tl_data = (buf + sizeof(struct ethhdr) + sizeof(struct iphdr));


    iphdrlen = iph->ihl * 4;
    tl_data_len = plen - (iphdrlen + sizeof(struct ethhdr));

    //Extracting IP Header
    switch (iph->protocol) {
        case IPPROTO_ICMP:  //1
            //TODO
            break;

        case IPPROTO_IGMP:  //2
            //TODO
            break;

        case IPPROTO_TCP:   //6
            is_tcp = true;
            break;

        case IPPROTO_UDP:   //17
            is_udp = true;
            break;

        case IPPROTO_GRE:   //47
            //TODO
            break;

        case IPPROTO_ESP:   //50
            //TODO
            break;

        case IPPROTO_MPLS:  //137
            //TODO
            break;

        default:            //other protocols can be found in
            //include/uapi/linux/in.h
            break;
    }

    if(is_tcp || is_udp) {


        if(is_tcp) {
            tcp = (struct tcphdr *) tl_data;
            //print_tcp_hdr(tcp, sizeof(struct tcphdr));

            user_data = tl_data + sizeof(struct tcphdr);
            rdata_len = plen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct tcphdr));
        }

        if(is_udp) {
            udp = (struct udphdr *) tl_data;
            //print_udp_hdr(udp, sizeof(struct udphdr));

            user_data = tl_data + sizeof(struct udphdr);
            rdata_len = plen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
        }


        if(process_payload(re, user_data, tl_data_len)) {
            print_ethr_hdr(eth, sizeof(struct ethhdr));
            print_ip_hdr(iph, sizeof(struct iphdr));
            printf("\n%s :\t %ld\n", "DATA", rdata_len);
            //hex_dump(user_data, tl_data_len);
            print_payload(user_data, tl_data_len);
            printf("\n###################################################\n");
        }
    }
}

