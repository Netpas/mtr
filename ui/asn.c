/*
    mtr  --  a network diagnostic tool
    Copyright (C) 1997,1998  Matt Kimball

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "config.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_ERROR_H
#include <error.h>
#else
#include "portability/error.h"
#endif
#include <errno.h>

#ifdef __APPLE__
#define BIND_8_COMPAT
#endif
#include <arpa/nameser.h>
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <string.h>
#include <sys/socket.h>
#include <search.h>
#include <ares.h>
#include <pthread.h>
#include <semaphore.h>
#include <fcntl.h>

#include "mtr.h"
#include "asn.h"
#include "utils.h"
#include "display.h"

/* #define IIDEBUG */
#ifdef IIDEBUG
#include <syslog.h>
#define DEB_syslog syslog
#else
#define DEB_syslog(...) do {} while (0)
#endif

#define IIHASH_HI   128
#define ITEMSMAX    15
#define ITEMSEP '|'
#define NAMELEN 127
#define UNKN    "???"
#define EMPTY   "--"
#define SEMPATH "sem"

typedef char *items_t[ITEMSMAX + 1];
struct comparm {
    struct mtr_ctl *ctl;
    char key[NAMELEN];
};

static int iihash = 0;
static pthread_t tid;
static ares_channel channel;
static char syncstr[20];
static items_t items_a;
static sem_t sem;
static volatile int sigstat = 0;
/* items width: ASN, Route, Country, Registry, Allocated, City, Carrier, Geo */
static const int iiwidth[] = {9, 18, 6, 7, 13, 8, 10, 15};   /* item len + space */
/* used for checking private ip */
static int prefix_arr[6] = {8, 17, 16, 12, 16, 16};
static unsigned int mask_ip_scope[6];
static unsigned int special_ip_scope[6];

#ifdef ENABLE_IPV6
char ipinfo_domain6[128] = "origin6.asn.cymru.com";
#endif
char ipinfo_domain[128] = "origin.asn.cymru.com";


static char *split_txtrec(
    struct mtr_ctl *ctl,
    char *txt_rec,
    items_t **p_items)
{
    char *prev;
    char *next;
    int i = 0;
    items_t *items = &items_a;

    if (!txt_rec)
        return NULL;
    if (iihash) {
        if (!(items = malloc(sizeof(*items)))) {
            free(txt_rec);
            return NULL;
        }
    }

    prev = txt_rec;

    while ((next = strchr(prev, ITEMSEP)) && (i < ITEMSMAX)) {
        *next = '\0';
        next++;
        (*items)[i] = trim(prev, ITEMSEP);
        prev = next;
        i++;
    }
    (*items)[i] = trim(prev, ITEMSEP);

    if (i < ITEMSMAX)
        i++;
    for (; i <= ITEMSMAX; i++)
        (*items)[i] = NULL;

    *p_items = items;

    return (*items)[ctl->ipinfo_no] ? (*items)[ctl->ipinfo_no] : UNKN;
}

static void query_callback (
    void* arg,
    int status,
    int timeouts,
    unsigned char *abuf,
    int aslen)
{
    struct ares_txt_reply *txt_out = NULL;
    struct comparm *parm = (struct comparm *)arg;
    items_t *items_tmp = NULL;
    char *retstr = NULL;
    char *unknown_txt = NULL;
    ENTRY item;
    ENTRY *found_item;

    if (ARES_SUCCESS != ares_parse_txt_reply(abuf, aslen, &txt_out)) {
        ares_free_data(txt_out);
        unknown_txt = (char *)malloc(strlen(UNKN) + 1);
        if (unknown_txt == NULL) {
            return;
        }
        strcpy(unknown_txt, UNKN);
        retstr = split_txtrec(parm->ctl, unknown_txt, &items_tmp);
    } else {
        retstr = split_txtrec(parm->ctl, txt_out->txt, &items_tmp);
    }
    if (retstr != NULL)
        strncpy(syncstr, retstr, sizeof(syncstr)-1);

    if (retstr && iihash) {
        item.key = parm->key;
        if ((found_item = hsearch(item, FIND))) {
        	if (found_item->data == NULL) {
        		found_item->data = (void *) items_tmp;
        	}
        }
    } else if (iihash) {
        free(items_tmp);
    }

    /*  cannot free, hash use it!
    if (txt_out) {
        ares_free_data(txt_out);
    }*/

    free(parm);
}

void *wait_loop(
    void *arg)
{
    int nfds;
    fd_set readers, writers;
    ares_channel channel = (ares_channel)arg;

    while (1) {
        if (sigstat == 1)
            break;

        FD_ZERO(&readers);
        FD_ZERO(&writers);
        nfds = ares_fds(channel, &readers, &writers);
        if (nfds == 0) {
            if (!iihash) {
                break;
            } else {
                sem_wait(&sem);
                continue;
            }
        }
        if (select(nfds, &readers, &writers, NULL, NULL) > 0) {
            ares_process(channel, &readers, &writers);
        }
     }

     return NULL;
}

static void ipinfo_lookup(
    struct mtr_ctl *ctl,
    const char *domain,
    struct comparm *parm)
{
    if (!iihash) {
        if(ares_init(&channel) != ARES_SUCCESS) {
            error(0, 0, "ares_init failed");
            free(parm);
            return;
        }
        memset(syncstr, 0, sizeof(syncstr));
    }

    ares_query(channel, domain, C_IN, T_TXT, query_callback, parm);
    if (iihash) {
        sem_post(&sem);
    }

    if (!iihash) {
        wait_loop(channel);
    }
}

#ifdef ENABLE_IPV6
/* from dns.c:addr2ip6arpa() */
static void reverse_host6(
    struct in6_addr *addr,
    char *buff,
    int buff_length)
{
    int i;
    char *b = buff;
    for (i = (sizeof(*addr) / 2 - 1); i >= 0; i--, b += 4)      /* 64b portion */
        snprintf(b, buff_length,
                 "%x.%x.", addr->s6_addr[i] & 0xf, addr->s6_addr[i] >> 4);

    buff[strlen(buff) - 1] = '\0';
}
#endif

static void init_private_ip(void)
{
    int i;

    special_ip_scope[0] = 167772160L;	// 10.0.0.0/8
	special_ip_scope[1] = 174063616L;	// 10.96.0.0/17
	special_ip_scope[2] = 176095232L;	// 10.127.0.0/16
	special_ip_scope[3] = 2886729728L;	// 172.16.0.0/12
	special_ip_scope[4] = 3232235520L;	// 192.168.0.0/16
	special_ip_scope[5] = 1681915904L;	// 100.64.0.0/16
	for (i = 0; i < 6; i++) {
		mask_ip_scope[i] = 0xffffffff;
		mask_ip_scope[i] <<= (32 - prefix_arr[i]);
		mask_ip_scope[i] &= 0xffffffff;
	}
}

static int is_private_ip(ip_t *addr)
{
	int i;
	unsigned int ipaddr;

    if (!iihash) {
        init_private_ip();
    }

    ipaddr = htonl((*(struct in_addr *)addr).s_addr);
	for (i = 3; i < 6; i++) {
		if ((ipaddr & mask_ip_scope[i]) == special_ip_scope[i])
			return 1;
	}
	if ((ipaddr & mask_ip_scope[0]) == special_ip_scope[0]) {
		if (!((ipaddr & mask_ip_scope[1]) == special_ip_scope[1]) &&
		    !((ipaddr & mask_ip_scope[2]) == special_ip_scope[2]))
		    return 1;
	}

	return 0;
}

static char *get_ipinfo(
    struct mtr_ctl *ctl,
    ip_t * addr,
    int hops)
{
    char key[NAMELEN];
    char lookup_key[NAMELEN];
    char *val = NULL;
    struct comparm *parm;
    ENTRY item;

    if (!addr)
        return NULL;

    if ((ctl->af == AF_INET) && is_private_ip(addr)) {
        return NULL;
    }

    if (ctl->af == AF_INET6) {
#ifdef ENABLE_IPV6
        reverse_host6(addr, key, NAMELEN);
        if (snprintf(lookup_key, NAMELEN, "%s.%s", key, ipinfo_domain6)
            >= NAMELEN)
            return NULL;
#else
        return NULL;
#endif
    } else {
        unsigned char buff[4];
        memcpy(buff, addr, 4);
        if (snprintf
            (key, NAMELEN, "%d.%d.%d.%d", buff[3], buff[2], buff[1],
             buff[0]) >= NAMELEN)
            return NULL;
        if (snprintf(lookup_key, NAMELEN, "%d.mtr.%s.%s", hops, key, ipinfo_domain)
            >= NAMELEN)
            return NULL;
    }

    if (iihash) {
        ENTRY *found_item;

        DEB_syslog(LOG_INFO, ">> Search: %s", key);
        item.key = key;
        if ((found_item = hsearch(item, FIND))) {
            if (found_item->data == NULL) {
                return NULL;
            }

            if (!(val = (*((items_t *) found_item->data))[ctl->ipinfo_no])) {
                val = UNKN;
            }
            DEB_syslog(LOG_INFO, "Found (hashed): %s", val);
        }
    }

    if (!val) {
        parm = (struct comparm *)malloc(sizeof(struct comparm));
        if (parm == NULL) {
            return NULL;
        }
        parm->ctl = ctl;
        strncpy(parm->key, key, sizeof(parm->key)-1);

        if (iihash) {
            if ((item.key = xstrdup(key))) {
                item.data = NULL;
                hsearch(item, ENTER);
            } else {
                return NULL;
            }
        }

        ipinfo_lookup(ctl, lookup_key, parm);
        if (!iihash) {
            return syncstr;
        }
    }

    return val;
}

ATTRIBUTE_CONST size_t get_iiwidth_len(
    void)
{
    return (sizeof(iiwidth) / sizeof((iiwidth)[0]));
}

ATTRIBUTE_CONST int get_iiwidth(
    int ipinfo_no)
{
    static const int len = (sizeof(iiwidth) / sizeof((iiwidth)[0]));

    if (ipinfo_no < len)
        return iiwidth[ipinfo_no];
    return iiwidth[ipinfo_no % len];
}

int get_allinuse_iiwidth(
    struct mtr_ctl *ctl)
{
    int i;
    int width = 0;

    for (i = 0; i < IPINFO_NUMS; i++) {
        if (IS_INDEX_IPINFO(ctl->ipinfo_arr, i)) {
            width += get_iiwidth(i);
            if (i == ASN) {
                width += 2; /* align header: AS */
            }
        }
    }

    return width;
}

char *fmt_ipinfo(
    struct mtr_ctl *ctl,
    ip_t * addr,
    int hops)
{
    char fmt[8];
    static char fmtinfo[32];
    char *ipinfo = NULL;

    ipinfo = get_ipinfo(ctl, addr, hops);
    snprintf(fmt, sizeof(fmt), "%s%%-%ds", ctl->ipinfo_no ? "" : "AS",
             get_iiwidth(ctl->ipinfo_no));

    if (ipinfo && (strlen(ipinfo) == 0)) {
        snprintf(fmtinfo, sizeof(fmtinfo), fmt, EMPTY);
    } else {
        snprintf(fmtinfo, sizeof(fmtinfo), fmt, ipinfo ? ipinfo : UNKN);
    }

    return fmtinfo;
}

int is_printii(
    struct mtr_ctl *ctl)
{
    return ((ctl->ipinfo_no >= 0) &&
            (ctl->ipinfo_no < ctl->ipinfo_max));
}

/*
 * Get the ipinfo individual field information.
 */
char *ipinfo_get_content(
    struct mtr_ctl *ctl,
    ip_t * addr,
    int ipinfo_index,
    int hops)
{
    char *content;

    ctl->ipinfo_no = ipinfo_index;
    content = fmt_ipinfo(ctl, addr, hops);

    if (strlen(content) == 0)
        content = EMPTY;

    return content;
}

/*
 * Gets all Ipinfo information based on the specified format in data_fields[]
 */
int get_ipinfo_compose(
    struct mtr_ctl *ctl, // [in] param
    ip_t *addr,          // [in] param
    char *buf,           // [in|output] param
    int buflen,          // [in] param
    int hops)
{
	int i, j, hd_len;
	unsigned char key;

    memset(buf, 0, buflen);
	for (i = 0, hd_len = 0; i < MAXFLD; i++) {
		j = ctl->fld_index[ctl->fld_active[i]];
		key = data_fields[j].key;

		if (!is_ipinfo_filed(key))
		    break;
		snprintf(buf + hd_len, buflen - hd_len,
		        data_fields[j].format,
		        data_fields[j].ipinfo_xxx(ctl, addr, ipinfo_key2no(key), hops));

		hd_len += (data_fields[j].length);
	}
	buf[hd_len] = 0;

    return i;
}

void asn_open(
    struct mtr_ctl *ctl)
{
    DEB_syslog(LOG_INFO, "hcreate(%d)", IIHASH_HI);
    if (!(iihash = hcreate(IIHASH_HI)))
        error(0, errno, "ipinfo hash");

    init_private_ip();

    if(ares_init(&channel) != ARES_SUCCESS) {
        error(0, 0, "ares_init failed");
        return;
    }

    if (sem_open(SEMPATH, O_CREAT|O_RDWR, 0666, 0) == SEM_FAILED) {
        error(0, 0, "sem_open failed");
        return;
    }

    if (pthread_create(&tid, NULL, wait_loop, channel)) {
        error(0, 0, "pthread_create failed");
        tid = pthread_self();
    }
    pthread_detach(tid);
}

void asn_close(
    struct mtr_ctl *ctl)
{
    if (iihash) {
        DEB_syslog(LOG_INFO, "hdestroy()");
        hdestroy();
        iihash = 0;
    }

    ares_destroy(channel);
    if (pthread_equal(tid, pthread_self()) == 0) {
        sigstat = 1;
        sem_post(&sem);
    }
    sem_close(&sem);
    sem_unlink(SEMPATH);
}
