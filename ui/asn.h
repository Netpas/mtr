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

#include "mtr.h"

// for ipinfo_arr: every bit represents an information field
// (0  |     1     |       2      |     3    |        4        |   5  |    6    |  7)
// ASN | IP-Prefix | Country-Code | Register | Allocation-Date | City | Carrier | Geo
enum IPINFO_INDEX {ASN, IP_PREFIX, COUNTRY_CODE, REG, ALLOC_DATE, CITY, CARRIER, GEO};
#define IS_INDEX_IPINFO(ipinfo_arr, index)  (ipinfo_arr & (1 << index))
#define IS_CLEAR_IPINFO(ipinfo_arr)         !(ipinfo_arr & ~0)
#define IPINFO_NUMS                         (8)

#ifdef ENABLE_IPV6
extern char ipinfo_domain6[128];
#endif
extern char ipinfo_domain[128];

extern void asn_open(
    struct mtr_ctl *ctl);
extern void asn_close(
    struct mtr_ctl *ctl);
extern ATTRIBUTE_CONST size_t get_iiwidth_len(
    void);
extern ATTRIBUTE_CONST int get_iiwidth(
    int ipinfo_no);
extern int get_allinuse_iiwidth(
        struct mtr_ctl *ctl);
/*extern int is_printii(
    struct mtr_ctl *ctl);*/
extern char *ipinfo_get_content(
    struct mtr_ctl *ctl,
    ip_t * addr,
    int ipinfo_index,
    int hops);
extern int get_ipinfo_compose(
    struct mtr_ctl *ctl,
    ip_t *addr,
    char *buf,
    int buflen,
    int hops);
extern void process_ip_prefix(
    char *ipprefix);
extern int ipinfo_waitfd(fd_set *readfd);
extern void ipinfo_ack(fd_set *readfd);
