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

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#ifdef HAVE_ERROR_H
#include <error.h>
#else
#include "portability/error.h"
#endif
#ifdef HAVE_VALUES_H
#include <values.h>
#endif
#ifdef HAVE_SYS_LIMITS_H
#include <sys/limits.h>
#endif

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <ctype.h>
#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "mtr.h"
#include "mtr-curses.h"
#include "display.h"
#include "dns.h"
#include "report.h"
#include "net.h"
#include "asn.h"
#include "utils.h"

#ifdef HAVE_GETOPT
#include <getopt.h>
#else
#include "portability/getopt.h"
#endif

#ifdef ENABLE_IPV6
#define DEFAULT_AF AF_UNSPEC
#else
#define DEFAULT_AF AF_INET
#endif


char *myname;

const struct fields data_fields[MAXFLD] = {
    /* key, Remark, Header, Format, Width, CallBackFunc */
    {' ', "<sp>: Space between fields", " ", " ", 1, &net_drop, NULL},
    {'L', "L: Loss Ratio", "Loss%", " %4.1f%%", 6, &net_loss, NULL},
    {'D', "D: Dropped Packets", "Drop", " %4d", 5, &net_drop, NULL},
    {'R', "R: Received Packets", "Rcv", " %5d", 6, &net_returned, NULL},
    {'S', "S: Sent Packets", "Snt", " %5d", 6, &net_xmit, NULL},
    {'N', "N: Newest RTT(ms)", "Last", " %5.1f", 6, &net_last, NULL},
    {'B', "B: Min/Best RTT(ms)", "Best", " %5.1f", 6, &net_best, NULL},
    {'A', "A: Average RTT(ms)", "Avg", " %5.1f", 6, &net_avg, NULL},
    {'W', "W: Max/Worst RTT(ms)", "Wrst", " %5.1f", 6, &net_worst, NULL},
    {'V', "V: Standard Deviation", "StDev", " %5.1f", 6, &net_stdev, NULL},
    {'G', "G: Geometric Mean", "Gmean", " %5.1f", 6, &net_gmean, NULL},
    {'J', "J: Current Jitter", "Jttr", " %4.1f", 5, &net_jitter, NULL},
    {'M', "M: Jitter Mean/Avg.", "Javg", " %4.1f", 5, &net_javg, NULL},
    {'X', "X: Worst Jitter", "Jmax", " %4.1f", 5, &net_jworst, NULL},
    {'I', "I: Interarrival Jitter", "Jint", " %4.1f", 5, &net_jinta, NULL},
    {'Z', "Z: ASN Number", "ASN", "%-9s", 9, NULL, &ipinfo_get_content},
    {'P', "P: IP Prefix", "IP-PRFX", "%-18s", 18, NULL, &ipinfo_get_content},
    {'C', "C: Country Code", "CTRY", "%-6s", 6, NULL, &ipinfo_get_content},
    {'E', "E: Registry", "REG", "%-7s", 7, NULL, &ipinfo_get_content},
    {'Y', "Y: Allocation Date", "DATE", "%-13s", 13, NULL, &ipinfo_get_content},
    {'T', "T: City", "CTY", "%-8s", 8, NULL, &ipinfo_get_content},
    {'K', "K: Carrier", "CRIR", "%-10s", 10, NULL, &ipinfo_get_content},
    {'O', "O: Geo", "GEO", "%-25s", 25, NULL, &ipinfo_get_content},
    {'\0', NULL, NULL, NULL, 0, NULL, NULL}
};

typedef struct names {
    char *name;
    struct names *next;
} names_t;

unsigned char ipinfo_no2key(int no)
{
    unsigned char key = 0;

    switch (no) {
        case ASN:           key = 'Z'; break;
        case IP_PREFIX:     key = 'P'; break;
        case COUNTRY_CODE:  key = 'C'; break;
        case REG:           key = 'E'; break;
        case ALLOC_DATE:    key = 'Y'; break;
        case CITY:          key = 'T'; break;
        case CARRIER:       key = 'K'; break;
        case GEO:           key = 'O'; break;
    }

    return key;
}

int is_ipinfo_filed(unsigned char key)
{
    if ((key == 'Z') || (key == 'P') || (key == 'C') || (key == 'E') ||
        (key == 'Y') || (key == 'T') || (key == 'K') || (key == 'O')) {
        return 1;
    }
    return 0;
}

int ipinfo_key2no(unsigned char key)
{
    int val = -1;

    switch (key) {
        case 'Z': val = ASN; break;
        case 'P': val = IP_PREFIX; break;
        case 'C': val = COUNTRY_CODE; break;
        case 'E': val = REG; break;
        case 'Y': val = ALLOC_DATE; break;
        case 'T': val = CITY; break;
        case 'K': val = CARRIER; break;
        case 'O': val = GEO; break;
        default:  break;
    }

    return val;
}

static void __attribute__ ((__noreturn__)) usage(FILE * out)
{
    fputs("\nUsage:\n", out);
    fputs(" mtr [options] hostname\n", out);
    fputs("\n", out);
    fputs(" -F, --filename FILE            read hostname(s) from a file\n",
          out);
    fputs(" -4                             use IPv4 only\n", out);
#ifdef ENABLE_IPV6
    fputs(" -6                             use IPv6 only\n", out);
#endif
    fputs(" -u, --udp                      use UDP instead of ICMP echo\n",
          out);
    fputs(" -T, --tcp                      use TCP instead of ICMP echo\n",
          out);
    fputs(" -I, --interface NAME           use named network interface\n",
         out);
    fputs
        (" -a, --address ADDRESS          bind the outgoing socket to ADDRESS\n",
         out);
    fputs(" -f, --first-ttl NUMBER         set what TTL to start\n", out);
    fputs(" -m, --max-ttl NUMBER           maximum number of hops\n", out);
    fputs(" -U, --max-unknown NUMBER       maximum unknown host\n", out);
    fputs
        (" -P, --port PORT                target port number for TCP, SCTP, or UDP\n",
         out);
    fputs(" -L, --localport LOCALPORT      source port number for UDP\n", out);
    fputs
        (" -s, --psize PACKETSIZE         set the packet size used for probing\n",
         out);
    fputs
        (" -B, --bitpattern NUMBER        set bit pattern to use in payload\n",
         out);
    fputs(" -i, --interval SECONDS         ICMP echo request interval\n", out);
    fputs
        (" -Q, --tos NUMBER               type of service field in IP header\n",
         out);
    fputs
        (" -e, --mpls                     display information from ICMP extensions\n",
         out);
    fputs
        (" -Z, --timeout SECONDS          seconds to wait for a probe response\n",
         out);
#ifdef SO_MARK
    fputs(" -M, --mark MARK                mark each sent packet\n", out);
#endif
    fputs(" -r, --report                   output using report mode\n", out);
    fputs(" -w, --report-wide              output wide report\n", out);
    fputs(" -c, --report-cycles COUNT      set the number of pings sent\n",
          out);
    fputs(" -j, --json                     output json\n", out);
    fputs(" -x, --xml                      output xml\n", out);
    fputs(" -C, --csv                      output comma separated values\n",
          out);
    fputs(" -l, --raw                      output raw format\n", out);
    fputs(" -p, --split                    split output\n", out);
#ifdef HAVE_CURSES
    fputs(" -t, --curses                   use curses terminal interface\n",
          out);
#endif
    fputs("     --displaymode MODE         select initial display mode\n",
          out);
#ifdef HAVE_GTK
    fputs(" -g, --gtk                      use GTK+ xwindow interface\n", out);
#endif
    fputs(" -n, --no-dns                   do not resolve host names\n", out);
    fputs(" -b, --show-ips                 show IP numbers and host names\n",
          out);
    fputs(" -o, --order FIELDS             select output fields\n", out);
#ifdef HAVE_IPINFO
    fputs(" -y, --ipinfo NUMBER,……         select IP information(NUMBER:0~7) in output\n", out);
    fputs("                                <NUMBER 0: AS number>\n", out);
    fputs("                                <NUMBER 1: IP prefix>\n", out);
    fputs("                                <NUMBER 2: country code>\n", out);
    fputs("                                <NUMBER 3: registry>\n", out);
    fputs("                                <NUMBER 4: allocation date>\n", out);
    fputs("                                <NUMBER 5: city>\n", out);
    fputs("                                <NUMBER 6: carrier>\n", out);
    fputs("                                <NUMBER 7: geo>\n", out);
    fputs("     --ipinfo-asn               display AS number, equal to -y 0\n", out);
    fputs("     --ipinfo-ip-prefix         display IP prefix, equal to -y 1\n", out);
    fputs("     --ipinfo-country           display country code, equal to -y 2\n", out);
    fputs("     --ipinfo-register          display registry, equal to -y 3\n", out);
    fputs("     --ipinfo-date              display allocation date, equal to -y 4\n", out);
    fputs("     --ipinfo-city              display city, equal to -y 5\n", out);
    fputs("     --ipinfo-carrier           display carrier, equal to -y 6\n", out);
    fputs("     --ipinfo-geo               display geo, equal to -y 7\n", out);
    fputs("     --ipinfo-dns DOMAIN_NAME   Specify DOMAIN_NAME to query DNS data\n", out);
    fputs("     --ipinfo-spec-ip IP/SUBNET-MASK[,IP/SUBNET-MASK,...]\n"
          "                                reserved for Netpas\n", out);
    fputs(" -z, --aslookup                 display AS number\n", out);
#endif
    fputs(" -h, --help                     display this help and exit\n", out);
    fputs
        (" -v, --version                  output version information and exit\n",
         out);
    fputs("\n", out);
    fputs("See the 'man 8 mtr' for details.\n", out);
    exit(out == stderr ? EXIT_FAILURE : EXIT_SUCCESS);
}


static void append_to_names(
    names_t ** names_head,
    const char *item)
{
    names_t **name_tail = names_head;

    while (*name_tail) {
        name_tail = &(*name_tail)->next;
    }

    names_t *name = calloc(1, sizeof(names_t));
    if (name == NULL) {
        error(EXIT_FAILURE, errno, "memory allocation failure");
    }
    name->name = xstrdup(item);
    name->next = NULL;

    *name_tail = name;
}

static void read_from_file(
    names_t ** names,
    const char *filename)
{

    FILE *in;
    char line[512];

    if (!filename || strcmp(filename, "-") == 0) {
        clearerr(stdin);
        in = stdin;
    } else {
        in = fopen(filename, "r");
        if (!in) {
            error(EXIT_FAILURE, errno, "open %s", filename);
        }
    }

    while (fgets(line, sizeof(line), in)) {
        char *name = trim(line, '\0');
        append_to_names(names, name);
    }

    if (ferror(in)) {
        error(EXIT_FAILURE, errno, "ferror %s", filename);
    }

    if (in != stdin)
        fclose(in);
}

/*
 * If the file stream is associated with a regular file, lock the file
 * in order coordinate writes to a common file from multiple mtr
 * instances. This is useful if, for example, multiple mtr instances
 * try to append results to a common file.
 */

static void lock(
    FILE * f)
{
    int fd;
    struct stat buf;
    static struct flock lock;

    assert(f);

    lock.l_type = F_WRLCK;
    lock.l_start = 0;
    lock.l_whence = SEEK_END;
    lock.l_len = 0;
    lock.l_pid = getpid();

    fd = fileno(f);
    if ((fstat(fd, &buf) == 0) && S_ISREG(buf.st_mode)) {
        if (fcntl(fd, F_SETLKW, &lock) == -1) {
            error(0, errno, "fcntl (ignored)");
        }
    }
}

/*
 * If the file stream is associated with a regular file, unlock the
 * file (which presumably has previously been locked).
 */

static void unlock(
    FILE * f)
{
    int fd;
    struct stat buf;
    static struct flock lock;

    assert(f);

    lock.l_type = F_UNLCK;
    lock.l_start = 0;
    lock.l_whence = SEEK_END;
    lock.l_len = 0;
    lock.l_pid = getpid();

    fd = fileno(f);
    if ((fstat(fd, &buf) == 0) && S_ISREG(buf.st_mode)) {
        if (fcntl(fd, F_SETLKW, &lock) == -1) {
            error(0, errno, "fcntl (ignored)");
        }
    }
}


static void init_fld_options(
    struct mtr_ctl *ctl)
{
    int i;

    memset(ctl->fld_index, -1, FLD_INDEX_SZ);

    for (i = 0; data_fields[i].key != 0; i++) {
        ctl->available_options[i] = data_fields[i].key;
        ctl->fld_index[data_fields[i].key] = i;
    }
    ctl->available_options[i] = 0;
}

static void process_ipinfo_arr(struct mtr_ctl *ctl, char *optarg)
{
	char *t;
	int index;

	if (optarg == NULL)
		return;

	t = strtok(optarg, ",");
	while (t != NULL) {
		index = strtonum_or_err(t, "invalid argument", STRTO_INT);
        if (index < 0 || index >= IPINFO_NUMS) {
            error(EXIT_FAILURE, 0, "value %d out of range (0 - %d)",
                    index, IPINFO_NUMS - 1);
        }

        ctl->ipinfo_arr |= (1 << index);
		t = strtok(NULL, ",");
	}
}

static void process_specific_ip_segment(char *optarg)
{
    char *t;

	if (optarg == NULL)
		return;

	t = strtok(optarg, ",");
	while (t != NULL) {
        process_ip_prefix(t);

		t = strtok(NULL, ",");
	}
}

static void parse_arg(
    struct mtr_ctl *ctl,
    names_t ** names,
    int argc,
    char **argv)
{
    int opt;
    int i, j;
    /* IMPORTANT: when adding or modifying an option:
       0/ try to find a somewhat logical order;
       1/ add the long option name in "long_options" below;
       2/ update the man page (use the same order);
       3/ update the help message (see usage() function).
     */
    enum {
        OPT_DISPLAYMODE = CHAR_MAX + 1,
        OPT_ASN,
        OPT_IP_PREFIX,
        OPT_COUNTRY,
        OPT_REGISTER,
        OPT_ALLOCATION_DATE,
        OPT_CITY,
        OPT_CARRIER,
        OPT_GEO,
        OPT_DNS,
        OPT_SPECIP
    };
    static const struct option long_options[] = {
        /* option name, has argument, NULL, short name */
        {"help", 0, NULL, 'h'},
        {"version", 0, NULL, 'v'},

        {"inet", 0, NULL, '4'}, /* IPv4 only */
#ifdef ENABLE_IPV6
        {"inet6", 0, NULL, '6'},        /* IPv6 only */
#endif
        {"filename", 1, NULL, 'F'},

        {"report", 0, NULL, 'r'},
        {"report-wide", 0, NULL, 'w'},
        {"xml", 0, NULL, 'x'},
#ifdef HAVE_CURSES
        {"curses", 0, NULL, 't'},
#endif
#ifdef HAVE_GTK
        {"gtk", 0, NULL, 'g'},
#endif
        {"raw", 0, NULL, 'l'},
        {"csv", 0, NULL, 'C'},
        {"json", 0, NULL, 'j'},
        {"displaymode", 1, NULL, OPT_DISPLAYMODE},
        {"split", 0, NULL, 'p'},        /* BL */
        /* maybe above should change to -d 'x' */

        {"no-dns", 0, NULL, 'n'},
        {"show-ips", 0, NULL, 'b'},
        {"order", 1, NULL, 'o'},        /* fields to display & their order */
#ifdef HAVE_IPINFO
        {"ipinfo", 1, NULL, 'y'},       /* IP info lookup */
        {"aslookup", 0, NULL, 'z'},     /* Do AS lookup (--ipinfo 0) */
        {"ipinfo-asn", 0, NULL, OPT_ASN},
        {"ipinfo-ip-prefix", 0, NULL, OPT_IP_PREFIX},
        {"ipinfo-country", 0, NULL, OPT_COUNTRY},
        {"ipinfo-register", 0, NULL, OPT_REGISTER},
        {"ipinfo-date", 0, NULL, OPT_ALLOCATION_DATE},
        {"ipinfo-city", 0, NULL, OPT_CITY},
        {"ipinfo-carrier", 0, NULL, OPT_CARRIER},
        {"ipinfo-geo", 0, NULL, OPT_GEO},
        {"ipinfo-dns", 1, NULL, OPT_DNS},
        {"ipinfo-spec-ip", 1, NULL, OPT_SPECIP},
#endif

        {"interval", 1, NULL, 'i'},
        {"report-cycles", 1, NULL, 'c'},
        {"psize", 1, NULL, 's'},        /* overload psize<0, ->rand(min,max) */
        {"bitpattern", 1, NULL, 'B'},   /* overload B>255, ->rand(0,255) */
        {"tos", 1, NULL, 'Q'},  /* typeof service (0,255) */
        {"mpls", 0, NULL, 'e'},
        {"interface", 1, NULL, 'I'},
        {"address", 1, NULL, 'a'},
        {"first-ttl", 1, NULL, 'f'},    /* -f & -m are borrowed from traceroute */
        {"max-ttl", 1, NULL, 'm'},
        {"max-unknown", 1, NULL, 'U'},
        {"udp", 0, NULL, 'u'},  /* UDP (default is ICMP) */
        {"tcp", 0, NULL, 'T'},  /* TCP (default is ICMP) */
#ifdef HAS_SCTP
        {"sctp", 0, NULL, 'S'}, /* SCTP (default is ICMP) */
#endif
        {"port", 1, NULL, 'P'}, /* target port number for TCP/SCTP/UDP */
        {"localport", 1, NULL, 'L'},    /* source port number for UDP */
        {"timeout", 1, NULL, 'Z'},      /* timeout for probe sockets */
#ifdef SO_MARK
        {"mark", 1, NULL, 'M'}, /* use SO_MARK */
#endif
        {NULL, 0, NULL, 0}
    };
    enum { num_options = sizeof(long_options) / sizeof(struct option) };
    char short_options[num_options * 2];
    char fld_tmp[2 * MAXFLD] = {0};
    size_t n, p;

    for (n = p = 0; n < num_options; n++) {
        if (CHAR_MAX < long_options[n].val) {
            continue;
        }
        short_options[p] = long_options[n].val;
        p++;
        if (long_options[n].has_arg == 1) {
            short_options[p] = ':';
            p++;
        }
        /* optional options need two ':', but ignore them now as they are not in use */
    }

    opt = 0;
    while (1) {
        opt = getopt_long(argc, argv, short_options, long_options, NULL);
        if (opt == -1)
            break;

        switch (opt) {
        case 'v':
            printf("mtr " PACKAGE_VERSION "\n");
            exit(EXIT_SUCCESS);
            break;
        case 'h':
            usage(stdout);
            break;

        case 'r':
            ctl->DisplayMode = DisplayReport;
            break;
        case 'w':
            ctl->reportwide = 1;
            ctl->DisplayMode = DisplayReport;
            break;
#ifdef HAVE_CURSES
        case 't':
            ctl->DisplayMode = DisplayCurses;
            break;
#endif
#ifdef HAVE_GTK
        case 'g':
            ctl->DisplayMode = DisplayGTK;
            break;
#endif
        case 'p':              /* BL */
            ctl->DisplayMode = DisplaySplit;
            break;
        case 'l':
            ctl->DisplayMode = DisplayRaw;
            break;
        case 'C':
            ctl->DisplayMode = DisplayCSV;
            break;
        case 'j':
            ctl->DisplayMode = DisplayJSON;
            break;
        case 'x':
            ctl->DisplayMode = DisplayXML;
            break;

        case OPT_DISPLAYMODE:
            ctl->display_mode =
                strtonum_or_err(optarg, "invalid argument", STRTO_INT);
            if ((DisplayModeMAX - 1) < ctl->display_mode)
                error(EXIT_FAILURE, 0, "value out of range (%d - %d): %s",
                      DisplayModeDefault, (DisplayModeMAX - 1), optarg);
            break;
        case 'c':
            ctl->MaxPing =
                strtonum_or_err(optarg, "invalid argument", STRTO_INT);
            ctl->ForceMaxPing = 1;
            break;
        case 's':
            ctl->cpacketsize =
                strtonum_or_err(optarg, "invalid argument", STRTO_INT);
            break;
        case 'I':
            ctl->InterfaceName = optarg;
            break;
        case 'a':
            ctl->InterfaceAddress = optarg;
            break;
        case 'e':
            ctl->enablempls = 1;
            break;
        case 'n':
            ctl->dns = 0;
            break;
        case 'i':
            ctl->WaitTime = strtofloat_or_err(optarg, "invalid argument");
            if (ctl->WaitTime <= 0.0) {
                error(EXIT_FAILURE, 0, "wait time must be positive");
            }
            if (!running_as_root() && ctl->WaitTime < 1.0) {
                error(EXIT_FAILURE, 0,
                      "non-root users cannot request an interval < 1.0 seconds");
            }
            break;
        case 'f':
            ctl->fstTTL =
                strtonum_or_err(optarg, "invalid argument", STRTO_INT);
            if (ctl->fstTTL > ctl->maxTTL) {
                ctl->fstTTL = ctl->maxTTL;
            }
            if (ctl->fstTTL < 1) {      /* prevent 0 hop */
                ctl->fstTTL = 1;
            }
            break;
        case 'F':
            read_from_file(names, optarg);
            break;
        case 'm':
            ctl->maxTTL =
                strtonum_or_err(optarg, "invalid argument", STRTO_INT);
            if (ctl->maxTTL > (MaxHost - 1)) {
                ctl->maxTTL = MaxHost - 1;
            }
            if (ctl->maxTTL < 1) {      /* prevent 0 hop */
                ctl->maxTTL = 1;
            }
            if (ctl->fstTTL > ctl->maxTTL) {    /* don't know the pos of -m or -f */
                ctl->fstTTL = ctl->maxTTL;
            }
            break;
        case 'U':
            ctl->maxUnknown =
                strtonum_or_err(optarg, "invalid argument", STRTO_INT);
            if (ctl->maxUnknown < 1) {
                ctl->maxUnknown = 1;
            }
            break;
        case 'o':
            /* Check option before passing it on to fld_active. */
            if (strlen(optarg) > MAXFLD) {
                error(EXIT_FAILURE, 0, "Too many fields: %s", optarg);
            }
            /* Filter out the ipinfo fields, which will be regenerated after
               this function and added to the front of ctl->fld_active.*/
            for (i = 0, j = 0; optarg[i]; i++) {
                if (is_ipinfo_filed(optarg[i])) {
                    ctl->ipinfo_arr |= (1 << ipinfo_key2no(optarg[i]));
                    continue;
                }
                fld_tmp[j++] = optarg[i];

                if (!strchr(ctl->available_options, optarg[i])) {
                    error(EXIT_FAILURE, 0, "Unknown field identifier: %c",
                          optarg[i]);
                }
            }
            xstrncpy(ctl->fld_active, fld_tmp, 2 * MAXFLD);
            break;
        case 'B':
            ctl->bitpattern =
                strtonum_or_err(optarg, "invalid argument", STRTO_INT);
            if (ctl->bitpattern > 255)
                ctl->bitpattern = -1;
            break;
        case 'Q':
            ctl->tos =
                strtonum_or_err(optarg, "invalid argument", STRTO_INT);
            if (ctl->tos > 255 || ctl->tos < 0) {
                /* error message, should do more checking for valid values,
                 * details in rfc2474 */
                ctl->tos = 0;
            }
            break;
        case 'u':
            if (ctl->mtrtype != IPPROTO_ICMP) {
                error(EXIT_FAILURE, 0,
                      "-u , -T and -S are mutually exclusive");
            }
            ctl->mtrtype = IPPROTO_UDP;
            break;
        case 'T':
            if (ctl->mtrtype != IPPROTO_ICMP) {
                error(EXIT_FAILURE, 0,
                      "-u , -T and -S are mutually exclusive");
            }
            if (!ctl->remoteport) {
                ctl->remoteport = 80;
            }
            ctl->mtrtype = IPPROTO_TCP;
            break;
#ifdef HAS_SCTP
        case 'S':
            if (ctl->mtrtype != IPPROTO_ICMP) {
                error(EXIT_FAILURE, 0,
                      "-u , -T and -S are mutually exclusive");
            }
            if (!ctl->remoteport) {
                ctl->remoteport = 80;
            }
            ctl->mtrtype = IPPROTO_SCTP;
            break;
#endif
        case 'b':
            ctl->show_ips = 1;
            break;
        case 'P':
            ctl->remoteport =
                strtonum_or_err(optarg, "invalid argument", STRTO_INT);
            if (ctl->remoteport < 1 || MaxPort < ctl->remoteport) {
                error(EXIT_FAILURE, 0, "Illegal port number: %d",
                      ctl->remoteport);
            }
            break;
        case 'L':
            ctl->localport =
                strtonum_or_err(optarg, "invalid argument", STRTO_INT);
            if (ctl->localport < MinPort || MaxPort < ctl->localport) {
                error(EXIT_FAILURE, 0, "Illegal port number: %d",
                      ctl->localport);
            }
            break;
        case 'Z':
            ctl->probe_timeout =
                strtonum_or_err(optarg, "invalid argument", STRTO_INT);
            ctl->GraceTime = ctl->probe_timeout;
            ctl->probe_timeout *= 1000000;
            break;
        case '4':
            ctl->af = AF_INET;
            break;
#ifdef ENABLE_IPV6
        case '6':
            ctl->af = AF_INET6;
            break;
#endif
#ifdef HAVE_IPINFO
        case 'y':
            process_ipinfo_arr(ctl, optarg);
            break;
        case 'z':
            ctl->ipinfo_arr |= (1 << ASN);
            break;
        case OPT_ASN:
            ctl->ipinfo_arr |= (1 << ASN);
            break;
        case OPT_IP_PREFIX:
            ctl->ipinfo_arr |= (1 << IP_PREFIX);
            break;
        case OPT_COUNTRY:
            ctl->ipinfo_arr |= (1 << COUNTRY_CODE);
            break;
        case OPT_REGISTER:
            ctl->ipinfo_arr |= (1 << REG);
            break;
        case OPT_ALLOCATION_DATE:
            ctl->ipinfo_arr |= (1 << ALLOC_DATE);
            break;
        case OPT_CARRIER:
            ctl->ipinfo_arr |= (1 << CARRIER);
            break;
        case OPT_GEO:
            ctl->ipinfo_arr |= (1 << GEO);
            break;
        case OPT_CITY:
            ctl->ipinfo_arr |= (1 << CITY);
            break;
        case OPT_DNS:
            if (optarg) {
                strncpy(ipinfo_domain, optarg, sizeof(ipinfo_domain) - 1);
            }
            break;
        case OPT_SPECIP:
            if (optarg) {
                process_specific_ip_segment(optarg);
            }
            break;
#endif
#ifdef SO_MARK
        case 'M':
            ctl->mark =
                strtonum_or_err(optarg, "invalid argument", STRTO_U32INT);
            break;
#endif
        default:
            usage(stderr);
        }
    }

    if (ctl->DisplayMode == DisplayReport ||
        ctl->DisplayMode == DisplayTXT ||
        ctl->DisplayMode == DisplayJSON ||
        ctl->DisplayMode == DisplayXML ||
        ctl->DisplayMode == DisplayRaw || ctl->DisplayMode == DisplayCSV)
        ctl->Interactive = 0;

    if (optind > argc - 1)
        return;
}


static void parse_mtr_options(
    struct mtr_ctl *ctl,
    names_t ** names,
    char *string)
{
    int argc = 1;
    char *argv[128], *p;

    if (!string)
        return;
    argv[0] = xstrdup(PACKAGE_NAME);
    argc = 1;
    p = strtok(string, " \t");
    while (p != NULL && ((size_t) argc < (sizeof(argv) / sizeof(argv[0])))) {
        argv[argc++] = p;
        p = strtok(NULL, " \t");
    }
    if (p != NULL) {
        error(0, 0, "Warning: extra arguments ignored: %s", p);
    }

    parse_arg(ctl, names, argc, argv);

    free(argv[0]);
    optind = 0;
}

static void init_rand(
    void)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    srand((getpid() << 16) ^ getuid() ^ tv.tv_sec ^ tv.tv_usec);
}


/*
    For historical reasons, we need a hostent structure to represent
    our remote target for probing.  The obsolete way of doing this
    would be to use gethostbyname().  We'll use getaddrinfo() instead
    to generate the hostent.
*/
static int get_hostent_from_name(
    struct mtr_ctl *ctl,
    struct hostent *host,
    const char *name,
    char **alptr)
{
    int gai_error;
    struct addrinfo hints, *res;
    struct sockaddr_in *sa4;
#ifdef ENABLE_IPV6
    struct sockaddr_in6 *sa6;
#endif

    /* gethostbyname2() is deprecated so we'll use getaddrinfo() instead. */
    memset(&hints, 0, sizeof hints);
    hints.ai_family = ctl->af;
    hints.ai_socktype = SOCK_DGRAM;
    gai_error = getaddrinfo(name, NULL, &hints, &res);
    if (gai_error) {
        if (gai_error == EAI_SYSTEM)
            error(0, 0, "Failed to resolve host: %s", name);
        else
            error(0, 0, "Failed to resolve host: %s: %s", name,
                  gai_strerror(gai_error));

        return -1;
    }

    /* Convert the first addrinfo into a hostent. */
    memset(host, 0, sizeof(struct hostent));
    host->h_name = res->ai_canonname;
    host->h_aliases = NULL;
    host->h_addrtype = res->ai_family;
    ctl->af = res->ai_family;
    host->h_length = res->ai_addrlen;
    host->h_addr_list = alptr;
    switch (ctl->af) {
    case AF_INET:
        sa4 = (struct sockaddr_in *) res->ai_addr;
        alptr[0] = (void *) &(sa4->sin_addr);
        break;
#ifdef ENABLE_IPV6
    case AF_INET6:
        sa6 = (struct sockaddr_in6 *) res->ai_addr;
        alptr[0] = (void *) &(sa6->sin6_addr);
        break;
#endif
    default:
        error(0, 0, "unknown address type");

        errno = EINVAL;
        return -1;
    }
    alptr[1] = NULL;

    return 0;
}


int main(
    int argc,
    char **argv)
{
    struct hostent *host = NULL;
    struct hostent trhost;
    char *alptr[2];
    char ipinfo_fld[2 * MAXFLD] = {0};
    names_t *names_head = NULL;
    names_t *names_walk;
    int i, j;

    myname = argv[0];
    struct mtr_ctl ctl;
    memset(&ctl, 0, sizeof(ctl));
    /* initialize non-null values */
    ctl.Interactive = 1;
    ctl.MaxPing = 10;
    ctl.WaitTime = 1.0;
    ctl.dns = 1;
    ctl.use_dns = 1;
    ctl.cpacketsize = 64;
    ctl.af = DEFAULT_AF;
    ctl.mtrtype = IPPROTO_ICMP;
    ctl.fstTTL = 1;
    ctl.maxTTL = 30;
    ctl.maxUnknown = 12;
    ctl.probe_timeout = 10 * 1000000;
    ctl.GraceTime = ctl.probe_timeout / 1000000.0;
    ctl.ipinfo_arr = 0;
    ctl.ipinfo_no = -1;
    ctl.ipinfo_max = IPINFO_NUMS;
    xstrncpy(ctl.fld_active, "LS NABWV", 2 * MAXFLD);

    /*
       mtr used to be suid root.  It should not be with this version.
       We'll check so that we can notify people using installation
       mechanisms with obsolete assumptions.
     */
    if ((geteuid() != getuid()) || (getegid() != getgid())) {
        error(EXIT_FAILURE, errno, "mtr should not run suid");
    }

    /* This will check if stdout/stderr writing is successful */
    atexit(close_stdout);

    /* reset the random seed */
    init_rand();

    display_detect(&ctl, &argc, &argv);
    ctl.display_mode = DisplayModeDefault;

    /* The field options are now in a static array all together,
       but that requires a run-time initialization. */
    init_fld_options(&ctl);

    parse_mtr_options(&ctl, &names_head, getenv("MTR_OPTIONS"));

    parse_arg(&ctl, &names_head, argc, argv);

    if (!IS_CLEAR_IPINFO(ctl.ipinfo_arr)) {
        ctl.ipinfo_no = (int)log2(ctl.ipinfo_arr & (0 - ctl.ipinfo_arr));
    }
    // use ctl.ipinfo_arr to fill up ctl.fld_active
    for (i = 0, j = 0; i < IPINFO_NUMS; i++) {
        if (IS_INDEX_IPINFO(ctl.ipinfo_arr, i)) {
            switch (i) {
                case ASN:          ipinfo_fld[j++] = 'Z'; break;
                case IP_PREFIX:    ipinfo_fld[j++] = 'P'; break;
                case COUNTRY_CODE: ipinfo_fld[j++] = 'C'; break;
                case REG:          ipinfo_fld[j++] = 'E'; break;
                case ALLOC_DATE:   ipinfo_fld[j++] = 'Y'; break;
                case CITY:         ipinfo_fld[j++] = 'T'; break;
                case CARRIER:      ipinfo_fld[j++] = 'K'; break;
                case GEO:          ipinfo_fld[j++] = 'O'; break;
            }
        }
    }
    strcat(ipinfo_fld, ctl.fld_active);
    strcpy(ctl.fld_active, ipinfo_fld);

    while (optind < argc) {
        char *name = argv[optind++];
        append_to_names(&names_head, name);
    }

    /* default: localhost. */
    if (!names_head)
        append_to_names(&names_head, "localhost");

    names_walk = names_head;
    while (names_walk != NULL) {

        ctl.Hostname = names_walk->name;
        if (gethostname(ctl.LocalHostname, sizeof(ctl.LocalHostname))) {
            xstrncpy(ctl.LocalHostname, "UNKNOWNHOST",
                     sizeof(ctl.LocalHostname));
        }

        host = &trhost;
        if (get_hostent_from_name(&ctl, host, ctl.Hostname, alptr) != 0) {
            if (ctl.Interactive)
                exit(EXIT_FAILURE);
            else {
                names_walk = names_walk->next;
                continue;
            }
        }

        if (net_open(&ctl, host) != 0) {
            error(0, 0, "Unable to start net module");
            if (ctl.Interactive)
                exit(EXIT_FAILURE);
            else {
                names_walk = names_walk->next;
                continue;
            }
        }

        lock(stdout);
        dns_open(&ctl);
        display_open(&ctl);

        display_loop(&ctl);

        net_end_transit();
        display_close(&ctl);
        unlock(stdout);

        if (ctl.Interactive)
            break;
        else
            names_walk = names_walk->next;

    }

    net_close();

    while (names_head != NULL) {
        names_t *item = names_head;
        free(item->name);
        item->name = NULL;
        names_head = item->next;
        free(item);
        item = NULL;
    }

    return 0;
}
