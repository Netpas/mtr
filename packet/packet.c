/*
    mtr  --  a network diagnostic tool
    Copyright (C) 2016  Matt Kimball

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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef HAVE_LIBCAP
#include <sys/capability.h>
#endif

#include "wait.h"

#define BIND(socket, addr, len)   \
do {\
    if ((socket > 0) && (bind(socket, addr, len) < 0)) {  \
        return -1; \
    }\
} while(0)


/*  Drop SUID privileges.  To be used after accquiring raw sockets.  */
static
int drop_elevated_permissions(
    void)
{
#ifdef HAVE_LIBCAP
    cap_t cap;
#endif

    /*  Drop any suid permissions granted  */
    if (setgid(getgid()) || setuid(getuid())) {
        return -1;
    }

    if (geteuid() != getuid() || getegid() != getgid()) {
        return -1;
    }

    /*
       Drop all process capabilities.
       This will revoke anything granted by a commandline 'setcap'
     */
#ifdef HAVE_LIBCAP
    cap = cap_get_proc();
    if (cap == NULL) {
        return -1;
    }
    if (cap_clear(cap)) {
        return -1;
    }
    if (cap_set_proc(cap)) {
        return -1;
    }
#endif

    return 0;
}

static int init_bind(struct net_state_t *net_state, char *localaddr, char *af)
{
#ifdef ENABLE_IPV6
    struct sockaddr_storage sourcesockaddr_struct;
    struct sockaddr_in6 *ssa6 = (struct sockaddr_in6 *)&sourcesockaddr_struct;
#else
    struct sockaddr_in sourcesockaddr_struct;
#endif
    struct sockaddr *sourcesockaddr = (struct sockaddr *)&sourcesockaddr_struct;
    struct sockaddr_in *ssa4 = (struct sockaddr_in *)&sourcesockaddr_struct;
    int len;

    if (strcmp(af, "6") == 0) {     // AF_INET6
        sourcesockaddr->sa_family = AF_INET6;
        ssa6->sin6_port = 0;
        if (inet_pton(AF_INET6, localaddr, &(ssa6->sin6_addr)) < 1) {
            return -1;
        }
        len = sizeof(struct sockaddr_in6);

        BIND(net_state->platform.icmp6_send_socket, sourcesockaddr, len);
        BIND(net_state->platform.ip6_txrx_icmp_socket, sourcesockaddr, len);
        BIND(net_state->platform.udp6_send_socket, sourcesockaddr, len);
        BIND(net_state->platform.ip6_txrx_udp_socket, sourcesockaddr, len);
    } else {    // AF_INET
        sourcesockaddr->sa_family = AF_INET;
        ssa4->sin_port = 0;
        if (inet_aton(localaddr, &(ssa4->sin_addr)) < 1) {
            return -1;
        }
        len = sizeof(struct sockaddr);

        BIND(net_state->platform.ip4_send_socket, sourcesockaddr, len);
        BIND(net_state->platform.ip4_txrx_icmp_socket, sourcesockaddr, len);
        BIND(net_state->platform.ip4_txrx_udp_socket, sourcesockaddr, len);
    }

    return 0;
}

int main(
    int argc,
    char **argv)
{
    bool command_pipe_open;
    struct command_buffer_t command_buffer;
    struct net_state_t net_state;

    // argv[1]:localaddr argv[2]:af
    if (argc != 3) {
        exit(EXIT_FAILURE);
    }

    /*
       To minimize security risk, the only thing done prior to
       dropping SUID should be opening the network state for
       raw sockets.
     */
    init_net_state_privileged(&net_state);
    if (drop_elevated_permissions()) {
        perror("Unable to drop elevated permissions");
        exit(EXIT_FAILURE);
    }
    init_net_state(&net_state);
    if (init_bind(&net_state, argv[1], argv[2]) < 0) {
        perror("failed to bind to interface:");
        exit(EXIT_FAILURE);
    }

    init_command_buffer(&command_buffer, fileno(stdin));

    command_pipe_open = true;

    /*
       Dispatch commands and respond to probe replies until the
       command stream is closed.
     */
    while (true) {
        /*  Ensure any responses are written before waiting  */
        fflush(stdout);
        wait_for_activity(&command_buffer, &net_state);

        /*
           Receive replies first so that the timestamps are as
           close to the response arrival time as possible.
         */
        receive_replies(&net_state);

        if (command_pipe_open) {
            if (read_commands(&command_buffer)) {
                if (errno == EPIPE) {
                    command_pipe_open = false;
                }
            }
        }

        check_probe_timeouts(&net_state);

        /*
           Dispatch commands late so that the window between probe
           departure and arriving replies is as small as possible.
         */
        dispatch_buffer_commands(&command_buffer, &net_state);

        /*
           If the command pipe has been closed, exit after all
           in-flight probes have reported their status.
         */
        if (!command_pipe_open) {
            if (net_state.outstanding_probe_count == 0) {
                break;
            }
        }
    }

    return 0;
}
