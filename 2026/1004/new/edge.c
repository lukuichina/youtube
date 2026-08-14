/**
 * (C) 2007-09 - Luca Deri <deri@ntop.org>
 *               Richard Andrews <andrews@ntop.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not see see <http://www.gnu.org/licenses/>
 *
 * Code contributions courtesy of:
 * Don Bindner <don.bindner@gmail.com>
 * Sylwester Sosnowski <syso-n2n@no-route.org>
 * Wilfried "Wonka" Klaebe
 * Lukasz Taczuk
 *
 */

#include "n2n.h"
#include "n2n_transforms.h"
#include "speck.h"
#include "pearson.h"
#include "assert.h"
#include <fcntl.h>
#include "minilzo.h"
#include "random.h"
#include "string.h"
#include "upnp.h"

#ifdef _WIN32
#include <iphlpapi.h>
#include <windns.h>
#pragma comment(lib, "dnsapi.lib")
/* Interface types for filtering virtual interfaces */
#ifndef IF_TYPE_PPP
#define IF_TYPE_PPP 23
#endif
#ifndef IF_TYPE_TUNNEL
#define IF_TYPE_TUNNEL 131
#endif
#else
#include <resolv.h>
#endif

/* reallocarray compatibility for older glibc versions */
#ifndef HAVE_REALLOCARRAY
#define reallocarray(p, n, s) realloc((p), (n) * (s))
#endif

#define SOCKET_TIMEOUT_INTERVAL_SECS    1    /* sec */
#define REGISTER_SUPER_INTERVAL_DFL     20   /* sec */
#define REGISTER_SUPER_INTERVAL_MIN     10   /* sec */
#define REGISTER_SUPER_INTERVAL_MAX     120  /* sec */
#define IFACE_UPDATE_INTERVAL           (30) /* sec. How long it usually takes to get an IP lease. */
#define TRANSOP_TICK_INTERVAL           (10) /* sec */
#define PUNCH_TIMEOUT                   7    /* sec: give up hole-punch after this */

/** maximum length of command line arguments */
#define MAX_CMDLINE_BUFFER_LENGTH       4096

/** maximum length of a line in the configuration file */
#define MAX_CONFFILE_LINE_LENGTH        1024

#define N2N_PATHNAME_MAXLEN             256
#define N2N_MAX_TRANSFORMS              16
#define N2N_EDGE_MGMT_PORT              5664

/* Portable temporary buffer macros - avoids C99 compound literals which
 * cause issues on older ARM compilers (GCC 4.x / ARMv5). */
#define MACSTR_TMP(var)      macstr_t var; memset(var, 0, sizeof(var))
#define SOCKSTR_TMP(var)     n2n_sock_str_t var; memset(var, 0, sizeof(var))

/* Format a peer identifier: virtual IP if known, otherwise MAC address.
 * buf must be at least INET_ADDRSTRLEN bytes; macstr_t (18 bytes) is sufficient. */
#define PEER_ID(buf, peer) peer_id_str_impl((buf), (peer)->assigned_ip, (peer)->mac_addr)
static inline const char * peer_id_str_impl(char *buf, uint32_t assigned_ip, const uint8_t *mac) {
    if (assigned_ip != 0) {
        struct in_addr a;
        a.s_addr = htonl(assigned_ip);
        inet_ntop(AF_INET, &a, buf, INET_ADDRSTRLEN);
        return buf;
    }
    return macaddr_str(buf, mac);
}

static int default_ip_assignment = 0;
static int initial_connection_complete = 0;

/* Global flag set by signal handler to request graceful shutdown */
static volatile int g_edge_running = 1;

#ifdef _WIN32
static BOOL WINAPI edge_console_ctrl_handler(DWORD ctrl_type) {
    if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT ||
        ctrl_type == CTRL_CLOSE_EVENT || ctrl_type == CTRL_SHUTDOWN_EVENT) {
        g_edge_running = 0;
        return TRUE;
    }
    return FALSE;
}
#else
#include <signal.h>
static void edge_signal_handler(int sig) {
    (void)sig;
    g_edge_running = 0;
}
#endif

/* struct n2n_edge is fully defined in n2n.h */

#ifdef _WIN32
#define PEERS_LOCK(eee)   EnterCriticalSection(&(eee)->peers_lock)
#define PEERS_UNLOCK(eee) LeaveCriticalSection(&(eee)->peers_lock)
#else
#define PEERS_LOCK(eee)   /* no-op on Linux: single-threaded TAP */
#define PEERS_UNLOCK(eee) /* no-op on Linux: single-threaded TAP */
#endif

/** Return the IP address of the current supernode in the ring. */
static const char * supernode_ip( const n2n_edge_t * eee )
{
    return (eee->sn_ip_array)[eee->sn_idx];
}


static int supernode2addr(n2n_sock_t * sn, int af, const n2n_sn_name_t addr);

static void send_packet2net(n2n_edge_t * eee,
                uint8_t *decrypted_msg, size_t len);

/* ************************************** */

static int readConfFile(const char * filename, char * const linebuffer) {
    FILE* fd;
    char* buffer;

    buffer = (char*) malloc(MAX_CONFFILE_LINE_LENGTH);
    if (!buffer) return -1;

    if (access(filename, R_OK)) {
        if (errno == ENOENT)
            traceEvent(TRACE_ERROR, "parameter file %s not found/unable to access", filename);
        else
            traceEvent(TRACE_ERROR, "cannot stat file %s, %s",filename, strerror(errno));
        free(buffer);
        return -1;
    }

				fd = fopen(filename, "rb");
    if (!fd) {
        traceEvent(TRACE_ERROR, "Unable to open parameter file '%s': %s", filename, strerror(errno));
        free(buffer);
        return -1;
    }
    while(fgets(buffer, MAX_CONFFILE_LINE_LENGTH,fd)) {
        char* p;

        p = strchr(buffer, '#');
        if (p) *p ='\0';

        p = strchr(buffer, '\n');
        if (p) *p ='\0';

        if (strlen(buffer) == 0) continue;

        p = buffer;
        while (*p == ' ') ++p;
        if (p != buffer) {
            size_t len = strlen(p);
            if (len < MAX_CONFFILE_LINE_LENGTH) {
                memmove(buffer, p, len + 1);
            } else {
                traceEvent(TRACE_ERROR, "line too long");
                continue;
            }
        }

        size_t buf_len = strlen(buffer);
        while(buf_len > 0 && buffer[buf_len-1] == ' ') {
            buffer[buf_len-1] = '\0';
            buf_len--;
        }

        if (strchr(buffer, '@')) {
            traceEvent(TRACE_ERROR, "@file in file nesting is not supported");
            free(buffer);
            fclose(fd);
            return -1;
        }
        
        size_t line_len = strlen(linebuffer);
        if (line_len + buf_len + 2 <= MAX_CMDLINE_BUFFER_LENGTH) {
            linebuffer[line_len] = ' ';
            memcpy(linebuffer + line_len + 1, buffer, buf_len + 1);
        } else {
            traceEvent(TRACE_ERROR, "too many arguments");
            free(buffer);
            fclose(fd);
            return -1;
        }
    }

    free(buffer);
    fclose(fd);

    return 0;
}

static int edge_init_speck( n2n_edge_t * eee, uint8_t *encrypt_pwd, uint64_t encrypt_pwd_len )
{
    n2n_cipherspec_t spec;
    int retval;

    /* Create a cipherspec for single-key Speck operation */
    spec.t = N2N_TRANSFORM_ID_SPECK;
    spec.valid_from = 0;
    spec.valid_until = 0xFFFFFFFF;

    /* Format: "0_hexkey" where 0 is SA ID */
    snprintf((char*)spec.opaque, sizeof(spec.opaque), "0_");

    /* Try hex first, if fails use ASCII directly */
    int pstat = n2n_parse_hex(spec.opaque + 2, sizeof(spec.opaque) - 2,
                             (char*)encrypt_pwd, encrypt_pwd_len);

    if (pstat <= 0) {
        /* Hex parsing failed, use ASCII directly */
        size_t max_copy = sizeof(spec.opaque) - 2 - 1; /* leave room for '\0' */
        size_t copy_len = (encrypt_pwd_len <= max_copy) ? encrypt_pwd_len : max_copy;
        memcpy(spec.opaque + 2, encrypt_pwd, copy_len);
        spec.opaque[2 + copy_len] = '\0';
        pstat = (int)copy_len;
    }

    /* Add the spec to the Speck transform */
    retval = (eee->transop[N2N_TRANSOP_SPECK_IDX].addspec)(
                &(eee->transop[N2N_TRANSOP_SPECK_IDX]), &spec );

    if (retval == 0) {
        eee->tx_transop_idx = N2N_TRANSOP_SPECK_IDX;
    }

    return retval;
}

/* Create the argv vector */
static char ** buildargv(int * effectiveargc, char * const linebuffer) {
    const int  INITIAL_MAXARGC = 16;	/* Number of args + NULL in initial argv */
    int     maxargc;
    int     argc=0;
    char ** argv;
    char *  buffer, * buff;

    if (!linebuffer) {
        return NULL;
    }

    *effectiveargc = 0;
    buffer = (char *)calloc(1, strlen(linebuffer)+2);
    if (!buffer) return NULL;

    memcpy(buffer, linebuffer, strlen(linebuffer) + 1);

    maxargc = INITIAL_MAXARGC;
    argv = (char **)malloc(maxargc * sizeof(char*));
    if (!argv) {
        traceEvent(TRACE_ERROR, "Unable to allocate memory");
        free(buffer);
        return NULL;
    }
    buff = buffer;
    while(buff) {
        char * p = strchr(buff,' ');
        if (p) {
            *p='\0';
            argv[argc] = strdup(buff);
            if (!argv[argc]) {
                traceEvent(TRACE_ERROR, "Unable to allocate memory for argv[%d]", argc);
                for (int j = 0; j < argc; j++) free(argv[j]);
                free(argv);
                free(buffer);
                return NULL;
            }
            argc++;
            while(*++p == ' ');
            buff=p;
        } else {
            argv[argc] = strdup(buff);
            if (!argv[argc]) {
                traceEvent(TRACE_ERROR, "Unable to allocate memory for argv[%d]", argc);
                for (int j = 0; j < argc; j++) free(argv[j]);
                free(argv);
                free(buffer);
                return NULL;
            }
            argc++;
            break;
        }
        if (argc >= maxargc) {
            maxargc *= 2;
            char** new_argv = (char **)realloc(argv, maxargc * sizeof(char*));
            if (new_argv == NULL) {
                traceEvent(TRACE_ERROR, "Unable to re-allocate memory");
                for (int i = 0; i < argc; i++) free(argv[i]);
                free(argv);
                free(buffer);
                return NULL;
            }
            argv = new_argv;
        }
    }
    free(buffer);
    *effectiveargc = argc;
    return argv;
}

/* ************************************** */


/** Initialise an edge to defaults.
 *
 *  This also initialises the NULL transform operation opstruct.
 */
static int edge_init(n2n_edge_t * eee)
{
#ifdef _WIN32
    initWin32();
#endif
    memset(eee, 0, sizeof(n2n_edge_t));
    eee->start_time = n2n_now();

    transop_null_init(    &(eee->transop[N2N_TRANSOP_NULL_IDX]) );
    transop_twofish_init( &(eee->transop[N2N_TRANSOP_TF_IDX]  ) );
    transop_aes_init(     &(eee->transop[N2N_TRANSOP_AESCBC_IDX]) );
    transop_cc20_init(    &(eee->transop[N2N_TRANSOP_CC20_IDX]) );
    transop_speck_init(   &(eee->transop[N2N_TRANSOP_SPECK_IDX]) );

    eee->tx_transop_idx = N2N_TRANSOP_NULL_IDX; /* No guarantee the others have been setup */

    eee->daemon = 1;
    eee->re_resolve_supernode_ip = 0;
    eee->null_transop   = 0;
    eee->udp_sock       = -1;
    eee->udp_sock6      = -1;
    eee->mgmt_sock      = -1;
    eee->dyn_ip_mode    = 0;
    eee->allow_routing  = 0;
    eee->drop_multicast = 1;
    eee->known_peers    = NULL;
    eee->pending_peers  = NULL;
    eee->upnp_mapped_port = 0;
#ifdef _WIN32
    InitializeCriticalSection(&eee->peers_lock);
    eee->keep_running   = 1;
#endif
    eee->last_register_req = 0;
    eee->register_lifetime = 120;
    eee->last_p2p = 0;
    eee->last_sup = 0;
    eee->sup_attempts = N2N_EDGE_SUP_ATTEMPTS;
    eee->sn_af = AF_UNSPEC;
    memset(&eee->my_public_sock, 0, sizeof(n2n_sock_t));
    memset(&eee->last_resolved_supernode, 0, sizeof(n2n_sock_t));
    eee->last_resolve_check = 0;
    eee->peer_sync_active = 0;
    eee->peer_sync_time = 0;
    eee->peer_sync_ips_count = 0;
    eee->enable_gaming_mode = 0;
    eee->gaming_started = 0;
    eee->bp_proxy_port = 0; /* will use default */
    eee->bp = NULL;
    eee->bp_user_disabled = 1; /* default: bypass off */

    if(lzo_init() != LZO_E_OK)
    {
        traceEvent(TRACE_ERROR, "LZO compression error");
        return(-1);
    }

    pearson_hash_init();

    return(0);
}

/** Called in main() after options are parsed. */
static int edge_init_twofish( n2n_edge_t * eee, uint8_t *encrypt_pwd, uint64_t encrypt_pwd_len )
{
    int retval;

    retval = transop_twofish_setup( &(eee->transop[N2N_TRANSOP_TF_IDX]), 0, encrypt_pwd, encrypt_pwd_len );

    if (retval == 0) {
        eee->tx_transop_idx = N2N_TRANSOP_TF_IDX;
    }

    return retval;
}

#ifdef N2N_HAVE_AES
static int edge_init_aes( n2n_edge_t * eee, uint8_t *encrypt_pwd, uint64_t encrypt_pwd_len )
{
    int retval = edge_init_aes_from_key(&eee->transop[N2N_TRANSOP_AESCBC_IDX],
                                        encrypt_pwd, (size_t)encrypt_pwd_len);
    if (retval == 0)
        eee->tx_transop_idx = N2N_TRANSOP_AESCBC_IDX;
    return retval;
}
#endif

#ifdef N2N_HAVE_CC20
static int edge_init_cc20( n2n_edge_t * eee, uint8_t *encrypt_pwd, uint64_t encrypt_pwd_len )
{
    int retval = edge_init_cc20_from_key(&eee->transop[N2N_TRANSOP_CC20_IDX],
                                         encrypt_pwd, (size_t)encrypt_pwd_len);
    if (retval == 0)
        eee->tx_transop_idx = N2N_TRANSOP_CC20_IDX;
    return retval;
}
#endif

/* ************************************** */

/* Setup encryption based on mode and key */
static int setup_encryption(n2n_edge_t *eee, int encrypt_mode, const char *encrypt_key) {
    if (encrypt_mode == 1) {
        traceEvent(TRACE_NORMAL, "Using no encryption");
        eee->null_transop = 1;
        return 0;
    }
    
    if (encrypt_mode == 2) {
        if (!encrypt_key) {
            traceEvent(TRACE_WARNING, "No encryption key, data is not encrypted");
            eee->null_transop = 1;
            return 0;
        }
        traceEvent(TRACE_NORMAL, "Using Twofish encryption");
        if (edge_init_twofish(eee, (uint8_t*)encrypt_key, strlen(encrypt_key)) < 0) {
            fprintf(stderr, "Error: twofish setup failed.\n");
            return -1;
        }
        return 0;
    }
    
#ifdef N2N_HAVE_AES
    if (encrypt_mode == 3) {
        if (!encrypt_key) {
            fprintf(stderr, "Error: B3 requires -k <key>\n");
            exit(1);
        }
        traceEvent(TRACE_NORMAL, "Using AES-CBC encryption");
        if (edge_init_aes(eee, (uint8_t*)encrypt_key, strlen(encrypt_key)) < 0) {
            fprintf(stderr, "Error: AES setup failed.\n");
            return -1;
        }
        return 0;
    }
#endif

#ifdef N2N_HAVE_CC20
    if (encrypt_mode == 4) {
        if (!encrypt_key) {
            fprintf(stderr, "Error: B4 requires -k <key>\n");
            exit(1);
        }
        traceEvent(TRACE_NORMAL, "Using ChaCha20 encryption");
        if (edge_init_cc20(eee, (uint8_t*)encrypt_key, strlen(encrypt_key)) < 0) {
            fprintf(stderr, "Error: ChaCha20 setup failed.\n");
            return -1;
        }
        return 0;
    }
#endif

    if (encrypt_mode == 5) {
        if (!encrypt_key) {
            fprintf(stderr, "Error: B5 requires -k <key>\n");
            exit(1);
        }
        traceEvent(TRACE_NORMAL, "Using Speck encryption");
        if (edge_init_speck(eee, (uint8_t*)encrypt_key, strlen(encrypt_key)) < 0) {
            fprintf(stderr, "Error: Speck setup failed.\n");
            return -1;
        }
        return 0;
    }
    
    return 0;
}

/* ************************************** */

/* Setup UDP sockets for edge */
static int setup_sockets(n2n_edge_t *eee, int local_port) {
    eee->udp_sock = open_socket(local_port, 1 /*bind ANY*/);
    if (eee->udp_sock == -1) {
        traceEvent(TRACE_ERROR, "Failed to bind main UDP port %u", (signed int)local_port);
        return -1;
    }

    eee->udp_sock6 = open_socket6(local_port, 1 /*bind ANY*/);
    
    int has_ipv4 = (eee->udp_sock != -1);
    int has_ipv6 = 0;
    memset(&eee->own_ipv6, 0, sizeof(n2n_sock_t));
    
    if (eee->udp_sock6 != -1) {
        /* Actual listening port of udp_sock6: needed as own_ipv6 port so
         * peers can be told where our IPv6 UDP socket is running. Use
         * getsockname since the port may be auto-assigned when local_port=0. */
        uint16_t v6_port = (uint16_t)local_port;
        struct sockaddr_in6 lsock;
        socklen_t llen = sizeof(lsock);
        if (getsockname(eee->udp_sock6, (struct sockaddr*)&lsock, &llen) == 0 && llen >= sizeof(lsock))
            v6_port = ntohs(lsock.sin6_port);

        struct ifaddrs *ifap = NULL;
#ifndef _WIN32
        if (getifaddrs(&ifap) == 0) {
            struct ifaddrs *ifa;
            for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
                if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET6) continue;
                struct sockaddr_in6 *s6 = (struct sockaddr_in6*)ifa->ifa_addr;
                if (IN6_IS_ADDR_LOOPBACK(&s6->sin6_addr) ||
                    IN6_IS_ADDR_LINKLOCAL(&s6->sin6_addr))
                    continue;
                has_ipv6 = 1;
                /* Only a globally-routable GUA (2000::/3) is worth reporting:
                 * fd00 (ULA) / site-local would mislead peers into useless probe
                 * attempts. Pick the first GUA as our reportable IPv6. */
                if (!eee->own_ipv6.family && (s6->sin6_addr.s6_addr[0] & 0xE0) == 0x20) {
                    eee->own_ipv6.family = AF_INET6;
                    eee->own_ipv6.port = v6_port;
                    memcpy(eee->own_ipv6.addr.v6, &s6->sin6_addr, IPV6_SIZE);
                }
            }
            freeifaddrs(ifap);
        }
#else
        ULONG buflen = 15000;
        IP_ADAPTER_ADDRESSES *addrs = (IP_ADAPTER_ADDRESSES*)malloc(buflen);
        if (addrs && GetAdaptersAddresses(AF_INET6, 0, NULL, addrs, &buflen) == NO_ERROR) {
            IP_ADAPTER_ADDRESSES *a;
            for (a = addrs; a; a = a->Next) {
                IP_ADAPTER_UNICAST_ADDRESS *ua;
                for (ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
                    struct sockaddr_in6 *s6 = (struct sockaddr_in6*)ua->Address.lpSockaddr;
                    if (s6->sin6_family != AF_INET6 ||
                        IN6_IS_ADDR_LOOPBACK(&s6->sin6_addr) ||
                        IN6_IS_ADDR_LINKLOCAL(&s6->sin6_addr))
                        continue;
                    has_ipv6 = 1;
                    if (!eee->own_ipv6.family && (s6->sin6_addr.s6_addr[0] & 0xE0) == 0x20) {
                        eee->own_ipv6.family = AF_INET6;
                        eee->own_ipv6.port = v6_port;
                        memcpy(eee->own_ipv6.addr.v6, &s6->sin6_addr, 16);
                    }
                }
                if (has_ipv6) break;
            }
        }
        if (addrs) free(addrs);
#endif
    }

    if (has_ipv4 && has_ipv6)
        traceEvent(TRACE_NORMAL, "Edge support: IPv4+IPv6 (dual-stack)");
    else if (has_ipv6)
        traceEvent(TRACE_NORMAL, "Edge support: IPv6 only");
    else
        traceEvent(TRACE_NORMAL, "Edge support: IPv4 only");

    return 0;
}

/* ************************************** */

/* Setup management socket */
static int setup_mgmt_socket(n2n_edge_t *eee, int mgmt_port, const char *mgmt_path) {
#if !defined(_WIN32)
    if (mgmt_port == 0) {
        eee->mgmt_sock = open_socket_unix(mgmt_path, 0660);
        if (eee->mgmt_sock == -1) {
            traceEvent(TRACE_ERROR, "Failed to bind management socket %s", mgmt_path);
            return -1;
        }
        return 0;
    }
#endif
    
    eee->mgmt_sock = open_socket(mgmt_port, 0 /* bind LOOPBACK*/);
    if (eee->mgmt_sock == -1) {
        if (mgmt_port == N2N_EDGE_MGMT_PORT) {
            traceEvent(TRACE_WARNING, "Mgmt port %u busy, running without it",
                       (unsigned int)mgmt_port);
            eee->mgmt_sock = -1;
        } else {
            traceEvent(TRACE_ERROR, "Failed to bind management socket %u", (unsigned int)mgmt_port);
            return -1;
        }
    }
    return 0;
}

/* ************************************** */

/* Setup UPnP port mapping */
static void setup_upnp(n2n_edge_t *eee, int local_port) {
    uint16_t actual_port = 0;
    
    if (local_port > 0) {
        actual_port = (uint16_t)local_port;
    } else {
        struct sockaddr_in bound;
        socklen_t blen = sizeof(bound);
        if (getsockname(eee->udp_sock, (struct sockaddr*)&bound, &blen) == 0)
            actual_port = ntohs(bound.sin_port);
    }

    if (actual_port > 0) {
        uint16_t mapped = 0;
        traceEvent(TRACE_INFO, "Upnp: attempting port mapping for UDP port %u", (unsigned)actual_port);
        if (upnp_map_port(actual_port, actual_port, &mapped) == UPNP_OK) {
            traceEvent(TRACE_NORMAL, "Upnp: mapped udp port %u", (unsigned)mapped);
            eee->upnp_mapped_port = mapped;
        } else {
            traceEvent(TRACE_INFO, "Upnp: ... mapping failed");
        }
    }
}

/* ************************************** */

static int transop_enum_to_index( n2n_transform_t id )
{
    switch (id) {
    case N2N_TRANSFORM_ID_TWOFISH:  return N2N_TRANSOP_TF_IDX;
    case N2N_TRANSFORM_ID_NULL:     return N2N_TRANSOP_NULL_IDX;
    case N2N_TRANSFORM_ID_AESCBC:   return N2N_TRANSOP_AESCBC_IDX;
    case N2N_TRANSFORM_ID_CHACHA20: return N2N_TRANSOP_CC20_IDX;
    case N2N_TRANSFORM_ID_SPECK:    return N2N_TRANSOP_SPECK_IDX;
    default:                        return -1;
    }
}

static int n2n_tick_transop( n2n_edge_t * eee, time_t now )
{
    /* Tick all transops for maintenance only.
     * tx_transop_idx is set by -A option and must not be overridden here. */
    (eee->transop[N2N_TRANSOP_NULL_IDX].tick)( &(eee->transop[N2N_TRANSOP_NULL_IDX]), now );
    (eee->transop[N2N_TRANSOP_TF_IDX].tick)( &(eee->transop[N2N_TRANSOP_TF_IDX]), now );
    (eee->transop[N2N_TRANSOP_AESCBC_IDX].tick)( &(eee->transop[N2N_TRANSOP_AESCBC_IDX]), now );
    (eee->transop[N2N_TRANSOP_CC20_IDX].tick)( &(eee->transop[N2N_TRANSOP_CC20_IDX]), now );
    (eee->transop[N2N_TRANSOP_SPECK_IDX].tick)( &(eee->transop[N2N_TRANSOP_SPECK_IDX]), now );
    return 0;
}

/** Deinitialise the edge and deallocate any owned memory. */
static void edge_deinit(n2n_edge_t * eee)
{
    if (eee->bp) {
        bypass_deinit(eee->bp);
        free(eee->bp);
        eee->bp = NULL;
    }

    if (eee->udp_sock != -1) closesocket(eee->udp_sock);
    if (eee->udp_sock6 != -1) closesocket(eee->udp_sock6);
    if (eee->mgmt_sock != -1) closesocket(eee->mgmt_sock);

    if (eee->upnp_mapped_port != 0) {
        traceEvent(TRACE_NORMAL, "Removing upnp port mapping for port %u (async)",
                   (unsigned)eee->upnp_mapped_port);
        /* Async: don't block shutdown on slow UPnP/NAT-PMP/PCP timeouts.
         * The mapping cleanup runs in a detached worker thread. */
        upnp_unmap_port_async(eee->upnp_mapped_port);
        eee->upnp_mapped_port = 0;
    }

    clear_peer_list( &(eee->pending_peers) );
    clear_peer_list( &(eee->known_peers) );

    (eee->transop[N2N_TRANSOP_TF_IDX].deinit)(&eee->transop[N2N_TRANSOP_TF_IDX]);
    (eee->transop[N2N_TRANSOP_NULL_IDX].deinit)(&eee->transop[N2N_TRANSOP_NULL_IDX]);
    (eee->transop[N2N_TRANSOP_AESCBC_IDX].deinit)(&eee->transop[N2N_TRANSOP_AESCBC_IDX]);
    (eee->transop[N2N_TRANSOP_CC20_IDX].deinit)(&eee->transop[N2N_TRANSOP_CC20_IDX]);
    (eee->transop[N2N_TRANSOP_SPECK_IDX].deinit)(&eee->transop[N2N_TRANSOP_SPECK_IDX]);

#ifdef _WIN32
    WSACleanup();
    DeleteCriticalSection(&eee->peers_lock);
#endif
}

static int readFromIPSocket( n2n_edge_t * eee, SOCKET fd );

static void readFromMgmtSocket( n2n_edge_t * eee, int * keep_running );

static void edge_ws_connect( n2n_edge_t * eee );

static void help() {
    print_n2n_version();
    printf("\n");

    printf("Usage: edge [config_file] <options>\n");
    printf("or: edge -c <community> (default: -a 10.64.0.x -A4 -l n2n6.ouno.eu.org)\n");
    printf("or: edge -a <tun IP address> -c <community> -k <encrypt key> -A <mode> -l <supernode host:port>\n");
    printf("\n");

    printf("-a <addr>[/<prefixlen>]  | Set interface IP address (IPv4 or IPv6, auto-detected).\n");
    printf("                         : for DHCP use '-r -a dhcp:0.0.0.0/0'\n");
    printf("                         : if not specified, auto-assigns 10.64.0.x from supernode.\n");
    printf("-A <mode>                | Encryption:");
    printf(" A1 = disable, A2 = twofish(-k)");
    #ifdef N2N_HAVE_AES
    printf(", A3 = AES-CBC(-k)");
    #endif
    #ifdef N2N_HAVE_CC20
    printf(", A4 = ChaCha20(-k)");
    #endif
    printf("\n");
    printf("                         : A5 = Speck(-k). '-A1' can also be used as '-A 1' (default: chacha20).\n");
    printf("-c <community>           | N2n community name the edge belongs to.\n");
    printf("-k <encrypt key>         | Encryption key (ASCII, max 32) - also N2N_KEY=<encrypt key>.\n");
    printf("-l <supernode host:port> | Supernode address Formats:\n");
    printf("                         : host:port - direct address, common format (e.g. 1.2.3.4:5678)\n");
    printf("                         : host      - dns txt address (e.g. n2n6.ouno.eu.org, it's default).\n");
    printf("-4/-6                    | Resolve supernode DNS name as IPv4 or IPv6 (default: auto).\n");
    printf("-b <port>                | Enable bypass (no port = default port %d).\n", BYPASS_DEFAULT_PORT);
#if N2N_CAN_NAME_IFACE && !defined(_WIN32)
    printf("-d <tun device>          | Tun device name (optional)\n");
#elif N2N_CAN_NAME_IFACE && defined(_WIN32)
    printf("-d <tun device>          | Tun device name (optional)\n");
#endif
    printf("-p <local port>          | Fixed local UDP port.\n");
#ifndef _WIN32
    printf("-u <UID>                 | User ID (numeric) to use when privileges are dropped.\n");
    printf("-g <GID>                 | Group ID (numeric) to use when privileges are dropped.\n");
#endif /* ifndef _WIN32 */
    printf("-G                       | Gaming mode: actively probe all peers to trigger P2P.\n");
#ifdef N2N_HAVE_DAEMON
    printf("-f                       | Do not fork and run as a daemon; rather run in foreground.\n");
#endif /* #ifdef N2N_HAVE_DAEMON */
#ifndef _WIN32
    printf("-m <MAC address>         | Fix MAC address for the TAP interface (otherwise it may be random)\n"
           "                         : eg. -m 01:02:03:04:05:06.\n");
    printf("-M <mtu>                 | Specify n2n MTU of edge interface (default: %d).\n", DEFAULT_MTU);
#endif
    printf("-r                       | Enable packet forwarding through n2n community.\n");
    printf("-R <dest>/<length>,<gw>  | Enable packet forwarding and add a route, IPv4/6 is autodetected.\n");
    printf("-E                       | Accept multicast MAC addresses (default: drop).\n");
    printf("-v                       | Make more verbose. Repeat as required.\n");
    printf("-w                       | WebSocket mode: relay via supernode over WS (TCP), disable P2P.\n");
    printf("-Q <port>                | Query management port (for standalone use). (default: %d).\n", N2N_EDGE_MGMT_PORT);
    printf("-t <port|path>           | Management Socket (UDP Port or absolute path). (default: %d).\n", N2N_EDGE_MGMT_PORT);
    printf("-h                       | Show this help message.\n");

    printf("\nEnvironment variables:\n");
    printf("  N2N_KEY                | Encryption key (ASCII). Not with -K or -k.\n" );
    printf("\n");
}

/** Send a datagram to a socket defined by a n2n_sock_t */
ssize_t sendto_sock( SOCKET fd, const void * buf, size_t len, const n2n_sock_t * dest )
{
    struct sockaddr_in6 peer_addr;
    ssize_t sent;
    socklen_t addr_len;

    fill_sockaddr( (struct sockaddr*) &peer_addr, sizeof(peer_addr), dest );
    addr_len = (dest->family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);

    sent = sendto( fd, buf, len, 0/*flags*/,
                   (struct sockaddr*) &peer_addr, addr_len );
    if ( sent < 0 )
    {
#ifdef _WIN32
        int error = WSAGetLastError();
        /* WSAEFAULT: IPv6 socket sending to IPv4 address - silent */
        /* WSAEAFNOSUPPORT: IPv4 socket sending to IPv6 address - silent */
        /* Transient errors during network transition (e.g. WiFi switch) */
         if ( error == WSAENETUNREACH ||
              error == WSAECONNRESET  ||
              error == WSAENETRESET   ||
              error == WSAEHOSTUNREACH ) {
             const char *why = (error == WSAENETUNREACH) ? "Network is unreachable" :
                               (error == WSAECONNRESET)  ? "Connection was reset"   :
                               (error == WSAENETRESET)   ? "Network dropped connection" :
                                                           "No route to host";
             traceEvent( TRACE_DEBUG, "sendto: %s (network change, harmless)", why );
         } else if ( error != WSAEFAULT && error != WSAEAFNOSUPPORT && error != WSAENOBUFS && error != WSAEWOULDBLOCK ) {
            const char *desc = "unknown";
            switch (error) {
                case 10004: desc = "WSAEINTR, interrupted"; break;
                case 10013: desc = "WSAEACCES, permission denied"; break;
                case 10014: desc = "WSAEFAULT, bad address"; break;
                case 10022: desc = "WSAEINVAL, invalid argument"; break;
                case 10024: desc = "WSAEMFILE, too many open files"; break;
                case 10035: desc = "WSAEWOULDBLOCK, would block"; break;
                case 10036: desc = "WSAEINPROGRESS, in progress"; break;
                case 10037: desc = "WSAEALREADY, already in progress"; break;
                case 10038: desc = "WSAENOTSOCK, not a socket"; break;
                case 10039: desc = "WSAEDESTADDRREQ, dest addr required"; break;
                case 10040: desc = "WSAEMSGSIZE, message too long"; break;
                case 10041: desc = "WSAEPROTOTYPE, wrong protocol"; break;
                case 10042: desc = "WSAENOPROTOOPT, bad option"; break;
                case 10043: desc = "WSAEPROTONOSUPPORT, proto unsupported"; break;
                case 10044: desc = "WSAESOCKTNOSUPPORT, socket unsupported"; break;
                case 10045: desc = "WSAEOPNOTSUPP, operation unsupported"; break;
                case 10046: desc = "WSAEPFNOSUPPORT, family unsupported"; break;
                case 10047: desc = "WSAEAFNOSUPPORT, addr family unsupported"; break;
                case 10048: desc = "WSAEADDRINUSE, address in use"; break;
                case 10049: desc = "WSAEADDRNOTAVAIL, address not available"; break;
                case 10050: desc = "WSAENETDOWN, network down"; break;
                case 10051: desc = "WSAENETUNREACH, network unreachable"; break;
                case 10052: desc = "WSAENETRESET, network reset"; break;
                case 10053: desc = "WSAECONNABORTED, connection aborted"; break;
                case 10054: desc = "WSAECONNRESET, connection reset"; break;
                case 10055: desc = "WSAENOBUFS, no buffer space"; break;
                case 10056: desc = "WSAEISCONN, already connected"; break;
                case 10057: desc = "WSAENOTCONN, not connected"; break;
                case 10058: desc = "WSAESHUTDOWN, shutdown"; break;
                case 10060: desc = "WSAETIMEDOUT, timed out"; break;
                case 10061: desc = "WSAECONNREFUSED, connection refused"; break;
                case 10064: desc = "WSAEHOSTDOWN, host down"; break;
                case 10065: desc = "WSAEHOSTUNREACH, host unreachable"; break;
                case 10091: desc = "WSASYSNOTREADY, network subsystem unavailable"; break;
                case 10092: desc = "WSAVERNOTSUPPORTED, winsock version"; break;
                case 10093: desc = "WSANOTINITIALISED, not initialized"; break;
                case 10094: desc = "WSAEDISCON, disconnected"; break;
                case 10101: desc = "WSAEDQUOT, disk quota"; break;
                case 11001: desc = "WSAHOST_NOT_FOUND, host not found"; break;
                case 11002: desc = "WSATRY_AGAIN, try again"; break;
                case 11003: desc = "WSANO_RECOVERY, non-recoverable"; break;
                case 11004: desc = "WSANO_DATA, no data"; break;
            }
            traceEvent( TRACE_ERROR, "sendto %s", desc );
        }
#else
        char * c = strerror(errno);
        traceEvent( TRACE_DEBUG, "sendto failed (%d) %s", errno, c );
#endif
    }
    else
    {
        traceEvent( TRACE_DEBUG, "sendto sent=%d to", (signed int) sent );
    }

    return sent;
}

/** Select the correct UDP socket based on destination address family */
SOCKET sock_for_dest( const n2n_edge_t * eee, const n2n_sock_t * dest )
{
    if (dest->family == AF_INET6 && eee->udp_sock6 != -1) return eee->udp_sock6;
    return eee->udp_sock;
}

/* WS mode: use ws_send, otherwise UDP. Send failure drops only this packet. */
static ssize_t edge_send_to_sn( n2n_edge_t * eee,
                                const uint8_t * pktbuf, size_t idx )
{
    if (eee->use_ws && eee->ws_conn.state == WS_OPEN) {
        return ws_send(&eee->ws_conn, pktbuf, idx);
    }
    return sendto_sock(sock_for_dest(eee, &eee->supernode), pktbuf, idx, &eee->supernode);
}

/** Send a REGISTER packet to another edge.
 *  If temp_local_sock is provided, use it instead of eee->local_sock in the packet. */
static void send_register_with_local( n2n_edge_t * eee,
    const n2n_sock_t * remote_peer,
    const n2n_sock_t * temp_local_sock)
{
    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx;
    n2n_common_t cmn;
    n2n_REGISTER_t reg;
    n2n_sock_str_t sockbuf;

    memset(&cmn, 0, sizeof(cmn) );
    memset(&reg, 0, sizeof(reg) );
    cmn.ttl=N2N_DEFAULT_TTL;
    cmn.pc = n2n_register;
    cmn.flags = 0;
    memcpy( cmn.community, eee->community_name, N2N_COMMUNITY_SIZE );

    strncpy(reg.version, n2n_sw_version, sizeof(reg.version) - 1);
    strncpy(reg.os_name, n2n_sw_osName, sizeof(reg.os_name) - 1);

    random_bytes(NULL, reg.cookie, N2N_COOKIE_SIZE);
    idx=0;
    encode_mac( reg.srcMac, &idx, eee->device.mac_addr );

    /* Use temp_local_sock if provided, otherwise use eee->local_sock */
    if ( temp_local_sock && temp_local_sock->family != 0 ) {
        reg.sock = *temp_local_sock;
        cmn.flags |= N2N_FLAGS_SOCKET;
    } else if ( eee->local_sock_ena ) {
        reg.sock = eee->local_sock;
        cmn.flags |= N2N_FLAGS_SOCKET;
    }

    idx=0;
    encode_REGISTER( pktbuf, &idx, &cmn, &reg );

    traceEvent( TRACE_INFO, "send REGISTER %s",
        sock_to_cstr( sockbuf, remote_peer ) );

    sendto_sock( sock_for_dest(eee, remote_peer), pktbuf, idx, remote_peer );
}

/** Check if two IPv4 sockets are on the same /24 or /16 subnet */
static int same_subnet(const n2n_sock_t *sock1, const n2n_sock_t *sock2) {
    if (sock1->family == AF_INET && sock2->family == AF_INET) {
        uint32_t addr1, addr2;
        memcpy(&addr1, sock1->addr.v4, IPV4_SIZE);
        memcpy(&addr2, sock2->addr.v4, IPV4_SIZE);
        addr1 = ntohl(addr1);
        addr2 = ntohl(addr2);
        /* Check /24 subnet */
        if ((addr1 & 0xFFFFFF00) == (addr2 & 0xFFFFFF00))
            return 1;
        /* Check /16 subnet */
        if ((addr1 & 0xFFFF0000) == (addr2 & 0xFFFF0000))
            return 1;
    }
    return 0;
}

/** Dynamically find best local IP that matches peer's subnet by enumerating all interfaces.
 *  Returns 1 and fills best_ip if found, 0 if not found. */
static int find_best_local_ip(n2n_edge_t * eee, const n2n_sock_t * peer_lan_sock, n2n_sock_t * best_ip) {
    if (!peer_lan_sock || peer_lan_sock->family != AF_INET || !best_ip)
        return 0;
    
    /* Check primary local_sock first */
    if (eee->local_sock_ena && same_subnet(&eee->local_sock, peer_lan_sock)) {
        *best_ip = eee->local_sock;
        return 1;
    }
    
    /* Dynamically enumerate all interfaces to find matching subnet */
#ifdef _WIN32
    /* Windows: use GetAdaptersAddresses */
    ULONG buflen = 15000;
    IP_ADAPTER_ADDRESSES *pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(buflen);
    if (pAddresses && GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, NULL, pAddresses, &buflen) == NO_ERROR) {
        IP_ADAPTER_ADDRESSES *pCurrAddresses = pAddresses;
        while (pCurrAddresses) {
            IP_ADAPTER_UNICAST_ADDRESS *pUnicast = pCurrAddresses->FirstUnicastAddress;
            while (pUnicast) {
                if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                    struct sockaddr_in *pAddr = (struct sockaddr_in *)pUnicast->Address.lpSockaddr;
                    uint32_t addr_ip = ntohl(pAddr->sin_addr.s_addr);
                    int is_private = ((addr_ip >> 24) == 10) ||
                                     ((addr_ip & 0xFFF00000) == 0xAC100000) ||
                                     ((addr_ip >> 16) == (192 << 8 | 168));
                    if (is_private && addr_ip != ntohl(eee->device.ip_addr)) {
                        /* Skip if same as local_sock (already checked) */
                        if (eee->local_sock_ena && memcmp(&pAddr->sin_addr.s_addr, eee->local_sock.addr.v4, IPV4_SIZE) == 0) {
                            pUnicast = pUnicast->Next;
                            continue;
                        }
                        /* Check if this IP matches peer's subnet */
                        n2n_sock_t candidate;
                        candidate.family = AF_INET;
                        memcpy(candidate.addr.v4, &pAddr->sin_addr.s_addr, IPV4_SIZE);
                        if (same_subnet(&candidate, peer_lan_sock)) {
                            *best_ip = candidate;
                            free(pAddresses);
                            return 1;
                        }
                    }
                }
                pUnicast = pUnicast->Next;
            }
            pCurrAddresses = pCurrAddresses->Next;
        }
        free(pAddresses);
    }
#else
    /* Linux/Unix: use getifaddrs */
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == 0) {
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            struct sockaddr_in *pAddr;
            uint32_t addr_ip;
            int is_private;
            
            if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET)
                continue;
            /* Skip loopback and n2n interface */
            if (ifa->ifa_flags & IFF_LOOPBACK)
                continue;
            if (strncmp(ifa->ifa_name, "n2n", 3) == 0 || strncmp(ifa->ifa_name, "tun", 3) == 0)
                continue;
            /* Skip interfaces without broadcast (point-to-point, VPN) */
            if (!(ifa->ifa_flags & IFF_BROADCAST))
                continue;
            
            pAddr = (struct sockaddr_in *)ifa->ifa_addr;
            addr_ip = ntohl(pAddr->sin_addr.s_addr);
            is_private = ((addr_ip >> 24) == 10) ||
                         ((addr_ip & 0xFFF00000) == 0xAC100000) ||
                         ((addr_ip >> 16) == (192 << 8 | 168));
            if (is_private && addr_ip != ntohl(eee->device.ip_addr)) {
                /* Skip if same as local_sock (already checked) */
                if (eee->local_sock_ena && memcmp(&pAddr->sin_addr.s_addr, eee->local_sock.addr.v4, IPV4_SIZE) == 0)
                    continue;
                /* Check if this IP matches peer's subnet */
                n2n_sock_t candidate;
                candidate.family = AF_INET;
                memcpy(candidate.addr.v4, &pAddr->sin_addr.s_addr, IPV4_SIZE);
                if (same_subnet(&candidate, peer_lan_sock)) {
                    *best_ip = candidate;
                    freeifaddrs(ifaddr);
                    return 1;
                }
            }
        }
        freeifaddrs(ifaddr);
    }
#endif
    
    return 0;  /* No matching IP found */
}


/** Send a REGISTER packet to another edge (using global local_sock). */
static void send_register( n2n_edge_t * eee,
    const n2n_sock_t * remote_peer)
{
    send_register_with_local(eee, remote_peer, NULL);
}


/** Automatically detect LAN IP address for same-NAT direct connect.
 *  Uses connect()+getsockname() to find the exit IP towards supernode.
 *  Only uses the result if it's a private IP address. */
static void set_localip( n2n_edge_t * eee )
{
    n2n_sock_str_t sockbuf;
    eee->local_sock_ena = 0;

    struct sockaddr_in sa2;
    socklen_t sa2_len = sizeof(sa2);
    if (getsockname(eee->udp_sock, (struct sockaddr*)&sa2, &sa2_len) < 0) return;
    uint16_t local_port = ntohs(sa2.sin_port);

    struct sockaddr_in sa, sa_sn;
    socklen_t sa_len = sizeof(sa);
#ifdef _WIN32
    SOCKET fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == INVALID_SOCKET) return;
#else
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return;
#endif
    fill_sockaddr((struct sockaddr*)&sa_sn, sizeof(sa_sn), &eee->supernode);
    if (connect(fd, (struct sockaddr*)&sa_sn, sizeof(sa_sn)) == 0 &&
        getsockname(fd, (struct sockaddr*)&sa, &sa_len) == 0 &&
        sa.sin_family == AF_INET && sa.sin_addr.s_addr != 0)
    {
        uint32_t ip = ntohl(sa.sin_addr.s_addr);
        int is_private = ((ip >> 24) == 10) ||
                         ((ip & 0xFFF00000) == 0xAC100000) ||
                         ((ip >> 16) == (192 << 8 | 168));
        if (is_private && ip != ntohl(eee->device.ip_addr)) {
            eee->local_sock.family = AF_INET;
            eee->local_sock.port   = local_port;
            memcpy(eee->local_sock.addr.v4, &sa.sin_addr.s_addr, IPV4_SIZE);
            eee->local_sock_ena = 1;
        }
    }
    closesocket(fd);

    if (eee->local_sock_ena)
        traceEvent(TRACE_NORMAL, "Local lan socket: %s",
                   sock_to_cstr(sockbuf, &eee->local_sock));
    else
        traceEvent(TRACE_WARNING, "set_localip: no private lan address found");
    
    /* Collect additional local IPs for multi-homed hosts */
    eee->local_socks_count = 0;
    
#ifdef _WIN32
    /* Windows: use GetAdaptersAddresses */
    ULONG buflen = 15000;
    IP_ADAPTER_ADDRESSES *pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(buflen);
    if (pAddresses && GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, NULL, pAddresses, &buflen) == NO_ERROR) {
        IP_ADAPTER_ADDRESSES *pCurrAddresses = pAddresses;
        while (pCurrAddresses && eee->local_socks_count < 3) {
            IP_ADAPTER_UNICAST_ADDRESS *pUnicast = pCurrAddresses->FirstUnicastAddress;
            while (pUnicast && eee->local_socks_count < 3) {
                if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                    struct sockaddr_in *pAddr = (struct sockaddr_in *)pUnicast->Address.lpSockaddr;
                    uint32_t addr_ip = ntohl(pAddr->sin_addr.s_addr);
                    int is_private = ((addr_ip >> 24) == 10) ||
                                     ((addr_ip & 0xFFF00000) == 0xAC100000) ||
                                     ((addr_ip >> 16) == (192 << 8 | 168));
                    if (!is_private || addr_ip == ntohl(eee->device.ip_addr)) {
                        pUnicast = pUnicast->Next;
                        continue;
                    }
                    /* Skip if same as local_sock */
                    if (eee->local_sock_ena && memcmp(&pAddr->sin_addr.s_addr, eee->local_sock.addr.v4, IPV4_SIZE) == 0) {
                        pUnicast = pUnicast->Next;
                        continue;
                    }
                    eee->local_socks[eee->local_socks_count].family = AF_INET;
                    eee->local_socks[eee->local_socks_count].port = local_port;
                    memcpy(eee->local_socks[eee->local_socks_count].addr.v4, &pAddr->sin_addr.s_addr, IPV4_SIZE);
                    eee->local_socks_count++;
                    traceEvent(TRACE_INFO, "Additional local IP: %s",
                               sock_to_cstr(sockbuf, &eee->local_socks[eee->local_socks_count-1]));
                }
                pUnicast = pUnicast->Next;
            }
            pCurrAddresses = pCurrAddresses->Next;
        }
        free(pAddresses);
    }
#else
    /* Linux/Unix: use getifaddrs */
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == 0) {
        for (ifa = ifaddr; ifa != NULL && eee->local_socks_count < 3; ifa = ifa->ifa_next) {
            struct sockaddr_in *pAddr;
            uint32_t addr_ip;
            int is_private;
            
            if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET)
                continue;
            /* Skip loopback and n2n interface */
            if (ifa->ifa_flags & IFF_LOOPBACK)
                continue;
            if (strncmp(ifa->ifa_name, "n2n", 3) == 0 || strncmp(ifa->ifa_name, "tun", 3) == 0)
                continue;
            /* Skip interfaces without broadcast (point-to-point, VPN) */
            if (!(ifa->ifa_flags & IFF_BROADCAST))
                continue;
            
            pAddr = (struct sockaddr_in *)ifa->ifa_addr;
            addr_ip = ntohl(pAddr->sin_addr.s_addr);
            is_private = ((addr_ip >> 24) == 10) ||
                         ((addr_ip & 0xFFF00000) == 0xAC100000) ||
                         ((addr_ip >> 16) == (192 << 8 | 168));
            if (is_private && addr_ip != ntohl(eee->device.ip_addr)) {
                /* Skip if same as local_sock */
                if (eee->local_sock_ena && memcmp(&pAddr->sin_addr.s_addr, eee->local_sock.addr.v4, IPV4_SIZE) == 0)
                    continue;
                eee->local_socks[eee->local_socks_count].family = AF_INET;
                eee->local_socks[eee->local_socks_count].port = local_port;
                memcpy(eee->local_socks[eee->local_socks_count].addr.v4, &pAddr->sin_addr.s_addr, IPV4_SIZE);
                eee->local_socks_count++;
                traceEvent(TRACE_INFO, "Additional local IP: %s",
                           sock_to_cstr(sockbuf, &eee->local_socks[eee->local_socks_count-1]));
            }
        }
        freeifaddrs(ifaddr);
    }
#endif
    if (eee->local_socks_count > 0)
        traceEvent(TRACE_NORMAL, "Found %d additional local IP(s)", eee->local_socks_count);
}

/** Send a QUERY_PEER packet to supernode asking for target's address. */
static void send_query_peer( n2n_edge_t * eee, const n2n_mac_t targetMac )
{
    uint8_t          pktbuf[N2N_PKT_BUF_SIZE];
    size_t           idx = 0;
    n2n_common_t     cmn;
    n2n_QUERY_PEER_t query;

    memset(&cmn, 0, sizeof(cmn));
    cmn.ttl = N2N_DEFAULT_TTL;
    cmn.pc  = n2n_query_peer;
    cmn.flags = 0;
    memcpy(cmn.community, eee->community_name, N2N_COMMUNITY_SIZE);

    memcpy(query.srcMac,    eee->device.mac_addr, N2N_MAC_SIZE);
    memcpy(query.targetMac, targetMac,            N2N_MAC_SIZE);

    encode_QUERY_PEER(pktbuf, &idx, &cmn, &query);
    edge_send_to_sn(eee, pktbuf, idx);
}

/** Send a REGISTER_SUPER packet to the current supernode. */
static void send_register_super( n2n_edge_t * eee,
                                const n2n_sock_t * supernode)
{
    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx;
    n2n_common_t cmn;
    n2n_REGISTER_SUPER_t reg;
    n2n_sock_str_t sockbuf;

    memset(&cmn, 0, sizeof(cmn) );
    memset(&reg, 0, sizeof(reg) );
    cmn.ttl=N2N_DEFAULT_TTL;
    cmn.pc = n2n_register_super;
    cmn.flags = 0;
    memcpy( cmn.community, eee->community_name, N2N_COMMUNITY_SIZE );

    /* Generate cookie once; both primary and alt address use the same cookie
     * so both ACKs pass the cookie check and neither triggers a spurious warning. */
    random_bytes(NULL, eee->last_cookie, N2N_COOKIE_SIZE);
    eee->sn_ack_count = 0; /* reset duplicate-ACK counter */

    memcpy( reg.cookie, eee->last_cookie, N2N_COOKIE_SIZE );
    reg.auth.scheme=0; /* No auth yet */

    idx=0;
    encode_mac( reg.edgeMac, &idx, eee->device.mac_addr );

    /* Fill dev_addr: net_addr=0 means request auto-assign from supernode */
    reg.dev_addr.net_addr = default_ip_assignment ? 0 : ntohl(eee->device.ip_addr);
    reg.dev_addr.net_bitlen = eee->device.ip_prefixlen;

    /* Attach LAN address for same-NAT direct connect */
    if (eee->local_sock_ena) {
        reg.aflags    |= N2N_AFLAGS_LOCAL_SOCKET;
        reg.local_sock = eee->local_sock;
    }

    /* Report our routable global IPv6 (GUA) to the supernode. When the
     * supernode is IPv4-only it cannot observe our IPv6 itself, so it
     * relies on this reported address to hand to peers for IPv6 hole-
     * punching. Only reported if we actually have a GUA. */
    if (eee->own_ipv6.family == AF_INET6) {
        reg.aflags |= N2N_AFLAGS_IPV6_SOCKET;
        reg.own_ipv6 = eee->own_ipv6;
    }

    /* Request full peer list push when "f" sync is in progress */
    if (eee->peer_sync_active) {
        reg.aflags |= N2N_AFLAGS_FORCE_PEER_INFO;
    }

    /* Gaming mode: first registration asks SN to push all peers */
    if (eee->enable_gaming_mode && !eee->gaming_started) {
        reg.aflags |= N2N_AFLAGS_FORCE_PEER_INFO;
        eee->gaming_started = 1;
    }

    idx=0;
    encode_REGISTER_SUPER( pktbuf, &idx, &cmn, &reg );

    traceEvent( TRACE_INFO, "send REGISTER_SUPER to %s",
        sock_to_cstr( sockbuf, supernode ) );

    edge_send_to_sn(eee, pktbuf, idx);

    /* Also register via alternate address family so supernode knows both our addresses.
     * WS mode only uses a single WS connection, skip alt family registration.
     * Only send if alternate family differs from primary to avoid duplicate registrations. */
    if (!eee->use_ws && eee->supernode_alt.family != 0 && eee->supernode_alt.family != supernode->family) {
        SOCKET alt_sock = (eee->supernode_alt.family == AF_INET6) ? eee->udp_sock6 : eee->udp_sock;
        if (alt_sock != -1) {
            traceEvent(TRACE_INFO, "send REGISTER_SUPER (alt) to %s",
                       sock_to_cstr(sockbuf, &eee->supernode_alt));
            sendto_sock(alt_sock, pktbuf, idx, &eee->supernode_alt);
        }
    }
}

/** Send a REGISTER_ACK packet to a peer edge. */
static void send_register_ack( n2n_edge_t * eee,
                               const n2n_sock_t * remote_peer,
                               const n2n_REGISTER_t * reg )
{
    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx;
    n2n_common_t cmn;
    n2n_REGISTER_ACK_t ack;
    n2n_sock_str_t sockbuf;

    memset(&cmn, 0, sizeof(cmn) );
    memset(&ack, 0, sizeof(ack) );
    cmn.ttl=N2N_DEFAULT_TTL;
    cmn.pc = n2n_register_ack;
    cmn.flags = 0;
    memcpy( cmn.community, eee->community_name, N2N_COMMUNITY_SIZE );

    memcpy( ack.cookie, reg->cookie, N2N_COOKIE_SIZE );
    memcpy( ack.srcMac, eee->device.mac_addr, N2N_MAC_SIZE );
    memcpy( ack.dstMac, reg->srcMac, N2N_MAC_SIZE );

    idx=0;
    encode_REGISTER_ACK( pktbuf, &idx, &cmn, &ack );

    traceEvent( TRACE_INFO, "send REGISTER_ACK %s",
        sock_to_cstr( sockbuf, remote_peer ) );


    sendto_sock( sock_for_dest(eee, remote_peer), pktbuf, idx, remote_peer );
}


/** Send a DEREGISTER packet to supernode and all known peers to notify going offline. */
static void send_deregister(n2n_edge_t * eee,
    n2n_sock_t * remote_peer)
{
    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx;
    n2n_common_t cmn;
    n2n_DEREGISTER_t reg;

    memset(&cmn, 0, sizeof(cmn));
    memset(&reg, 0, sizeof(reg));
    cmn.ttl = N2N_DEFAULT_TTL;
    cmn.pc  = n2n_deregister;
    cmn.flags = 0;
    memcpy(cmn.community, eee->community_name, N2N_COMMUNITY_SIZE);
    memcpy(reg.srcMac, eee->device.mac_addr, N2N_MAC_SIZE);

    idx = 0;
    encode_DEREGISTER(pktbuf, &idx, &cmn, &reg);
    sendto_sock(sock_for_dest(eee, remote_peer), pktbuf, idx, remote_peer);
}

/** Send a PROBE packet directly to a peer to open NAT mapping */
static void send_probe( n2n_edge_t * eee, const n2n_sock_t * peer_sock, const n2n_mac_t dstMac )
{
    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx = 0;
    n2n_common_t cmn;
    n2n_PROBE_t probe;
    n2n_sock_str_t sockbuf;

    memset(&cmn, 0, sizeof(cmn));
    cmn.ttl = N2N_DEFAULT_TTL;
    cmn.pc = n2n_probe;
    cmn.flags = 0;
    memcpy(cmn.community, eee->community_name, N2N_COMMUNITY_SIZE);

    memcpy(probe.srcMac, eee->device.mac_addr, N2N_MAC_SIZE);
    memcpy(probe.dstMac, dstMac, N2N_MAC_SIZE);

    encode_PROBE(pktbuf, &idx, &cmn, &probe);

    traceEvent(TRACE_INFO, "send PROBE to %s", sock_to_cstr(sockbuf, peer_sock));
    sendto_sock(sock_for_dest(eee, peer_sock), pktbuf, idx, peer_sock);
}

/** Send PROBE_ACK directly to peer: tell srcMac what addr we observed from their PROBE */
static void send_probe_ack( n2n_edge_t * eee,
                            const n2n_mac_t srcMac,
                            const n2n_sock_t * observed_addr )
{
    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx = 0;
    n2n_common_t cmn;
    n2n_PROBE_ACK_t ack;

    memset(&cmn, 0, sizeof(cmn));
    cmn.ttl = N2N_DEFAULT_TTL;
    cmn.pc = n2n_probe_ack;
    cmn.flags = 0;
    memcpy(cmn.community, eee->community_name, N2N_COMMUNITY_SIZE);

    memcpy(ack.srcMac, srcMac, N2N_MAC_SIZE);
    memcpy(ack.dstMac, eee->device.mac_addr, N2N_MAC_SIZE);
    ack.observed_addr = *observed_addr;

    encode_PROBE_ACK(pktbuf, &idx, &cmn, &ack);

    {
        MACSTR_TMP(mac_tmp);
        traceEvent(TRACE_INFO, "send PROBE_ACK direct to %s",
                   macaddr_str(mac_tmp, srcMac));
    }
    sendto_sock(sock_for_dest(eee, observed_addr), pktbuf, idx, observed_addr);
}

static int is_empty_ip_address( const n2n_sock_t * sock );

/** Start hole-punch for a peer: send PROBE directly, record punch start time */
static void start_punch( n2n_edge_t * eee, struct peer_info * peer )
{
    MACSTR_TMP(mac_tmp);

    if (eee->use_ws) return;  /* WS mode: no P2P hole-punching */

    if ( peer->punch_failed ) return;           /* already gave up */
    if ( peer->punch_start_time != 0 ) return;  /* already in progress */

    int we_have_ipv4 = (eee->udp_sock != -1);
    int we_have_ipv6 = (eee->udp_sock6 != -1);
    int peer_has_ipv4 = (peer->sock.family == AF_INET);
    int peer_has_ipv6 = (peer->sock6.family == AF_INET6);

    /* Cross-protocol: no punch if protocols don't match */
    if (!we_have_ipv4 && !we_have_ipv6) return;
    if (peer_has_ipv4 && !we_have_ipv4 && !peer_has_ipv6) return;
    if (peer_has_ipv6 && !we_have_ipv6 && !peer_has_ipv4) return;

    int punched = 0;
    
    /* Try IPv4 punch if both sides have IPv4 */
    if ( peer_has_ipv4 && we_have_ipv4 ) {
        send_probe(eee, &peer->sock, peer->mac_addr);
        punched = 1;
        traceEvent(TRACE_INFO, "IPv4 hole-punch started for %s",
                   macaddr_str(mac_tmp, peer->mac_addr));
    }
    
    /* Try IPv6 punch if both sides have IPv6 */
    if ( peer_has_ipv6 && we_have_ipv6 ) {
        send_probe(eee, &peer->sock6, peer->mac_addr);
        punched = 1;
        traceEvent(TRACE_INFO, "IPv6 hole-punch started for %s",
                   macaddr_str(mac_tmp, peer->mac_addr));
    }
    
    if (punched) {
        peer->punch_start_time = n2n_now();
        peer->last_punch_probe = peer->punch_start_time;
    }
}

/** Check punch timeouts in pending_peers: give up after PUNCH_TIMEOUT seconds,
 *  but reset and retry every 5 minutes in case NAT conditions change. */
static void check_punch_timeouts( n2n_edge_t * eee, time_t now )
{
    struct peer_info * scan = eee->pending_peers;
    struct peer_info * prev = NULL;
    MACSTR_TMP(mac_tmp);
    while ( scan ) {
        /* LAN punch phase: retransmit REGISTER to LAN address */
        if ( scan->num_sockets == 2 && !scan->lan_punch_done &&
             scan->lan_punch_start != 0 )
        {
            time_t lan_elapsed = now - scan->lan_punch_start;
            
            /* Retransmit REGISTER every 1s for first 3s */
            if ( lan_elapsed < 3 && (now - scan->last_seen) >= 1 )
            {
                /* Use temp_local_sock if valid (dynamically selected best IP) */
                if (scan->temp_local_sock_valid) {
                    send_register_with_local(eee, &scan->sockets[1], &scan->temp_local_sock);
                } else {
                    send_register(eee, &scan->sockets[1]);
                }
                scan->last_seen = now;
            }
            
            /* LAN punch timeout: fall back to WAN punch */
            if ( lan_elapsed >= 3 )
            {
                scan->lan_punch_done = 1;
                traceEvent(TRACE_INFO, "LAN punch timeout for %s - trying WAN",
                           macaddr_str(mac_tmp, scan->mac_addr));
                send_register(eee, &scan->sockets[0]);
                send_register(eee, &(eee->supernode));
                start_punch(eee, scan);
            }
        }

        if ( scan->punch_start_time != 0 &&
             !scan->punch_failed &&
             (now - scan->punch_start_time) > PUNCH_TIMEOUT )
        {
            scan->punch_failed = 1;
            scan->punch_reset_time = now;
            if (memcmp(scan->mac_addr, eee->last_psp_log_mac, N2N_MAC_SIZE)) {
                traceEvent(TRACE_NORMAL, "PsP (supernode relay) for %s",
                           PEER_ID(mac_tmp, scan));
                memcpy(eee->last_psp_log_mac, scan->mac_addr, N2N_MAC_SIZE);
            }
        } else if ( scan->punch_start_time != 0 &&
                    !scan->punch_failed &&
                    (now - scan->punch_start_time) <= 5 &&
                    (now - scan->last_punch_probe) >= 1 )
        {
            /* Retransmit PROBE every 1s for first 5s */
            int sent_probe = 0;
            
            /* Try IPv4 if available */
            if ( scan->sock.family == AF_INET && eee->udp_sock != -1 ) {
                send_probe(eee, &scan->sock, scan->mac_addr);
                sent_probe = 1;
            }
            
            /* Try IPv6 if available */
            if ( scan->sock6.family == AF_INET6 && eee->udp_sock6 != -1 ) {
                send_probe(eee, &scan->sock6, scan->mac_addr);
                sent_probe = 1;
            }
            
            if (sent_probe) {
                scan->last_punch_probe = now;
            }
        } else if ( scan->register_retry_count > 0 && !scan->punch_failed )
        {
            if ( scan->register_retry_count < 3 &&
                 (now - scan->last_register_sent) >= 1 )
            {
                n2n_sock_t *target_addr = (scan->sock.family == AF_INET) ? &scan->sock : &scan->sock6;
                if (target_addr->family != 0) {
                    send_register(eee, target_addr);
                    send_register(eee, &(eee->supernode));
                }
                scan->register_retry_count++;
                scan->last_register_sent = now;
                traceEvent(TRACE_INFO, "REGISTER retry %u/3 for %s",
                           scan->register_retry_count,
                           macaddr_str(mac_tmp, scan->mac_addr));
            }
            else if ( scan->register_retry_count >= 3 &&
                      (now - scan->last_register_sent) >= 1 )
            {
                scan->punch_failed = 1;
                scan->punch_reset_time = now;
                scan->register_retry_count = 0;
                if (!scan->psp_logged) {
                    traceEvent(TRACE_NORMAL, "REGISTER retries exhausted for %s, PsP",
                               PEER_ID(mac_tmp, scan));
                    scan->psp_logged = 1;
                }
            }
        } else if ( scan->punch_start_time == 0 && !scan->punch_failed &&
                    scan->last_seen != 0 &&
                    (now - scan->last_seen) > 1800 )
        {
            traceEvent(TRACE_NORMAL, "Removing stuck pending peer %s (no punch possible, idle %lus)",
                       PEER_ID(mac_tmp, scan),
                       (unsigned long)(now - scan->last_seen));
            struct peer_info *tmp = scan;
            if ( prev ) prev->next = scan->next;
            else eee->pending_peers = scan->next;
            scan = scan->next;
            free(tmp);
            continue;
        } else if ( scan->punch_failed )
        {
            if ( scan->punch_retry_count >= 3 ) {
                prev = scan;
                scan = scan->next;
                continue;
            }
            if ( (now - scan->punch_reset_time) > 40 )
            {
                scan->punch_retry_count++;
                if ( scan->punch_retry_count >= 3 ) {
                    traceEvent(TRACE_NORMAL, "Giving up on %s after %u punch retries, relay only",
                               PEER_ID(mac_tmp, scan),
                               scan->punch_retry_count);
                    prev = scan;
                    scan = scan->next;
                    continue;
                }
                scan->punch_failed = 0;
                scan->punch_start_time = 0;
                scan->lan_punch_done = 0;
                scan->lan_punch_start = 0;
                scan->register_retry_count = 0;
                scan->psp_logged = 0;
                traceEvent(TRACE_INFO, "Retrying P2P punch for %s (attempt %u/3)",
                           PEER_ID(mac_tmp, scan),
                           scan->punch_retry_count);
                start_punch(eee, scan);
            }
        }
        prev = scan;
        scan = scan->next;
    }
}

#define KEEPALIVE_IDLE_SECONDS   8    /* send probe after this many seconds of silence */
#define KEEPALIVE_RETRY_INTERVAL  2   /* seconds between retries */
#define KEEPALIVE_MAX_FAILS       3   /* fall back to relay after this many consecutive failures */
#define KEEPALIVE_TOTAL_TIMEOUT   (KEEPALIVE_IDLE_SECONDS + KEEPALIVE_RETRY_INTERVAL * KEEPALIVE_MAX_FAILS)  /* 14s */
#define P2P_EST_GRACE           1    /* sec: after P2P established, keep relay for this long */

static void update_peer_address(n2n_edge_t * eee,
                                uint8_t from_supernode,
                                const n2n_mac_t mac,
                                const n2n_sock_t * peer,
                                time_t when);

/** @brief Check peer liveness and fall back to relay if P2P is dead.
 *
 *  For each peer in known_peers with established P2P (direct_seen > 0):
 *  - If edge-level data is flowing (total TX/RX changed), skip keepalive.
 *  - If idle too long, send PROBE directly to peer's P2P address.
 *  - After KEEPALIVE_MAX_FAILS consecutive failures, clear P2P state
 *    (direct_seen=0) so find_peer_destination falls back to relay.
 *  - Peer stays in known_peers — relay works immediately while
 *    QUERY_PEER re-establishes P2P in the background. */
static void check_keepalive( n2n_edge_t * eee, time_t now )
{
    struct peer_info *scan = eee->known_peers;
    MACSTR_TMP(mac_tmp);

    /* WS mode: skip P2P keepalive — all traffic goes via supernode */
    if (eee->use_ws)
        return;

    /* Per-peer keepalive: each peer is checked individually based on its own
     * last_seen time. A peer actively receiving traffic will not receive probes. */

    while ( scan ) {
        struct peer_info *next = scan->next;
        time_t idle = now - scan->last_seen;

        /* Only run keepalive for peers that have established P2P.
         * For such peers: skip keepalive if direct P2P traffic is flowing.
         * direct_seen is updated by P2P packets only (handle_PACKET), so
         * relay traffic and other peers' activity do NOT mask this peer's
         * silence — each peer pair is kept alive independently. */
        if (scan->direct_seen > 0) {
            if ((now - scan->direct_seen) < KEEPALIVE_IDLE_SECONDS) {
                /* Recent direct traffic: peer is alive, skip probe */
                scan = next;
                continue;
            }
        } else {
            /* Relay peer: detect broken relay path.
             * Since PEER_INFO no longer updates last_seen, this correctly
             * reflects the time since we last received a packet FROM the peer.
             * If idle > 60s and we haven't recently re-registered (30s rate
             * limit), force supernode re-registration + query peer to
             * re-discover the peer's status.
             * While relayed, send periodic gratuitous ARP (~10s) to keep
              * NAT mappings fresh on intermediate routers (gaming mode only). */
             if (eee->enable_gaming_mode && idle >= 10 &&
                 (scan->last_probe_sent == 0 || (now - scan->last_probe_sent) >= 10)) {
                /* Send GARP through relay to keep NAT alive */
                uint8_t arp[42];
                memset(arp, 0, sizeof(arp));
                memcpy(arp,   scan->mac_addr, 6);              /* dst: peer's MAC */
                memcpy(arp+6, eee->device.mac_addr, 6);        /* src: our MAC */
                arp[12] = 0x08; arp[13] = 0x06;                /* EtherType: ARP */
                arp[14] = 0x00; arp[15] = 0x01;                /* HW type: Ethernet */
                arp[16] = 0x08; arp[17] = 0x00;                /* Protocol: IPv4 */
                arp[18] = 6;    arp[19] = 4;                   /* HW size, Proto size */
                arp[20] = 0x00; arp[21] = 0x02;                /* Opcode: Reply (gratuitous) */
                memcpy(arp+22, eee->device.mac_addr, 6);       /* sender MAC: ours */
                memcpy(arp+28, &eee->device.ip_addr, 4);       /* sender IP: ours */
                memcpy(arp+32, scan->mac_addr, 6);             /* target MAC: peer */
                memcpy(arp+38, &eee->device.ip_addr, 4);       /* target IP: ours (gratuitous) */
                send_packet2net(eee, arp, sizeof(arp));
                scan->last_probe_sent = now;
                traceEvent(TRACE_DEBUG, "Relay GARP sent to %s (idle %lds)",
                           macaddr_str(mac_tmp, scan->mac_addr), (long)idle);
            }
            if (idle > 60 && (now - eee->last_register_req) > 30) {
                traceEvent(TRACE_NORMAL, "Relay check: peer %s unreachable for %lds, querying supernode",
                           PEER_ID(mac_tmp, scan), (long)idle);
                eee->last_register_req = 0;
                send_query_peer(eee, scan->mac_addr);
            }
            scan = next;
            continue;
        }

        /* Skip keepalive if this peer has received any traffic recently */
        if (idle < KEEPALIVE_IDLE_SECONDS) {
            scan = next;
            continue;
        }

        /* Determine which address to use for keepalive (prefer IPv4 if available) */
        /* Note: each peer only has ONE active address (either IPv4 or IPv6) */
        n2n_sock_t *keepalive_addr = NULL;
        if ( scan->sock.family == AF_INET && eee->udp_sock != -1 ) {
            keepalive_addr = &scan->sock;
        } else if ( scan->sock6.family == AF_INET6 && eee->udp_sock6 != -1 ) {
            keepalive_addr = &scan->sock6;
        }
        
        if ( !keepalive_addr ) {
            /* No valid address for keepalive */
            scan = next;
            continue;
        }

        if ( scan->last_probe_sent == 0 ) {
            /* No probe sent yet: send one if idle too long */
            if ( idle >= KEEPALIVE_IDLE_SECONDS ) {
                n2n_common_t cmn;
                n2n_PROBE_t probe;
                uint8_t pktbuf[N2N_PKT_BUF_SIZE];
                size_t idx = 0;

                memset(&cmn, 0, sizeof(cmn));
                cmn.ttl = N2N_DEFAULT_TTL;
                cmn.pc  = n2n_probe;
                cmn.flags = 0;
                memcpy(cmn.community, eee->community_name, N2N_COMMUNITY_SIZE);
                memcpy(probe.srcMac, eee->device.mac_addr, N2N_MAC_SIZE);
                memcpy(probe.dstMac, scan->mac_addr, N2N_MAC_SIZE);

                encode_PROBE(pktbuf, &idx, &cmn, &probe);
                sendto_sock(sock_for_dest(eee, keepalive_addr), pktbuf, idx, keepalive_addr);

                scan->last_probe_sent = now;
                traceEvent(TRACE_INFO, "Keepalive PROBE sent to %s (idle %lds)",
                           macaddr_str(mac_tmp, scan->mac_addr), (long)idle);
            }
        } else {
            /* Probe already sent: check if a DIRECT reply came back.
             * Only a P2P packet (which updates direct_seen) counts as the
             * direct path being alive. Relay packets must NOT count —
             * they update last_seen but come via the supernode, so they
             * would falsely reset the probe while the direct path is
             * actually dead (e.g. peer lost its NAT mapping). */
            if ( scan->direct_seen >= scan->last_probe_sent ) {
                /* Got a direct reply: reset */
                scan->last_probe_sent = 0;
                scan->keepalive_fails = 0;
            } else if ( (now - scan->last_probe_sent) >= KEEPALIVE_RETRY_INTERVAL ) {
                /* No reply within timeout */
                scan->keepalive_fails++;
                scan->last_probe_sent = 0;

                traceEvent(TRACE_NORMAL, "Keepalive PROBE no reply from %s (fail %u/%u)",
                           PEER_ID(mac_tmp, scan),
                           scan->keepalive_fails, KEEPALIVE_MAX_FAILS);

                if ( scan->keepalive_fails >= KEEPALIVE_MAX_FAILS ) {
                    traceEvent(TRACE_NORMAL, "Keepalive: peer %s unreachable, clearing P2P state for relay",
                               PEER_ID(mac_tmp, scan));
                    /*
                     * Stay in known_peers — do NOT move to pending.
                     * Clearing direct_seen causes find_peer_destination to
                     * fall back to relay, which keeps the data path alive
                     * while we re-punch in the background via QUERY_PEER.
                     */
                    scan->direct_seen        = 0;
                    scan->punch_start_time   = 0;
                    scan->punch_failed       = 0;
                    scan->punch_retry_count  = 0;
                    scan->punch_reset_time   = 0;
                    scan->lan_punch_start    = 0;
                    scan->lan_punch_done     = 0;
                    scan->keepalive_fails    = 0;
                    scan->last_probe_sent    = 0;
                    scan->p2p_logged         = 0;
                    scan->psp_logged         = 0;
                    send_query_peer(eee, scan->mac_addr);
                    start_punch(eee, scan);
                    /* Force immediate supernode re-registration so the
                     * supernode gets our current NAT address. Without this,
                     * relayed replies from the peer would be forwarded to
                     * our old address until the next periodic re-registration
                     * (up to 30s + 3×12s retries). */
                    eee->last_register_req = 0;
                    /* Keep scan in known_peers — relay works immediately */
                    scan = next;
                    continue;
                }
            }
        }

        scan = next;
    }
}

/** Forward declarations for P2P registration functions. */
void try_send_register( n2n_edge_t * eee,
                        uint8_t from_supernode,
                        const n2n_mac_t mac,
                        const n2n_sock_t * peer );
void try_send_register_lan( n2n_edge_t * eee,
                        uint8_t from_supernode,
                        const n2n_mac_t mac,
                        const n2n_sock_t * peer,
                        const n2n_sock_t * local_sock );
void set_peer_operational( n2n_edge_t * eee,
                           const n2n_mac_t mac,
                           const n2n_sock_t * peer );



/** Start the registration process.
 *
 *  If the peer is already in pending_peers, ignore the request.
 *  If not in pending_peers, add it and send a REGISTER.
 *
 *  If hdr is for a direct peer-to-peer packet, try to register back to sender
 *  even if the MAC is in pending_peers. This is because an incident direct
 *  packet indicates that peer-to-peer exchange should work so more aggressive
 *  registration can be permitted (once per incoming packet) as this should only
 *  last for a small number of packets..
 *
 *  Called from the main loop when Rx a packet for our device mac.
 */
void try_send_register( n2n_edge_t * eee,
                        uint8_t from_supernode,
                        const n2n_mac_t mac,
                        const n2n_sock_t * peer )
{
    struct peer_info * scan = find_peer_by_mac( eee->pending_peers, mac );

    if ( NULL == scan ) {
        macstr_t mac_buf;
        n2n_sock_str_t sockbuf;

        scan = (struct peer_info*) calloc( 1, sizeof( struct peer_info ) );
        if (!scan) return;

        memcpy(scan->mac_addr, mac, N2N_MAC_SIZE);
        
        /* Store address in correct slot based on family - don't clear the other */
        if (peer->family == AF_INET6) {
            scan->sock6 = *peer;
        } else {
            scan->sock = *peer;
        }
        
        scan->last_seen = n2n_now();
        scan->punch_start_time = 0;
        scan->punch_failed = 0;
        scan->register_retry_count = 0;

        strncpy(scan->version, n2n_sw_version, sizeof(scan->version) - 1);
        strncpy(scan->os_name, n2n_sw_osName, sizeof(scan->os_name) - 1);

        peer_list_add( &(eee->pending_peers), scan );

        /* Send REGISTER directly to peer (punch hole) and also via supernode */
        if ( from_supernode ) {
            send_register(eee, peer);
            send_register(eee, &(eee->supernode) );
        } else {
            send_register(eee, peer);
        }

        /* Start parallel hole-punch if different public IP */
        start_punch(eee, scan);

    } else {
        /* Already pending: update address based on family - preserve other family */
        n2n_sock_t *target_sock = (peer->family == AF_INET6) ? &scan->sock6 : &scan->sock;
        
        if ( sock_equal(target_sock, peer) != 0 ) {
            *target_sock = *peer;
            scan->num_sockets = 1;
            scan->sockets[0] = *peer;
            scan->punch_start_time = 0;
            scan->punch_failed = 0;
            scan->register_retry_count = 0;
            scan->punch_retry_count = 0;
            scan->punch_reset_time = 0;
            scan->lan_punch_start = 0;
            scan->lan_punch_done = 0;
            scan->psp_logged = 0;
            send_register(eee, peer);
            send_register(eee, &(eee->supernode));
            start_punch(eee, scan);
        } else if ( scan->punch_start_time == 0 && !scan->punch_failed ) {
            scan->psp_logged = 0;
            start_punch(eee, scan);
        }
    }
}

/** Like try_send_register but tries LAN address first; WAN punch deferred
 *  until LAN times out (handled in check_punch_timeouts). */
void try_send_register_lan( n2n_edge_t * eee,
                        uint8_t from_supernode,
                        const n2n_mac_t mac,
                        const n2n_sock_t * peer,
                        const n2n_sock_t * local_sock )
{
    struct peer_info * scan = find_peer_by_mac( eee->pending_peers, mac );
    n2n_sock_t found_ip;
    n2n_sock_t best_local_sock;
    n2n_sock_str_t sockbuf;
    int found = 0;
    
    /* Dynamically find best local IP that matches peer's subnet */
    if (find_best_local_ip(eee, local_sock, &found_ip)) {
        /* Found a better IP, prepare it with correct port */
        best_local_sock.family = found_ip.family;
        memcpy(best_local_sock.addr.v4, found_ip.addr.v4, IPV4_SIZE);
        best_local_sock.port = eee->local_sock.port;  /* Use our own port */
        found = 1;
        traceEvent(TRACE_INFO, "Found better local IP %s for peer's subnet",
                   sock_to_cstr(sockbuf, &best_local_sock));
    }

    if ( NULL == scan ) {
        scan = (struct peer_info*) calloc( 1, sizeof( struct peer_info ) );
        if (!scan) return;

        memcpy(scan->mac_addr, mac, N2N_MAC_SIZE);
        /* Store address in correct slot based on family */
        if (peer->family == AF_INET6) {
            scan->sock6 = *peer;
        } else {
            scan->sock = *peer;
        }
        scan->num_sockets  = 2;
        scan->sockets[0]   = *peer;
        scan->sockets[1]   = *local_sock;
        scan->last_seen    = n2n_now();
        scan->lan_punch_start = n2n_now();
        scan->lan_punch_done  = 0;
        
        /* Save temp_local_sock for LAN punch retransmissions */
        if (found) {
            scan->temp_local_sock = best_local_sock;
            scan->temp_local_sock_valid = 1;
        } else {
            scan->temp_local_sock_valid = 0;
        }

        peer_list_add( &(eee->pending_peers), scan );
    } else {
        /* Update address in correct slot based on family */
        if (peer->family == AF_INET6) {
            scan->sock6 = *peer;
        } else {
            scan->sock = *peer;
        }
        scan->num_sockets = 2;
        scan->sockets[0]  = *peer;
        scan->sockets[1]  = *local_sock;
        scan->lan_punch_start = n2n_now();
        scan->lan_punch_done  = 0;
        scan->punch_start_time = 0;
        scan->punch_failed = 0;
        scan->register_retry_count = 0;
        scan->psp_logged = 0;
        
        /* Save temp_local_sock for LAN punch retransmissions */
        if (found) {
            scan->temp_local_sock = best_local_sock;
            scan->temp_local_sock_valid = 1;
        } else {
            scan->temp_local_sock_valid = 0;
        }
    }

    /* Send REGISTER to peer's LAN address, using best local IP if found */
    if (found) {
        send_register_with_local(eee, local_sock, &best_local_sock);
    } else {
        send_register(eee, local_sock);
    }
    
    {
        MACSTR_TMP(mac_tmp);
        traceEvent(TRACE_INFO, "LAN punch started for %s", macaddr_str(mac_tmp, mac));
    }
}

/* Move the peer from the pending_peers list to the known_peers lists.
 *
 * peer must be a pointer to an element of the pending_peers list.
 *
 * Called by main loop when Rx a REGISTER_ACK.
 */
void set_peer_operational( n2n_edge_t * eee,
                        const n2n_mac_t mac,
                        const n2n_sock_t * peer )
{
    struct peer_info * prev = NULL;
    struct peer_info * scan;
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;

    traceEvent( TRACE_INFO, "set_peer_operational: %s -> %s",
                macaddr_str( mac_buf, mac),
                sock_to_cstr( sockbuf, peer ) );

    scan=eee->pending_peers;

    while ( NULL != scan ) {
        if ( 0 == memcmp( scan->mac_addr, mac, N2N_MAC_SIZE ) ) {
            break; /* found. */
        }

        prev = scan;
        scan = scan->next;
    }

    if ( scan ) {
        /* Remove scan from pending_peers. */
        if ( prev ) {
            prev->next = scan->next;
        } else {
            eee->pending_peers = scan->next;
        }

        /* Add scan to known_peers. */
        scan->next = eee->known_peers;
        eee->known_peers = scan;

        /* Store address: each peer uses ONLY ONE protocol stack (first successful wins) */
        if (peer->family == AF_INET6) {
            scan->sock6 = *peer;
            memset(&scan->sock, 0, sizeof(n2n_sock_t));  /* Clear IPv4 completely */
        } else {
            scan->sock = *peer;
            memset(&scan->sock6, 0, sizeof(n2n_sock_t));  /* Clear IPv6 completely */
        }
        scan->last_seen = n2n_now();
        scan->direct_seen = n2n_now();
        scan->p2p_est_time = scan->direct_seen;
        scan->punch_start_time = 0;
        scan->punch_failed = 0;
        scan->register_retry_count = 0;
        scan->psp_logged = 0;

        if (memcmp(scan->mac_addr, eee->last_p2p_log_mac, N2N_MAC_SIZE) ||
            memcmp(peer, &eee->last_p2p_log_addr, sizeof(n2n_sock_t))) {
            /* New P2P connection or address changed — log it */
            char mac_buf[18];
            n2n_sock_str_t sockbuf;
            traceEvent( TRACE_NORMAL, "P2P direct with %s at %s",
                        PEER_ID(mac_buf, scan), sock_to_cstr( sockbuf, peer ) );
            memcpy(eee->last_p2p_log_mac, scan->mac_addr, N2N_MAC_SIZE);
            memcpy(&eee->last_p2p_log_addr, peer, sizeof(n2n_sock_t));
        }

        /* Send REGISTER back to confirm our new address to the peer */
        send_register( eee, peer );

        /* Send unicast gratuitous ARP Reply to the newly established peer so it
         * updates its ARP table with our MAC immediately (no waiting for ARP request). */
        {
            uint8_t arp[42];
            memset(arp, 0, sizeof(arp));
            memcpy(arp,   scan->mac_addr, 6);              /* dst: peer's MAC */
            memcpy(arp+6, eee->device.mac_addr, 6);        /* src: our MAC */
            arp[12] = 0x08; arp[13] = 0x06;               /* EtherType: ARP */
            arp[14] = 0x00; arp[15] = 0x01;               /* HW type: Ethernet */
            arp[16] = 0x08; arp[17] = 0x00;               /* Protocol: IPv4 */
            arp[18] = 6;    arp[19] = 4;                  /* HW size, Proto size */
            arp[20] = 0x00; arp[21] = 0x02;               /* Opcode: Reply (gratuitous) */
            memcpy(arp+22, eee->device.mac_addr, 6);       /* sender MAC: ours */
            memcpy(arp+28, &eee->device.ip_addr, 4);       /* sender IP: ours */
            memcpy(arp+32, scan->mac_addr, 6);             /* target MAC: peer */
            memcpy(arp+38, &eee->device.ip_addr, 4);       /* target IP: ours (gratuitous) */
            tuntap_write(&eee->device, arp, sizeof(arp));
        }

        traceEvent( TRACE_INFO, "Pending peers list size=%u",
                    (unsigned int)peer_list_size( eee->pending_peers ) );

        traceEvent( TRACE_INFO, "Operational peers list size=%u",
                    (unsigned int)peer_list_size( eee->known_peers ) );

        /* Start bypass negotiation for this peer if applicable.
         * Delayed by 2 seconds after P2P establishment (principle 10):
         * the actual check happens in the main loop via check_delayed_bypass(). */

    } else {
        /* Peer not in pending_peers - check if already in known_peers (late REGISTER_ACK) */
        scan = find_peer_by_mac(eee->known_peers, mac);
        if (scan) {
            /* Peer already operational. Check if we should upgrade to IPv4 (more reliable) */
            int current_is_ipv6 = (scan->sock6.family == AF_INET6 && scan->sock.family == 0);
            int new_is_ipv4 = (peer->family == AF_INET);
            
            if (current_is_ipv6 && new_is_ipv4) {
                /* Upgrade from IPv6 to IPv4 (better NAT traversal) */
                scan->sock = *peer;
                memset(&scan->sock6, 0, sizeof(n2n_sock_t));  /* Clear IPv6 completely */
                scan->last_seen = n2n_now();
                
                traceEvent( TRACE_NORMAL, "P2P upgraded to IPv4 for %s at %s (was IPv6)",
                            PEER_ID(mac_buf, scan),
                            sock_to_cstr( sockbuf, peer ) );
                
                /* Send REGISTER to confirm new address */
                send_register( eee, peer );
            } else {
                /* Already operational with same or better protocol - ignore duplicate REGISTER_ACK */
                traceEvent( TRACE_DEBUG, "Ignoring duplicate REGISTER_ACK for %s (already operational via %s)",
                            macaddr_str(mac_buf, mac),
                            (scan->sock.family == AF_INET) ? "IPv4" : "IPv6" );
            }
        } else {
            traceEvent( TRACE_DEBUG, "Failed to find sender in pending_peers or known_peers." );
        }
    }
}

n2n_mac_t broadcast_mac = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

static int is_empty_ip_address( const n2n_sock_t * sock )
{
    const uint8_t * ptr=NULL;
    size_t len=0;
    size_t i;

    if ( AF_INET6 == sock->family )
    {
        ptr = sock->addr.v6;
        len = 16;
    }
    else
    {
        ptr = sock->addr.v4;
        len = 4;
    }

    for (i=0; i<len; ++i)
    {
        if ( 0 != ptr[i] )
        {
            /* found a non-zero byte in address */
            return 0;
        }
    }

    return 1;
}

/** Keep the known_peers list straight.
 *
 *  Ignore broadcast L2 packets, and packets with invalid public_ip.
 *  If the dst_mac is in known_peers make sure the entry is correct:
 *  - if the public_ip socket has changed, erase the entry
 *  - if the same, update its last_seen = when
 */
static void update_peer_address(n2n_edge_t * eee,
                                uint8_t from_supernode,
                                const n2n_mac_t mac,
                                const n2n_sock_t * peer,
                                time_t when)
{
    struct peer_info *scan = eee->known_peers;
    struct peer_info *prev = NULL; /* use to remove bad registrations. */
    n2n_sock_str_t sockbuf1;
    n2n_sock_str_t sockbuf2; /* don't clobber sockbuf1 if writing two addresses to trace */
    macstr_t mac_buf;

    if (is_empty_ip_address(peer)) return;  /* Not to be registered. */
    if (0 == memcmp(mac, broadcast_mac, N2N_MAC_SIZE)) return;  /* Not to be registered. */


    while(scan != NULL)
    {
        if(memcmp(mac, scan->mac_addr, N2N_MAC_SIZE) == 0) break;
        prev = scan;
        scan = scan->next;
    }

    if (NULL == scan) return;  /* Not in known_peers. */

    if (scan->version[0] == '\0') {
        strncpy(scan->version, "unknown", sizeof(scan->version) - 1);
    }
    if (scan->os_name[0] == '\0') {
        strncpy(scan->os_name, "unknown", sizeof(scan->os_name) - 1);
    }

    /* Determine which address this peer is using (only ONE active) */
    n2n_sock_t *active_sock = NULL;
    int active_is_ipv4 = 0;
    
    if (scan->sock.family == AF_INET) {
        active_sock = &scan->sock;
        active_is_ipv4 = 1;
    } else if (scan->sock6.family == AF_INET6) {
        active_sock = &scan->sock6;
        active_is_ipv4 = 0;
    }
    
    if (!active_sock) {
        /* No active address - shouldn't happen for known_peers */
        traceEvent(TRACE_WARNING, "update_peer_address: peer %s has no active address",
                   macaddr_str(mac_buf, mac));
        return;
    }
    
    /* Only update if incoming packet matches the active protocol family */
    int incoming_is_ipv4 = (peer->family == AF_INET);
    
    if (active_is_ipv4 != incoming_is_ipv4) {
        /* Incoming packet uses different protocol than established connection.
         * This can happen if:
         * 1. Packet relayed via supernode (different path)
         * 2. Peer's address changed
         * Ignore it to maintain single-channel policy. */
        traceEvent(TRACE_DEBUG, "Ignoring %s packet from %s (peer uses %s)",
                   incoming_is_ipv4 ? "IPv4" : "IPv6",
                   macaddr_str(mac_buf, mac),
                   active_is_ipv4 ? "IPv4" : "IPv6");
        scan->last_seen = when;  /* Still update last_seen */
        return;
    }
    
    /* Same protocol family: update address if changed */
    if ( 0 != sock_equal( active_sock, peer))
    {
        if ( 0 == from_supernode )
        {
            /* Peer address changed but P2P is established: update in-place, no re-punch. */
            traceEvent( TRACE_INFO, "Peer addr updated %s: %s -> %s",
                        macaddr_str( mac_buf, scan->mac_addr ),
                        sock_to_cstr(sockbuf1, active_sock),
                        sock_to_cstr(sockbuf2, peer) );
            *active_sock = *peer;
        }
        else
        {
            /* Don't worry about what the supernode reports, it could be seeing a different socket. */
        }
    }
    else
    {
        /* Found and unchanged. */
        *active_sock = *peer;
    }
    scan->last_seen = when;
}

/** @brief Check to see if we should re-register with the supernode.
 *
 *  This is frequently called by the main loop.
 */
static void update_supernode_reg( n2n_edge_t * eee, time_t nowTime )
{
    if ( nowTime > (time_t) (eee->last_register_req + 30) )
    {
        eee->sn_wait = 0;
        eee->sup_attempts = N2N_EDGE_SUP_ATTEMPTS;
        send_register_super( eee, &(eee->supernode) );
        eee->sn_wait = 1;
        eee->last_register_req = nowTime;
        return;
    }

    if ( eee->sn_wait && ( nowTime > (time_t) (eee->last_register_req + (eee->register_lifetime/10) ) ) )
    {
        /* fall through - fast retry */
    }
    else if ( nowTime < (time_t) (eee->last_register_req + eee->register_lifetime))
    {
        return; /* Too early */
    }

    if ( 0 == eee->sup_attempts )
    {
        if ( eee->sn_num > 1 )
        {
            ++(eee->sn_idx);
            if (eee->sn_idx >= eee->sn_num) eee->sn_idx=0;
            traceEvent(TRACE_WARNING, "Supernode not responding - moving to %u of %u",
                       (unsigned int)eee->sn_idx, (unsigned int)eee->sn_num);
        } else {
            /* Single supernode: no point "switching", just retry */
            traceEvent(TRACE_DEBUG, "Supernode not responding - retrying same supernode");
        }
        eee->sup_attempts = N2N_EDGE_SUP_ATTEMPTS;

        /* Only re-open the UDP sockets when the supernode is unreachable AND
         * the local connection is completely dead (no P2P direct traffic and
         * no supernode traffic for a while). Re-opening changes the local UDP
         * port, which invalidates the NAT mapping of healthy P2P direct paths
         * — a busy supernode (e.g. evening peak) missing registration ACKs is
         * NOT a reason to disturb working direct links. But if everything is
         * truly dead, a fresh socket may clear a stale local state and help
         * reconnect to the supernode. */
        {
            int local_alive = 0;
            if (eee->last_p2p > 0 && (nowTime - eee->last_p2p) < 30)
                local_alive = 1;   /* recent direct traffic: local net is fine */
            else if (eee->last_sup > 0 && (nowTime - eee->last_sup) < 30)
                local_alive = 1;   /* recent supernode reply: local net is fine */

            if ( !local_alive && ( eee->local_port == 0 || eee->local_port > 1024 ) )
            {
                if (eee->udp_sock != -1) closesocket(eee->udp_sock);
                if (eee->udp_sock6 != -1) closesocket(eee->udp_sock6);
                eee->udp_sock  = open_socket(eee->local_port, 1);
                eee->udp_sock6 = open_socket6(eee->local_port, 1);
                traceEvent(TRACE_NORMAL, "Supernode unreachable and no local traffic: re-opened UDP sockets");
            }
        }

        /* Re-resolve supernode address when switching to a different supernode */
        if(eee->re_resolve_supernode_ip)
        {
            supernode2addr(&(eee->supernode), eee->sn_af, eee->sn_ip_array[eee->sn_idx]);
            
            /* Re-resolve alternate address for dual-stack registration */
            {
                int alt_af = (eee->supernode.family == AF_INET6) ? AF_INET : AF_INET6;
                int can_resolve = (alt_af == AF_INET6) ? (eee->udp_sock6 != -1) : (eee->udp_sock != -1);
                memset(&eee->supernode_alt, 0, sizeof(n2n_sock_t));
                if (can_resolve) {
                    supernode2addr(&eee->supernode_alt, alt_af, eee->sn_ip_array[eee->sn_idx]);
                }
            }
        }
    }
    else
    {
        --(eee->sup_attempts);
    }

    /* Note: Domain re-resolution during normal registration is handled by
     * check_supernode_domain_and_update() which runs every 300 seconds when idle. */

    send_register_super( eee, &(eee->supernode) );
    eee->sn_wait=1;
    eee->last_register_req = nowTime;
}

/* @return 1 if destination is a peer, 0 if destination is supernode */
static int find_peer_destination(n2n_edge_t * eee,
                                 n2n_mac_t mac_address,
                                 n2n_sock_t * destination)
{
    const struct peer_info *scan = eee->known_peers;
    macstr_t mac_buf;
    n2n_sock_str_t sockbuf;
    time_t now = n2n_now();
    int retval=0;

    traceEvent(TRACE_DEBUG, "Searching destination peer for MAC %02X:%02X:%02X:%02X:%02X:%02X",
               mac_address[0] & 0xFF, mac_address[1] & 0xFF, mac_address[2] & 0xFF,
               mac_address[3] & 0xFF, mac_address[4] & 0xFF, mac_address[5] & 0xFF);

    while(scan != NULL) {
        traceEvent(TRACE_DEBUG, "Evaluating peer [MAC=%02X:%02X:%02X:%02X:%02X:%02X]",
                   scan->mac_addr[0] & 0xFF, scan->mac_addr[1] & 0xFF, scan->mac_addr[2] & 0xFF,
                   scan->mac_addr[3] & 0xFF, scan->mac_addr[4] & 0xFF, scan->mac_addr[5] & 0xFF
            );

        if((scan->last_seen > 0) &&
           !scan->punch_failed &&
           (memcmp(mac_address, scan->mac_addr, N2N_MAC_SIZE) == 0))
        {
            /* If never had direct P2P communication, use relay */
            if (scan->direct_seen == 0) {
                traceEvent(TRACE_DEBUG, "find_peer_destination: no direct_seen yet, using relay");
                break;
            }

            /* P2P establishment grace period: for the first P2P_EST_GRACE seconds
             * after set_peer_operational, continue using relay. The first few P2P
             * packets may be lost before the direct path stabilizes (NAT mapping);
             * this gives the P2P path time to settle before we rely on it. */
            if ((now - scan->p2p_est_time) < P2P_EST_GRACE) {
                traceEvent(TRACE_DEBUG, "find_peer_destination: P2P established %lus ago, grace, relay",
                           (unsigned long)(now - scan->p2p_est_time));
                break;
            }

            /* If keepalive probe is pending and total timeout exceeded, fall back to relay.
             * Uses direct_seen (P2P packets only) — relay packets must not extend the
             * probe window, otherwise a dead direct path is never abandoned. */
            if (scan->last_probe_sent > 0 && (now - scan->direct_seen) > KEEPALIVE_TOTAL_TIMEOUT) {
                traceEvent(TRACE_DEBUG, "find_peer_destination: keepalive failed, using relay");
                break;
            }

            /* Keepalive is not probing (last_probe_sent == 0) — P2P path is alive.
             * Use the direct P2P address regardless of direct_seen age.
             * This keeps data and keepalive on the same path. */
            if (scan->sock.family == AF_INET && eee->udp_sock != -1) {
                memcpy(destination, &scan->sock, sizeof(n2n_sock_t));
            } else if (scan->sock6.family == AF_INET6 && eee->udp_sock6 != -1) {
                memcpy(destination, &scan->sock6, sizeof(n2n_sock_t));
            } else {
                /* No valid direct address available */
                break;
            }
            
            retval=1;
            break;
        }
        scan = scan->next;
    }

    if ( 0 == retval )
    {
        memcpy(destination, &(eee->supernode), sizeof(n2n_sock_t));
    }

    traceEvent(TRACE_DEBUG, "find_peer_address (%s) -> %s",
               macaddr_str( mac_buf, mac_address ),
               sock_to_cstr( sockbuf, destination ) );

    return retval;
}

/* *********************************************** */

static const struct option long_options[] = {
  { "community",       required_argument, NULL, 'c' },
  { "supernode-list",  required_argument, NULL, 'l' },
  { "tun-device",      required_argument, NULL, 'd' },
  { "euid",            required_argument, NULL, 'u' },
  { "egid",            required_argument, NULL, 'g' },
  { "help"   ,         no_argument,       NULL, 'h' },
  { "verbose",         no_argument,       NULL, 'v' },
  { "bypass",          optional_argument, NULL, 'b' },
  { "gaming",          no_argument,       NULL, 'G' },
  { NULL,              0,                 NULL,  0  }
};

/* ***************************************************** */

/** Send an ecapsulated ethernet PACKET to a destination edge or broadcast MAC
 *  address. */
static int send_PACKET( n2n_edge_t * eee,
                        n2n_mac_t dstMac,
                        const uint8_t * pktbuf,
                        size_t pktlen )
{
    int dest;
    n2n_sock_str_t sockbuf;
    n2n_sock_t destination;
    time_t now;

    /* hexdump( pktbuf, pktlen ); */

    now = n2n_now();

    /* No destination cache: look up the current destination on every packet.
     * The peer table always holds the freshest address (updated by the main
     * loop via PACKET piggybacking / REGISTER), so a restarted or NAT-mapped
     * peer is reached immediately, without waiting for a stale cache to expire.
     *
     * WS mode: completely disable P2P, force relay via supernode.
     *
     * Windows: TAP thread briefly blocks on PEERS_LOCK if the main loop
     * holds it — contention windows are microseconds (find_peer_destination
     * is a short list scan). Blocking is preferable to relaying: dropping a
     * packet to relay on lock contention would corrupt the P2P path. The
     * actual UDP send happens after the lock is released. */
    int probing = 0;
    if (eee->use_ws) {
        dest = 0;
        destination = eee->supernode;
        ++(eee->tx_sup); eee->super_tx_bytes += pktlen;
    } else {
        /* Both platforms: lock only covers the destination lookup, never
         * the send. Short critical section, no cache involved. */
        PEERS_LOCK(eee);
        dest = find_peer_destination(eee, dstMac, &destination);
        if (dest) {
            ++(eee->tx_p2p); eee->p2p_tx_bytes += pktlen;
            /* If keepalive is currently probing this peer (a PROBE was sent
             * and no direct reply yet), send data over BOTH the direct path
             * and the relay. This keeps the data flowing while the direct
             * path is being verified — no packets lost during the probe
             * window. The relay leg is dropped as soon as a direct reply
             * clears last_probe_sent. */
            struct peer_info *p = find_peer_by_mac(eee->known_peers, dstMac);
            if (p && p->last_probe_sent > 0)
                probing = 1;
        } else {
            ++(eee->tx_sup); eee->super_tx_bytes += pktlen;
            destination = eee->supernode;
        }
        PEERS_UNLOCK(eee);
    }

    traceEvent( TRACE_DEBUG, "send_PACKET to %s", sock_to_cstr( sockbuf, &destination ) );

    if (dest) {
        /* Direct path first */
        sendto_sock( sock_for_dest(eee, &destination), pktbuf, pktlen, &destination );
        if (probing) {
            /* Probe window: also relay via supernode so no data is lost
             * while the direct path is being verified. */
            if (edge_send_to_sn(eee, pktbuf, pktlen) <= 0) {
                if (++eee->sn_relay_fails >= 3)
                    eee->last_register_req = 0;
            } else {
                eee->sn_relay_fails = 0;
            }
            ++(eee->tx_sup); eee->super_tx_bytes += pktlen;
        }
    } else {
        /* Relay via supernode: WS mode uses ws_send, otherwise UDP */
        if (edge_send_to_sn(eee, pktbuf, pktlen) <= 0) {
            /* Consecutive failures trigger supernode re-registration */
            if (++eee->sn_relay_fails >= 3)
                eee->last_register_req = 0;
        } else {
            eee->sn_relay_fails = 0;
        }
    }

    /* If routing via supernode for a unicast peer, re-register with supernode
     * and query peer's latest address - triggers full reconnect like a restart. */
    if ( !dest && !is_multi_broadcast(dstMac) )
    {
        time_t now = n2n_now();
        PEERS_LOCK(eee);
        struct peer_info *p = find_peer_by_mac(eee->pending_peers, dstMac);
        if ( !p ) p = find_peer_by_mac(eee->known_peers, dstMac);
        int do_query;
        if ( !p ) {
            p = calloc(1, sizeof(struct peer_info));
            if (p) {
                memcpy(p->mac_addr, dstMac, N2N_MAC_SIZE);
                p->last_query_sent = now;
                p->last_seen = now;
                peer_list_add(&eee->pending_peers, p);
            }
            do_query = 1;
        } else {
            do_query = ((now - p->last_query_sent) >= 5);
            if (do_query)
                p->last_query_sent = now;
        }
        PEERS_UNLOCK(eee);

        if (do_query && p) {
            update_supernode_reg(eee, now);
            send_query_peer(eee, dstMac);
        }
    }

    return 0;
}

/* Choose the transop for Tx. This should be based on the newest valid
 * cipherspec in the key schedule.
 *
 * Never fall back to NULL tranform unless no key sources were specified. It is
 * better to render edge inoperative than to expose user data in the clear. In
 * the case where all SAs are expired an arbitrary transform will be chosen for
 * Tx. It will fail having no valid SAs but one must be selected.
 */
static size_t edge_choose_tx_transop( const n2n_edge_t * eee )
{
    if (eee->null_transop) return N2N_TRANSOP_NULL_IDX;
    return eee->tx_transop_idx;
}

/** A layer-2 packet was received at the tunnel and needs to be sent via UDP. */
static void send_packet2net(n2n_edge_t * eee,
                            uint8_t *tap_pkt, size_t len)
{
    ipstr_t ip_buf;
    n2n_mac_t destMac;

    n2n_common_t cmn;
    n2n_PACKET_t pkt;

    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx=0;
    size_t tx_transop_idx=0;

    ether_hdr_t eh;

    /* tap_pkt is not aligned so we have to copy to aligned memory */
    memcpy( &eh, tap_pkt, sizeof(ether_hdr_t) );

    /* Discard IP packets that are not originated by this hosts */
    if(!(eee->allow_routing)) {
        if(htons(0x0800) == eh.type) {
            /* This is an IP packet from the local source address - not forwarded. */
#define ETH_FRAMESIZE 14
#define IP4_SRCOFFSET 12
            uint32_t dst;
            memcpy(&dst, &tap_pkt[ETH_FRAMESIZE + IP4_SRCOFFSET], sizeof(dst));

            /* Note: all elements of the_ip are in network order */
            if( dst != eee->device.ip_addr) {
                /* This is a packet that needs to be routed */
                traceEvent(TRACE_INFO, "Discarding routed packet [%s]",
                           inet_ntop(AF_INET, &dst, ip_buf, sizeof(ip_buf)));
                return;
            } else {
                /* This packet is originated by us */
            }
        } else if(htons(0x86dd) == eh.type) {
            /* IPv6 package */
#define IP6_SRCOFFSET 8
            struct in6_addr dst6;
            memcpy(&dst6, &tap_pkt[ETH_FRAMESIZE + IP6_SRCOFFSET], sizeof(dst6));
            if( memcmp(&dst6, &eee->device.ip6_addr, IPV6_SIZE ) != 0 ) {
                traceEvent(TRACE_INFO, "Discarding routed packet [%s]",
                           inet_ntop(AF_INET6, &dst6, ip_buf, sizeof(ip_buf)));
                return;
            }
        }
    }

    /* Optionally compress then apply transforms, eg encryption. */

    memcpy( destMac, tap_pkt, N2N_MAC_SIZE );

    /* Once processed, send to destination in PACKET */
    tx_transop_idx = edge_choose_tx_transop( eee );

    /* Build the header from scratch on every packet.
     * No shared cache: send_packet2net is called from both the TAP thread
     * and the main loop thread, so a shared header template would be
     * written/read without locking (data race). All state here is local. */
    memset( &cmn, 0, sizeof(cmn) );
    cmn.ttl = N2N_DEFAULT_TTL;
    cmn.pc = n2n_packet;
    cmn.flags=0;
    memcpy( cmn.community, eee->community_name, N2N_COMMUNITY_SIZE );

    memset( &pkt, 0, sizeof(pkt) );
    memcpy( pkt.srcMac, eee->device.mac_addr, N2N_MAC_SIZE);
    memcpy( pkt.dstMac, destMac, N2N_MAC_SIZE);

    pkt.sock.family=0;
    pkt.transform = eee->transop[tx_transop_idx].transform_id;

    idx=0;
    encode_PACKET( pktbuf, &idx, &cmn, &pkt );

    traceEvent( TRACE_DEBUG, "encoded PACKET header of size=%u transform %u (idx=%u)",
                (unsigned int)idx, (unsigned int)eee->transop[tx_transop_idx].transform_id, (unsigned int)tx_transop_idx );

    idx += eee->transop[tx_transop_idx].fwd( &(eee->transop[tx_transop_idx]),
                                             pktbuf+idx, N2N_PKT_BUF_SIZE-idx,
                                             tap_pkt, len, destMac );
    ++(eee->transop[tx_transop_idx].tx_cnt); /* stats */

    send_PACKET( eee, destMac, pktbuf, idx ); /* to peer or supernode */
}

/** Destination MAC 33:33:0:00:00:00 - 33:33:FF:FF:FF:FF is reserved for IPv6
 *  neighbour discovery.
 */
static int is_ip6_discovery( const void * buf, size_t bufsize )
{
    int retval = 0;

    if ( bufsize >= sizeof(ether_hdr_t) )
    {
        /* copy to aligned memory */
        ether_hdr_t eh;
        memcpy( &eh, buf, sizeof(ether_hdr_t) );

        if ( (0x33 == eh.dhost[0]) &&
             (0x33 == eh.dhost[1]) )
        {
            retval = 1; /* This is an IPv6 multicast packet [RFC2464]. */
        }
    }
    return retval;
}

/** Destination 01:00:5E:00:00:00 - 01:00:5E:7F:FF:FF is multicast ethernet.
 */
static int is_ethMulticast( const void * buf, size_t bufsize )
{
    int retval = 0;

    /* Match 01:00:5E:00:00:00 - 01:00:5E:7F:FF:FF */
    if ( bufsize >= sizeof(ether_hdr_t) )
    {
        /* copy to aligned memory */
        ether_hdr_t eh;
        memcpy( &eh, buf, sizeof(ether_hdr_t) );

        if ( (0x01 == eh.dhost[0]) &&
             (0x00 == eh.dhost[1]) &&
             (0x5E == eh.dhost[2]) &&
             (0 == (0x80 & eh.dhost[3])) )
        {
            retval = 1; /* This is an ethernet multicast packet [RFC1112]. */
        }
    }
    return retval;
}

/** Read a single packet from the TAP interface, process it and write out the
 *  corresponding packet to the cooked socket.
 */
static void readFromTAPSocket( n2n_edge_t * eee )
{
    /* tun -> remote */
    uint8_t             eth_pkt[N2N_PKT_BUF_SIZE];
    macstr_t            mac_buf;
    ssize_t             len;
retry:
    len = tuntap_read( &(eee->device), eth_pkt, N2N_PKT_BUF_SIZE );

    if( (len <= 0) || (len > N2N_PKT_BUF_SIZE) )
    {
#ifdef _WIN32
        DWORD err = GetLastError();
        if (ERROR_OPERATION_ABORTED == err) {
            /* If the process is shutting down, don't restart - just exit. */
            if (!eee->keep_running)
                return;
retry2:
            traceEvent(TRACE_NORMAL, "Restart TAP device");
            if (tuntap_restart( &eee->device ) < 0) {
                if (!eee->keep_running)
                    return;
                Sleep(2000);
                goto retry2;
            }
            goto retry;
        }
        /* Non-critical errors (no data, etc.) are normal when idle. */
        if (err != ERROR_NO_DATA && err != ERROR_HANDLE_EOF) {
            W32_ERROR(err, error);
            traceEvent(TRACE_DEBUG, "read()=%d [%d/%ls]", (signed int)len, err, error);
            W32_ERROR_FREE(error);
        }
#else
        if (len < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return; /* no more frames available */
        traceEvent(TRACE_WARNING, "read()=%d [%d/%s]", (signed int)len, errno, strerror(errno));
#endif
    }
    else
        {
            const uint8_t * mac = eth_pkt;
            traceEvent(TRACE_DEBUG, "### Rx TAP packet (%4d) for %s",
                       (signed int)len, macaddr_str(mac_buf, mac) );

            /* don't filter ip6_discovery this is needed for ip6 connectivity */
            if ( eee->drop_multicast && (
                 is_ethMulticast( eth_pkt, len) /* || is_ip6_discovery( eth_pkt, len ) */
                ) )
            {
                traceEvent(TRACE_DEBUG, "Dropping multicast");
            }
            else
            {
                /* Try bypass first (ICMP to bypass-active peers) */
                if (!bypass_has_peers(eee->bp) || bypass_tap_forward(eee->bp, eth_pkt, len) == 0)
                    send_packet2net(eee, eth_pkt, len);
            }

            /* Drain more frames (TAP is non-blocking now) */
            for (int _di = 0; _di < 7; _di++) {
                ssize_t dlen = tuntap_read(&(eee->device), eth_pkt, N2N_PKT_BUF_SIZE);
                if (dlen <= 0) break;
                traceEvent(TRACE_DEBUG, "### Rx TAP packet (drain %d) for %s",
                           (signed int)dlen, macaddr_str(mac_buf, eth_pkt));
                if (!bypass_has_peers(eee->bp) || bypass_tap_forward(eee->bp, eth_pkt, dlen) == 0)
                    send_packet2net(eee, eth_pkt, dlen);
            }
        }
}

/** A PACKET has arrived containing an encapsulated ethernet datagram - usually
 *  encrypted. */
static int handle_PACKET( n2n_edge_t * eee,
                          const n2n_common_t * cmn,
                          const n2n_PACKET_t * pkt,
                          const n2n_sock_t * orig_sender,
                          uint8_t * payload,
                          size_t psize )
{
    ssize_t             data_sent_len;
    uint8_t             from_supernode;
    uint8_t *           eth_payload=NULL;
    int                 retval = -1;
    time_t              now;

    now = n2n_now();

    traceEvent( TRACE_DEBUG, "handle_PACKET size %u transform %u",
                (unsigned int)psize, (unsigned int)pkt->transform );
    /* hexdump( payload, psize ); */

    from_supernode= cmn->flags & N2N_FLAGS_FROM_SUPERNODE;

    if (from_supernode) {
        ++(eee->rx_sup);
        eee->super_rx_bytes += psize;
        eee->last_sup=now;
    } else {
        ++(eee->rx_p2p);
        eee->p2p_rx_bytes += psize;
        eee->last_p2p=now;
    }

    /* Update the sender in peer table entry */
    PEERS_LOCK(eee);
    struct peer_info *scan = find_peer_by_mac(eee->known_peers, pkt->srcMac);
    if (NULL == scan) {
        scan = find_peer_by_mac(eee->pending_peers, pkt->srcMac);
    }
    if (NULL == scan) {
        if (from_supernode) {
            /* Unknown peer sent via relay. Save its address so we can
             * contact it via relay in return. */
            macstr_t mac_buf;
            struct peer_info *p = (struct peer_info *)calloc(1, sizeof(struct peer_info));
            if (p) {
                memcpy(p->mac_addr, pkt->srcMac, N2N_MAC_SIZE);
                if (orig_sender->family == AF_INET6) {
                    p->sock6 = *orig_sender;
                    p->sock = *orig_sender;
                } else {
                    p->sock = *orig_sender;
                }
                p->sockets[0] = *orig_sender;
                p->num_sockets = 1;
                p->last_seen = now;
                peer_list_add(&eee->pending_peers, p);
                traceEvent(TRACE_DEBUG, "handle_PACKET: saved relayed peer %s",
                           macaddr_str(mac_buf, pkt->srcMac));
                /* A supernode that never pushes PEER_INFO (e.g. cnn2n)
                 * still relays PACKETs whose pkt.sock carries the real
                 * source address. Kick off hole punching immediately so
                 * we try to go direct instead of staying on relay. */
                if (orig_sender->family == AF_INET) {
                    try_send_register(eee, 1, pkt->srcMac, orig_sender);
                }
            }
        }
    } else if (!from_supernode) {
        /* P2P packet: refresh direct communication timestamp */
        scan->direct_seen = now;
        scan->last_probe_sent = 0;
        scan->keepalive_fails = 0;
        
        /* Check which protocol this peer is using */
        int peer_uses_ipv4 = (scan->sock.family == AF_INET);
        int peer_uses_ipv6 = (scan->sock6.family == AF_INET6);
        int packet_is_ipv4 = (orig_sender->family == AF_INET);
        
        /* Only update if packet matches peer's active protocol */
        if ((peer_uses_ipv4 && packet_is_ipv4) || (peer_uses_ipv6 && !packet_is_ipv4)) {
            n2n_sock_t *expected_sock = peer_uses_ipv4 ? &scan->sock : &scan->sock6;
            if (0 != sock_equal(expected_sock, orig_sender)) {
                /* Principle 13: peer's address changed during P2P communication.
                 * Update address and send REGISTER to confirm our reverse path. */
                update_peer_address(eee, from_supernode, pkt->srcMac, orig_sender, now);
                send_register(eee, orig_sender);
                send_register(eee, &(eee->supernode));
            } else {
                scan->last_seen = now;
            }
        } else {
            /* Packet from different protocol family - just update last_seen */
            scan->last_seen = now;
        }
    } else {
        /* Relayed packet from known peer.
         * If P2P has never been established (direct_seen == 0), the
         * peer's address in pkt->sock (from supernode) may be more
         * current — overwrite and trigger re-punch (Principle 13).
         *
         * If P2P has been established (direct_seen > 0), the stored
         * address is already correct. A relay packet is not evidence
         * of address change — overwriting would destroy the correct
         * address and cause unnecessary breakage (especially for LAN
         * peers where pkt->sock is the public address, not LAN addr).
         * Keepalive handles true P2P failure detection and recovery. */
        if (scan->direct_seen == 0 && !is_empty_ip_address(&pkt->sock)) {
            n2n_sock_t *active_sock = (scan->sock.family == AF_INET) ? &scan->sock : &scan->sock6;
            if (sock_equal(active_sock, &pkt->sock) != 0) {
                macstr_t mb;
                traceEvent(TRACE_INFO, "Peer %s addr from SN, updating",
                           macaddr_str(mb, pkt->srcMac));
                *active_sock = pkt->sock;
            }
        }
        scan->last_seen = now;
    }
    PEERS_UNLOCK(eee);

    /* Handle transform. */
    {
        uint8_t decodebuf[N2N_PKT_BUF_SIZE];
        size_t eth_size;
        int rx_transop_idx=0;

        rx_transop_idx = transop_enum_to_index(pkt->transform);

        /* Check encryption consistency: if peer uses a different transform
         * than our local configuration, we cannot decrypt it. */
        if ( pkt->transform != eee->transop[eee->tx_transop_idx].transform_id )
        {
            return -1;
        }

        if ( rx_transop_idx >= 0 )
        {
            eth_payload = decodebuf;
            eth_size = eee->transop[rx_transop_idx].rev( &(eee->transop[rx_transop_idx]),
                                                         eth_payload, N2N_PKT_BUF_SIZE,
                                                         payload, psize, pkt->srcMac );
            ++(eee->transop[rx_transop_idx].rx_cnt); /* stats */

            /* Write ethernet packet to tap device. */

            /* Extract sender's virtual IP from first packet if not yet known */
            if ( eth_size >= 34 ) {
                uint16_t ethertype = (eth_payload[12] << 8) | eth_payload[13];
                uint32_t src_ip = 0;
                struct peer_info *sp;
                if ( ethertype == 0x0800 && eth_size >= 34 ) {
                    memcpy(&src_ip, eth_payload + 26, 4);
                } else if ( ethertype == 0x0806 && eth_size >= 42 ) {
                    memcpy(&src_ip, eth_payload + 28, 4);
                }
                if ( src_ip != 0 ) {
                    PEERS_LOCK(eee);
                    sp = find_peer_by_mac(eee->known_peers, pkt->srcMac);
                    if ( !sp ) sp = find_peer_by_mac(eee->pending_peers, pkt->srcMac);
                    if ( sp && sp->assigned_ip == 0 )
                        sp->assigned_ip = ntohl(src_ip);
                    PEERS_UNLOCK(eee);
                }
            }

            /* Check for bypass probe frames before writing to TAP */
            if (eee->bp && eth_size >= 14) {
                uint16_t bp_etype = (eth_payload[12] << 8) | eth_payload[13];
                if (bp_etype == BYPASS_ETYPE_PROBE || bp_etype == BYPASS_ETYPE_PROBE_ACK) {
                    int is_ack = (bp_etype == BYPASS_ETYPE_PROBE_ACK);
                    int need_resp = bypass_handle_probe_frame(eee->bp, eth_payload, eth_size, is_ack, orig_sender);
                    if (need_resp && !is_ack) {
                        /* Send PROBE_ACK directly to the sender's P2P address,
                         * bypassing find_peer_destination's relay-via-supernode logic.
                         * This prevents "Relayed packet: addr changed" on the peer side
                         * when the peer is still in pending_peers. */
                        uint8_t probe_ack[19];
                        size_t pa_len = bypass_build_probe_frame(probe_ack, eee->device.ip_addr, 1, 0);
                        memcpy(probe_ack + 6, eee->device.mac_addr, 6); /* src MAC */
                        memcpy(probe_ack, eth_payload + 6, 6); /* dst MAC = sender's MAC */

                        n2n_mac_t destMac;
                        uint8_t pktbuf[N2N_PKT_BUF_SIZE];
                        size_t idx = 0;
                        n2n_common_t cmn;
                        n2n_PACKET_t pkt;
                        size_t tx_transop_idx = edge_choose_tx_transop(eee);
                        memcpy(destMac, eth_payload + 6, N2N_MAC_SIZE);
                        memset(&cmn, 0, sizeof(cmn));
                        cmn.ttl = N2N_DEFAULT_TTL;
                        cmn.pc = n2n_packet;
                        cmn.flags = 0;
                        memcpy(cmn.community, eee->community_name, N2N_COMMUNITY_SIZE);
                        memset(&pkt, 0, sizeof(pkt));
                        memcpy(pkt.srcMac, eee->device.mac_addr, N2N_MAC_SIZE);
                        memcpy(pkt.dstMac, destMac, N2N_MAC_SIZE);
                        pkt.sock.family = 0;
                        pkt.transform = eee->transop[tx_transop_idx].transform_id;
                        encode_PACKET(pktbuf, &idx, &cmn, &pkt);
                        idx += eee->transop[tx_transop_idx].fwd(
                            &(eee->transop[tx_transop_idx]),
                            pktbuf+idx, N2N_PKT_BUF_SIZE-idx,
                            probe_ack, pa_len, destMac);
                        ++(eee->transop[tx_transop_idx].tx_cnt);
                        n2n_sock_t dest = *orig_sender;
                        sendto_sock(sock_for_dest(eee, &dest), pktbuf, idx, &dest);
                    }
                    retval = 0;
                    return retval;
                }
            }

            data_sent_len = tuntap_write(&(eee->device), eth_payload, eth_size);
            traceEvent(TRACE_DEBUG, "handle_PACKET: tuntap_write done, len=%d", (signed int)data_sent_len);

            if (data_sent_len == eth_size)
            {
                retval = 0;
            }
        }
        else
        {
            traceEvent( TRACE_ERROR, "handle_PACKET dropped unknown transform enum %u",
                        (unsigned int)pkt->transform );
        }
    }

    return retval;
}

/** Format bytes with auto-scaled unit: B, K, M, G. */
static void fmt_bytes(char *buf, size_t bufsize, size_t bytes) {
    unsigned long b = (unsigned long)bytes;
    if (b == 0) {
        snprintf(buf, bufsize, "0");
    } else if (b < 1024) {
        snprintf(buf, bufsize, "%luB", b);
    } else if (b < 1024ul * 1024) {
        unsigned long k = b / 1024;
        unsigned long d = (b % 1024) * 10 / 1024;
        if (k < 10 || d > 0)
            snprintf(buf, bufsize, "%lu.%luK", k, d);
        else
            snprintf(buf, bufsize, "%luK", k);
    } else if (b < 1024ul * 1024 * 1024) {
        unsigned long m = b / (1024ul * 1024);
        unsigned long d = (b % (1024ul * 1024)) * 10 / (1024ul * 1024);
        if (m < 10 || d > 0)
            snprintf(buf, bufsize, "%lu.%luM", m, d);
        else
            snprintf(buf, bufsize, "%luM", m);
    } else {
        unsigned long g = b / (1024ul * 1024 * 1024);
        unsigned long d = (b % (1024ul * 1024 * 1024)) * 10 / (1024ul * 1024 * 1024);
        if (g < 10 || d > 0)
            snprintf(buf, bufsize, "%lu.%luG", g, d);
        else
            snprintf(buf, bufsize, "%luG", g);
    }
}

/** Read a datagram from the management UDP socket and take appropriate
 *  action. */
static void readFromMgmtSocket(n2n_edge_t *eee, int *keep_running) {
    uint8_t udp_buf[N2N_PKT_BUF_SIZE];      /* Complete UDP packet */
    ssize_t recvlen;
    _unused_ ssize_t sendlen;
#ifdef _WIN32
    struct sockaddr_storage sender_sock;
#else
    struct sockaddr_un sender_sock;
#endif
    socklen_t i;
    size_t msg_len;
    time_t now;

    now = n2n_now();
    i = sizeof(sender_sock);
    recvlen = recvfrom(eee->mgmt_sock, udp_buf, N2N_PKT_BUF_SIZE, 0/*flags*/,
                      (struct sockaddr*) &sender_sock, &i);
    if (i > 0) {
#ifndef _WIN32
        if (((struct sockaddr*) &sender_sock)->sa_family == AF_UNIX) {
            traceEvent( TRACE_INFO, "mgmt pkg from %s", ((struct sockaddr_un*) &sender_sock)->sun_path );
        } else {
#endif
            {
                char tmp[INET6_ADDRSTRLEN] = "unknown";
                int is_localhost = 0;
                if (((struct sockaddr*)&sender_sock)->sa_family == AF_INET) {
                    inet_ntop(AF_INET, &((struct sockaddr_in*)&sender_sock)->sin_addr, tmp, sizeof(tmp));
                    uint32_t addr = ((struct sockaddr_in*)&sender_sock)->sin_addr.s_addr;
                    is_localhost = (addr == htonl(INADDR_LOOPBACK)) || (addr == 0);
                } else if (((struct sockaddr*)&sender_sock)->sa_family == AF_INET6) {
                    inet_ntop(AF_INET6, &((struct sockaddr_in6*)&sender_sock)->sin6_addr, tmp, sizeof(tmp));
                    struct in6_addr *a6 = &((struct sockaddr_in6*)&sender_sock)->sin6_addr;
                    is_localhost = (memcmp(a6, &in6addr_loopback, sizeof(*a6)) == 0);
                }
                traceEvent( TRACE_INFO, "mgmt pkg from %s", tmp);
                if (!is_localhost) {
                    traceEvent( TRACE_WARNING, "mgmt request from non-localhost %s rejected", tmp);
                    return;
                }
            }
#ifndef _WIN32
        }
#endif
    }
    if (recvlen < 0) {
#ifdef _WIN32
        W32_ERROR(WSAGetLastError(), c)
        traceEvent( TRACE_ERROR, "mgmt recvfrom failed with %ls", c );
        W32_ERROR_FREE(c)
#else
        traceEvent(TRACE_ERROR, "mgmt recvfrom failed with %s", strerror(errno));
#endif
        return; /* failed to receive data from UDP */
    }

    /* Handle commands */
    if (eee->peer_sync_active) {
        /* During "f" sync, only accept "stop" */
        if (recvlen >= 4 && 0 == memcmp(udp_buf, "stop", 4)) {
            traceEvent(TRACE_ERROR, "stop command received.");
            *keep_running = 0;
            return;
        }
        return; /* ignore all other input during sync */
    }

    if (recvlen >= 2) {
        if (recvlen >= 4 && 0 == memcmp(udp_buf, "stop", 4)) {
            traceEvent(TRACE_ERROR, "stop command received.");
            *keep_running = 0;
            return;
        }

        if (recvlen >= 4 && 0 == memcmp(udp_buf, "help", 4)) {
            msg_len = 0;
            msg_len += snprintf((char*)(udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                                "Help for edge management console:\n"
                                "  stop    Gracefully exit edge\n"
                                "  help    This help message\n"
                                "  +       Increase verbosity of logging\n"
                                "  -       Decrease verbosity of logging\n"
                                "  b       Toggle bypass on/off\n"
                                "  f       Sync peers with supernode\n"
                                "  <enter> Display statistics\n\n");
            sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
                   (struct sockaddr*) &sender_sock, i);
            return;
        }

        if (recvlen >= 1 && 0 == memcmp(udp_buf, "f", 1)) {
            msg_len = 0;
            if (eee->peer_sync_active) {
                msg_len += snprintf((char*)(udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                                    "> sync already in progress, please wait\n");
                sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
                       (struct sockaddr*) &sender_sock, i);
                return;
            }
            /* Mark sync active to lock mgmt input */
            eee->peer_sync_active = 1;
            eee->peer_sync_time = n2n_now();
            /* Snapshot all local peer assigned_ips */
            {
                struct peer_info *p;
                uint16_t count = 0;
                PEERS_LOCK(eee);
                p = eee->pending_peers;
                while (p && count < 256) {
                    if (p->assigned_ip != 0)
                        eee->peer_sync_ips[count++] = p->assigned_ip;
                    p = p->next;
                }
                p = eee->known_peers;
                while (p && count < 256) {
                    if (p->assigned_ip != 0) {
                        /* Don't snapshot peers that have active P2P */
                        if (p->direct_seen == 0)
                            eee->peer_sync_ips[count++] = p->assigned_ip;
                    }
                    p = p->next;
                }
                eee->peer_sync_ips_count = count;
                PEERS_UNLOCK(eee);
            }
            /* Force REGISTER_SUPER - SN will push all peer info */
            send_register_super(eee, &eee->supernode);
            eee->sn_wait = 1;
            eee->last_register_req = n2n_now();
            msg_len += snprintf((char*)(udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                                "> peer sync started...\n");
            sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
                   (struct sockaddr*) &sender_sock, i);
            return;
        }

        if (recvlen >= 1 && 0 == memcmp(udp_buf, "b", 1)) {
            msg_len = 0;
            if (eee->bp) {
                bypass_mgmt_toggle(eee->bp);
                eee->bp_user_disabled = eee->bp->user_disabled;
                msg_len += snprintf((char*)(udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                                    "> x %s\n", eee->bp->user_disabled ? "disabled" : "enabled");
            } else {
                msg_len += snprintf((char*)(udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                                    "> bypass not available\n");
            }
            sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
                   (struct sockaddr*) &sender_sock, i);
            return;
        }

        if (recvlen >= 1 && 0 == memcmp(udp_buf, "+", 1)) {
            msg_len = 0;
            ++traceLevel;
            traceEvent(TRACE_ERROR, "+verb traceLevel=%d", traceLevel);
            msg_len += snprintf((char*) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                                "> +OK traceLevel=%d\n", traceLevel);
            sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
                   (struct sockaddr*) &sender_sock, i);
            return;
        }

        if (recvlen >= 1 && 0 == memcmp(udp_buf, "-", 1)) {
            msg_len = 0;
            if (traceLevel > 0) {
                --traceLevel;
                msg_len += snprintf((char*) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                                    "> -OK traceLevel=%d\n", traceLevel);
            } else {
                msg_len += snprintf((char*) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                                    "> -NOK traceLevel=%d\n", traceLevel);
            }
            traceEvent(TRACE_ERROR, "-verb traceLevel=%d", traceLevel);
            sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
                   (struct sockaddr*) &sender_sock, i);
            return;
        }

    }

    traceEvent(TRACE_DEBUG, "mgmt status rq");

    /* Drain any stale data from mgmt_sock before sending response */
    {
        uint8_t discard[256];
        while (recvfrom(eee->mgmt_sock, (char*)discard, sizeof(discard), 0, NULL, NULL) > 0) {}
    }

    /* Send community info */
    msg_len = snprintf((char*)udp_buf, N2N_PKT_BUF_SIZE,
                       "community: %s\n", eee->community_name_full[0] ? eee->community_name_full : eee->community_name);
    sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
           (struct sockaddr*) &sender_sock, i);

    /* Send header */
    msg_len = snprintf((char*)udp_buf, N2N_PKT_BUF_SIZE,
                       " id  mac                n2n_ip           wan_ip                                            ver      os\n");
	msg_len += snprintf((char*) (udp_buf + msg_len), (N2N_PKT_BUF_SIZE - msg_len),
                        "---v2.3----------------------------------------------------------------------------------------------------\n");
    sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
           (struct sockaddr*) &sender_sock, i);

    /* Send PsP_with section */
    msg_len = snprintf((char*)udp_buf, N2N_PKT_BUF_SIZE, "PsP_with:\n");
    sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
           (struct sockaddr*) &sender_sock, i);

    macstr_t mac;
    n2n_sock_str_t sockaddr;
    struct peer_info* peer = eee->pending_peers;
    int id = 1;
    while(peer) {
        /* Skip if same virtual IP as local edge */
        if (peer->assigned_ip == ntohl(eee->device.ip_addr)) {
            peer = peer->next;
            continue;
        }
        const char *version = (peer->version[0] != '\0') ? peer->version : "unknown";
        const char *os_name = (peer->os_name[0] != '\0') ? peer->os_name : "unknown";

        /* Format virtual IP */
        char virt_ip[16] = "-";
        if (peer->assigned_ip != 0) {
            struct in_addr addr;
            addr.s_addr = htonl(peer->assigned_ip);
            inet_ntop(AF_INET, &addr, virt_ip, sizeof(virt_ip));
        }

        {
            n2n_sock_str_t sbuf, sbuf6;
            char wan[64];
            snprintf(wan, sizeof(wan), "%s", sock_to_cstr(sbuf, &peer->sock));
            if (peer->sock6.family != 0) {
                const char *v6 = sock_to_cstr(sbuf6, &peer->sock6);
                size_t cur = strlen(wan);
                int budget = 48 - (int)cur - 1; /* column width - primary - '/' */
                if (budget >= 6) {
                    wan[cur++] = '/';
                    if ((int)strlen(v6) <= budget) {
                        strcpy(wan + cur, v6);
                    } else {
                        const char *port = strrchr(v6, ':');
                        int port_len = port ? (int)strlen(port) : 0;
                        int addr_max = budget - port_len;
                        if (addr_max < 3) addr_max = 3;
                        int w = 0;
                        while (w < addr_max - 2 && v6[w]) { wan[cur + w] = v6[w]; w++; }
                        wan[cur + w++] = '*';
                        wan[cur + w++] = ']';
                        if (port && w + port_len <= budget)
                            memcpy(wan + cur + w, port, port_len + 1);
                        else
                            wan[cur + w] = '\0';
                    }
                }
            }
            msg_len = snprintf((char*)udp_buf, N2N_PKT_BUF_SIZE,
                               " %2u  %-17s  %-15s  %-48s  %-7s  %s\n",
                               id++, macaddr_str(mac, peer->mac_addr), virt_ip,
                               wan, version, os_name);
        }
        sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
               (struct sockaddr*) &sender_sock, i);
        peer = peer->next;
    }

    /* Send P2P_with section */
    msg_len = snprintf((char*)udp_buf, N2N_PKT_BUF_SIZE, "P2P_with:\n");
    sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
           (struct sockaddr*) &sender_sock, i);

    peer = eee->known_peers;
    id = 1;
    while(peer) {
        /* Skip if same virtual IP as local edge */
        if (peer->assigned_ip == ntohl(eee->device.ip_addr)) {
            peer = peer->next;
            continue;
        }
        const char *version = (peer->version[0] != '\0') ? peer->version : "unknown";
        const char *os_name = (peer->os_name[0] != '\0') ? peer->os_name : "unknown";

        /* Format virtual IP */
        char virt_ip[16] = "-";
        if (peer->assigned_ip != 0) {
            struct in_addr addr;
            addr.s_addr = htonl(peer->assigned_ip);
            inet_ntop(AF_INET, &addr, virt_ip, sizeof(virt_ip));
        }

        {
            n2n_sock_str_t sbuf, sbuf6;
            char wan[64];
            snprintf(wan, sizeof(wan), "%s", sock_to_cstr(sbuf, &peer->sock));
            if (peer->sock6.family != 0) {
                const char *v6 = sock_to_cstr(sbuf6, &peer->sock6);
                size_t cur = strlen(wan);
                int budget = 48 - (int)cur - 1; /* column width - primary - '/' */
                if (budget >= 6) {
                    wan[cur++] = '/';
                    if ((int)strlen(v6) <= budget) {
                        strcpy(wan + cur, v6);
                    } else {
                        const char *port = strrchr(v6, ':');
                        int port_len = port ? (int)strlen(port) : 0;
                        int addr_max = budget - port_len;
                        if (addr_max < 3) addr_max = 3;
                        int w = 0;
                        while (w < addr_max - 2 && v6[w]) { wan[cur + w] = v6[w]; w++; }
                        wan[cur + w++] = '*';
                        wan[cur + w++] = ']';
                        if (port && w + port_len <= budget)
                            memcpy(wan + cur + w, port, port_len + 1);
                        else
                            wan[cur + w] = '\0';
                    }
                }
            }
            msg_len = snprintf((char*)udp_buf, N2N_PKT_BUF_SIZE,
                               " %2u  %-17s  %-15s  %-48s  %-7s  %s\n",
                               id++, macaddr_str(mac, peer->mac_addr), virt_ip,
                               wan, version, os_name);
        }
        sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
               (struct sockaddr*) &sender_sock, i);
        peer = peer->next;
    }

    /* Send supernode info */
    const char *sn_support;
    if (eee->sn_ipv4_support && eee->sn_ipv6_support)
        sn_support = "IPv4+IPv6";
    else if (eee->sn_ipv6_support)
        sn_support = "IPv6";
    else if (eee->sn_ipv4_support)
        sn_support = "IPv4";
    else
        sn_support = "unknown";

    msg_len = snprintf((char*)udp_buf, N2N_PKT_BUF_SIZE, "Supernodes\n");
    sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
           (struct sockaddr*) &sender_sock, i);
    msg_len = snprintf((char*)udp_buf, N2N_PKT_BUF_SIZE,
                       "  l* |  %s | v%s | supp:%s | conn:%s\n",
                       eee->sn_ip_array[eee->sn_idx],
                       eee->supernode_version,
                       sn_support,
                       (eee->supernode.family == AF_INET6) ? "IPv6" : "IPv4");
    sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
           (struct sockaddr*) &sender_sock, i);

    /* Send statistics */
    msg_len = snprintf((char*)udp_buf, N2N_PKT_BUF_SIZE,
                       "----------------------------------------------------------------------------------------------------v2.3---\n");
    sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
           (struct sockaddr*) &sender_sock, i);

    time_t uptime = now - eee->start_time;
    int days = uptime / 86400;
    int hours = (uptime % 86400) / 3600;
    int mins = (uptime % 3600) / 60;
    int secs = uptime % 60;
    char date_str[64];
    struct tm *tm_now = localtime(&now);
    strftime(date_str, sizeof(date_str), "%Y-%m-%d %H:%M", tm_now);
    {
        char sup_str[32], p2p_str[32];
        if (eee->last_sup) snprintf(sup_str, sizeof(sup_str), "%lus ago", (unsigned long)(now - eee->last_sup));
        else strcpy(sup_str, "never");
        if (eee->last_p2p) snprintf(p2p_str, sizeof(p2p_str), "%lus ago", (unsigned long)(now - eee->last_p2p));
        else strcpy(p2p_str, "never");
        msg_len = snprintf((char*)udp_buf, N2N_PKT_BUF_SIZE,
                           "%s up %dd_%02dh_%02dm | pend/known_peers %u/%u | last_super/p2p %s/%s",
                           date_str, days, hours, mins,
                           (unsigned int)peer_list_size(eee->pending_peers),
                           (unsigned int)peer_list_size(eee->known_peers),
                           sup_str, p2p_str);
        msg_len += snprintf((char*)udp_buf + msg_len, N2N_PKT_BUF_SIZE - (size_t)msg_len,
                            "\n");
    }
    sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
           (struct sockaddr*) &sender_sock, i);

    {
        size_t total_tx = eee->super_tx_bytes + eee->p2p_tx_bytes;
        size_t total_rx = eee->super_rx_bytes + eee->p2p_rx_bytes;
        char ft[16], fr[16], fst[16], fsr[16], fpt[16], fpr[16];
        if (eee->bp && eee->bp->enabled) {
            total_tx += eee->bp->bp_tx_bytes;
            total_rx += eee->bp->bp_rx_bytes;
            char fbt[16], fbr[16];
            fmt_bytes(ft, sizeof(ft), total_tx);
            fmt_bytes(fr, sizeof(fr), total_rx);
            fmt_bytes(fst, sizeof(fst), eee->super_tx_bytes);
            fmt_bytes(fsr, sizeof(fsr), eee->super_rx_bytes);
            fmt_bytes(fpt, sizeof(fpt), eee->p2p_tx_bytes);
            fmt_bytes(fpr, sizeof(fpr), eee->p2p_rx_bytes);
            fmt_bytes(fbt, sizeof(fbt), eee->bp->bp_tx_bytes);
            fmt_bytes(fbr, sizeof(fbr), eee->bp->bp_rx_bytes);
            msg_len = snprintf((char*)udp_buf, N2N_PKT_BUF_SIZE,
                               "Tx/rx: total %s/%s | psp %s/%s | p2p %s/%s"
                               " | bp %s/%s on %u\n",
                               ft, fr, fst, fsr, fpt, fpr, fbt, fbr,
                               (unsigned int)eee->bp->proxy_port);
        } else {
            fmt_bytes(ft, sizeof(ft), total_tx);
            fmt_bytes(fr, sizeof(fr), total_rx);
            fmt_bytes(fst, sizeof(fst), eee->super_tx_bytes);
            fmt_bytes(fsr, sizeof(fsr), eee->super_rx_bytes);
            fmt_bytes(fpt, sizeof(fpt), eee->p2p_tx_bytes);
            fmt_bytes(fpr, sizeof(fpr), eee->p2p_rx_bytes);
            msg_len = snprintf((char*)udp_buf, N2N_PKT_BUF_SIZE,
                               "Tx/rx: total %s/%s | psp %s/%s | p2p %s/%s\n",
                               ft, fr, fst, fsr, fpt, fpr);
        }
    }
    sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
           (struct sockaddr*) &sender_sock, i);

    msg_len = snprintf((char*)udp_buf, N2N_PKT_BUF_SIZE,
                       "Type \"help\" to see more commands.\n");
    sendto(eee->mgmt_sock, udp_buf, msg_len, 0/*flags*/,
           (struct sockaddr*) &sender_sock, i);
}

/** Attempt LAN / IPv4 direct registration for a peer described by a PEER_INFO.
 *
 * This is the shared LAN/IPv4 flow used when there is no IPv6 candidate
 * (original behaviour) AND when there is an IPv6 candidate from an IPv4-only
 * supernode (edge-reported address). When \p ipv6_candidate is non-NULL and
 * valid, the IPv6 address is additionally tried as a parallel candidate — the
 * LAN/IPv4 flow itself is left completely unchanged so that an IPv4-only
 * supernode never degrades LAN / IPv4 direct connectivity.
 *
 * Must be called with PEERS_LOCK held. */
static void try_peer_lan_ipv4( n2n_edge_t * eee,
                               uint16_t aflags,
                               const n2n_sock_t * pub_sock,
                               const n2n_sock_t * lan_sock,
                               struct peer_info * pending,
                               const n2n_sock_t * ipv6_candidate )
{
    int same_lan = (aflags & N2N_AFLAGS_LOCAL_SOCKET) &&
                    lan_sock->family != 0 && lan_sock->port != 0 &&
                    eee->my_public_sock.family == AF_INET &&
                    pub_sock->family == AF_INET &&
                    memcmp(eee->my_public_sock.addr.v4, pub_sock->addr.v4, IPV4_SIZE) == 0;
    pending->p2p_is_lan = same_lan ? 1 : 0;

    if (same_lan) {
        n2n_sock_t lan = *lan_sock;
        n2n_sock_str_t lanbuf;
        lan.port = pub_sock->port;
        traceEvent(TRACE_INFO, "Same public IP - trying LAN direct: %s",
                   sock_to_cstr(lanbuf, &lan));
        try_send_register_lan(eee, 1, pending->mac_addr, pub_sock, &lan);
    } else {
        try_send_register(eee, 1, pending->mac_addr, &pending->sock);
        if (pending->num_sockets >= 2 && pending->sockets[1].family != 0 && pending->sockets[1].port != 0) {
            n2n_sock_t lan = pending->sockets[1];
            lan.port = pending->sockets[0].port;
            send_register(eee, &lan);
        }
    }

    /* Reported IPv6 as a parallel candidate only (never replaces LAN/IPv4). */
    if (ipv6_candidate && ipv6_candidate->family == AF_INET6 && eee->udp_sock6 != -1)
        try_send_register(eee, 1, pending->mac_addr, ipv6_candidate);
}

/** Read a datagram from the main UDP socket to the internet.
 *  @return 1 if a packet was read (caller should try to read more),
 *          0 if no more data is available (queue drained). */
static int readFromIPSocket( n2n_edge_t * eee, SOCKET fd )
{
    n2n_common_t        cmn; /* common fields in the packet header */
    static int          first_ok_message_shown = 0;

    n2n_sock_str_t      sockbuf1;
    n2n_sock_str_t      sockbuf2; /* don't clobber sockbuf1 if writing two addresses to trace */
    macstr_t            mac_buf1;
    macstr_t            mac_buf2;

    static uint8_t udp_buf[BYPASS_PKT_BUF_SIZE];    /* Complete UDP packet (static to reduce stack pressure on embedded) */
    ssize_t             recvlen;
    size_t              rem;
    size_t              idx;
    size_t              msg_type;
    uint8_t             from_supernode;
    struct sockaddr_in6 sender_sock;
    n2n_sock_t          sender = {0};
    n2n_sock_t *        orig_sender = NULL;
    time_t              now = 0;

    size_t              i;

    /* WS mode: read from WebSocket connection, sender is fixed as supernode */
    if (eee->use_ws && fd == eee->ws_conn.fd && eee->ws_conn.state == WS_OPEN) {
        recvlen = ws_recv(&eee->ws_conn, udp_buf, sizeof(udp_buf));
        if (recvlen < 0) {
            ws_close(&eee->ws_conn);
            eee->ws_last_reconnect = n2n_now();
            return 0;
        }
        if (recvlen == 0) return 0;
        sender = eee->supernode;
        orig_sender = &sender;
        goto process_n2n_packet;
    }

    i = sizeof(sender_sock);
    recvlen = recvfrom(fd, udp_buf, sizeof(udp_buf), 0/*flags*/,
                      (struct sockaddr*) &sender_sock, (socklen_t*) &i);

    if ( recvlen < 0 )
    {
#ifdef _WIN32
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK) {
            W32_ERROR(err, c)
            traceEvent( TRACE_DEBUG, "recvfrom failed [%d] %ls", err, c ? c : L"" );
            W32_ERROR_FREE(c)
        }
#else
        traceEvent(TRACE_DEBUG, "recvfrom failed with %s", strerror(errno) );
#endif

        return 0; /* failed to receive data from UDP — queue drained or error */
    }

    /* Determine sender address from socket family */
    sender.family = (uint8_t) sender_sock.sin6_family;
    if (AF_INET == sender.family) {
        struct sockaddr_in* sock = (struct sockaddr_in*) &sender_sock;
        sender.port = ntohs(sock->sin_port);
        memcpy( &(sender.addr.v4), &(sock->sin_addr), IPV4_SIZE );
    } else if (AF_INET6 == sender.family) {
        sender.port = ntohs(sender_sock.sin6_port);
        memcpy( &(sender.addr.v6), &(sender_sock.sin6_addr), IPV6_SIZE );
    }

    /* The packet may not have an orig_sender socket spec. So default to last
     * hop as sender. */
    orig_sender=&sender;

    traceEvent(TRACE_DEBUG, "### Rx N2N UDP (%d) from %s",
               (signed int) recvlen, sock_to_cstr(sockbuf1, &sender) );

    /* Check for bypass packet (has its own magic header, not n2n format).
     * Always check magic first so packets from non-negotiated peers
     * are silently dropped instead of falling through to decode_common(). */
    if (recvlen >= BYPASS_HEADER_SIZE &&
        udp_buf[0] == BYPASS_MAGIC_0 && udp_buf[1] == BYPASS_MAGIC_1 &&
        udp_buf[2] == BYPASS_MAGIC_2) {
        if (bypass_has_peers(eee->bp)) {
            bypass_handle_recv(eee->bp, udp_buf, recvlen, &sender);
            /* Drain a few more bypass packets from UDP buffer
             * to reduce select cycle overhead at high throughput. */
            for (int _di = 0; _di < 7; _di++) {
                static uint8_t db[BYPASS_PKT_BUF_SIZE];
                struct sockaddr_storage dsa;
                socklen_t dsl = sizeof(dsa);
                ssize_t dlen = recvfrom(fd, (char *)db, sizeof(db),
#ifdef _WIN32
                                         0,
#else
                                         MSG_DONTWAIT,
#endif
                                         (struct sockaddr *)&dsa, &dsl);
                if (dlen <= 0) break;
                if (dlen < BYPASS_HEADER_SIZE ||
                    db[0] != BYPASS_MAGIC_0 || db[1] != BYPASS_MAGIC_1 || db[2] != BYPASS_MAGIC_2) {
                    if ((size_t)dlen <= sizeof(udp_buf)) {
                        memcpy(udp_buf, db, dlen);
                        recvlen = dlen;
                        if (dsa.ss_family == AF_INET) {
                            struct sockaddr_in *si = (struct sockaddr_in *)&dsa;
                            sender.family = AF_INET;
                            memcpy(sender.addr.v4, &si->sin_addr, 4);
                            sender.port = ntohs(si->sin_port);
                        } else if (dsa.ss_family == AF_INET6) {
                            struct sockaddr_in6 *si6 = (struct sockaddr_in6 *)&dsa;
                            sender.family = AF_INET6;
                            memcpy(sender.addr.v6, &si6->sin6_addr, 16);
                            sender.port = ntohs(si6->sin6_port);
                        }
                        goto process_n2n_packet;
                    }
                    break;
                }
                n2n_sock_t ds; memset(&ds, 0, sizeof(ds));
                if (dsa.ss_family == AF_INET) {
                    struct sockaddr_in *si = (struct sockaddr_in *)&dsa;
                    ds.family = AF_INET; memcpy(ds.addr.v4, &si->sin_addr, 4); ds.port = ntohs(si->sin_port);
                } else if (dsa.ss_family == AF_INET6) {
                    struct sockaddr_in6 *si6 = (struct sockaddr_in6 *)&dsa;
                    ds.family = AF_INET6; memcpy(ds.addr.v6, &si6->sin6_addr, 16); ds.port = ntohs(si6->sin6_port);
                } else continue;
                bypass_handle_recv(eee->bp, db, (size_t)dlen, &ds);
            }
        }
        return 1; /* bypass packet processed, may be more queued */
    }

process_n2n_packet:

    /* hexdump( udp_buf, recvlen ); */

    rem = recvlen; /* Counts down bytes of packet to protect against buffer overruns. */
    idx = 0; /* marches through packet header as parts are decoded. */
    if ( decode_common(&cmn, udp_buf, &rem, &idx) < 0 )
    {
        traceEvent( TRACE_ERROR, "Failed to decode common section in N2N_UDP" );
        return 0; /* failed to decode packet */
    }

    now = n2n_now();

    msg_type = cmn.pc;
    from_supernode= cmn.flags & N2N_FLAGS_FROM_SUPERNODE;

    if( 0 == memcmp(cmn.community, eee->community_name, N2N_COMMUNITY_SIZE) )
    {
        if( msg_type == MSG_TYPE_PACKET)
        {
            /* process PACKET - most frequent so first in list. */
            n2n_PACKET_t pkt;

            decode_PACKET( &pkt, &cmn, udp_buf, &rem, &idx );

            if ( pkt.sock.family )
            {
                orig_sender = &(pkt.sock);
            }

            traceEvent(TRACE_DEBUG, "Rx PACKET from %s (%s)",
                       sock_to_cstr(sockbuf1, &sender),
                       sock_to_cstr(sockbuf2, orig_sender) );

            handle_PACKET( eee, &cmn, &pkt, orig_sender, udp_buf + idx, recvlen - idx );
            traceEvent(TRACE_DEBUG, "handle_PACKET returned");
        }
        else if(msg_type == MSG_TYPE_REGISTER)
        {
            /* Another edge is registering with us */
            n2n_REGISTER_t reg;

            decode_REGISTER( &reg, &cmn, udp_buf, &rem, &idx );

            if ( reg.sock.family &&
                 eee->my_public_sock.family == AF_INET &&
                 sender.family == AF_INET &&
                 memcmp(eee->my_public_sock.addr.v4, sender.addr.v4, IPV4_SIZE) == 0 )
            {
                orig_sender = &(reg.sock);
            }

            traceEvent(TRACE_INFO, "Rx REGISTER src=%s dst=%s from peer %s (%s)",
                       macaddr_str( mac_buf1, reg.srcMac ),
                       macaddr_str( mac_buf2, reg.dstMac ),
                       sock_to_cstr(sockbuf1, &sender),
                       sock_to_cstr(sockbuf2, orig_sender) );

            if ( 0 == memcmp(reg.dstMac, (eee->device.mac_addr), 6) ||
                 0 == memcmp(reg.dstMac, "\x00\x00\x00\x00\x00\x00", 6) )
            {
                PEERS_LOCK(eee);
                struct peer_info *scan = find_peer_by_mac(eee->known_peers, reg.srcMac);
                if (NULL == scan) {
                    if ( reg.sock.family != 0 && reg.sock.port != 0 &&
                         eee->local_sock_ena &&
                         eee->my_public_sock.family == AF_INET &&
                         sender.family == AF_INET &&
                         memcmp(eee->my_public_sock.addr.v4, sender.addr.v4, IPV4_SIZE) == 0 )
                    {
                        n2n_sock_t lan_sock = reg.sock;
                        lan_sock.port = orig_sender->port;
                        traceEvent(TRACE_INFO, "Rx REGISTER with LAN addr %s - trying LAN direct",
                                   sock_to_cstr(sockbuf1, &lan_sock));
                        try_send_register_lan(eee, from_supernode, reg.srcMac, orig_sender, &lan_sock);
                    } else {
                        try_send_register(eee, from_supernode, reg.srcMac, orig_sender);
                    }
                } else {
                    int peer_uses_ipv4 = (scan->sock.family == AF_INET);
                    int register_is_ipv4 = (orig_sender->family == AF_INET);
                    if ((peer_uses_ipv4 && register_is_ipv4) || (!peer_uses_ipv4 && !register_is_ipv4)) {
                        n2n_sock_t *expected_sock = peer_uses_ipv4 ? &scan->sock : &scan->sock6;
                        if (sock_equal(expected_sock, orig_sender) != 0) {
                            *expected_sock = *orig_sender;
                            scan->sockets[0] = *orig_sender;
                            scan->last_seen = n2n_now();
                            send_register(eee, orig_sender);
                        } else {
                            scan->last_seen = n2n_now();
                        }
                    }
                    /* Update version/os_name from REGISTER */
                    if (reg.version[0] != '\0') {
                        strncpy(scan->version, reg.version, sizeof(scan->version) - 1);
                        scan->version[sizeof(scan->version) - 1] = '\0';
                    }
                    if (reg.os_name[0] != '\0') {
                        strncpy(scan->os_name, reg.os_name, sizeof(scan->os_name) - 1);
                        scan->os_name[sizeof(scan->os_name) - 1] = '\0';
                    }
                    /* Peer already in known_peers - don't reset bypass state.
                     * If peer restarted with different bypass preference,
                     * it will be detected via PROBE timeout (peer won't reply).
                     * This preserves existing bypass connections. */
                }
                PEERS_UNLOCK(eee);
            }

            send_register_ack(eee, orig_sender, &reg);
        }
        else if(msg_type == MSG_TYPE_REGISTER_ACK)
        {
            /* Peer edge is acknowledging our register request */
            n2n_REGISTER_ACK_t ra;

            decode_REGISTER_ACK( &ra, &cmn, udp_buf, &rem, &idx );

            if ( ra.sock.family )
            {
                orig_sender = &(ra.sock);
            }

            traceEvent(TRACE_INFO, "Rx REGISTER_ACK src=%s dst=%s from peer %s (%s)",
                       macaddr_str( mac_buf1, ra.srcMac ),
                       macaddr_str( mac_buf2, ra.dstMac ),
                       sock_to_cstr(sockbuf1, &sender),
                       sock_to_cstr(sockbuf2, orig_sender) );

            /* Move from pending_peers to known_peers; ignore if not in pending. */
            PEERS_LOCK(eee);
            if ( from_supernode ) {
                /* REGISTER_ACK relayed via supernode: direct path NOT verified.
                 * Do NOT move to known_peers. Keep in pending_peers so traffic uses
                 * supernode relay. Only promote to known_peers on a direct REGISTER_ACK. */
                struct peer_info *pscan = find_peer_by_mac(eee->pending_peers, ra.srcMac);
                if ( pscan ) {
                    pscan->last_seen = n2n_now(); /* keep alive in pending_peers */
                    traceEvent(TRACE_INFO, "REGISTER_ACK via supernode for %s - direct unverified, staying in pending",
                               macaddr_str(mac_buf1, ra.srcMac));
                }
            } else {
                /* Direct REGISTER_ACK: sender is the real peer address. Direct path confirmed. */
                set_peer_operational( eee, ra.srcMac, &sender );
            }
            PEERS_UNLOCK(eee);
        }
        else if(msg_type == n2n_probe)
        {
            /* Another edge sent us a direct PROBE to open NAT mapping.
             * 1. Send PROBE_ACK via supernode so sender learns their public addr.
             * 2. Start reverse punch only if not already in progress/done. */
            n2n_PROBE_t probe;
            decode_PROBE(&probe, &cmn, udp_buf, &rem, &idx);

            traceEvent(TRACE_INFO, "Rx PROBE from %s at %s - sending PROBE_ACK",
                       macaddr_str(mac_buf1, probe.srcMac), sock_to_cstr(sockbuf1, &sender));

            /* Send PROBE_ACK via supernode: tell sender what addr we observed */
            send_probe_ack(eee, probe.srcMac, &sender);

            /* sender is the peer's real public address (direct UDP packet).
             * Update pending_peers sock so subsequent REGISTERs go directly. */
            PEERS_LOCK(eee);
            struct peer_info *known = find_peer_by_mac(eee->known_peers, probe.srcMac);
            if ( NULL == known ) {
                struct peer_info *pscan = find_peer_by_mac(eee->pending_peers, probe.srcMac);
                if ( NULL == pscan ) {
                    try_send_register(eee, 0, probe.srcMac, &sender);
                } else {
                    if (sender.family == AF_INET6) {
                        pscan->sock6 = sender;
                    } else {
                        pscan->sock = sender;
                    }
                    send_register(eee, &sender);
                }
            } else {
                known->last_seen = now;
                known->direct_seen = now;
            }
            PEERS_UNLOCK(eee);
        }
        else if(msg_type == n2n_probe_ack)
        {
            /* Received PROBE_ACK: we now know our real public addr
             * as observed by the remote peer. Update that peer's sock and retry REGISTER. */
            n2n_PROBE_ACK_t ack;
            decode_PROBE_ACK(&ack, &cmn, udp_buf, &rem, &idx);

            traceEvent(TRACE_INFO, "Rx PROBE_ACK from %s: my observed addr = %s",
                       macaddr_str(mac_buf1, ack.dstMac), sock_to_cstr(sockbuf1, &ack.observed_addr));

            /* The peer that sent PROBE_ACK is ack.dstMac; their sock is 'sender'.
             * More importantly, we now know our own public addr. Update and retry REGISTER. */
            PEERS_LOCK(eee);
            /* Update last_seen in known_peers so keepalive knows peer is alive */
            struct peer_info *kp = find_peer_by_mac(eee->known_peers, ack.dstMac);
            if (kp) {
                kp->last_seen = now;
                kp->direct_seen = now;
                kp->last_probe_sent = 0;
                kp->keepalive_fails = 0;
            }
            struct peer_info * scan = find_peer_by_mac(eee->pending_peers, ack.dstMac);
            if ( scan && !scan->punch_failed ) {
                /* Send REGISTER to the address that was probed (based on observed_addr family) */
                n2n_sock_t *target_addr = (ack.observed_addr.family == AF_INET6) ? &scan->sock6 : &scan->sock;
                if (target_addr->family != 0) {
                    send_register(eee, target_addr);
                    send_register(eee, &(eee->supernode));
                    scan->register_retry_count = 1;
                    scan->last_register_sent = now;
                    traceEvent(TRACE_INFO, "PROBE_ACK: REGISTER sent to %s (attempt 1/3)",
                               macaddr_str(mac_buf1, ack.dstMac));
                }
            }
            PEERS_UNLOCK(eee);
        }
        else if(msg_type == n2n_peer_info)
        {
            n2n_PEER_INFO_t pi;
            decode_PEER_INFO(&pi, &cmn, udp_buf, &rem, &idx);

            int do_punch = (pi.aflags & N2N_AFLAGS_PUNCH_REQUEST) != 0;

            if (pi.assigned_ip) {
                traceEvent(TRACE_INFO, "Rx PEER_INFO for %s [%u.%u.%u.%u] at %s%s",
                           macaddr_str(mac_buf1, pi.mac),
                           (pi.assigned_ip>>24)&0xFF, (pi.assigned_ip>>16)&0xFF,
                           (pi.assigned_ip>>8)&0xFF, pi.assigned_ip&0xFF,
                           sock_to_cstr(sockbuf1, &pi.sockets[0]),
                           do_punch ? " [PUNCH]" : "");
            } else {
                traceEvent(TRACE_INFO, "Rx PEER_INFO for %s at %s%s",
                           macaddr_str(mac_buf1, pi.mac),
                           sock_to_cstr(sockbuf1, &pi.sockets[0]),
                           do_punch ? " [PUNCH]" : "");
            }

            /* If peer is in same LAN as supernode, replace its private IP
             * with supernode's public IP (keeping peer's port). */
            if ((pi.aflags & N2N_AFLAGS_SAME_LAN_AS_SN) && eee->supernode.family != 0) {
                if (pi.sockets[0].family == AF_INET) {
                    if (eee->supernode.family == AF_INET) {
                        memcpy(pi.sockets[0].addr.v4, eee->supernode.addr.v4, IPV4_SIZE);
                    } else if (eee->supernode_alt.family == AF_INET) {
                        memcpy(pi.sockets[0].addr.v4, eee->supernode_alt.addr.v4, IPV4_SIZE);
                    }
                    traceEvent(TRACE_INFO, "SAME_LAN_AS_SN: replaced IPv4 with SN IP %s",
                               sock_to_cstr(sockbuf1, &pi.sockets[0]));
                }
            }

            PEERS_LOCK(eee);
            struct peer_info *known = find_peer_by_mac(eee->known_peers, pi.mac);
            struct peer_info *pending = find_peer_by_mac(eee->pending_peers, pi.mac);

            /* During "f" sync: remove this peer's IP from snapshot (confirms SN has it) */
            if (eee->peer_sync_active && pi.assigned_ip != 0) {
                uint16_t j;
                for (j = 0; j < eee->peer_sync_ips_count; j++) {
                    if (eee->peer_sync_ips[j] == pi.assigned_ip) {
                        eee->peer_sync_ips[j] = eee->peer_sync_ips[--eee->peer_sync_ips_count];
                        break;
                    }
                }
            }

            if (!do_punch) {
                if (known) {
                    /* During "f" sync: preserve existing P2P, skip address change detection */
                    if (eee->peer_sync_active && known->direct_seen != 0) {
                        PEERS_UNLOCK(eee);
                        return 1;
                    }
                    int addr_changed = 0;
                    /* Principle 8+13: detect address change whenever P2P
                     * is idle (relay) or has been idle for >= 5 seconds.
                     * Reduced from 15s to 5s for faster re-punch response. */
                    if (known->direct_seen == 0 || (now - known->direct_seen) >= 5) {
                        if (pi.sockets[0].family == AF_INET) {
                            if (known->sock.family != AF_INET ||
                                sock_equal(&known->sock, &pi.sockets[0]) != 0) {
                                addr_changed = 1;
                            }
                        }
                        if (!addr_changed && pi.sock6.family == AF_INET6) {
                            if (known->sock6.family != AF_INET6 ||
                                sock_equal(&known->sock6, &pi.sock6) != 0) {
                                addr_changed = 1;
                            }
                        }
                    }

                    if (!addr_changed) {
                        if ((pi.aflags & N2N_AFLAGS_LOCAL_SOCKET) &&
                            pi.sockets[1].family != 0 && pi.sockets[1].port != 0) {
                            known->sockets[1] = pi.sockets[1];
                            known->num_sockets = 2;
                        }
                        if ((pi.aflags & N2N_AFLAGS_IPV6_SOCKET) && pi.sock6.family == AF_INET6)
                            known->sock6 = pi.sock6;
                        if (pi.version[0]) strncpy(known->version, pi.version, sizeof(known->version) - 1);
                        if (pi.os_name[0]) strncpy(known->os_name, pi.os_name, sizeof(known->os_name) - 1);
                        if (pi.assigned_ip) known->assigned_ip = pi.assigned_ip;
                        /* Do NOT update last_seen here — PEER_INFO is from the
                         * supernode, not from the peer itself. Updating last_seen
                         * would mask relay failures: if the relay is broken but
                         * the supernode still sends PEER_INFO (because the peer
                         * is still registered), last_seen stays current and the
                         * relay failure detection in check_keepalive never triggers.
                         * last_seen should only reflect actual peer communication
                         * (PACKET, REGISTER), not metadata from the supernode. */
                        PEERS_UNLOCK(eee);
                        return 1;
                    }

                    struct peer_info *prev = NULL, *scan = eee->known_peers;
                    while (scan && memcmp(scan->mac_addr, pi.mac, N2N_MAC_SIZE) != 0) {
                        prev = scan; scan = scan->next;
                    }
                    if (scan) {
                        if (prev) prev->next = scan->next;
                        else eee->known_peers = scan->next;
                        scan->next = eee->pending_peers;
                        eee->pending_peers = scan;
                        pending = scan;
                    }
                }
                if (pending) {
                    if (pi.sockets[0].family == AF_INET) {
                        pending->sock = pi.sockets[0];
                        pending->sockets[0] = pi.sockets[0];
                    }
                    if ((pi.aflags & N2N_AFLAGS_LOCAL_SOCKET) &&
                        pi.sockets[1].family != 0 && pi.sockets[1].port != 0) {
                        pending->sockets[1] = pi.sockets[1];
                        pending->num_sockets = 2;
                    }
                    if ((pi.aflags & N2N_AFLAGS_IPV6_SOCKET) && pi.sock6.family == AF_INET6)
                        pending->sock6 = pi.sock6;
                    if (pi.version[0]) strncpy(pending->version, pi.version, sizeof(pending->version) - 1);
                    if (pi.os_name[0]) strncpy(pending->os_name, pi.os_name, sizeof(pending->os_name) - 1);
                    pending->assigned_ip = pi.assigned_ip;
                    pending->last_seen = n2n_now();
                    PEERS_UNLOCK(eee);
                    if (eee->enable_gaming_mode && pi.assigned_ip != 0) {
                        uint8_t probe[42];
                        memset(probe, 0, sizeof(probe));
                        memset(probe, 0xFF, 6);
                        memcpy(probe + 6, eee->device.mac_addr, 6);
                        probe[12] = 0x08; probe[13] = 0x06;
                        probe[14] = 0x00; probe[15] = 0x01;
                        probe[16] = 0x08; probe[17] = 0x00;
                        probe[18] = 6;    probe[19] = 4;
                        probe[20] = 0x00; probe[21] = 0x01;
                        memcpy(probe + 22, eee->device.mac_addr, 6);
                        memcpy(probe + 28, &eee->device.ip_addr, 4);
                        memset(probe + 32, 0, 6);
                        uint32_t target_ip = htonl(pi.assigned_ip);
                        memcpy(probe + 38, &target_ip, 4);
                        send_packet2net(eee, probe, sizeof(probe));
                        traceEvent(TRACE_INFO, "Gaming: ARP probe sent to %u.%u.%u.%u",
                                   (pi.assigned_ip>>24)&0xFF, (pi.assigned_ip>>16)&0xFF,
                                   (pi.assigned_ip>>8)&0xFF, pi.assigned_ip&0xFF);
                    }
                    return 1;
                }
                pending = calloc(1, sizeof(struct peer_info));
                if (!pending) { PEERS_UNLOCK(eee); return 1; }
                memcpy(pending->mac_addr, pi.mac, N2N_MAC_SIZE);
                pending->sock = pi.sockets[0];
                pending->sockets[0] = pi.sockets[0];
                pending->num_sockets = 1;
                if ((pi.aflags & N2N_AFLAGS_LOCAL_SOCKET) &&
                    pi.sockets[1].family != 0 && pi.sockets[1].port != 0) {
                    pending->sockets[1] = pi.sockets[1];
                    pending->num_sockets = 2;
                }
                if ((pi.aflags & N2N_AFLAGS_IPV6_SOCKET) && pi.sock6.family == AF_INET6)
                    pending->sock6 = pi.sock6;
                if (pi.version[0]) strncpy(pending->version, pi.version, sizeof(pending->version) - 1);
                if (pi.os_name[0]) strncpy(pending->os_name, pi.os_name, sizeof(pending->os_name) - 1);
                pending->assigned_ip = pi.assigned_ip;
                pending->last_seen = n2n_now();
                peer_list_add(&eee->pending_peers, pending);
                PEERS_UNLOCK(eee);
                if (eee->enable_gaming_mode && pi.assigned_ip != 0) {
                    uint8_t probe[42];
                    memset(probe, 0, sizeof(probe));
                    memset(probe, 0xFF, 6);
                    memcpy(probe + 6, eee->device.mac_addr, 6);
                    probe[12] = 0x08; probe[13] = 0x06;
                    probe[14] = 0x00; probe[15] = 0x01;
                    probe[16] = 0x08; probe[17] = 0x00;
                    probe[18] = 6;    probe[19] = 4;
                    probe[20] = 0x00; probe[21] = 0x01;
                    memcpy(probe + 22, eee->device.mac_addr, 6);
                    memcpy(probe + 28, &eee->device.ip_addr, 4);
                    memset(probe + 32, 0, 6);
                    uint32_t target_ip = htonl(pi.assigned_ip);
                    memcpy(probe + 38, &target_ip, 4);
                    send_packet2net(eee, probe, sizeof(probe));
                    traceEvent(TRACE_INFO, "Gaming: ARP probe sent to %u.%u.%u.%u",
                               (pi.assigned_ip>>24)&0xFF, (pi.assigned_ip>>16)&0xFF,
                               (pi.assigned_ip>>8)&0xFF, pi.assigned_ip&0xFF);
                }
                return 1;
            }

            if (known) {
                struct peer_info *prev = NULL, *scan = eee->known_peers;
                while (scan && memcmp(scan->mac_addr, pi.mac, N2N_MAC_SIZE) != 0) {
                    prev = scan; scan = scan->next;
                }
                if (scan) {
                    if (prev) prev->next = scan->next;
                    else eee->known_peers = scan->next;
                    scan->next = eee->pending_peers;
                    eee->pending_peers = scan;
                    pending = scan;
                }
            }

            if (!pending) {
                pending = calloc(1, sizeof(struct peer_info));
                if (!pending) { PEERS_UNLOCK(eee); return 1; }
                memcpy(pending->mac_addr, pi.mac, N2N_MAC_SIZE);
                peer_list_add(&eee->pending_peers, pending);
            }

            if (pi.sockets[0].family == AF_INET6) pending->sock6 = pi.sockets[0];
            else pending->sock = pi.sockets[0];
            pending->sockets[0] = pi.sockets[0];
            if ((pi.aflags & N2N_AFLAGS_LOCAL_SOCKET) &&
                pi.sockets[1].family != 0 && pi.sockets[1].port != 0) {
                pending->sockets[1] = pi.sockets[1];
                pending->num_sockets = 2;
            } else {
                pending->num_sockets = 1;
            }
            if ((pi.aflags & N2N_AFLAGS_IPV6_SOCKET) && pi.sock6.family == AF_INET6)
                pending->sock6 = pi.sock6;
            if (pi.version[0]) strncpy(pending->version, pi.version, sizeof(pending->version) - 1);
            if (pi.os_name[0]) strncpy(pending->os_name, pi.os_name, sizeof(pending->os_name) - 1);
            pending->assigned_ip = pi.assigned_ip;
            pending->last_seen = n2n_now();
            pending->punch_start_time = 0;
            pending->punch_failed = 0;
            pending->register_retry_count = 0;
            pending->psp_logged = 0;
            pending->p2p_logged = 0;

            if (pending->sock6.family == AF_INET6 && eee->udp_sock6 != -1 &&
                eee->sn_ipv6_support) {
                /* Dual-stack supernode: sock6 was learned via real IPv6
                 * registration. Keep the original behaviour exactly — try
                 * the IPv6 address directly. */
                try_send_register(eee, 1, pi.mac, &pending->sock6);
            } else if (pending->sock6.family == AF_INET6 && eee->udp_sock6 != -1) {
                /* IPv4-only supernode: sock6 is an edge-reported address
                 * (extra way to obtain an IPv6 address). It must NOT change
                 * the LAN / IPv4 direct flow — run the exact same LAN/IPv4
                 * logic, using the reported IPv6 only as an ADDITIONAL
                 * parallel candidate. */
                try_peer_lan_ipv4(eee, pi.aflags, &pi.sockets[0], &pi.sockets[1],
                                  pending, &pending->sock6);
            } else {
                /* No IPv6 candidate: unchanged LAN / IPv4 direct flow. */
                try_peer_lan_ipv4(eee, pi.aflags, &pi.sockets[0], &pi.sockets[1],
                                  pending, NULL);
            }

            PEERS_UNLOCK(eee);
        }
        else if(msg_type == MSG_TYPE_REGISTER_SUPER_NAK)
        {
            n2n_REGISTER_SUPER_NAK_t nak;
            decode_buf(nak.cookie, N2N_COOKIE_SIZE, udp_buf, &rem, &idx);

            if (eee->sn_wait || eee->sn_ack_count > 0) {
                if (0 == memcmp(nak.cookie, eee->last_cookie, N2N_COOKIE_SIZE)) {
                    traceEvent(TRACE_ERROR, "%s already in use by other, exiting",
                               inet_ntoa(*(struct in_addr*)&eee->device.ip_addr));
                    exit(1);
                }
            }
        }
        else if(msg_type == MSG_TYPE_REGISTER_SUPER_ACK)
        {
            n2n_REGISTER_SUPER_ACK_t ra;

            if ( eee->sn_wait || eee->sn_ack_count > 0 )
            {
                decode_REGISTER_SUPER_ACK( &ra, &cmn, udp_buf, &rem, &idx );

                if ( ra.sock.family )
                {
                    orig_sender = &(ra.sock);
                }

                if ( 0 == memcmp( ra.cookie, eee->last_cookie, N2N_COOKIE_SIZE ) )
                {
                    eee->sn_ack_count++;

                    if ( ra.num_sn > 0 )
                    {
                        traceEvent(TRACE_DEBUG, "Rx REGISTER_SUPER_ACK backup supernode at %s",
                                   sock_to_cstr(sockbuf1, &(ra.sn_bak) ) );
                    }

                    /* Only do full processing on the first ACK; subsequent ACKs
                     * (from alt address family) just refresh last_sup silently. */
                    if ( eee->sn_ack_count == 1 ) {
                        eee->last_sup = now;
                        eee->sn_wait = 0;
                        eee->sup_attempts = N2N_EDGE_SUP_ATTEMPTS;
                        eee->sn_relay_fails = 0;

                        if (default_ip_assignment && ra.dev_addr.net_addr != 0) {
                            struct in_addr addr;
                            addr.s_addr = ra.dev_addr.net_addr;
                            char assigned_ip_str[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &addr, assigned_ip_str, sizeof(assigned_ip_str));

                            if (eee->device.ip_addr != addr.s_addr) {
                                eee->device.ip_addr = addr.s_addr;
                                eee->device.ip_prefixlen = ra.dev_addr.net_bitlen ? ra.dev_addr.net_bitlen : 24;
                                if (set_ipaddress(&eee->device, 1) < 0)
                                    traceEvent(TRACE_ERROR, "Failed to configure TAP interface with assigned IP");
                                else
                                    traceEvent(TRACE_NORMAL, "TAP interface configured with IP %s/%u",
                                               assigned_ip_str, eee->device.ip_prefixlen);
                            }
                        } else if (!default_ip_assignment && ra.dev_addr.net_addr == 0) {
                            /* Static IP requested via -a, but the supernode did not
                             * echo any IP back (e.g. third-party supernodes like
                             * cnn2n keep dev_addr zero for a valid static request).
                             * Keep our own configured static IP instead of exiting. */
                            traceEvent(TRACE_DEBUG, "Supernode did not echo an IP for static address; keeping %s",
                                       inet_ntoa(*(struct in_addr*)&eee->device.ip_addr));
                        }

                        /* Set sn_caps before daemonize so the log line is visible on terminal */
                        if (ra.sn_caps != 0) {
                            eee->sn_ipv4_support = (ra.sn_caps & N2N_SN_CAPS_IPV4) ? 1 : 0;
                            eee->sn_ipv6_support = (ra.sn_caps & N2N_SN_CAPS_IPV6) ? 1 : 0;
                        } else {
                            /* Old supernode: infer from resolved addresses */
                            eee->sn_ipv4_support = (eee->supernode.family == AF_INET) ? 1 :
                                                   (eee->supernode_alt.family == AF_INET ? 1 : 0);
                            eee->sn_ipv6_support = (eee->supernode.family == AF_INET6) ? 1 :
                                                   (eee->supernode_alt.family == AF_INET6 ? 1 : 0);
                        }

                        if (first_ok_message_shown == 0) {
                            const char *caps_str;
                            if (eee->sn_ipv4_support && eee->sn_ipv6_support)
                                caps_str = "IPv4+IPv6 (dual-stack)";
                            else if (eee->sn_ipv6_support)
                                caps_str = "IPv6 only";
                            else if (eee->sn_ipv4_support)
                                caps_str = "IPv4 only";
                            else
                                caps_str = "unknown (old supernode)";
                            traceEvent(TRACE_NORMAL, "Supernode support: %s", caps_str);
                            traceEvent(TRACE_NORMAL, "[OK] edge <<< ======= %s ======= >>> supernode",
                                       sender.family == AF_INET6 ? "IPv6" : "IPv4");
                            first_ok_message_shown = 1;
                        } else {
                            traceEvent(TRACE_DEBUG, "[OK] edge <<< ======= %s ======= >>> supernode",
                                       eee->supernode.family == AF_INET6 ? "IPv6" : "IPv4");
                        }

                        if (!initial_connection_complete && eee->daemon) {
#ifdef N2N_HAVE_DAEMON
                            useSyslog = 1; /* traceEvent output now goes to syslog. */
#ifdef __linux__
                            prctl(PR_SET_KEEPCAPS, 1L);
#endif
                            if ( -1 == daemon( 0, 0 ) ) {
                                traceEvent( TRACE_ERROR, "Failed to become daemon." );
                                exit(-5);
                            }
#endif
                            initial_connection_complete = 1;
                        }

                        /* Store our own public address as seen by supernode.
                         * Log if it changed (e.g. WiFi switch). */
                        n2n_sock_t old_pub = eee->my_public_sock;
                        eee->my_public_sock = ra.sock;
                        if (old_pub.family != 0 &&
                            sock_equal(&old_pub, &eee->my_public_sock) != 0)
                        {
                            traceEvent(TRACE_NORMAL, "Our public address changed to %s",
                                       sock_to_cstr(sockbuf1, &eee->my_public_sock));
                        }

                        /* TODO: store sn_bak for backup supernode failover */
                        eee->register_lifetime = ra.lifetime;
                        eee->register_lifetime = max( eee->register_lifetime, REGISTER_SUPER_INTERVAL_MIN );
                        eee->register_lifetime = min( eee->register_lifetime, REGISTER_SUPER_INTERVAL_MAX );

                        /* Store supernode version (reported by SN in REGISTER_SUPER_ACK) */
                        if (ra.sn_version[0] != '\0') {
                            strncpy(eee->supernode_version, ra.sn_version, sizeof(eee->supernode_version) - 1);
                            eee->supernode_version[sizeof(eee->supernode_version) - 1] = '\0';
                        } else {
                            strcpy(eee->supernode_version, "unknown");
                        }

                    } else {
                        /* Duplicate ACK from alt address family: just refresh last_sup */
                        eee->last_sup = now;
                        traceEvent(TRACE_DEBUG, "Rx REGISTER_SUPER_ACK (alt addr, ack#%u) - refreshing last_sup",
                                   eee->sn_ack_count);
                    }
                }
                else
                {
                    traceEvent( TRACE_WARNING, "Rx REGISTER_SUPER_ACK with wrong or old cookie." );
                    /* SN restarted — force immediate re-registration */
                    eee->last_register_req = 0;
                }
            }
            else
            {
                traceEvent( TRACE_INFO, "Rx REGISTER_SUPER_ACK (no pending req)." );
            }
        }
        else if(msg_type == n2n_deregister)
        {
            n2n_DEREGISTER_t dereg;
            decode_DEREGISTER(&dereg, &cmn, udp_buf, &rem, &idx);

            traceEvent(TRACE_INFO, "Rx DEREGISTER from %s",
                       macaddr_str(mac_buf1, dereg.srcMac));

            PEERS_LOCK(eee);
            /* Remove from known_peers */
            uint32_t dereg_ip = 0;
            struct peer_info *prev = NULL, *scan = eee->known_peers;
            while (scan) {
                if (memcmp(scan->mac_addr, dereg.srcMac, N2N_MAC_SIZE) == 0) {
                    dereg_ip = scan->assigned_ip;
                    if (prev) prev->next = scan->next;
                    else eee->known_peers = scan->next;
                    free(scan);
                    break;
                }
                prev = scan;
                scan = scan->next;
            }
            /* Remove from pending_peers too */
            prev = NULL; scan = eee->pending_peers;
            while (scan) {
                if (memcmp(scan->mac_addr, dereg.srcMac, N2N_MAC_SIZE) == 0) {
                    if (prev) prev->next = scan->next;
                    else eee->pending_peers = scan->next;
                    free(scan);
                    break;
                }
                prev = scan;
                scan = scan->next;
            }
            /* Clean up bypass peer entry */
            if (dereg_ip != 0 && eee->bp)
                bypass_peer_gone(eee->bp, dereg_ip);
            PEERS_UNLOCK(eee);
        }
        else
        {
            /* Not a known message type */
            traceEvent(TRACE_WARNING, "Unable to handle packet type %d: ignored", (signed int)msg_type);
            return 0;
        }
    } /* if (community match) */
    else
    {
        traceEvent(TRACE_WARNING, "Received packet with invalid community");
    }

    return 1; /* packet processed, may be more queued */
}

/* ***************************************************** */


#ifdef _WIN32
static DWORD tunReadThread(LPVOID lpArg )
{
    n2n_edge_t *eee = (n2n_edge_t*)lpArg;

    while(eee->keep_running)
    {
        readFromTAPSocket(eee);
    }

    return 0;
}

/** Start a second thread in Windows because TUNTAP interfaces do not expose
 *  file descriptors. */
static void startTunReadThread(n2n_edge_t *eee)
{
    HANDLE hThread;
    DWORD dwThreadId;

    hThread = CreateThread(NULL,         /* security attributes */
                           0,            /* use default stack size */
                           (LPTHREAD_START_ROUTINE)tunReadThread, /* thread function */
                           (void*)eee,   /* argument to thread function */
                           0,            /* thread creation flags */
                           &dwThreadId); /* thread id out */
    eee->tun_thread_handle = (hThread != NULL) ? hThread : NULL;
}
#endif

/* ***************************************************** */

/** Build DNS query packet for TXT record.
 *  Returns the length of the query packet.
 */
static int build_dns_txt_query(const char *domain, uint8_t *buf, size_t buf_size, uint16_t txn_id) {
    if (!domain || !buf || buf_size < 256)
        return -1;
    /* DNS header: 12 bytes */
    buf[0] = (txn_id >> 8) & 0xFF;  /* Transaction ID high */
    buf[1] = txn_id & 0xFF;         /* Transaction ID low */
    buf[2] = 0x01;  /* Flags: Recursion Desired */
    buf[3] = 0x00;
    buf[4] = 0x00; buf[5] = 0x01;  /* Questions: 1 */
    buf[6] = 0x00; buf[7] = 0x00;  /* Answer RRs: 0 */
    buf[8] = 0x00; buf[9] = 0x00;  /* Authority RRs: 0 */
    buf[10] = 0x00; buf[11] = 0x00; /* Additional RRs: 0 */
    /* Build domain name in DNS format (length-prefixed labels) */
    size_t pos = 12;
    const char *p = domain;
    while (*p && pos < buf_size - 20) {
        const char *dot = strchr(p, '.');
        size_t label_len = dot ? (size_t)(dot - p) : strlen(p);
        if (label_len > 63 || label_len == 0) return -1;
        buf[pos++] = (uint8_t)label_len;
        memcpy(buf + pos, p, label_len);
        pos += label_len;
        p = dot ? dot + 1 : p + label_len;
        if (!dot) break;
    }
    buf[pos++] = 0x00;  /* End of domain name */
    /* Query type: TXT (16) */
    buf[pos++] = 0x00; buf[pos++] = 0x10;
    /* Query class: IN (1) */
    buf[pos++] = 0x00; buf[pos++] = 0x01;
    return (int)pos;
}
/** Parse DNS response for TXT record.
 *  Returns 0 on success, -1 on failure.
 */
static int parse_dns_txt_response(const uint8_t *buf, size_t buf_len, uint16_t txn_id,
                                   char *txt_result, size_t result_size) {
    if (!buf || buf_len < 12 || !txt_result)
        return -1;
    /* Check transaction ID */
    if (buf[0] != ((txn_id >> 8) & 0xFF) || buf[1] != (txn_id & 0xFF))
        return -1;
    /* Check flags: must be a response (QR=1) and no error (RCODE=0) */
    if (!(buf[2] & 0x80)) return -1;  /* Not a response */
    if (buf[3] & 0x0F) return -1;      /* Error in response */
    /* Get answer count */
    uint16_t ancount = (buf[6] << 8) | buf[7];
    if (ancount == 0) return -1;
    /* Skip header (12 bytes) and question section */
    size_t pos = 12;
    /* Skip question name */
    while (pos < buf_len && buf[pos] != 0) {
        if (buf[pos] & 0xC0) { pos += 2; break; }  /* Compression pointer */
        pos += buf[pos] + 1;
    }
    if (pos < buf_len && buf[pos] == 0) pos++;
    pos += 4;  /* Skip QTYPE and QCLASS */
    /* Parse answers */
    for (uint16_t i = 0; i < ancount && pos < buf_len; i++) {
        /* Skip name (may be compressed) */
        if (buf[pos] & 0xC0) {
            pos += 2;
        } else {
            while (pos < buf_len && buf[pos] != 0) {
                pos += buf[pos] + 1;
            }
            if (pos < buf_len) pos++;
        }
        if (pos + 10 > buf_len) return -1;
        uint16_t rtype = (buf[pos] << 8) | buf[pos+1];
        uint16_t rdlength = (buf[pos+8] << 8) | buf[pos+9];
        pos += 10;  /* Skip TYPE, CLASS, TTL, RDLENGTH */
        if (rtype == 0x10) {  /* TXT record */
            if (pos + rdlength > buf_len) return -1;
            /* TXT RDATA: first byte is length of the text string */
            uint8_t txt_len = buf[pos];
            if (txt_len > 0 && txt_len < rdlength && txt_len < result_size) {
                memcpy(txt_result, buf + pos + 1, txt_len);
                txt_result[txt_len] = '\0';
                return 0;
            }
        }
        pos += rdlength;
    }
    return -1;
}
/** Query DNS TXT record for supernode address using raw UDP.
 *  Returns 0 on success, -1 on failure.
 *  On success, txt_result contains the supernode address (host:port format).
 */
static int query_txt_record(const char *domain, char *txt_result, size_t result_size) {
    if (!domain || !txt_result || result_size == 0)
        return -1;
    traceEvent(TRACE_INFO, "Querying TXT record for %s", domain);
    /* Public DNS servers to try */
    const char *dns_servers[] = {"8.8.8.8", "119.29.29.29", "1.1.1.1", "223.5.5.5"};
    uint8_t query_buf[256];
    uint8_t response_buf[1024];
    uint16_t txn_id = (uint16_t)(time(NULL) & 0xFFFF);
    /* Build DNS query packet */
    int query_len = build_dns_txt_query(domain, query_buf, sizeof(query_buf), txn_id);
    if (query_len < 0) {
        traceEvent(TRACE_WARNING, "Failed to build DNS query for %s", domain);
        return -1;
    }
    /* Try each DNS server */
    for (int i = 0; i < 4; i++) {
        struct sockaddr_in dns_addr;
        memset(&dns_addr, 0, sizeof(dns_addr));
        dns_addr.sin_family = AF_INET;
        dns_addr.sin_port = htons(53);
        
#ifdef _WIN32
        dns_addr.sin_addr.s_addr = inet_addr(dns_servers[i]);
#else
        inet_pton(AF_INET, dns_servers[i], &dns_addr.sin_addr);
#endif
        /* Create UDP socket */
        SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) continue;
        /* Set socket timeout */
#ifdef _WIN32
        DWORD timeout = 5000;  /* 5 seconds */
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
#else
        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
        /* Send DNS query */
        if (sendto(sock, (char*)query_buf, query_len, 0,
                   (struct sockaddr*)&dns_addr, sizeof(dns_addr)) < 0) {
            closesocket(sock);
            continue;
        }
        /* Receive DNS response */
        socklen_t addr_len = sizeof(dns_addr);
        int resp_len = recvfrom(sock, (char*)response_buf, sizeof(response_buf), 0,
                                 (struct sockaddr*)&dns_addr, &addr_len);
        closesocket(sock);
        if (resp_len > 0) {
            /* Parse DNS response */
            if (parse_dns_txt_response(response_buf, resp_len, txn_id, txt_result, result_size) == 0) {
                traceEvent(TRACE_INFO, "TXT record found: %s", txt_result);
                return 0;
            }
        }
    }
    traceEvent(TRACE_WARNING, "No valid TXT record found for %s", domain);
    return -1;
}

/* ***************************************************** */

/** Query DNS A or AAAA record using raw UDP.
 *  @param domain Domain name to query
 *  @param ip_result Buffer to store result IP address string
 *  @param result_size Size of result buffer
 *  @param query_ipv6 1 for AAAA (IPv6), 0 for A (IPv4)
 *  Returns 0 on success, -1 on failure.
 */
static int query_dns_record(const char *domain, char *ip_result, size_t result_size, int query_ipv6) {
    if (!domain || !ip_result || result_size < (query_ipv6 ? 40 : 16))
        return -1;
    
    const char *dns_servers[] = {"8.8.8.8", "119.29.29.29", "1.1.1.1", "223.5.5.5"};
    uint8_t query_buf[256];
    uint8_t response_buf[1024];
    uint16_t txn_id = (uint16_t)(time(NULL) & 0xFFFF) + query_ipv6;
    uint16_t qtype = query_ipv6 ? 0x1C : 0x01;  /* AAAA=28, A=1 */
    uint16_t expected_rdlen = query_ipv6 ? 16 : 4;
    
    /* Build DNS query */
    query_buf[0] = (txn_id >> 8) & 0xFF;
    query_buf[1] = txn_id & 0xFF;
    query_buf[2] = 0x01; query_buf[3] = 0x00;
    query_buf[4] = 0x00; query_buf[5] = 0x01;
    query_buf[6] = 0x00; query_buf[7] = 0x00;
    query_buf[8] = 0x00; query_buf[9] = 0x00;
    query_buf[10] = 0x00; query_buf[11] = 0x00;
    
    size_t pos = 12;
    const char *p = domain;
    while (*p && pos < sizeof(query_buf) - 20) {
        const char *dot = strchr(p, '.');
        size_t label_len = dot ? (size_t)(dot - p) : strlen(p);
        if (label_len > 63 || label_len == 0) return -1;
        query_buf[pos++] = (uint8_t)label_len;
        memcpy(query_buf + pos, p, label_len);
        pos += label_len;
        p = dot ? dot + 1 : p + label_len;
        if (!dot) break;
    }
    query_buf[pos++] = 0x00;
    query_buf[pos++] = (qtype >> 8) & 0xFF; query_buf[pos++] = qtype & 0xFF;
    query_buf[pos++] = 0x00; query_buf[pos++] = 0x01;
    int query_len = (int)pos;
    
    /* Try each DNS server */
    for (int i = 0; i < 4; i++) {
        struct sockaddr_in dns_addr;
        memset(&dns_addr, 0, sizeof(dns_addr));
        dns_addr.sin_family = AF_INET;
        dns_addr.sin_port = htons(53);
#ifdef _WIN32
        dns_addr.sin_addr.s_addr = inet_addr(dns_servers[i]);
#else
        inet_pton(AF_INET, dns_servers[i], &dns_addr.sin_addr);
#endif
        
        SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) continue;
        
#ifdef _WIN32
        DWORD timeout = 5000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
#else
        struct timeval tv = {5, 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
        
        if (sendto(sock, (char*)query_buf, query_len, 0,
                   (struct sockaddr*)&dns_addr, sizeof(dns_addr)) < 0) {
            closesocket(sock);
            continue;
        }
        
        socklen_t addr_len = sizeof(dns_addr);
        int resp_len = recvfrom(sock, (char*)response_buf, sizeof(response_buf), 0,
                                 (struct sockaddr*)&dns_addr, &addr_len);
        closesocket(sock);
        
        if (resp_len > 12 && 
            response_buf[0] == ((txn_id >> 8) & 0xFF) && 
            response_buf[1] == (txn_id & 0xFF) &&
            (response_buf[2] & 0x80) && !(response_buf[3] & 0x0F)) {
            
            uint16_t ancount = (response_buf[6] << 8) | response_buf[7];
            if (ancount == 0) continue;
            
            /* Skip question */
            pos = 12;
            while (pos < (size_t)resp_len && response_buf[pos] != 0) {
                if ((response_buf[pos] & 0xC0) == 0xC0) { pos += 2; break; }
                pos += response_buf[pos] + 1;
            }
            if (response_buf[pos] == 0) pos++;
            pos += 4;
            
            /* Parse answers */
            for (int j = 0; j < ancount && pos < (size_t)resp_len; j++) {
                if ((response_buf[pos] & 0xC0) == 0xC0) {
                    pos += 2;
                } else {
                    while (pos < (size_t)resp_len && response_buf[pos] != 0)
                        pos += response_buf[pos] + 1;
                    pos++;
                }
                
                if (pos + 10 > (size_t)resp_len) break;
                uint16_t rtype = (response_buf[pos] << 8) | response_buf[pos+1];
                uint16_t rdlength = (response_buf[pos+8] << 8) | response_buf[pos+9];
                pos += 10;
                
                if (rtype == qtype && rdlength == expected_rdlen && pos + rdlength <= (size_t)resp_len) {
                    if (query_ipv6) {
                        snprintf(ip_result, result_size, 
                                "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                                response_buf[pos], response_buf[pos+1], response_buf[pos+2], response_buf[pos+3],
                                response_buf[pos+4], response_buf[pos+5], response_buf[pos+6], response_buf[pos+7],
                                response_buf[pos+8], response_buf[pos+9], response_buf[pos+10], response_buf[pos+11],
                                response_buf[pos+12], response_buf[pos+13], response_buf[pos+14], response_buf[pos+15]);
                    } else {
                        snprintf(ip_result, result_size, "%u.%u.%u.%u",
                                response_buf[pos], response_buf[pos+1], response_buf[pos+2], response_buf[pos+3]);
                    }
                    return 0;
                }
                pos += rdlength;
            }
        }
    }
    return -1;
}

/* ***************************************************** */

/** Resolve the supernode IP address.
 *
 *  REVISIT: This is a really bad idea. The edge will block completely while the
 *           hostname resolution is performed. This could take 15 seconds.
 */
static int supernode2addr(n2n_sock_t * sn, int af, const n2n_sn_name_t addrIn) {
    n2n_sn_name_t addr;
    size_t len;
    int err;

    memcpy( addr, addrIn, N2N_EDGE_SN_HOST_SIZE );
    addr[N2N_EDGE_SN_HOST_SIZE - 1] = '\0'; /* ensure null-terminated */
    len = strlen(addr);

    if ( len > 0) {
        int ip_error = 0;
        char *supernode_port = NULL;

        if (addr[len - 1] != ']') {
            supernode_port = strrchr(addr, ':');
            if ( supernode_port ) {
                sn->port = atoi(supernode_port + 1);
                *(supernode_port) = '\0';
            } else {
                /* No port: query TXT record for supernode address */
                query_txt_record(addr, addr, N2N_EDGE_SN_HOST_SIZE);
                len = strlen(addr);
                supernode_port = strrchr(addr, ':');
                if (supernode_port) {
                    sn->port = atoi(supernode_port + 1);
                    *supernode_port = '\0';
                } else {
                    sn->port = SUPERNODE_PORT;
                }
            }
        }
        if (sn->port == 0)
            sn->port = SUPERNODE_PORT;

        /* try to resolve as numeric address */
        if ( addr[0] == '[' ) {
            /* cut leading and trailing brackets */
            addr[strlen(addr) - 1] = '\0';
            if ((err = inet_pton(AF_INET6, addr + 1, &sn->addr.v6)) != 1) {
                ip_error = errno;
            } else {
                sn->family = AF_INET6;
            }
        } else {
            if ((err = inet_pton(AF_INET, addr, &sn->addr.v4)) != 1) {
                ip_error = errno;
            } else {
                sn->family = AF_INET;
            }
        }

        /* fallback to resolving as a DNS name */
        if (err != 1) {
            /* For domain names, use AF_UNSPEC to get any available address (don't force address family) */
            const struct addrinfo aihints = { 0, AF_UNSPEC, SOCK_DGRAM, 0, 0, NULL, NULL, NULL };
            struct addrinfo * ainfo = NULL;

            err = getaddrinfo( addr, NULL, &aihints, &ainfo );
            if( 0 == err ) {
                if (ainfo) {
                    struct addrinfo *selected = ainfo;
                    
                    /* Prefer user-specified address family, otherwise prefer IPv4 for compatibility */
                    int prefer_af = (af != AF_UNSPEC) ? af : AF_INET;
                    for (struct addrinfo *scan = ainfo; scan; scan = scan->ai_next) {
                        if (scan->ai_family == prefer_af) {
                            selected = scan;
                            break;
                        }
                    }
                    
                    if (PF_INET == selected->ai_family) {
                        struct sockaddr_in* saddr = (struct sockaddr_in*) selected->ai_addr;
                        memcpy( sn->addr.v4, &(saddr->sin_addr), IPV4_SIZE );
                        sn->family = AF_INET;
                    } else if (PF_INET6 == selected->ai_family) {
                        struct sockaddr_in6 * saddr = (struct sockaddr_in6*) selected->ai_addr;
                        memcpy( sn->addr.v6, &(saddr->sin6_addr), IPV6_SIZE );
                        sn->family = AF_INET6;
                    } else {
                        /* Unexpected address family */
                        traceEvent(TRACE_WARNING, "Unsupported address family %d for %s", selected->ai_family, addr);
                        freeaddrinfo(ainfo);
                        err = -1;
                        return -1;
                    }

                    /* If a specific family was requested, verify the result matches */
                    if (err == 0 && af != AF_UNSPEC && sn->family != af) {
                        traceEvent(TRACE_DEBUG, "supernode2addr: resolved family %d for %s does not match requested %d, accept as fallback",
                                   sn->family, addr, af);
                    }
                } else {
                    traceEvent(TRACE_WARNING, "Failed to resolve supernode IP address for %s", addr);
                }

                freeaddrinfo(ainfo);
                err = 0;
            } else {
                /* getaddrinfo failed, try public DNS: prefer requested family, fallback to other */
                char ip_str[64];

                if ( (af != AF_INET) /* want IPv6 */ &&
                     query_dns_record(addr, ip_str, sizeof(ip_str), 1) == 0 &&
                     inet_pton(AF_INET6, ip_str, &sn->addr.v6) == 1) {
                    sn->family = AF_INET6;
                    err = 0;
                } else if ( (af != AF_INET6) /* want IPv4 */ &&
                            query_dns_record(addr, ip_str, sizeof(ip_str), 0) == 0 &&
                            inet_pton(AF_INET, ip_str, &sn->addr.v4) == 1) {
                    sn->family = AF_INET;
                    err = 0;
                } else if (query_dns_record(addr, ip_str, sizeof(ip_str), 0) == 0 &&
                           inet_pton(AF_INET, ip_str, &sn->addr.v4) == 1) {
                    /* Fallback: IPv4 */
                    sn->family = AF_INET;
                    err = 0;
                } else if (query_dns_record(addr, ip_str, sizeof(ip_str), 1) == 0 &&
                           inet_pton(AF_INET6, ip_str, &sn->addr.v6) == 1) {
                    /* Fallback: IPv6 */
                    sn->family = AF_INET6;
                    err = 0;
                } else {
                    /* Both methods failed */
#if _WIN32
                    traceEvent(TRACE_WARNING, "Failed to resolve supernode host %s: %ls", addr, gai_strerror(err));
#else
                    traceEvent(TRACE_WARNING, "Failed to resolve supernode host %s: %s", addr, gai_strerror(err));
#endif
                    err = -1;
                }
            }
        } else {
            err = 0;
        }

    } else {
        traceEvent(TRACE_WARNING, "Wrong supernode parameter (-l <host:port>)");
        err = -1;
    }

    return err;
}

/* ***************************************************** */

/** Check if supernode domain resolved to a new address and re-register if changed.
 *  
 *  Main-thread implementation: periodically re-resolves supernode domain when idle.
 *  Checks every 300 seconds (5 minutes) and only when no communication in last 30 seconds.
 *  If supernode domain resolves to a different address, update and re-register.
 *  
 *  @return 1 if address changed and re-registered, 0 otherwise
 */
static int check_supernode_domain_and_update(n2n_edge_t * eee, time_t now)
{
    n2n_sock_t new_addr;
    
    /* Skip if supernode is not a domain name (re_resolve_supernode_ip == 0) */
    if (!eee->re_resolve_supernode_ip) {
        return 0;
    }
    
    /* Check every 300 seconds (5 minutes) */
    if (eee->last_resolve_check != 0 && (now - eee->last_resolve_check) < 300) {
        return 0;
    }
    
    /* Only resolve if edge is idle (no communication in last 30 seconds) */
    if ((now - eee->last_p2p <= 30)) {
        return 0;
    }
    if ((now - eee->last_sup <= 30)) {
        return 0;
    }
    
    eee->last_resolve_check = now;
    
    /* Resolve supernode domain in main thread (may block briefly) */
    memset(&new_addr, 0, sizeof(n2n_sock_t));
    if (supernode2addr(&new_addr, eee->sn_af, eee->sn_ip_array[eee->sn_idx]) != 0) {
        traceEvent(TRACE_WARNING, "Failed to resolve supernode domain");
        return 0;
    }
    
    /* Check if address changed */
    if (eee->last_resolved_supernode.family != 0 &&
        sock_equal(&eee->last_resolved_supernode, &new_addr) != 0)
    {
        n2n_sock_str_t new_str;
        sock_to_cstr(new_str, &new_addr);
        traceEvent(TRACE_NORMAL, "Supernode address updated to %s", new_str);
        
        /* Update supernode address and re-register */
        eee->supernode = new_addr;
        eee->last_resolved_supernode = new_addr;
        
        /* Re-resolve alternate address for dual-stack registration */
        {
            int alt_af = (eee->supernode.family == AF_INET6) ? AF_INET : AF_INET6;
            int can_resolve = (alt_af == AF_INET6) ? (eee->udp_sock6 != -1) : (eee->udp_sock != -1);
            memset(&eee->supernode_alt, 0, sizeof(n2n_sock_t));
            if (can_resolve) {
                supernode2addr(&eee->supernode_alt, alt_af, eee->sn_ip_array[eee->sn_idx]);
            }
        }
        
        traceEvent(TRACE_NORMAL, "Re-registering with supernode at new address");
        
        /* Reset supernode connection state */
        eee->sup_attempts = N2N_EDGE_SUP_ATTEMPTS;
        eee->sn_wait = 0;
        
        send_register_super(eee, &(eee->supernode));
        eee->last_register_req = now;
        return 1;
    }
    else if (eee->last_resolved_supernode.family == 0)
    {
        /* First resolution - just store it */
        eee->last_resolved_supernode = new_addr;
    }
    
    return 0;
}

/* ***************************************************** */

/** Find the address and IP mode for the tuntap device.
 *
 *  s is one of these forms:
 *
 *  <host> := <hostname> | A.B.C.D
 *
 *  <host> | static:<host> | dhcp:<host>
 *
 *  If the mode is present (colon required) then fill ip_mode with that value
 *  otherwise do not change ip_mode. Fill ip_mode with everything after the
 *  colon if it is present; or s if colon is not present.
 *
 *  ip_add and ip_mode are NULL terminated if modified.
 *
 *  return 0 on success and -1 on error
 */
static int scan_address( char * ip_addr, size_t addr_size,
                         char * ip_mode, size_t mode_size,
                         int* prefixlen,
                         const char * s )
{
    int retval = -1;
    size_t addr_end = addr_size;
    char * p;

    if ( ( NULL == s ) || ( NULL == ip_addr) )
    {
        return -1;
    }

    memset(ip_addr, 0, addr_size);

    p = strpbrk(s, "/");
    if ( p )
    {
        if (prefixlen)
        {
            // TODO error check 0 <= prefixlen <=32
            *prefixlen = atoi(p+1);
        }
        addr_end = p - s;
    }

    p = strpbrk(s, ":");

    if ( p )
    {
        /* colon is present */
        if ( ip_mode )
        {
            size_t end=0;

            memset(ip_mode, 0, mode_size);
            end = min( p - s, (ssize_t)(mode_size - 1) ); /* ensure NULL term */
            strncpy( ip_mode, s, end );
            end = min( addr_end - end - 1, addr_size - 1);
            strncpy( ip_addr, p + 1, end ); /* ensure NULL term */
            retval = 0;
        }
    }
    else
    {
        /* colon is not present */
        strncpy( ip_addr, s, addr_end );
    }

    return retval;
}

/** IP6 Address for TUNTAP device
 *
 * s should be in the form of:
 *
 * aa:bb:cc:ee::01
 *
 * or
 *
 * aa:bb:cc:ee::01/48
 *
 * where 48 is the prefix length (netmask lenth), if not
 * provided, the string is not changed.
 */
static int scan_address6( char * ip6_addr, size_t addr_size,
                          int* ip6_prefixlen,
                          const char * s )
{
    int retval = -1;
    char * p;

    if ( ( NULL == s ) || ( NULL == ip6_addr) )
    {
        return -1;
    }

    memset(ip6_addr, 0, addr_size);

    p = strchr(s, '/');

    if ( p )
    {
        if ( ip6_prefixlen )
        {
            size_t end=0;

            // TODO error check 0 <= prefixlen <= 128
            *ip6_prefixlen = atoi(p + 1);
            end = min( p - s, (ssize_t)(addr_size - 1) );
            strncpy( ip6_addr, s, end );
            retval = 0;
        }
    }
    else
    {
        strncpy( ip6_addr, s, addr_size );
    }

    return retval;
}

/** Scan argument for route and add to route list
 */
static int scan_route(char* optarg, struct tuntap_config* tuntap_config) {
    char* dest = optarg;
    char* prefix = NULL;
    char* gateway;
    char* p = NULL;

    prefix = strchr(dest, '/');
    if (!prefix)
    {
        traceEvent(TRACE_ERROR, "%s is not a valid route", optarg);
        return 0;
    }
    *prefix = '\0';
    prefix += 1;
    gateway = strchr(prefix, ',');
    if (!gateway)
    {
        *prefix = '/';
        traceEvent(TRACE_ERROR, "%s is not a valid route", optarg);
        return 0;
    }
    *gateway = '\0';
    gateway += 1;

    assert((tuntap_config->routes_count == 0) == (tuntap_config->routes == NULL));
    if (!tuntap_config->routes)
    {
        tuntap_config->routes = (route*) calloc(16, sizeof(route));
        if (!tuntap_config->routes) {
            traceEvent(TRACE_ERROR, "Out of memory for routes");
            return 0;
        }
    }
    else if ((tuntap_config->routes_count % 16) == 15)
    {
        tuntap_config->routes = (route*)realloc(tuntap_config->routes,
            ((tuntap_config->routes_count / 16 + 2) * 16) * sizeof(route));
    }

    route* r = &tuntap_config->routes[tuntap_config->routes_count];
    if (inet_pton(AF_INET, dest, r->dest))
    {
        r->family = AF_INET;
        if (!inet_pton(AF_INET, gateway, r->gateway))
        {
            traceEvent(TRACE_ERROR, "%s is not a valid gateway for an IPv4 network", gateway);
            goto fail;
        }
        r->prefixlen = (uint8_t) strtol(prefix, &p, 10);
        if (p == NULL || p == prefix || r->prefixlen > 32)
        {
            traceEvent(TRACE_ERROR, "%s is not a valid prefix length for an IPv4 network", prefix);
            goto fail;
        }
    } else {
        if (!inet_pton(AF_INET6, dest, r->dest))
        {
            traceEvent(TRACE_ERROR, "%s is neither a valid IPv4 or IPv6 address", dest);
            goto fail;
        }
        r->family = AF_INET6;
        if (!inet_pton(AF_INET6, gateway, r->gateway))
        {
            traceEvent(TRACE_ERROR, "%s is not a valid gateway for an IPv6 network", gateway);
            goto fail;
        }
        r->prefixlen = (uint8_t) strtol(prefix, &p, 10);
        if (p == NULL || p == prefix || r->prefixlen > 128)
        {
            traceEvent(TRACE_ERROR, "%s is not a valid prefix length for an IPv6 network", prefix);
            goto fail;
        }
    }

    tuntap_config->routes_count++;
    return 1;
fail:
    if (tuntap_config->routes_count == 0)
    {
        free(tuntap_config->routes);
        tuntap_config->routes = NULL;
    }
    else if ((tuntap_config->routes_count % 16) == 15)
    {
        tuntap_config->routes = (route*) reallocarray(tuntap_config->routes, ((tuntap_config->routes_count / 16 + 1) * 16), sizeof(route));
    }
    return 0;
}

/** In the main loop: start bypass negotiation for known_peers that have
 *  had P2P established for >= 2 seconds (principle 10: "旁路只是备选项").
 *  The 2s guard is enforced by bypass_start_negotiation(). */
static void check_delayed_bypass(n2n_edge_t *eee, time_t now)
{
    if (!eee->bp) return;
    struct peer_info *scan = eee->known_peers;
    while (scan) {
        if (scan->p2p_est_time > 0 && (now - scan->p2p_est_time) >= 2 &&
            scan->assigned_ip != 0)
        {
            bypass_start_negotiation(eee->bp, scan);
        }
        scan = scan->next;
    }
}

static int run_loop(n2n_edge_t * eee );

#define N2N_NETMASK_STR_SIZE    16 /* dotted decimal 12 numbers + 3 dots */
#define N2N_MACNAMSIZ           18 /* AA:BB:CC:DD:EE:FF + NULL*/
#define N2N_IF_MODE_SIZE        16 /* static | dhcp */

/** Entry point to program from kernel. */
int main(int argc, char* argv[])
{
    int     opt;
    int     local_port = 0 /* any port */;
    int     mgmt_port = N2N_EDGE_MGMT_PORT; /* 5644 by default */
    char    mgmt_path[108];
    char    tuntap_dev_name[N2N_IFNAMSIZ] = "n2n0";
    char    ip_mode[N2N_IF_MODE_SIZE]="static";
    ipstr_t ip_addr = "";
    int     ip_prefixlen = 24;
    ipstr_t ip6_addr = "";
    int     ip6_prefixlen = 64;
    int     mtu = DEFAULT_MTU;
    int     got_s = 0;
    struct tuntap_config tuntap_config;
    int encrypt_mode = 4;

#ifndef _WIN32
    uid_t   userid = 0;
    gid_t   groupid = 0;
#endif
#ifdef HAVE_LIBCAP
    cap_t caps, caps_original;
    cap_value_t caps_array[] = { CAP_NET_ADMIN, CAP_SETUID, CAP_SETGID };
    cap_flag_value_t is_flag_set;
#endif

    char    device_mac[N2N_MACNAMSIZ]="";
    char *  encrypt_key=NULL;
    int     has_k_flag = 0;
    int     has_A_flag = 0;

    n2n_edge_t eee; /* single instance for this program */

/* Handle -Q before any initialization: optional port argument */
{
    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-Q") == 0) {
#ifdef _WIN32
            initWin32();
#endif
            uint16_t qport = N2N_EDGE_MGMT_PORT;
            if (i + 1 < argc && argv[i+1][0] != '-') {
                int p = atoi(argv[i+1]);
                if (p > 0 && p <= 65535) qport = (uint16_t)p;
            }
            return query_mgmt(qport);
        }
    }
}

#ifdef HAVE_LIBCAP
#ifdef PR_CAP_AMBIENT
    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0L, 0L, 0L);
#endif
    caps_original = cap_get_proc();
    caps = cap_init();
    cap_set_flag(caps, CAP_PERMITTED, 1, caps_array, CAP_SET);
    cap_get_flag(caps_original, CAP_SETUID, CAP_PERMITTED, &is_flag_set);
    if (is_flag_set == CAP_SET)
        cap_set_flag(caps, CAP_PERMITTED, 1, caps_array+1, CAP_SET);
    cap_get_flag(caps_original, CAP_SETGID, CAP_PERMITTED, &is_flag_set);
    if (is_flag_set == CAP_SET)
        cap_set_flag(caps, CAP_PERMITTED, 1, caps_array+2, CAP_SET);
    cap_set_proc(caps);
    cap_free(caps);
    cap_free(caps_original);
#endif

#ifdef _WIN32
    /* Register console control handler so Ctrl+C / console close triggers
     * graceful shutdown and UPnP port cleanup. */
    SetConsoleCtrlHandler(edge_console_ctrl_handler, TRUE);
#else
    /* Register signal handlers early so SIGTERM/SIGINT always trigger
     * graceful shutdown and UPnP port cleanup, even during startup. */
    signal(SIGTERM, edge_signal_handler);
    signal(SIGINT,  edge_signal_handler);
    signal(SIGPIPE, SIG_IGN);  /* prevent write to closed socket from killing edge */
#endif

    if (-1 == edge_init(&eee) ) {
        traceEvent( TRACE_ERROR, "Failed in edge_init" );
        exit(1);
    }

    if( getenv( "N2N_KEY" ))
        encrypt_key = strdup( getenv( "N2N_KEY" ));

#ifndef _WIN32
    if ( getenv( "JOURNAL_STREAM" ) )
        useSystemd = true;
#else
    /* Windows: clear default device name so any TAP adapter is accepted */
    tuntap_dev_name[0] = '\0';
#endif
    memset(&tuntap_config, 0, sizeof(tuntap_config));

    memset(&(eee.supernode), 0, sizeof(eee.supernode));
    eee.supernode.family = AF_INET;

/* Check if first argument is a config file (not starting with '-') */
if (argc > 1 && argv[1][0] != '-' && access(argv[1], R_OK) == 0) {
    char linebuffer[MAX_CMDLINE_BUFFER_LENGTH] = {0};
    if (readConfFile(argv[1], linebuffer) < 0) {
        traceEvent(TRACE_ERROR, "Failed to read config file: %s", argv[1]);
        exit(1);
    }

    /* Build new argv from config file and remaining arguments */
    char **config_argv;
    int config_argc;

    /* Parse config file into argv */
    config_argv = buildargv(&config_argc, linebuffer);
    if (!config_argv) {
        traceEvent(TRACE_ERROR, "Failed to parse config file");
        exit(1);
    }

    /* Create new argv array with program name and remaining args */
    char **new_argv = malloc((config_argc + argc - 1) * sizeof(char*));
    new_argv[0] = argv[0];

    /* Copy config file arguments */
    for (int i = 0; i < config_argc; i++) {
        new_argv[i + 1] = config_argv[i];
    }

    /* Copy remaining command line arguments */
    for (int i = 2; i < argc; i++) {
        new_argv[config_argc + i - 1] = argv[i];
    }

    /* Update argc and argv for getopt_long */
    argc = config_argc + argc - 1;
    argv = new_argv;
    optind = 1; /* Reset getopt */
}

    optarg = NULL;
    while((opt = getopt_long(argc,
        argv,
        "46K:k:a:c:Eu:g:m:M:d:l:p:fvhrt:R:A:b::wG", long_options, NULL
    )) != EOF) {
        switch (opt) {
        case '4':
            eee.sn_af = AF_INET;
        break;
        case '6':
            eee.sn_af = AF_INET6;
        break;
        case 'A':
            has_A_flag = 1;
            if (!optarg || strlen(optarg) == 0) {
                fprintf(stderr, "Error: Invalid -A option format. Use -A3 or -A 3\n");
                exit(1);
            }
            for (int i = 0; optarg[i]; i++) {
                if (!isdigit(optarg[i])) {
                    fprintf(stderr, "Error: Invalid -A option format. Use -A3 or -A 3\n");
                    exit(1);
                }
            }
            encrypt_mode = atoi(optarg);
            if (encrypt_mode < 1 || encrypt_mode > 5) {
                fprintf(stderr, "Error: Invalid encryption mode. Use A1-A5\n");
                exit(1);
            }
            break;
        case'K':
            fprintf(stderr, "Error: -K (keyfile) is no longer supported. Use -k with -A3/-A4/-A5.\n");
            exit(1);
        case 'a': /* IP address and mode of TUNTAP interface (auto-detect IPv4/IPv6) */
            if (optarg && strlen(optarg) > 0) {
                if (strchr(optarg, ':')) {
                    scan_address6(ip6_addr, INET6_ADDRSTRLEN, &ip6_prefixlen, optarg );
                } else {
                    scan_address(ip_addr, N2N_NETMASK_STR_SIZE,
                                 ip_mode, N2N_IF_MODE_SIZE,
                                 &ip_prefixlen, optarg );
                }
            } else {
                default_ip_assignment = 1;
                strcpy(ip_mode, "static");
                ip_prefixlen = 24;
            }
            break;
        case 'c': /* community as a string */
            memset( eee.community_name, 0, N2N_COMMUNITY_SIZE );
            strncpy( (char *)eee.community_name, optarg, N2N_COMMUNITY_SIZE - 1);
            memcpy(eee.community_name_full, eee.community_name, N2N_COMMUNITY_SIZE);
            break;
        case 'E': /* multicast ethernet addresses accepted. */
            eee.drop_multicast=0;
            traceEvent(TRACE_DEBUG, "Enabling ethernet multicast traffic");
            break;

#ifndef _WIN32
        case 'u': /* unprivileged uid */
            userid = atoi(optarg);
            break;
        case 'g': /* unprivileged gid */
            groupid = atoi(optarg);
            break;
#endif
#ifdef N2N_HAVE_DAEMON
        case 'f' : /* do not fork as daemon */
            eee.daemon=0;
            break;
#endif

        case 'm' : /* TUNTAP MAC address */
            strncpy(device_mac,optarg,N2N_MACNAMSIZ);
            break;
        case 'M' : /* TUNTAP MTU */
            mtu = atoi(optarg);
            break;

        case 'k': /* encrypt key */
            has_k_flag = 1;
            if (encrypt_key) free(encrypt_key);
            encrypt_key = strdup(optarg);
            traceEvent(TRACE_DEBUG, "encrypt_key = '%s'", encrypt_key);
            break;
        case 'r': /* enable packet routing across n2n endpoints */
            eee.allow_routing = 1;
            break;
        case 'R': /* add a route */
            scan_route(optarg, &tuntap_config);
            eee.allow_routing = 1;
            break;

        case 'l': /* supernode-list */
        {
            if ( eee.sn_num < N2N_EDGE_NUM_SUPERNODES ) {
                strncpy( (eee.sn_ip_array[eee.sn_num]), optarg, N2N_EDGE_SN_HOST_SIZE);
                traceEvent(TRACE_DEBUG, "Adding supernode[%u] = %s", (unsigned int)eee.sn_num, (eee.sn_ip_array[eee.sn_num]) );
                ++eee.sn_num;
            } else {
                fprintf(stderr, "Too many supernodes!\n" );
                exit(1);
            }
            break;
        }

#if defined(N2N_CAN_NAME_IFACE)
        case 'd': /* TUNTAP name */
            strncpy(tuntap_dev_name, optarg, N2N_IFNAMSIZ);
            break;
#endif
        case 'p':
            local_port = atoi(optarg);
            eee.local_port = (uint16_t)local_port;
            break;

        case 't':
            if (optarg[0] == '/') {
                mgmt_port = 0;
                strncpy(mgmt_path, optarg, sizeof(mgmt_path));
            } else
                mgmt_port = atoi(optarg);
            break;

        case 'h': /* help */
            help();
            exit(0);

        case 'b': /* bypass port, -b or -b PORT enables bypass */
            if (optarg) {
                int bp_port = atoi(optarg);
                if (bp_port > 0 && bp_port < 65536) {
                    eee.bp_proxy_port = (uint16_t)bp_port;
                    eee.bp_user_disabled = 0; /* port given = enable bypass */
                }
            } else {
                /* Check next argv for a numeric argument (support -b 1234) */
                if (optind < argc) {
                    const char *next = argv[optind];
                    int isnum = 1;
                    for (const char *p = next; *p; p++) {
                        if (!isdigit(*p)) { isnum = 0; break; }
                    }
                    if (isnum) {
                        int bp_port = atoi(next);
                        if (bp_port > 0 && bp_port < 65536) {
                            eee.bp_proxy_port = (uint16_t)bp_port;
                            eee.bp_user_disabled = 0;
                            optind++;
                            break;
                        }
                    }
                }
                /* No numeric argument: enable bypass with default port */
                eee.bp_user_disabled = 0;
            }
            break;

        case 'v': /* verbose */
            ++traceLevel;
            break;

        case 'w': /* WebSocket mode: relay via supernode over WS (TCP), disable P2P */
            eee.use_ws = 1;
            break;

        case 'G': /* Gaming mode: actively probe all peers on start */
            eee.enable_gaming_mode = 1;
            break;

        } /* end switch */
    }

    /* Save full community name for local display, then obfuscate what
     * gets sent to the supernode when no encryption key is available
     * or encryption is explicitly disabled (-A1).
     *
     * When encryption is disabled (null_transop):
     *   - Only the first half of the community name is sent to the supernode
     *     (e.g. "mycommunity" → "mycom" on the wire)
     *   - If neither -k nor -A was explicitly given (simple mode), the second
     *     half is used as the encryption key */
    {
        char full_community[N2N_COMMUNITY_SIZE];
        memcpy(full_community, eee.community_name, N2N_COMMUNITY_SIZE);

        int no_encrypt = (encrypt_key == NULL) || (has_A_flag && encrypt_mode == 1);

        if (no_encrypt && eee.community_name[0] != 0) {
            size_t len = strlen((const char *)eee.community_name);
            size_t half = len / 2;

            if (half < len) {
                /* Simple mode: no -k and no -A given → use second half as key */
                if (!has_k_flag && !has_A_flag) {
                    encrypt_key = strdup((const char *)&eee.community_name[half]);
                }
                /* Truncate: only first half goes to supernode */
                memset(&eee.community_name[half], 0, N2N_COMMUNITY_SIZE - half);
            }
        }

        /* Use full name for local display */
        memcpy(eee.community_name_full, full_community, N2N_COMMUNITY_SIZE);
    }

    if (eee.sn_num == 0) {
        strcpy(eee.sn_ip_array[0], "n2n6.ouno.eu.org");
        eee.sn_num = 1;
    }

    if (default_ip_assignment == 0 && strlen(ip_addr) == 0) {
        default_ip_assignment = 1;
        tuntap_config.delay_ip_config = 1;
        strcpy(ip_mode, "static");
        ip_prefixlen = 24;
    }

#ifdef HAVE_LIBCAP
    caps = cap_init();
    cap_set_flag(caps, CAP_PERMITTED, 3, caps_array, CAP_SET);
    cap_set_flag(caps, CAP_EFFECTIVE, 2, caps_array + 1, CAP_SET);
    cap_set_proc(caps);
    cap_free(caps);
    prctl(PR_SET_KEEPCAPS, 1L);
    if ((userid != 0) || (groupid != 0)) {
        setregid(groupid, groupid);
        setreuid(userid, userid);
    }
    prctl(PR_SET_KEEPCAPS, 0L);
    caps = cap_init();
    cap_set_flag(caps, CAP_PERMITTED, 1, caps_array, CAP_SET);
    cap_set_proc(caps);
    cap_free(caps);
#endif

    srand((unsigned int) time(NULL));

    if(!(
#if N2N_CAN_NAME_IFACE && !defined(_WIN32)
        (tuntap_dev_name[0] != 0) &&
#endif
        (eee.community_name[0] != 0))) {
        help();
        exit(1);
    }

    printf("\n");
    traceEvent(TRACE_NORMAL, "Starting edge %s", n2n_sw_version_full);

    for (int i = 0; i < eee.sn_num; ++i) {
        if (strcmp(eee.sn_ip_array[i], "n2n6.ouno.eu.org") == 0) continue;
        traceEvent(TRACE_NORMAL, "Supernode %u => %s", i, (eee.sn_ip_array[i]));
    }

    while (supernode2addr(&(eee.supernode), eee.sn_af, eee.sn_ip_array[eee.sn_idx]) != 0) {
        if (!g_edge_running) break;
        traceEvent(TRACE_WARNING, "Failed to resolve supernode, retrying in 5 seconds...");
#ifdef _WIN32
        Sleep(5000);
#else
        sleep(5);
#endif
    }

    memset(&eee.supernode_alt, 0, sizeof(n2n_sock_t));

    /* Check if supernode is domain name, enable periodic re-resolution */
    {
        char *sn_host = eee.sn_ip_array[eee.sn_idx];
        char host_only[N2N_EDGE_SN_HOST_SIZE];
        strncpy(host_only, sn_host, sizeof(host_only) - 1);
        host_only[sizeof(host_only) - 1] = '\0';
        char *colon = strchr(host_only, ':');
        if (colon) *colon = '\0';
        struct in_addr ipv4_addr;
        struct in6_addr ipv6_addr;
        if (inet_pton(AF_INET, host_only, &ipv4_addr) != 1 &&
            inet_pton(AF_INET6, host_only, &ipv6_addr) != 1) {
            eee.re_resolve_supernode_ip = 1;
            traceEvent(TRACE_INFO, "'%s', enabling periodic resolution", sn_host);
        }
    }

    if (NULL == encrypt_key) {
        traceEvent(TRACE_DEBUG, "Encryption is disabled in edge.");
        eee.null_transop = 1;
    }

    if ( 0 == strcmp( "dhcp", ip_mode ) ) {
        traceEvent(TRACE_NORMAL, "Dynamic IP address assignment enabled.");
        eee.dyn_ip_mode = 1;
    }

    tuntap_config.if_name = tuntap_dev_name;
    tuntap_config.community_name = (const char*)eee.community_name_full;
    if (device_mac[0] != '\0') {
        if (6 != sscanf(device_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
            &tuntap_config.device_mac[0], &tuntap_config.device_mac[1],
            &tuntap_config.device_mac[2], &tuntap_config.device_mac[3],
            &tuntap_config.device_mac[4], &tuntap_config.device_mac[5])) {
            traceEvent(TRACE_ERROR, "not valid mac address: %s", device_mac);
        }
        if (1 == (tuntap_config.device_mac[0] % 2)) {
            traceEvent(TRACE_ERROR, "not a valid singlecast mac address: %s", device_mac);
        }
    }
    tuntap_config.mtu = mtu;
    tuntap_config.dyn_ip4 = eee.dyn_ip_mode;
    if (strlen(ip_addr) > 0) inet_pton(AF_INET, ip_addr, &tuntap_config.ip_addr);
    tuntap_config.ip_prefixlen = ip_prefixlen;

    /* Prevent multiple local processes with the same IP.
     * On Windows: use a named mutex (auto-released on process exit).
     * On Linux: TAP is destroyed on exit, use interface scan. */
    if (strlen(ip_addr) > 0 && default_ip_assignment == 0) {
#ifdef _WIN32
        char mutex_name[64];
        snprintf(mutex_name, sizeof(mutex_name), "Global\\n2n_edge_%s", ip_addr);
        HANDLE hMutex = CreateMutexA(NULL, TRUE, mutex_name);
        if (hMutex) {
            if (GetLastError() == ERROR_ALREADY_EXISTS) {
                CloseHandle(hMutex);
                traceEvent(TRACE_ERROR, "IP address %s already in use on this machine, exiting", ip_addr);
                exit(1);
            }
        }
#else
        int ip_conflict = 0;
        uint32_t target_ip = tuntap_config.ip_addr;
        struct ifaddrs *ifaddr, *ifa;
        if (getifaddrs(&ifaddr) == 0) {
            for (ifa = ifaddr; ifa != NULL && !ip_conflict; ifa = ifa->ifa_next) {
                if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
                    struct sockaddr_in *pAddr = (struct sockaddr_in *)ifa->ifa_addr;
                    if (pAddr->sin_addr.s_addr == target_ip)
                        ip_conflict = 1;
                }
            }
            freeifaddrs(ifaddr);
        }
        if (ip_conflict) {
            traceEvent(TRACE_ERROR, "IP address %s already in use on this machine, exiting", ip_addr);
            exit(1);
        }
#endif
    }

    if (ip6_addr[0] != '\0') {
        if (inet_pton(AF_INET6, ip6_addr, &tuntap_config.ip6_addr) != 1)
            traceEvent(TRACE_ERROR, "invalid ipv6 address: %s", ip6_addr);
        tuntap_config.ip6_prefixlen = ip6_prefixlen;
    } else {
        tuntap_config.ip6_prefixlen = 0;
    }

#if defined(HAVE_LIBCAP)
    /* set effective capabilitiy NET_ADMIN */
    caps = cap_init();
    cap_set_flag(caps, CAP_EFFECTIVE, 1, caps_array, CAP_SET);
    cap_set_flag(caps, CAP_PERMITTED, 1, caps_array, CAP_SET);
    cap_set_proc(caps);
    cap_free(caps);
#elif !defined(_WIN32)
    /* If running suid root then we need to setuid before using the force. */
    if (setuid(0) != 0) {
        traceEvent(TRACE_WARNING, "setuid failed");
    }
    /* setgid( 0 ); */
#endif

    if(tuntap_open(&(eee.device), &tuntap_config) < 0)
        return(-1);

#if defined(HAVE_LIBCAP)
    caps = cap_init();
    cap_set_proc(caps);
    cap_free(caps);
#elif !defined(_WIN32)
    if ((userid != 0) || (groupid != 0)) {
        traceEvent(TRACE_NORMAL, "Interface up. Dropping privileges to uid=%d, gid=%d",
                   (signed int)userid, (signed int)groupid);
        if (setregid(groupid, groupid) != 0) traceEvent(TRACE_WARNING, "setregid failed");
        if (setreuid(userid, userid) != 0) traceEvent(TRACE_WARNING, "setreuid failed");
    }
#endif

    if(local_port > 0)
        traceEvent(TRACE_NORMAL, "Binding to local port %d", (signed int)local_port);

    if (setup_encryption(&eee, encrypt_mode, encrypt_key) < 0)
        return -1;

    if (setup_sockets(&eee, local_port) < 0)
        return -1;

    /* Resolve alternate supernode address for dual-stack registration */
    if (eee.supernode_alt.family == 0) {
        char *sn_host = eee.sn_ip_array[eee.sn_idx];
        int alt_af = (eee.supernode.family == AF_INET6) ? AF_INET : AF_INET6;
        int can_resolve = (alt_af == AF_INET6) ? (eee.udp_sock6 != -1) : (eee.udp_sock != -1);

        if (can_resolve && supernode2addr(&eee.supernode_alt, alt_af, sn_host) == 0) {
            n2n_sock_str_t sockbuf_alt;
            if (eee.supernode_alt.family != alt_af) {
                traceEvent(TRACE_DEBUG, "Supernode alt address: expected %s but resolved to %s",
                           (alt_af == AF_INET6) ? "IPv6" : "IPv4",
                           sock_to_cstr(sockbuf_alt, &eee.supernode_alt));
                /* Keep it but will be skipped in send_register_super due to family check */
            }
        }
    }

    if (setup_mgmt_socket(&eee, mgmt_port, mgmt_path) < 0)
        return -1;

    /* Initialize bypass module */
    {
        uint16_t bp_port = eee.bp_proxy_port ? eee.bp_proxy_port : BYPASS_DEFAULT_PORT;
        eee.bp_proxy_port = bp_port;
        /* Allocate bypass context on heap to avoid large stack usage */
        eee.bp = (bypass_context_t *)calloc(1, sizeof(bypass_context_t));
        if (eee.bp) {
            if (bypass_init(eee.bp, &eee, &eee.device, eee.device.ip_addr,
                             eee.device.ip_prefixlen) < 0) {
                traceEvent(TRACE_WARNING, "Bypass init failed, continuing without bypass");
                free(eee.bp);
                eee.bp = NULL;
            } else {
                eee.bp_proxy_port = eee.bp->proxy_port;
            }
        }
    }

    traceEvent(TRACE_NORMAL, "Edge started");

    setup_upnp(&eee, local_port);
    set_localip(&eee);

    /* WS mode: establish WebSocket connection to supernode (TCP same port) */
    if (eee.use_ws) {
        edge_ws_connect(&eee);
    }

    update_supernode_reg(&eee, n2n_now());

    return run_loop(&eee);
}

static void edge_ws_connect(n2n_edge_t *eee) {
    char ws_host[INET6_ADDRSTRLEN];
    uint16_t ws_port = eee->supernode.port;

    if (eee->supernode.family == AF_INET6)
        inet_ntop(AF_INET6, eee->supernode.addr.v6, ws_host, sizeof(ws_host));
    else if (eee->supernode.family == AF_INET)
        inet_ntop(AF_INET, eee->supernode.addr.v4, ws_host, sizeof(ws_host));
    else {
        traceEvent(TRACE_WARNING, "WS: supernode address not resolved yet, skip");
        eee->ws_last_reconnect = n2n_now();
        return;
    }

    if (eee->ws_conn.state == WS_OPEN) return;
    if (n2n_now() - eee->ws_last_reconnect < 5 && eee->ws_last_reconnect != 0) return;

    ws_close(&eee->ws_conn);
    ws_init(&eee->ws_conn);
    eee->ws_conn.is_client = 1; /* edge side: send with mask */
    if (ws_connect(&eee->ws_conn, ws_host, ws_port) == 0) {
        traceEvent(TRACE_NORMAL, "WS connected to %s:%u", ws_host, ws_port);
    } else {
        /* Check if supernode is domain name, enable domain reconnecting */
        {
            char *sn_host = eee->sn_ip_array[eee->sn_idx];
            char host_only[N2N_EDGE_SN_HOST_SIZE];
            strncpy(host_only, sn_host, sizeof(host_only) - 1);
            host_only[sizeof(host_only) - 1] = '\0';
            char *colon = strchr(host_only, ':');
            if (colon) *colon = '\0';
            strncpy(ws_host, host_only, sizeof(ws_host) - 1);
            traceEvent(TRACE_WARNING, "'%s', enabling domain reconnecting", sn_host);
        }
        if (ws_connect(&eee->ws_conn, ws_host, ws_port) == 0) {
            traceEvent(TRACE_NORMAL, "WS connected to %s:%u", ws_host, ws_port);
        } else {
          traceEvent(TRACE_INFO, "WS connect to %s:%u failed (will retry)", ws_host, ws_port);
          eee->ws_last_reconnect = n2n_now();
        }
    }
}

static int run_loop(n2n_edge_t * eee )
{
    int   keep_running=1;
    size_t numPurged;
    time_t lastIfaceCheck=0;
    time_t lastTransop=0;
    time_t lastUpnpRenew=0;
    int   retval = 0;

#ifdef _WIN32
    startTunReadThread(eee);
#endif

    /* Main loop
     *
     * select() is used to wait for input on either the TAP fd or the UDP/TCP
     * socket. When input is present the data is read and processed by either
     * readFromIPSocket() or readFromTAPSocket()
     */

    while(keep_running && g_edge_running)
    {
        int rc, max_sock = 0;
        fd_set socket_mask;
        struct timeval wait_time;
        time_t nowTime;

        FD_ZERO(&socket_mask);
        FD_SET(eee->udp_sock, &socket_mask);
        max_sock = (int) eee->udp_sock;
        if (eee->udp_sock6 != -1) {
            FD_SET(eee->udp_sock6, &socket_mask);
            max_sock = max(max_sock, (int) eee->udp_sock6);
        }
        if (eee->mgmt_sock != -1) {
            FD_SET(eee->mgmt_sock, &socket_mask);
            max_sock = max(max_sock, (int) eee->mgmt_sock);
        }
#ifndef _WIN32
        FD_SET(eee->device.fd, &socket_mask);
        max_sock = max( (int) max_sock, (int) eee->device.fd );
#endif

        /* WS mode: add WebSocket connection fd to select */
        if (eee->use_ws && eee->ws_conn.state == WS_OPEN && eee->ws_conn.fd >= 0) {
            FD_SET(eee->ws_conn.fd, &socket_mask);
            max_sock = max(max_sock, (int)eee->ws_conn.fd);
        }

        /* Add bypass proxy and connection sockets to select */
        fd_set bypass_write_mask;
        int bypass_active = bypass_has_peers(eee->bp);
        if (bypass_active) {
            FD_ZERO(&bypass_write_mask);
            if (eee->bp->proxy_sock >= 0) {
                FD_SET(eee->bp->proxy_sock, &socket_mask);
                max_sock = max(max_sock, eee->bp->proxy_sock);
            }
            for (int _bci = 0; _bci < BYPASS_MAX_CONNS; _bci++) {
                if (eee->bp->conns[_bci].state != BYPASS_CONN_FREE &&
                    eee->bp->conns[_bci].local_sock >= 0) {
                    if (!eee->bp->conns[_bci].fin_sent) {
                        FD_SET(eee->bp->conns[_bci].local_sock, &socket_mask);
                        max_sock = max(max_sock, (int)eee->bp->conns[_bci].local_sock);
                    }
                    if (eee->bp->conns[_bci].tx_buf_len > 0 &&
                        !eee->bp->conns[_bci].fin_rcvd) {
                        FD_SET(eee->bp->conns[_bci].local_sock, &bypass_write_mask);
                    }
                }
            }
        }

        wait_time.tv_sec = SOCKET_TIMEOUT_INTERVAL_SECS; wait_time.tv_usec = 0;
        /* When KCP connections are active, use 10ms select timeout
         * for responsive KCP updates (ikcp_update every 10ms). */
        if (bypass_has_kcp_conns(eee->bp)) {
            wait_time.tv_sec = 0;
            wait_time.tv_usec = 10000;  /* 10ms */
        }

        rc = select(max_sock+1, &socket_mask, bypass_active ? &bypass_write_mask : NULL, NULL, &wait_time);
        nowTime=n2n_now();

        /* Handle signal interruption */
        if (rc < 0) {
#ifdef _WIN32
            int _sel_err = WSAGetLastError();
            if (_sel_err == WSAEINTR) {
                continue;
            }
            traceEvent(TRACE_ERROR, "select() failed: [%d]", _sel_err);
            if (_sel_err == WSAENOTSOCK || _sel_err == WSAENOBUFS) {
                retval = -1;
                goto cleanup;
            }
#else
            if (errno == EINTR) {
                continue;
            }
            traceEvent(TRACE_ERROR, "select() failed: %s", strerror(errno));
            if (errno == EBADF || errno == ENOMEM) {
                retval = -1;
                goto cleanup;
            }
#endif
            continue;
        }

        /* Make sure ciphers are updated before the packet is treated. */
        if ( ( nowTime - lastTransop ) > TRANSOP_TICK_INTERVAL )
        {
            lastTransop = nowTime;
            n2n_tick_transop( eee, nowTime );
        }

        if(rc > 0)
        {
            /* Any or all of the FDs could have input; check them all. */
            if(FD_ISSET(eee->udp_sock, &socket_mask))
            {
                /* Drain UDP queue: read until no more packets (non-blocking).
                 * 128 cap prevents starvation of other FDs (TAP, mgmt, etc). */
                for (int _di = 0; _di < 128; _di++) {
                    if (!readFromIPSocket(eee, eee->udp_sock))
                        break;
                }
            }

            if(eee->udp_sock6 != -1 && FD_ISSET(eee->udp_sock6, &socket_mask))
            {
                for (int _di = 0; _di < 128; _di++) {
                    if (!readFromIPSocket(eee, eee->udp_sock6))
                        break;
                }
            }

            /* WS mode: handle WebSocket fd read */
            if (eee->use_ws && eee->ws_conn.state == WS_OPEN &&
                eee->ws_conn.fd >= 0 &&
                FD_ISSET(eee->ws_conn.fd, &socket_mask)) {
                readFromIPSocket(eee, eee->ws_conn.fd);
            }

            if(eee->mgmt_sock != -1 && FD_ISSET(eee->mgmt_sock, &socket_mask))
            {
                readFromMgmtSocket(eee, &keep_running);
            }

            /* Handle bypass proxy and connection sockets */
            if (bypass_active) {
                if (eee->bp->proxy_sock >= 0 && FD_ISSET(eee->bp->proxy_sock, &socket_mask)) {
                    bypass_accept_proxy(eee->bp);
                }
                for (int _bci = 0; _bci < BYPASS_MAX_CONNS; _bci++) {
                    if (eee->bp->conns[_bci].state != BYPASS_CONN_FREE &&
                        eee->bp->conns[_bci].local_sock >= 0 &&
                        FD_ISSET(eee->bp->conns[_bci].local_sock, &socket_mask)) {
                        bypass_handle_local_read(eee->bp, _bci);
                    }
                }
                /* Handle bypass writable sockets (flush tx_buf) */
                for (int _bci = 0; _bci < BYPASS_MAX_CONNS; _bci++) {
                    if (eee->bp->conns[_bci].state != BYPASS_CONN_FREE &&
                        eee->bp->conns[_bci].local_sock >= 0 &&
                        FD_ISSET(eee->bp->conns[_bci].local_sock, &bypass_write_mask)) {
                        bypass_handle_local_write(eee->bp, _bci);
                    }
                }
            }

#ifndef _WIN32
            if(FD_ISSET(eee->device.fd, &socket_mask))
            {
                /* Read an ethernet frame from the TAP socket. Write on the IP
                 * socket. */
                readFromTAPSocket(eee);
            }
#endif
        }

        /* Finished processing select data. */

        update_supernode_reg(eee, nowTime);
        PEERS_LOCK(eee);
        /* WS mode disables P2P hole-punching, forces relay via supernode */
        if (!eee->use_ws) {
            check_punch_timeouts(eee, nowTime);
        }
        PEERS_UNLOCK(eee);

        /* WS reconnection: retry every 5s after disconnect, re-register immediately on reconnect */
        if (eee->use_ws && eee->ws_conn.state != WS_OPEN) {
            if (nowTime - eee->ws_last_reconnect >= 5) {
                edge_ws_connect(eee);
                if (eee->ws_conn.state == WS_OPEN) {
                    eee->last_register_req = 0;  /* skip 30s interval, re-register immediately */
                }
            }
        }
        /* WS mode: rely on TCP keepalive (set in ws_set_keepalive) to detect dead connections,
         * no application-level ping needed. */
        if (eee->use_ws && eee->ws_conn.state == WS_OPEN) {
            /* check for stale connection via last_seen (updated on data recv only) */
            if (nowTime - eee->ws_conn.last_seen > 120) {
                traceEvent(TRACE_WARNING, "WS connection stale, closing");
                ws_close(&eee->ws_conn);
                eee->ws_last_reconnect = nowTime;
            }
        }

        /* Periodically check if supernode domain resolved to a new address */
        check_supernode_domain_and_update(eee, nowTime);

        /* Delayed bypass start: ensure P2P has been established >= 2s
         * before starting negotiation (principle 10). */
        check_delayed_bypass(eee, nowTime);

        /* Bypass tick: handle timeouts and state transitions */
        if (bypass_has_peers(eee->bp)) {
            bypass_tick(eee->bp, nowTime);
        }

        /* Re-send bypass probe frames for peers still in PROBING state.
         * Build the encrypted n2n PACKET via send_packet2net, but override
         * the destination to send directly to the peer's P2P UDP address,
         * bypassing find_peer_destination's relay-via-supernode logic.
         * This prevents "Relayed packet: addr changed" on the peer side. */
        if (bypass_has_peers(eee->bp) && eee->bp->enabled && !eee->bp->user_disabled) {
            uint8_t probe_buf[19 * BYPASS_MAX_PEERS];
            int n = bypass_get_pending_probes(eee->bp, probe_buf, BYPASS_MAX_PEERS,
                                               eee->device.ip_addr, eee->device.mac_addr);
            for (int _pi = 0; _pi < n; _pi++) {
                uint8_t *frame = probe_buf + _pi * 19;
                /* Look up peer to get its P2P UDP address */
                uint32_t p_virt_ip = 0;
                for (int _bi = 0; _bi < BYPASS_MAX_PEERS; _bi++) {
                    if (eee->bp->peers[_bi].state == BYPASS_PEER_PROBING &&
                        eee->bp->peers[_bi].virt_ip != 0) {
                        p_virt_ip = eee->bp->peers[_bi].virt_ip;
                        break;
                    }
                }
                if (p_virt_ip != 0) {
                    struct peer_info *pi = bypass_find_peer_info(eee, p_virt_ip);
                    if (pi) {
                        n2n_sock_t p2p_dest;
                        int have_p2p = 0;
                        if (pi->sock.family == AF_INET && eee->udp_sock != -1) {
                            p2p_dest = pi->sock; have_p2p = 1;
                        } else if (pi->sock6.family == AF_INET6 && eee->udp_sock6 != -1) {
                            p2p_dest = pi->sock6; have_p2p = 1;
                        }
                        if (have_p2p) {
                            /* Build encrypted n2n PACKET */
                            n2n_mac_t destMac;
                            uint8_t pktbuf[N2N_PKT_BUF_SIZE];
                            size_t idx = 0;
                            n2n_common_t cmn;
                            n2n_PACKET_t pkt;
                            size_t tx_transop_idx = edge_choose_tx_transop(eee);
                            memcpy(destMac, frame, N2N_MAC_SIZE);
                            memset(&cmn, 0, sizeof(cmn));
                            cmn.ttl = N2N_DEFAULT_TTL;
                            cmn.pc = n2n_packet;
                            cmn.flags = 0;
                            memcpy(cmn.community, eee->community_name, N2N_COMMUNITY_SIZE);
                            memset(&pkt, 0, sizeof(pkt));
                            memcpy(pkt.srcMac, eee->device.mac_addr, N2N_MAC_SIZE);
                            memcpy(pkt.dstMac, destMac, N2N_MAC_SIZE);
                            pkt.sock.family = 0;
                            pkt.transform = eee->transop[tx_transop_idx].transform_id;
                            encode_PACKET(pktbuf, &idx, &cmn, &pkt);
                            idx += eee->transop[tx_transop_idx].fwd(
                                &(eee->transop[tx_transop_idx]),
                                pktbuf+idx, N2N_PKT_BUF_SIZE-idx,
                                frame, 19, destMac);
                            ++(eee->transop[tx_transop_idx].tx_cnt);
                            /* Send directly to peer's P2P address */
                            sendto_sock(sock_for_dest(eee, &p2p_dest),
                                        pktbuf, idx, &p2p_dest);
                            continue;
                        }
                    }
                }
                /* Fallback: normal path */
                send_packet2net(eee, frame, 19);
            }
        }

        PEERS_LOCK(eee);
        check_keepalive(eee, nowTime);

        /* "f" sync cleanup: after 2s, remove peers in pending_peers that
         * were in the snapshot but NOT confirmed by supernode. */
        if (eee->peer_sync_active && (nowTime - eee->peer_sync_time) > 2) {
            uint16_t i;
            size_t removed = 0;
            struct peer_info *prev, *scan;

            for (i = 0; i < eee->peer_sync_ips_count; i++) {
                prev = NULL;
                scan = eee->pending_peers;
                while (scan) {
                    if (scan->assigned_ip == eee->peer_sync_ips[i]) {
                        struct peer_info *next = scan->next;
                        if (prev) prev->next = next;
                        else eee->pending_peers = next;
                        free(scan);
                        scan = next;
                        ++removed;
                        break;
                    }
                    prev = scan;
                    scan = scan->next;
                }
            }

            /* Also remove relay-only known_peers not confirmed by SN */
            for (i = 0; i < eee->peer_sync_ips_count; i++) {
                prev = NULL;
                scan = eee->known_peers;
                while (scan) {
                    if (scan->assigned_ip == eee->peer_sync_ips[i] && scan->direct_seen == 0) {
                        struct peer_info *next = scan->next;
                        if (prev) prev->next = next;
                        else eee->known_peers = next;
                        if (bypass_has_peers(eee->bp) && scan->assigned_ip != 0)
                            bypass_peer_gone(eee->bp, scan->assigned_ip);
                        free(scan);
                        scan = next;
                        ++removed;
                        break;
                    }
                    prev = scan;
                    scan = scan->next;
                }
            }

            if (removed > 0) {
                traceEvent(TRACE_NORMAL, "Peer sync removed %u stale peer(s)", (unsigned int)removed);
            }
            eee->peer_sync_active = 0;
            eee->peer_sync_time = 0;
            eee->peer_sync_ips_count = 0;
            traceEvent(TRACE_NORMAL, "Peer sync complete");
        }

        /* Before purging, clean up bypass state for peers about to be removed.
         * Save assigned_ip of all known peers, then after purge, check which
         * ones are gone and call bypass_peer_gone. */
        uint32_t bp_known_ips[BYPASS_MAX_PEERS];
        int bp_known_count = 0;
        if (bypass_has_peers(eee->bp)) {
            struct peer_info *scan = eee->known_peers;
            while (scan && bp_known_count < BYPASS_MAX_PEERS) {
                if (scan->assigned_ip != 0)
                    bp_known_ips[bp_known_count++] = scan->assigned_ip;
                scan = scan->next;
            }
        }
        numPurged =  purge_expired_registrations( &(eee->known_peers) );
        /* pending_peers: use much longer timeout. These are relay-only peers
         * that we know exist but can't punch to. Forgetting them causes long
         * re-discovery delays when traffic resumes after idle (the "stop ping,
         * resume ping = unreachable" problem). The 1800s stuck-peer check in
         * check_punch_timeouts handles truly dead peers. */
        numPurged += purge_peer_list( &(eee->pending_peers), nowTime - 1800 );
        /* After purging, clean up bypass state for removed peers */
        if (bypass_has_peers(eee->bp) && bp_known_count > 0) {
            for (int _bki = 0; _bki < bp_known_count; _bki++) {
                /* Check if this peer still exists in known_peers */
                struct peer_info *scan = eee->known_peers;
                int found = 0;
                while (scan) {
                    if (scan->assigned_ip == bp_known_ips[_bki]) {
                        found = 1;
                        break;
                    }
                    scan = scan->next;
                }
                if (!found)
                    bypass_peer_gone(eee->bp, bp_known_ips[_bki]);
            }
        }
        PEERS_UNLOCK(eee);
        if ( numPurged > 0 )
        {
            traceEvent( TRACE_INFO, "Peer removed: pending=%u, operational=%u",
                        (unsigned int)peer_list_size( eee->pending_peers ),
                        (unsigned int)peer_list_size( eee->known_peers ) );
        }

        if ( eee->dyn_ip_mode &&
             (( nowTime - lastIfaceCheck ) > IFACE_UPDATE_INTERVAL ) )
        {
            traceEvent(TRACE_NORMAL, "Re-checking dynamic IP address.");
            tuntap_get_address( &(eee->device) );
            lastIfaceCheck = nowTime;
        }

        /* Renew UPnP/NAT-PMP lease before it expires */
        if (eee->upnp_mapped_port != 0 &&
            (nowTime - lastUpnpRenew) > UPNP_RENEW_THRESHOLD)
        {
            /* Determine actual local port from socket */
            uint16_t local_port = eee->upnp_mapped_port;
            struct sockaddr_in bound;
            socklen_t blen = sizeof(bound);
            if (getsockname(eee->udp_sock, (struct sockaddr*)&bound, &blen) == 0)
                local_port = ntohs(bound.sin_port);

            if (upnp_renew_port(local_port, eee->upnp_mapped_port) == UPNP_OK) {
                traceEvent(TRACE_INFO, "Upnp: lease renewed for port %u",
                           (unsigned)eee->upnp_mapped_port);
            } else {
                traceEvent(TRACE_WARNING,
                           "Upnp: lease renewal failed for port %u",
                           (unsigned)eee->upnp_mapped_port);
            }
            lastUpnpRenew = nowTime;
        }

    } /* while */

cleanup:
#ifdef _WIN32
    eee->keep_running = 0;
    /* Close TAP first to wake up the TUN reader thread blocked on tuntap_read() */
    tuntap_close(&(eee->device));
    if (eee->tun_thread_handle != NULL) {
        if (WaitForSingleObject(eee->tun_thread_handle, 5000) != WAIT_OBJECT_0)
            traceEvent(TRACE_WARNING, "TUN thread did not exit in 5s, terminating");
        CloseHandle(eee->tun_thread_handle);
        eee->tun_thread_handle = NULL;
    }
#else
    tuntap_close(&(eee->device));
#endif

    send_deregister( eee, &(eee->supernode));
    if (eee->supernode_alt.family != 0) {
        send_deregister( eee, &(eee->supernode_alt));
    }

    /* Notify all known peers */
    {
        struct peer_info *p = eee->known_peers;
        while (p) {
            if (p->sock.family != 0)  send_deregister(eee, &(p->sock));
            if (p->sock6.family != 0) send_deregister(eee, &(p->sock6));
            p = p->next;
        }
    }

    edge_deinit( eee );

    return retval;
}
