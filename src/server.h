/*
 * Copyright (c) 2024-2024, Yanruibing <antirez at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef __SERVER_H__
#define __SERVER_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <syslog.h>
#include <netinet/in.h>
#include <signal.h>

typedef long long mstime_t; /* millisecond time type. */

#include "ae.h"      /* Event driven programming library */
#include "sds.h"     /* Dynamic safe strings */
#include "adlist.h"  /* Linked lists */
#include "zmalloc.h" /* total memory usage aware version of malloc/free */
#include "anet.h"    /* Networking the easy way */
#include "util.h"    /* Misc functions useful in many places */

/* Error codes */
#define C_OK                            0
#define C_ERR                           -1
/* Anti-warning macro... */
#define UNUSED(V)                       ((void) V)

/* Log levels */
#define LL_DEBUG                        0
#define LL_VERBOSE                      1
#define LL_NOTICE                       2
#define LL_WARNING                      3
#define LL_RAW                          (1<<10) /* Modifier to log without timestamp */
#define CONFIG_DEFAULT_VERBOSITY        LL_NOTICE

/* Static server configuration */
#define CONFIG_DEFAULT_HZ               10        /* Time interrupt calls/sec. */
#define CONFIG_DEFAULT_MAX_CLIENTS      10000
#define CONFIG_DEFAULT_TCP_KEEPALIVE    300
#define CONFIG_BINDADDR_MAX             16
#define CONFIG_DEFAULT_SERVER_PORT      6388      /* TCP port. */
#define CONFIG_DEFAULT_SYSLOG_ENABLED   0
#define CONFIG_DEFAULT_LOGFILE          ""
#define CONFIG_DEFAULT_CLIENT_TIMEOUT   0         /* Default client timeout: infinite */
#define CONFIG_MIN_RESERVED_FDS         32

/* When configuring the server eventloop, we setup it so that the total number
 * of file descriptors we can handle are server.maxclients + RESERVED_FDS +
 * a few more to stay safe. Since RESERVED_FDS defaults to 32, we add 96
 * in order to make sure of not over provisioning more than 128 fds. */
#define CONFIG_FDSET_INCR               (CONFIG_MIN_RESERVED_FDS+96)

#define LOG_MAX_LEN                     1024      /* Default maximum length of syslog messages.*/
#define NET_IP_STR_LEN                  46        /* INET6_ADDRSTRLEN is 46, but we need to be sure */

/* Protocol and I/O related defines */
#define PROTO_IOBUF_LEN                 (1024*16)  /* Generic I/O buffer size */
#define PROTO_REPLY_CHUNK_BYTES         (16*1024)  /* 16k output buffer */

/* With multiplexing we need to take per-client state.
 * Clients are taken in a linked list. */
typedef struct client {
    uint64_t id;            /* Client incremental unique ID. */
    int fd;                 /* Client socket. */
    sds querybuf;           /* Buffer we use to accumulate client queries. */
    /* Response buffer */
    int bufpos;
    char buf[PROTO_REPLY_CHUNK_BYTES];
    time_t lastinteraction;         /* Time of the last interaction, used for timeout */
    listNode *client_list_node;     /* list node in client list */
} client;

struct Server {
    pid_t pid;                          /* Main process pid. */
    aeEventLoop *el;
    unsigned int maxclients;            /* Max number of simultaneous clients */
    /* time cache */
    time_t unixtime;                    /* Unix time sampled every cron cycle. */
    time_t timezone;                    /* Cached timezone. As set by tzset(). */
    int daylight_active;                /* Currently in daylight saving time. */
    long long mstime;                   /* Like 'unixtime' but with milliseconds resolution. */
    /* Configuration */
    int verbosity;                      /* Loglevel in redis.conf */
    int maxidletime;                    /* Client timeout in seconds */
    int tcpkeepalive;                   /* Set SO_KEEPALIVE if non-zero. */
    int config_hz;                      /* Configured HZ value. May be different than
                                            the actual 'hz' field value if dynamic-hz
                                            is enabled. */
    int hz;                             /* serverCron() calls frequency in hertz */
    /* Logging */
    char *logfile;                      /* Path of log file */
    int syslog_enabled;                 /* Is syslog enabled? */
    /* Networking */
    int port;                           /* TCP listening port */
    int tcp_backlog;                    /* TCP listen() backlog */
    uint64_t next_client_id;            /* Next client unique ID. Incremental. */
    int ipfd[CONFIG_BINDADDR_MAX];      /* TCP socket file descriptors */
    int ipfd_count;                     /* Used slots in ipfd[] */
    char *bindaddr[CONFIG_BINDADDR_MAX]; /* Addresses we should bind to */
    int bindaddr_count;                 /* Number of addresses in server.bindaddr[] */
    char neterr[ANET_ERR_LEN];          /* Error buffer for anet.c */
    client *current_client;             /* Current client, only used on crash report */
    list *clients;                      /* List of active clients */
    list *clients_pending_write;        /* There is to write or install handler. */
};

typedef void CommandProc(client *c);
struct Command {
    char *name;
    CommandProc *proc;
    long long microseconds;
};

/*-----------------------------------------------------------------------------
 * Extern declarations
 *----------------------------------------------------------------------------*/

extern struct Server server;

/* networking.c -- Networking and Client related operations */
client *createClient(int fd);
void freeClient(client *c);
int listenToPort(int port, int *fds, int *count);
void acceptTcpHandler(aeEventLoop *el, int fd, void *privdata, int mask);
void setupSignalHandlers(void);
void readQueryFromClient(aeEventLoop *el, int fd, void *privdata, int mask);
void processInputBuffer(client *c);
void updateCachedTime(void);
long long ustime(void);
void unlinkClient(client *c);
void linkClient(client *c);
#ifdef __GNUC__
void serverLog(int level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
#else
void serverLog(int level, const char *fmt, ...);
#endif
void serverLogRaw(int level, const char *msg);

#endif