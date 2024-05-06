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
#include <time.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <limits.h>
#include <float.h>
#include <math.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <locale.h>
#include <sys/socket.h>

#include "config.h"
#include "server.h"
#include "atomicvar.h"

char *ascii_logo ="\n" 
"    __                                      | Version: 1.0.0\n"                       
"   / /__________  ______   _____  _____     | Port: %d \n"
"  / //_/ ___/ _ \\/ ___/ | / / _ \\/ ___/     | PID: %ld\n"
" / ,< (__  )  __/ /   | |/ /  __/ /         | Author: Yanruibing\n"   
"/_/|_/____/\\___/_/    |___/\\___/_/          | Web: http://www.kxyk.com \n\n";

struct Server server;

/*============================ Utility functions ============================ */

/* We use a private localtime implementation which is fork-safe. The logging
 * function of Redis may be called from other threads. */
void nolocks_localtime(struct tm *tmp, time_t t, time_t tz, int dst);

/* Low level logging. To use only for very big messages, otherwise
 * serverLog() is to prefer. */
void serverLogRaw(int level, const char *msg) {
    const int syslogLevelMap[] = { LOG_DEBUG, LOG_INFO, LOG_NOTICE, LOG_WARNING };
    const char *c = ".-*#";
    FILE *fp;
    char buf[64];
    int rawmode = (level & LL_RAW);
    int log_to_stdout = server.logfile[0] == '\0';

    level &= 0xff; /* clear flags */
    if (level < server.verbosity) return;

    fp = log_to_stdout ? stdout : fopen(server.logfile, "a");
    if (!fp) return;

    if (rawmode) {
        fprintf(fp, "%s", msg);
    } else {
        int off;
        struct timeval tv;
        // pid_t pid = getpid();

        gettimeofday(&tv, NULL);
        struct tm tm;
        nolocks_localtime(&tm,tv.tv_sec,server.timezone,server.daylight_active);
        off = strftime(buf,sizeof(buf),"%d %b %Y %H:%M:%S.",&tm);
        snprintf(buf+off,sizeof(buf)-off,"%03d",(int)tv.tv_usec/1000);
        fprintf(fp,"%d:%c %s %c %s\n", (int)getpid(), 'M', buf, c[level], msg);
    }
    fflush(fp);

    if (!log_to_stdout) fclose(fp);
    if (server.syslog_enabled) syslog(syslogLevelMap[level], "%s", msg);
}

/* Like serverLogRaw() but with printf-alike support. This is the function that
 * is used across the code. The raw version is only used in order to dump
 * the INFO output on crash. */
void serverLog(int level, const char *fmt, ...) {
    va_list ap;
    char msg[LOG_MAX_LEN];

    if ((level & 0xff) < server.verbosity) return;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    serverLogRaw(level, msg);
}

void showLogo(void) {
    char *buf = zmalloc(1024*16);
    snprintf(buf,1024*16,ascii_logo, server.port, (long)getpid());
    serverLogRaw(LL_NOTICE|LL_RAW, buf);
    zfree(buf);
}

/* Log a fixed message without printf-alike capabilities, in a way that is
 * safe to call from a signal handler.
 *
 * We actually use this only for signals that are not fatal from the point
 * of view of Redis. Signals that are going to kill the server anyway and
 * where we need printf-alike features are served by serverLog(). */
void serverLogFromHandler(int level, const char *msg) {
    int fd;
    int log_to_stdout = server.logfile[0] == '\0';
    char buf[64];

    if ((level & 0xff) < server.verbosity)
        return;
    fd = log_to_stdout ? STDOUT_FILENO :
                         open(server.logfile, O_APPEND|O_CREAT|O_WRONLY, 0644);
    if (fd == -1) return;
    ll2string(buf, sizeof(buf), getpid());
    if (write(fd, buf, strlen(buf)) == -1) goto err;
    if (write(fd, ":signal-handler (", 17) == -1) goto err;
    ll2string(buf, sizeof(buf), time(NULL));
    if (write(fd, buf, strlen(buf)) == -1) goto err;
    if (write(fd, ") ", 2) == -1) goto err;
    if (write(fd, msg, strlen(msg)) == -1) goto err;
    if (write(fd, "\n", 1) == -1) goto err;
err:
    if (!log_to_stdout) close(fd);
}

uint64_t dictSdsHash(const void *key) {
    return dictGenHashFunction((unsigned char*)key, sdslen((char*)key));
}

int dictSdsKeyCompare(void *privdata, const void *key1, const void *key2) {
    int l1, l2;
    DICT_NOTUSED(privdata);

    l1 = sdslen((sds)key1);
    l2 = sdslen((sds)key2);
    if (l1 != l2) return 0;
    return memcmp(key1, key2, l1) == 0;
}

void dictSdsDestructor(void *privdata, void *val) {
    DICT_NOTUSED(privdata);

    sdsfree(val);
}

void dictObjectDestructor(void *privdata, void *val)
{
    DICT_NOTUSED(privdata);

    if (val == NULL) return; /* Lazy freeing will set value to NULL. */
    // decrRefCount(val);
}

/* Db->dict, keys are sds strings, vals are Redis objects. */
dictType dbDictType = {
    dictSdsHash,                /* hash function */
    NULL,                       /* key dup */
    NULL,                       /* val dup */
    dictSdsKeyCompare,          /* key compare */
    dictSdsDestructor,          /* key destructor */
    dictObjectDestructor   /* val destructor */
};

static void sigShutdownHandler(int sig) {
    char *msg;

    switch (sig) {
    case SIGINT:
        msg = "Received SIGINT scheduling shutdown...";
        break;
    case SIGTERM:
        msg = "Received SIGTERM scheduling shutdown...";
        break;
    default:
        msg = "Received shutdown signal, scheduling shutdown...";
    }
    serverLogFromHandler(LL_WARNING, msg);
    exit(1);
}

void setupSignalHandlers(void) {
    struct sigaction act;
    
    /* When the SA_SIGINFO flag is set in sa_flags then sa_sigaction is used.
     * Otherwise, sa_handler is used. */
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = sigShutdownHandler;
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT, &act, NULL);

    return;
}

/* Initialize a set of file descriptors to listen to the specified 'port'
 * binding the addresses specified in the Redis server configuration.
 *
 * The listening file descriptors are stored in the integer array 'fds'
 * and their number is set in '*count'.
 *
 * The addresses to bind are specified in the global server.bindaddr array
 * and their number is server.bindaddr_count. If the server configuration
 * contains no specific addresses to bind, this function will try to
 * bind * (all addresses) for both the IPv4 and IPv6 protocols.
 *
 * On success the function returns C_OK.
 *
 * On error the function returns C_ERR. For the function to be on
 * error, at least one of the server.bindaddr addresses was
 * impossible to bind, or no bind addresses were specified in the server
 * configuration but the function is not able to bind * for at least
 * one of the IPv4 or IPv6 protocols. */
int listenToPort(int port, int *fds, int *count) {
    int j;

    /* Force binding of 0.0.0.0 if no bind address is specified, always
     * entering the loop if j == 0. */
    if (server.bindaddr_count == 0) server.bindaddr[0] = NULL;
    for (j = 0; j < server.bindaddr_count || j == 0; j++) {
        if (server.bindaddr[j] == NULL) {
            int unsupported = 0;
            /* Bind * for both IPv6 and IPv4, we enter here only if
             * server.bindaddr_count == 0. */
            fds[*count] = anetTcp6Server(server.neterr, port, NULL, server.tcp_backlog);
            if (fds[*count] != ANET_ERR) {
                anetNonBlock(NULL,fds[*count]);
                (*count)++;
            } else if (errno == EAFNOSUPPORT) {
                unsupported++;
                serverLog(LL_WARNING,"Not listening to IPv6: unsupproted");
            }

            if (*count == 1 || unsupported) {
                /* Bind the IPv4 address as well. */
                fds[*count] = anetTcpServer(server.neterr, port, NULL, server.tcp_backlog);
                if (fds[*count] != ANET_ERR) {
                    anetNonBlock(NULL,fds[*count]);
                    (*count)++;
                } else if (errno == EAFNOSUPPORT) {
                    unsupported++;
                    serverLog(LL_WARNING,"Not listening to IPv4: unsupproted");
                }
                /* Exit the loop if we were able to bind * on IPv4 and IPv6,
                * otherwise fds[*count] will be ANET_ERR and we'll print an
                * error and return to the caller with an error. */
                if (*count + unsupported == 2) break;
            }
        } else if (strchr(server.bindaddr[j],':')) {
            /* Bind IPv6 address. */
            fds[*count] = anetTcp6Server(server.neterr,port,server.bindaddr[j],
                server.tcp_backlog);
        } else {
            /* Bind IPv4 address. */
            fds[*count] = anetTcpServer(server.neterr,port,server.bindaddr[j],
                server.tcp_backlog);
        }
        if (fds[*count] == ANET_ERR) {
            serverLog(LL_WARNING,
                "Creating Server TCP listening socket %s:%d: %s",
                server.bindaddr[j] ? server.bindaddr[j] : "*",
                port, server.neterr);
            return C_ERR;
        }
        anetNonBlock(NULL,fds[*count]);
        (*count)++;
    }
    return C_OK;
}

/* Return the UNIX time in microseconds */
long long ustime(void) {
    struct timeval tv;
    long long ust;

    gettimeofday(&tv, NULL);
    ust = ((long long)tv.tv_sec)*1000000;
    ust += tv.tv_usec;
    return ust;
}

/* Return the UNIX time in milliseconds */
mstime_t mstime(void) {
    return ustime()/1000;
}

/* We take a cached value of the unix time in the global state because with
 * virtual memory and aging there is to store the current time in objects at
 * every object access, and accuracy is not needed. To access a global var is
 * a lot faster than calling time(NULL) */
void updateCachedTime(void) {
    time_t unixtime = time(NULL);
    atomicSet(server.unixtime, unixtime);
    server.mstime = mstime();
    /* To get information about daylight saving time, we need to call localtime_r
     * and cache the result. However calling localtime_r in this context is safe
     * since we will never fork() while here, in the main thread. The logging
     * function will call a thread safe version of localtime that has no locks. */
    struct tm tm;
    localtime_r(&server.unixtime,&tm);
    server.daylight_active = tm.tm_isdst;
}

/* Check for timeouts. Returns non-zero if the client was terminated.
 * The function gets the current time in milliseconds as argument since
 * it gets called multiple times in a loop, so calling gettimeofday() for
 * each iteration would be costly without any actual gain. */
int clientsCronHandleTimeout(client *c, mstime_t now_ms) {
    time_t now = now_ms/1000;
    
    if (server.maxidletime &&
        (now - c->lastinteraction > server.maxidletime)) {
        serverLog(LL_WARNING,"Closing idle client");
        freeClient(c);
        return 1;
    }
    return 0;
}

/* This function is called by serverCron() and is used in order to perform
 * operations on clients that are important to perform constantly. For instance
 * we use this function in order to disconnect clients after a timeout, including
 * clients blocked in some blocking command with a non-zero timeout.
 *
 * The function makes some effort to process all the clients every second, even
 * if this cannot be strictly guaranteed, since serverCron() may be called with
 * an actual frequency lower than server.hz in case of latency events like slow
 * commands.
 *
 * It is very important for this function, and the functions it calls, to be
 * very fast: sometimes server has tens of hundreds of connected clients, and the
 * default server.hz value is 10, so sometimes here we need to process thousands
 * of clients per second, turning this function into a source of latency.
 */
#define CLIENTS_CRON_MIN_ITERATIONS 5
void clientsCron(void) {
    /* Try to process at least numclients/server.hz of clients
     * per call. Since normally (if there are no big latency events) this
     * function is called server.hz times per second, in the average case we
     * process all the clients in 1 second. */
    int numclients = listLength(server.clients);
    int iterations = numclients/server.hz;
    mstime_t now = mstime();

    /* Process at least a few clients while we are at it, even if we need
     * to process less than CLIENTS_CRON_MIN_ITERATIONS to meet our contract
     * of processing each client once per second. */
    if (iterations < CLIENTS_CRON_MIN_ITERATIONS)
        iterations = (numclients < CLIENTS_CRON_MIN_ITERATIONS) ?
                     numclients : CLIENTS_CRON_MIN_ITERATIONS;
    
    while (listLength(server.clients) && iterations--) {
        client *c;
        listNode *head;

        /* Rotate the list, take the current head, process.
         * This way if the client must be removed from the list it's the
         * first element and we don't incur into O(N) computation. */
        listRotate(server.clients);
        head = listFirst(server.clients);
        c = listNodeValue(head);
        /* The following functions do different service checks on the client.
         * The protocol is that they return non-zero if the client was
         * terminated. */
        if (clientsCronHandleTimeout(c,now)) continue;
    }
}

int serverCron(struct aeEventLoop *eventLoop, long long id, void *clientData) {
    UNUSED(eventLoop);
    UNUSED(id);
    UNUSED(clientData);

    /* Update the time cache. */
    updateCachedTime();

    server.hz = server.config_hz;

    /* We need to do a few operations on clients asynchronously. */
    clientsCron();

    return 1000/server.hz;
}

void initServerConfig(void) {
    server.port = CONFIG_DEFAULT_SERVER_PORT;
    server.maxclients = CONFIG_DEFAULT_MAX_CLIENTS;
    server.tcpkeepalive = CONFIG_DEFAULT_TCP_KEEPALIVE;
    server.syslog_enabled = CONFIG_DEFAULT_SYSLOG_ENABLED;
    server.verbosity = CONFIG_DEFAULT_VERBOSITY;
    server.logfile = zstrdup(CONFIG_DEFAULT_LOGFILE);
    server.config_hz = CONFIG_DEFAULT_HZ;
    server.maxidletime = CONFIG_DEFAULT_CLIENT_TIMEOUT;
}

void initServer(void) {
    int j;

    signal(SIGHUP, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    setupSignalHandlers();

    server.hz = server.config_hz;
    server.pid = getpid();
    server.current_client = NULL;
    server.clients = listCreate();
    server.clients_pending_write = listCreate();
    server.next_client_id = 1;
    server.el = aeCreateEventLoop(server.maxclients + CONFIG_FDSET_INCR);
    if (server.el == NULL) {
        serverLog(LL_WARNING,
            "Failed creating the event loop. Error message: '%s'",
            strerror(errno));
        exit(1);
    }
    server.ipfd_count = 0;
    server.bindaddr_count = 0;

    server.db = zmalloc(sizeof(kxykDb)*server.dbnum);

    /* Open the TCP listening socket for the user commands. */
    if (server.port != 0 && listenToPort(server.port, server.ipfd, &server.ipfd_count) == C_ERR)
        exit(1);
    
    /* Abort if there are no listening sockets at all. */
    if (server.ipfd_count == 0) {
        serverLog(LL_WARNING, "Configured to not listen anywhere, exiting.");
        exit(1);
    }

    /* Create the databases, and initialize other internal state. */
    for (j = 0; j < server.dbnum; j++) {
        server.db[j].dict = dictCreate(&dbDictType, NULL);
        server.db[j].id = j;
        server.db[j].avg_ttl = 0;
    }

    /* Create the timer callback, this is our way to process many background
     * operations incrementally, like clients timeout, eviction of unaccessed
     * expired keys and so forth. */
    if (aeCreateTimeEvent(server.el, 1, serverCron, NULL, NULL) == AE_ERR) {
        serverLog(LL_WARNING, "Can't create event loop timers.");
        exit(1);
    }

    /* Create an event handler for accepting new connections in TCP and Unix
     * domain sockets. */
    for (j = 0; j < server.ipfd_count; j++) {
        if (aeCreateFileEvent(server.el, server.ipfd[j], AE_READABLE,
            acceptTcpHandler,NULL) == AE_ERR) {
            serverLog(LL_WARNING,"!!! Software Failure. Press left mouse button to continue");  
        }
    }
}

int main(int argc, char **argv) {
    struct timeval tv;

    setlocale(LC_COLLATE, "");
    tzset();
    srand(time(NULL)^getpid());
    gettimeofday(&tv,NULL);

    initServerConfig();
    initServer();
    showLogo();
    
    aeMain(server.el);
    aeDeleteEventLoop(server.el);
    return 0;
}