bug: C:\Users\Hank Chen\Documents\pwnable_tw_writeup\cve_2018_1160\netatalk-3.1.11\libatalk\dsi\dsi_opensess.c:30-41

main
dsi_start
dsi_getsession 
dsi_opensession

```
typedef struct DSI {
    struct DSI *next;             /* multiple listening addresses */
    AFPObj   *AFPobj;
    int      statuslen;
    char     status[1400];
    char     *signature;
    struct dsi_block        header;
    struct sockaddr_storage server, client;
    struct itimerval        timer;
    int      tickle;            /* tickle count */
    int      in_write;          /* in the middle of writing multiple packets,
                                   signal handlers can't write to the socket */
    int      msg_request;       /* pending message to the client */
    int      down_request;      /* pending SIGUSR1 down in 5 mn */

    uint32_t attn_quantum, datasize, server_quantum;            0x6d8
    uint16_t serverID, clientID;                                0x6e4
    uint8_t  *commands; /* DSI recieve buffer */                0x6e8
    uint8_t  data[DSI_DATASIZ];    /* DSI reply buffer */       0x6f0
    size_t   datalen, cmdlen;                                   0x106f0
    off_t    read_count, write_count;
    uint32_t flags;             /* DSI flags like DSI_SLEEPING, DSI_DISCONNECTED */
    int      socket;            /* AFP session socket */
    int      serversock;        /* listening socket */

    /* DSI readahead buffer used for buffered reads in dsi_peek */
    size_t   dsireadbuf;        /* size of the DSI readahead buffer used in dsi_peek() */
    char     *buffer;           /* buffer start */
    char     *start;            /* current buffer head */
    char     *eof;              /* end of currently used buffer */
    char     *end;

#ifdef USE_ZEROCONF
    char *bonjourname;      /* server name as UTF8 maxlen MAXINSTANCENAMELEN */
    int zeroconf_registered;
#endif

    /* protocol specific open/close, send/receive
     * send/receive fill in the header and use dsi->commands.
     * write/read just write/read data */
    pid_t  (*proto_open)(struct DSI *);
    void   (*proto_close)(struct DSI *);
} DSI;
```
```

```

sudo apt install -y build-essential libevent-dev libssl-dev libgcrypt-dev libkrb5-dev libpam0g-dev libwrap0-dev libdb-dev libtdb-dev avahi-daemon libavahi-client-dev libacl1-dev libldap2-dev libcrack2-dev libdbus-1-dev libdbus-glib-1-dev libglib2.0-dev

./configure --with-init-style=debian-systemd --without-libevent --with-cracklib --enable-krbV-uam --with-pam-confdir=/etc/pam.d --with-dbus-daemon=/usr/bin/dbus-daemon --with-dbus-sysconf-dir=/etc/dbus-1/system.d

sudo checkinstall -D --pkgname='netatalk' --pkgversion="${NETATALK_VERSION}" --maintainer="${MAINTAINER}" make install

sudo apt install -y avahi-daemon cracklib-runtime db-util db5.3-util libtdb1 libavahi-client3 libcrack2 libcups2 libpam-cracklib libdbus-glib-1-2