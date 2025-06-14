/*
 * SOCKS5 proxy protocol
 * Copyright (c) 2024 FFmpeg contributors
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/**
 * @file
 * SOCKS5 proxy protocol implementation
 */

#include "libavutil/avstring.h"
#include "libavutil/mem.h"
#include "libavutil/opt.h"
#include "avformat.h"
#include "internal.h"
#include "network.h"
#include "url.h"

// SOCKS5 protocol constants
#define SOCKS5_VERSION          0x05
#define SOCKS5_AUTH_NONE        0x00
#define SOCKS5_AUTH_USERPASS    0x02
#define SOCKS5_AUTH_FAILED      0xFF
#define SOCKS5_CMD_CONNECT      0x01
#define SOCKS5_CMD_BIND         0x02
#define SOCKS5_CMD_UDP_ASSOC    0x03
#define SOCKS5_ATYP_IPV4        0x01
#define SOCKS5_ATYP_DOMAIN      0x03
#define SOCKS5_ATYP_IPV6        0x04
#define SOCKS5_REP_SUCCESS      0x00

typedef struct SOCKSContext {
    const AVClass *class;
    URLContext *tcp_hd;
    char *username;
    char *password;
} SOCKSContext;

#define OFFSET(x) offsetof(SOCKSContext, x)
#define D AV_OPT_FLAG_DECODING_PARAM
#define E AV_OPT_FLAG_ENCODING_PARAM

static const AVOption socks_options[] = {
    { "username", "SOCKS5 username", OFFSET(username), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D | E },
    { "password", "SOCKS5 password", OFFSET(password), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D | E },
    { NULL }
};

static const AVClass socks_class = {
    .class_name = "socks",
    .item_name  = av_default_item_name,
    .option     = socks_options,
    .version    = LIBAVUTIL_VERSION_INT,
};

static int socks5_auth_none(URLContext *h, SOCKSContext *s)
{
    uint8_t buf[3];
    int ret;

    // Send authentication method selection
    buf[0] = SOCKS5_VERSION;
    buf[1] = 1; // number of methods
    buf[2] = SOCKS5_AUTH_NONE; // no authentication method
    if ((ret = ffurl_write(s->tcp_hd, buf, 3)) < 0)
        return ret;

    // Read server response
    if ((ret = ffurl_read_complete(s->tcp_hd, buf, 2)) < 0)
        return ret;

    if (buf[0] != SOCKS5_VERSION) {
        av_log(h, AV_LOG_ERROR, "Invalid SOCKS5 version in response: %d\n", buf[0]);
        return AVERROR(EPROTO);
    }

    if (buf[1] == SOCKS5_AUTH_FAILED) {
        av_log(h, AV_LOG_ERROR, "SOCKS5 authentication failed\n");
        return AVERROR(EACCES);
    }

    if (buf[1] != SOCKS5_AUTH_NONE) {
        av_log(h, AV_LOG_ERROR, "SOCKS5 server requires authentication\n");
        return AVERROR(EACCES);
    }

    return 0;
}

static int socks5_auth_userpass(URLContext *h, SOCKSContext *s)
{
    uint8_t buf[256];
    int ret, len;

    // Send authentication method selection
    buf[0] = SOCKS5_VERSION;
    buf[1] = 1; // number of methods
    buf[2] = SOCKS5_AUTH_USERPASS; // username/password authentication method
    if ((ret = ffurl_write(s->tcp_hd, buf, 3)) < 0)
        return ret;

    // Read server response
    if ((ret = ffurl_read_complete(s->tcp_hd, buf, 2)) < 0)
        return ret;

    if (buf[0] != SOCKS5_VERSION) {
        av_log(h, AV_LOG_ERROR, "Invalid SOCKS5 version in response: %d\n", buf[0]);
        return AVERROR(EPROTO);
    }

    if (buf[1] == SOCKS5_AUTH_FAILED) {
        av_log(h, AV_LOG_ERROR, "SOCKS5 authentication method not supported\n");
        return AVERROR(EACCES);
    }

    if (buf[1] != SOCKS5_AUTH_USERPASS) {
        av_log(h, AV_LOG_ERROR, "SOCKS5 server doesn't support username/password auth\n");
        return AVERROR(EACCES);
    }

    // Send username/password authentication
    len = 0;
    buf[len++] = 0x01; // version of username/password authentication
    
    // Username
    int username_len = strlen(s->username);
    if (username_len > 255) {
        av_log(h, AV_LOG_ERROR, "Username too long\n");
        return AVERROR(EINVAL);
    }
    buf[len++] = username_len;
    memcpy(buf + len, s->username, username_len);
    len += username_len;

    // Password
    int password_len = strlen(s->password);
    if (password_len > 255) {
        av_log(h, AV_LOG_ERROR, "Password too long\n");
        return AVERROR(EINVAL);
    }
    buf[len++] = password_len;
    memcpy(buf + len, s->password, password_len);
    len += password_len;

    if ((ret = ffurl_write(s->tcp_hd, buf, len)) < 0)
        return ret;

    // Read authentication response
    if ((ret = ffurl_read_complete(s->tcp_hd, buf, 2)) < 0)
        return ret;

    if (buf[0] != 0x01) {
        av_log(h, AV_LOG_ERROR, "Invalid username/password auth version: %d\n", buf[0]);
        return AVERROR(EPROTO);
    }

    if (buf[1] != 0x00) {
        av_log(h, AV_LOG_ERROR, "SOCKS5 username/password authentication failed\n");
        return AVERROR(EACCES);
    }

    return 0;
}

static int socks5_connect(URLContext *h, SOCKSContext *s, const char *hostname, int port)
{
    uint8_t buf[256];
    int ret, len;

    // Build CONNECT request
    len = 0;
    buf[len++] = SOCKS5_VERSION;
    buf[len++] = SOCKS5_CMD_CONNECT;
    buf[len++] = 0x00; // reserved

    // Use domain name
    buf[len++] = SOCKS5_ATYP_DOMAIN;
    int hostname_len = strlen(hostname);
    if (hostname_len > 255) {
        av_log(h, AV_LOG_ERROR, "Hostname too long\n");
        return AVERROR(EINVAL);
    }
    buf[len++] = hostname_len;
    memcpy(buf + len, hostname, hostname_len);
    len += hostname_len;

    // Port (big-endian)
    buf[len++] = (port >> 8) & 0xFF;
    buf[len++] = port & 0xFF;

    if ((ret = ffurl_write(s->tcp_hd, buf, len)) < 0)
        return ret;

    // Read response
    if ((ret = ffurl_read_complete(s->tcp_hd, buf, 4)) < 0)
        return ret;

    if (buf[0] != SOCKS5_VERSION) {
        av_log(h, AV_LOG_ERROR, "Invalid SOCKS5 version in connect response: %d\n", buf[0]);
        return AVERROR(EPROTO);
    }

    if (buf[1] != SOCKS5_REP_SUCCESS) {
        av_log(h, AV_LOG_ERROR, "SOCKS5 connect failed with error code: %d\n", buf[1]);
        return AVERROR(ECONNREFUSED);
    }

    // Skip the rest of the response (address and port)
    uint8_t atyp = buf[3];
    int skip_len = 0;
    
    switch (atyp) {
    case SOCKS5_ATYP_IPV4:
        skip_len = 4 + 2; // IPv4 address + port
        break;
    case SOCKS5_ATYP_IPV6:
        skip_len = 16 + 2; // IPv6 address + port
        break;
    case SOCKS5_ATYP_DOMAIN:
        // Read domain length first
        if ((ret = ffurl_read_complete(s->tcp_hd, buf, 1)) < 0)
            return ret;
        skip_len = buf[0] + 2; // domain length + port
        break;
    default:
        av_log(h, AV_LOG_ERROR, "Unknown address type in SOCKS5 response: %d\n", atyp);
        return AVERROR(EPROTO);
    }

    // Skip the address and port
    if (skip_len > 0) {
        if ((ret = ffurl_read_complete(s->tcp_hd, buf, skip_len)) < 0)
            return ret;
    }

    return 0;
}

static int socks_open(URLContext *h, const char *uri, int flags)
{
    SOCKSContext *s = h->priv_data;
    char proxy_host[256], proxy_auth[256], dest_host[256], dest_path[1024];
    int proxy_port, dest_port;
    char tcp_url[512];
    int ret;

    h->is_streamed = 1;

    // Parse the URI: socks5://[username:password@]proxy_host:proxy_port/dest_host:dest_port
    av_url_split(NULL, 0, proxy_auth, sizeof(proxy_auth),
                 proxy_host, sizeof(proxy_host), &proxy_port,
                 dest_path, sizeof(dest_path), uri);

    if (proxy_port <= 0) {
        av_log(h, AV_LOG_ERROR, "Invalid proxy port\n");
        return AVERROR(EINVAL);
    }

    // Parse destination from path
    if (dest_path[0] == '/')
        memmove(dest_path, dest_path + 1, strlen(dest_path));

    char *colon = strrchr(dest_path, ':');
    if (!colon) {
        av_log(h, AV_LOG_ERROR, "Invalid destination format, expected host:port\n");
        return AVERROR(EINVAL);
    }

    *colon = '\0';
    dest_port = atoi(colon + 1);
    strcpy(dest_host, dest_path);

    if (dest_port <= 0) {
        av_log(h, AV_LOG_ERROR, "Invalid destination port\n");
        return AVERROR(EINVAL);
    }

    // Parse authentication from proxy_auth if present
    if (proxy_auth[0]) {
        char *colon_auth = strchr(proxy_auth, ':');
        if (colon_auth) {
            *colon_auth = '\0';
            s->username = av_strdup(proxy_auth);
            s->password = av_strdup(colon_auth + 1);
        } else {
            s->username = av_strdup(proxy_auth);
        }
    }

    // Connect to SOCKS5 proxy
    ff_url_join(tcp_url, sizeof(tcp_url), "tcp", NULL, proxy_host, proxy_port, NULL);
    ret = ffurl_open_whitelist(&s->tcp_hd, tcp_url, AVIO_FLAG_READ_WRITE,
                               &h->interrupt_callback, NULL,
                               h->protocol_whitelist, h->protocol_blacklist, h);
    if (ret < 0) {
        av_log(h, AV_LOG_ERROR, "Cannot connect to SOCKS5 proxy %s:%d\n", proxy_host, proxy_port);
        return ret;
    }

    // Perform SOCKS5 authentication
    if (s->username && s->password) {
        ret = socks5_auth_userpass(h, s);
    } else {
        ret = socks5_auth_none(h, s);
    }

    if (ret < 0) {
        ffurl_closep(&s->tcp_hd);
        return ret;
    }

    // Connect to destination through SOCKS5 proxy
    ret = socks5_connect(h, s, dest_host, dest_port);
    if (ret < 0) {
        ffurl_closep(&s->tcp_hd);
        return ret;
    }

    av_log(h, AV_LOG_INFO, "Successfully connected to %s:%d through SOCKS5 proxy %s:%d\n",
           dest_host, dest_port, proxy_host, proxy_port);

    return 0;
}

static int socks_read(URLContext *h, uint8_t *buf, int size)
{
    SOCKSContext *s = h->priv_data;
    return ffurl_read(s->tcp_hd, buf, size);
}

static int socks_write(URLContext *h, const uint8_t *buf, int size)
{
    SOCKSContext *s = h->priv_data;
    return ffurl_write(s->tcp_hd, buf, size);
}

static int socks_close(URLContext *h)
{
    SOCKSContext *s = h->priv_data;
    if (s->tcp_hd)
        ffurl_closep(&s->tcp_hd);
    av_freep(&s->username);
    av_freep(&s->password);
    return 0;
}

static int socks_get_file_handle(URLContext *h)
{
    SOCKSContext *s = h->priv_data;
    return ffurl_get_file_handle(s->tcp_hd);
}

const URLProtocol ff_socks_protocol = {
    .name                = "socks5",
    .url_open            = socks_open,
    .url_read            = socks_read,
    .url_write           = socks_write,
    .url_close           = socks_close,
    .url_get_file_handle = socks_get_file_handle,
    .priv_data_size      = sizeof(SOCKSContext),
    .priv_data_class     = &socks_class,
    .flags               = URL_PROTOCOL_FLAG_NETWORK,
}; 