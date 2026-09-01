/*
 * Copyright (c) ALRIGROUP and its affiliates.
 *
 * This code is licensed under the ARGLR - ALRI GROUP LICENSE RESERVED
 * found in the LICENSE file in the root directory of this source tree
 * and at: https://github.com/alrigroup/licenses/tree/main
 */

#include "arapiauth_client.h"
#include "arapiauth_config.h"
#include "aros_hal.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static char* extract_json_value(const char *json, const char *key) {
    if (!json || !key) return NULL;
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    char *pos = strstr(json, pattern);
    if (!pos) return NULL;

    char *colon = strchr(pos, ':');
    if (!colon) return NULL;

    char *val_start = colon + 1;
    while (*val_start && (*val_start == ' ' || *val_start == '\t')) val_start++;

    if (*val_start == '\"') {
        val_start++;
        char *val_end = strchr(val_start, '\"');
        if (!val_end) return NULL;
        size_t len = val_end - val_start;
        char *res = (char*)malloc(len + 1);
        if (!res) return NULL;
        memcpy(res, val_start, len);
        res[len] = '\0';
        return res;
    } else {
        char *val_end = val_start;
        while (*val_end && *val_end != ',' && *val_end != '}' && *val_end != '\r' && *val_end != '\n') {
            val_end++;
        }
        size_t len = val_end - val_start;
        char *res = (char*)malloc(len + 1);
        if (!res) return NULL;
        memcpy(res, val_start, len);
        res[len] = '\0';
        return res;
    }
}

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

static int http_post_arauth(const char *path, const char *json_body, const char *auth_header,
                            int *out_status, char *out_body, size_t out_body_size) {
    ArapiauthConfig *cfg = arapiauth_config_get();
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(cfg->arauth_port);
    inet_pton(AF_INET, cfg->arauth_host, &addr.sin_addr);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }

    size_t body_len = json_body ? strlen(json_body) : 0;
    char req[2048];
    int req_len = snprintf(req, sizeof(req),
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "%s%s%s"
        "Connection: close\r\n"
        "\r\n%s",
        path,
        cfg->arauth_host, cfg->arauth_port,
        body_len,
        auth_header ? "Authorization: " : "",
        auth_header ? auth_header : "",
        auth_header ? "\r\n" : "",
        json_body ? json_body : "");

    write(fd, req, req_len);

    char resp[8192];
    memset(resp, 0, sizeof(resp));
    int total_recvd = 0;
    while (total_recvd < (int)sizeof(resp) - 1) {
        int n = read(fd, resp + total_recvd, sizeof(resp) - 1 - total_recvd);
        if (n <= 0) break;
        total_recvd += n;
    }
    close(fd);

    if (total_recvd <= 0) return -1;

    int status = 0;
    if (sscanf(resp, "HTTP/1.1 %d", &status) != 1) {
        sscanf(resp, "HTTP/1.0 %d", &status);
    }
    if (out_status) *out_status = status;

    char *body = strstr(resp, "\r\n\r\n");
    if (body) {
        body += 4;
        if (out_body && out_body_size > 0) {
            strncpy(out_body, body, out_body_size - 1);
            out_body[out_body_size - 1] = '\0';
        }
    }
    return 0;
}

int arapiauth_client_login(const char *username, const char *password, const char *totp_code,
                           const char *client_ip, ArapiauthResult *out_res) {
    (void)client_ip;
    if (!username || !password || !out_res) return -1;
    memset(out_res, 0, sizeof(ArapiauthResult));

    char req_json[512];
    if (totp_code && totp_code[0]) {
        snprintf(req_json, sizeof(req_json),
            "{\"username\":\"%s\",\"password\":\"%s\",\"totp_code\":\"%s\",\"app\":\"arauth\"}",
            username, password, totp_code);
    } else {
        snprintf(req_json, sizeof(req_json),
            "{\"username\":\"%s\",\"password\":\"%s\",\"app\":\"arauth\"}",
            username, password);
    }

    int status = 0;
    char resp_body[4096] = {0};
    if (http_post_arauth("/api/v1/auth/login", req_json, NULL, &status, resp_body, sizeof(resp_body)) != 0) {
        out_res->status_code = 503;
        strncpy(out_res->error_message, "ARAUTH Identity Engine unavailable", sizeof(out_res->error_message) - 1);
        return -1;
    }

    out_res->status_code = status;
    if (status == 200) {
        out_res->success = 1;
        char *u = extract_json_value(resp_body, "user");
        char *t = extract_json_value(resp_body, "tenant");
        char *r = extract_json_value(resp_body, "role");
        char *sid = extract_json_value(resp_body, "session_token");
        char *rt = extract_json_value(resp_body, "refresh_token");
        char *exp = extract_json_value(resp_body, "expires_in");

        if (u) { strncpy(out_res->user, u, sizeof(out_res->user) - 1); free(u); }
        if (t) { strncpy(out_res->tenant, t, sizeof(out_res->tenant) - 1); free(t); }
        if (r) { strncpy(out_res->role, r, sizeof(out_res->role) - 1); free(r); }
        if (sid) { strncpy(out_res->session_token, sid, sizeof(out_res->session_token) - 1); free(sid); }
        if (rt) { strncpy(out_res->refresh_token, rt, sizeof(out_res->refresh_token) - 1); free(rt); }
        if (exp) { out_res->expires_in = atoi(exp); free(exp); }
        return 0;
    } else {
        out_res->success = 0;
        char *err = extract_json_value(resp_body, "error");
        if (err) {
            strncpy(out_res->error_message, err, sizeof(out_res->error_message) - 1);
            free(err);
        } else {
            strncpy(out_res->error_message, "Authentication failed", sizeof(out_res->error_message) - 1);
        }
        return -1;
    }
}

int arapiauth_client_verify_session(const char *session_token, ArapiauthResult *out_res) {
    if (!session_token || !out_res) return -1;
    memset(out_res, 0, sizeof(ArapiauthResult));

    char req_json[256];
    snprintf(req_json, sizeof(req_json), "{\"session_token\":\"%s\"}", session_token);

    int status = 0;
    char resp_body[2048] = {0};
    if (http_post_arauth("/api/v1/auth/session/verify", req_json, NULL, &status, resp_body, sizeof(resp_body)) != 0) {
        out_res->status_code = 503;
        return -1;
    }

    out_res->status_code = status;
    if (status == 200) {
        out_res->success = 1;
        char *u = extract_json_value(resp_body, "user");
        char *t = extract_json_value(resp_body, "tenant");
        char *r = extract_json_value(resp_body, "role");
        if (u) { strncpy(out_res->user, u, sizeof(out_res->user) - 1); free(u); }
        if (t) { strncpy(out_res->tenant, t, sizeof(out_res->tenant) - 1); free(t); }
        if (r) { strncpy(out_res->role, r, sizeof(out_res->role) - 1); free(r); }
        return 0;
    }
    return -1;
}

int arapiauth_client_rotate_session(const char *refresh_token, const char *client_ip, ArapiauthResult *out_res) {
    if (!refresh_token || !out_res) return -1;
    memset(out_res, 0, sizeof(ArapiauthResult));

    char req_json[256];
    snprintf(req_json, sizeof(req_json), "{\"refresh_token\":\"%s\"}", refresh_token);

    int status = 0;
    char resp_body[2048] = {0};
    if (http_post_arauth("/api/v1/auth/session/rotate", req_json, NULL, &status, resp_body, sizeof(resp_body)) != 0) {
        out_res->status_code = 503;
        return -1;
    }

    out_res->status_code = status;
    if (status == 200) {
        out_res->success = 1;
        char *u = extract_json_value(resp_body, "user");
        char *t = extract_json_value(resp_body, "tenant");
        char *r = extract_json_value(resp_body, "role");
        char *sid = extract_json_value(resp_body, "session_token");
        char *rt = extract_json_value(resp_body, "refresh_token");
        char *exp = extract_json_value(resp_body, "expires_in");
        if (u) { strncpy(out_res->user, u, sizeof(out_res->user) - 1); free(u); }
        if (t) { strncpy(out_res->tenant, t, sizeof(out_res->tenant) - 1); free(t); }
        if (r) { strncpy(out_res->role, r, sizeof(out_res->role) - 1); free(r); }
        if (sid) { strncpy(out_res->session_token, sid, sizeof(out_res->session_token) - 1); free(sid); }
        if (rt) { strncpy(out_res->refresh_token, rt, sizeof(out_res->refresh_token) - 1); free(rt); }
        if (exp) { out_res->expires_in = atoi(exp); free(exp); }
        return 0;
    }
    return -1;
}

int arapiauth_client_revoke_session(const char *session_token) {
    if (!session_token) return -1;
    char req_json[256];
    snprintf(req_json, sizeof(req_json), "{\"session_token\":\"%s\"}", session_token);
    int status = 0;
    char resp_body[1024] = {0};
    return http_post_arauth("/api/v1/auth/session/revoke", req_json, NULL, &status, resp_body, sizeof(resp_body));
}

int arapiauth_client_change_password(const char *username, const char *new_password) {
    if (!username || !new_password) return -1;
    char req_json[256];
    snprintf(req_json, sizeof(req_json), "{\"username\":\"%s\",\"new_password\":\"%s\"}", username, new_password);
    int status = 0;
    char resp_body[1024] = {0};
    return http_post_arauth("/api/v1/auth/user/passwd", req_json, NULL, &status, resp_body, sizeof(resp_body));
}
