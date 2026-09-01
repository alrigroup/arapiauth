/*
 * Copyright (c) ALRIGROUP and its affiliates.
 *
 * This code is licensed under the ARGLR - ALRI GROUP LICENSE RESERVED
 * found in the LICENSE file in the root directory of this source tree
 * and at: https://github.com/alrigroup/licenses/tree/main
 */

#include "arapiauth_http.h"
#include "arapiauth_config.h"
#include "arapiauth_client.h"
#include "aros_hal.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static int g_http_listen_fd = -1;
static volatile int g_http_running = 0;
static void *g_http_thread = NULL;

static void send_http_response(int client_fd, int status_code, const char *status_text,
                               const char *content_type, const char *extra_headers, const char *body) {
    size_t body_len = body ? strlen(body) : 0;
    char header[1024];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Headers: Content-Type, Authorization, X-Forwarded-For\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\n"
        "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n"
        "%s"
        "Connection: close\r\n"
        "\r\n",
        status_code, status_text, content_type, body_len,
        extra_headers ? extra_headers : "");

    ar_socket_send(client_fd, header, hlen);
    if (body_len > 0) {
        ar_socket_send(client_fd, body, (int)body_len);
    }
}

static char* extract_json_string(const char *json, const char *key) {
    if (!json || !key) return NULL;
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    char *pos = strstr((char*)json, pattern);
    if (!pos) return NULL;

    char *colon = strchr(pos, ':');
    if (!colon) return NULL;

    char *val_start = colon + 1;
    while (*val_start && isspace((unsigned char)*val_start)) val_start++;

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
    }
    return NULL;
}

static char* extract_session_token_from_request(const char *buf, const char *body) {
    /* 1. Try body if JSON */
    if (body) {
        char *t = extract_json_string(body, "session_token");
        if (t) return t;
    }
    /* 2. Try Authorization: Bearer */
    char *auth = strstr(buf, "Authorization: Bearer ");
    if (auth) {
        auth += 22;
        char token[128] = {0};
        sscanf(auth, "%127s", token);
        if (token[0]) return strdup(token);
    }
    /* 3. Try Cookie: __Host-arsession */
    const char *cookie = strstr(buf, "__Host-arsession=");
    if (cookie) {
        cookie += 17;
        while (*cookie == ' ' || *cookie == '\t') cookie++;
        char token[128] = {0};
        int i = 0;
        while (cookie[i] && cookie[i] != ';' && cookie[i] != '\r' && cookie[i] != '\n' && cookie[i] != ' ' && i < 127) {
            token[i] = cookie[i];
            i++;
        }
        token[i] = '\0';
        if (token[0]) return strdup(token);
    }
    return NULL;
}

static void* http_client_worker(void *arg) {
    int client_fd = (int)(intptr_t)arg;
    char buf[4096];
    memset(buf, 0, sizeof(buf));

    int received = ar_socket_recv(client_fd, buf, sizeof(buf) - 1);
    if (received <= 0) {
        ar_socket_close(client_fd);
        return NULL;
    }

    char method[16] = {0};
    char path[256] = {0};
    sscanf(buf, "%15s %255s", method, path);

    /* Handle OPTIONS Preflight */
    if (strcmp(method, "OPTIONS") == 0) {
        send_http_response(client_fd, 204, "No Content", "text/plain", NULL, "");
        ar_socket_close(client_fd);
        return NULL;
    }

    char client_ip[64] = "127.0.0.1";
    char *xff = strstr(buf, "X-Forwarded-For:");
    if (xff) {
        sscanf(xff + 16, "%63s", client_ip);
        char *comma = strchr(client_ip, ',');
        if (comma) *comma = '\0';
    }

    char *body = strstr(buf, "\r\n\r\n");
    if (body) body += 4;

    alri_print_force(CYN "[ARAPIAUTH-HTTP]" RST " INCOMING: %s %s body='%s'\n", method, path, body ? body : "");

    /* 1. GET /arapi/auth/status or /arapi/auth/health */
    if (strcmp(method, "GET") == 0 &&
        (strcmp(path, "/arapi/auth/status") == 0 || strcmp(path, "/arapi/auth/health") == 0 || strcmp(path, "/arapi/auth/") == 0)) {
        char json[512];
        snprintf(json, sizeof(json),
            "{\"status\":\"online\",\"backend\":\"arapiauth\",\"prefix\":\"/arapi/auth\","
            "\"public_registration_allowed\":false,\"security\":\"ARAUTH Sovereign Shield\"}\n");
        send_http_response(client_fd, 200, "OK", "application/json", NULL, json);
        ar_socket_close(client_fd);
        return NULL;
    }

    /* 2. POST /arapi/auth/login */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/arapi/auth/login") == 0) {
        if (!body) {
            send_http_response(client_fd, 400, "Bad Request", "application/json", NULL, "{\"error\":\"Missing JSON body\"}\n");
            ar_socket_close(client_fd);
            return NULL;
        }

        char *username = extract_json_string(body, "username");
        char *password = extract_json_string(body, "password");
        char *totp_code = extract_json_string(body, "totp_code");

        alri_print_force(CYN "[ARAPIAUTH-HTTP]" RST " Login attempt for user='%s'\n", username ? username : "null");

        if (!username || !password) {
            if (username) free(username);
            if (password) free(password);
            if (totp_code) free(totp_code);
            send_http_response(client_fd, 400, "Bad Request", "application/json", NULL, "{\"error\":\"Fields 'username' and 'password' are required\"}\n");
            ar_socket_close(client_fd);
            return NULL;
        }

        ArapiauthResult res;
        int ok = arapiauth_client_login(username, password, totp_code, client_ip, &res);
        alri_print_force(CYN "[ARAPIAUTH-HTTP]" RST " Client login res: ok=%d, success=%d, status=%d, err='%s'\n",
                         ok, res.success, res.status_code, res.error_message);
        free(username); free(password);
        if (totp_code) free(totp_code);

        if (ok == 0 && res.success) {
            char cookie[512];
            snprintf(cookie, sizeof(cookie),
                "Set-Cookie: __Host-arsession=%s; Max-Age=%d; Path=/; HttpOnly; SameSite=Strict; Secure\r\n",
                res.session_token, res.expires_in > 0 ? res.expires_in : 14400);

            char json[1024];
            snprintf(json, sizeof(json),
                "{\"status\":\"success\",\"message\":\"Authentication successful\","
                "\"user\":\"%s\",\"tenant\":\"%s\",\"role\":\"%s\","
                "\"session_token\":\"%s\",\"refresh_token\":\"%s\",\"expires_in\":%d}\n",
                res.user, res.tenant, res.role, res.session_token, res.refresh_token, res.expires_in);

            send_http_response(client_fd, 200, "OK", "application/json", cookie, json);
        } else {
            char err_json[512];
            snprintf(err_json, sizeof(err_json), "{\"error\":\"%s\"}\n",
                     res.error_message[0] ? res.error_message : "Authentication failed");
            send_http_response(client_fd, res.status_code > 0 ? res.status_code : 401, "Unauthorized", "application/json", NULL, err_json);
        }
        ar_socket_close(client_fd);
        return NULL;
    }

    /* 3. GET /arapi/auth/me (Protected Route) */
    if (strcmp(method, "GET") == 0 && strcmp(path, "/arapi/auth/me") == 0) {
        char *token = extract_session_token_from_request(buf, body);
        if (!token) {
            send_http_response(client_fd, 401, "Unauthorized", "application/json", NULL, "{\"error\":\"Missing session credentials\"}\n");
            ar_socket_close(client_fd);
            return NULL;
        }

        ArapiauthResult res;
        int ok = arapiauth_client_verify_session(token, &res);
        free(token);

        if (ok == 0 && res.success) {
            char json[512];
            snprintf(json, sizeof(json),
                "{\"authenticated\":true,\"user\":\"%s\",\"tenant\":\"%s\",\"role\":\"%s\"}\n",
                res.user, res.tenant, res.role);
            send_http_response(client_fd, 200, "OK", "application/json", NULL, json);
        } else {
            send_http_response(client_fd, 401, "Unauthorized", "application/json", NULL, "{\"authenticated\":false,\"error\":\"Session invalid or expired\"}\n");
        }
        ar_socket_close(client_fd);
        return NULL;
    }

    /* 4. POST /arapi/auth/refresh (Token Rotation) */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/arapi/auth/refresh") == 0) {
        char *refresh_token = body ? extract_json_string(body, "refresh_token") : NULL;
        if (!refresh_token) {
            send_http_response(client_fd, 400, "Bad Request", "application/json", NULL, "{\"error\":\"Field 'refresh_token' is required\"}\n");
            ar_socket_close(client_fd);
            return NULL;
        }

        ArapiauthResult res;
        int ok = arapiauth_client_rotate_session(refresh_token, client_ip, &res);
        free(refresh_token);

        if (ok == 0 && res.success) {
            char cookie[512];
            snprintf(cookie, sizeof(cookie),
                "Set-Cookie: __Host-arsession=%s; Max-Age=%d; Path=/; HttpOnly; SameSite=Strict; Secure\r\n",
                res.session_token, res.expires_in > 0 ? res.expires_in : 14400);

            char json[512];
            snprintf(json, sizeof(json),
                "{\"status\":\"success\",\"message\":\"Token rotated\","
                "\"session_token\":\"%s\",\"refresh_token\":\"%s\",\"expires_in\":%d}\n",
                res.session_token, res.refresh_token, res.expires_in);

            send_http_response(client_fd, 200, "OK", "application/json", cookie, json);
        } else {
            send_http_response(client_fd, 401, "Unauthorized", "application/json", NULL, "{\"error\":\"Invalid or consumed refresh token\"}\n");
        }
        ar_socket_close(client_fd);
        return NULL;
    }

    /* 5. POST /arapi/auth/logout */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/arapi/auth/logout") == 0) {
        char *token = extract_session_token_from_request(buf, body);
        if (token) {
            arapiauth_client_revoke_session(token);
            free(token);
        }

        /* Clear Cookie in client browser */
        char clear_cookie[256] = "Set-Cookie: __Host-arsession=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict; Secure\r\n";
        send_http_response(client_fd, 200, "OK", "application/json", clear_cookie, "{\"status\":\"success\",\"message\":\"Logged out successfully\"}\n");
        ar_socket_close(client_fd);
        return NULL;
    }

    /* 6. POST /arapi/auth/password (Change Password for Authenticated User) */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/arapi/auth/password") == 0) {
        char *token = extract_session_token_from_request(buf, body);
        if (!token) {
            send_http_response(client_fd, 401, "Unauthorized", "application/json", NULL, "{\"error\":\"Authentication required\"}\n");
            ar_socket_close(client_fd);
            return NULL;
        }

        ArapiauthResult session;
        if (arapiauth_client_verify_session(token, &session) != 0 || !session.success) {
            free(token);
            send_http_response(client_fd, 401, "Unauthorized", "application/json", NULL, "{\"error\":\"Session invalid or expired\"}\n");
            ar_socket_close(client_fd);
            return NULL;
        }
        free(token);

        char *new_password = body ? extract_json_string(body, "new_password") : NULL;
        if (!new_password) {
            send_http_response(client_fd, 400, "Bad Request", "application/json", NULL, "{\"error\":\"Field 'new_password' is required\"}\n");
            ar_socket_close(client_fd);
            return NULL;
        }

        if (arapiauth_client_change_password(session.user, new_password) == 0) {
            free(new_password);
            send_http_response(client_fd, 200, "OK", "application/json", NULL, "{\"status\":\"success\",\"message\":\"Password changed. All other sessions invalidated.\"}\n");
        } else {
            free(new_password);
            send_http_response(client_fd, 500, "Internal Server Error", "application/json", NULL, "{\"error\":\"Failed to change password\"}\n");
        }
        ar_socket_close(client_fd);
        return NULL;
    }

    /* Block registration / sign-up attempts explicitly */
    if (strstr(path, "register") || strstr(path, "signup") || strstr(path, "user/add")) {
        send_http_response(client_fd, 403, "Forbidden", "application/json", NULL, "{\"error\":\"Public self-registration is disabled. Identity must be provisioned by System Authority.\"}\n");
        ar_socket_close(client_fd);
        return NULL;
    }

    /* Fallback 404 */
    send_http_response(client_fd, 404, "Not Found", "application/json", NULL, "{\"error\":\"Endpoint not found in /arapi/auth\"}\n");
    ar_socket_close(client_fd);
    return NULL;
}

static void* http_listen_worker(void *arg) {
    (void)arg;
    while (g_http_running) {
        int client_fd = ar_socket_accept(g_http_listen_fd);
        if (client_fd >= 0) {
            ar_thread_create(http_client_worker, (void*)(intptr_t)client_fd);
        } else {
            ar_sleep_ms(10);
        }
    }
    return NULL;
}

int arapiauth_http_server_start(const char *bind_ip, int port) {
    if (g_http_running) return 0;

    g_http_listen_fd = ar_socket_create(1);
    if (g_http_listen_fd < 0) return -1;

    ar_socket_reuseaddr(g_http_listen_fd, 1);

    if (ar_socket_bind(g_http_listen_fd, bind_ip ? bind_ip : "127.0.0.1", port) != 0) {
        ar_socket_close(g_http_listen_fd);
        g_http_listen_fd = -1;
        return -1;
    }

    if (ar_socket_listen(g_http_listen_fd, 128) != 0) {
        ar_socket_close(g_http_listen_fd);
        g_http_listen_fd = -1;
        return -1;
    }

    g_http_running = 1;
    g_http_thread = ar_thread_create(http_listen_worker, NULL);
    alri_print(GRN "[ARAPIAUTH]" RST " Identity API Backend listening on %s:%d (prefix: /arapi/auth)\n", bind_ip ? bind_ip : "127.0.0.1", port);
    return 0;
}

void arapiauth_http_server_stop(void) {
    if (!g_http_running) return;
    g_http_running = 0;
    if (g_http_listen_fd >= 0) {
        ar_socket_close(g_http_listen_fd);
        g_http_listen_fd = -1;
    }
    alri_print(CYN "[ARAPIAUTH]" RST " Identity API Backend stopped.\n");
}

int arapiauth_http_is_running(void) {
    return g_http_running;
}
