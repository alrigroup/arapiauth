/*
 * Copyright (c) ALRIGROUP and its affiliates.
 *
 * This code is licensed under the ARGLR - ALRI GROUP LICENSE RESERVED
 * found in the LICENSE file in the root directory of this source tree
 * and at: https://github.com/alrigroup/licenses/tree/main
 */

#include "arapiauth_config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

static ArapiauthConfig g_config;

static void trim(char *s) {
    if (!s) return;
    char *p = s;
    while (isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);

    size_t len = strlen(s);
    while (len > 0 && (isspace((unsigned char)s[len - 1]) || s[len - 1] == '\r' || s[len - 1] == '\n')) {
        s[--len] = '\0';
    }
}

static void set_defaults(ArapiauthConfig *cfg) {
    if (!cfg) return;
    memset(cfg, 0, sizeof(ArapiauthConfig));

    strncpy(cfg->app_id, "arapiauth", sizeof(cfg->app_id) - 1);
    strncpy(cfg->app_name, "ALRI Sovereign Identity API Backend", sizeof(cfg->app_name) - 1);
    cfg->server_port = 9650;
    strncpy(cfg->server_bind, "127.0.0.1", sizeof(cfg->server_bind) - 1);
    strncpy(cfg->route_prefix, "/arapi/auth", sizeof(cfg->route_prefix) - 1);

    strncpy(cfg->arauth_host, "127.0.0.1", sizeof(cfg->arauth_host) - 1);
    cfg->arauth_port = 9550;
    cfg->arauth_ipc_port = 9500;
}

int arapiauth_config_load(const char *cfg_path, ArapiauthConfig *out_cfg) {
    if (!out_cfg) out_cfg = &g_config;
    set_defaults(out_cfg);

    const char *paths[3] = { cfg_path, "storage/arapiauth/arapiauth.cfg", "arapiauth.cfg" };
    FILE *f = NULL;
    for (int i = 0; i < 3; i++) {
        if (paths[i] && paths[i][0]) {
            f = fopen(paths[i], "r");
            if (f) break;
        }
    }

    if (!f) return 0;

    char line[512];
    char section[64] = "";

    while (fgets(line, sizeof(line), f)) {
        trim(line);
        if (line[0] == '#' || line[0] == ';' || line[0] == '\0') continue;

        if (line[0] == '[' && line[strlen(line) - 1] == ']') {
            strncpy(section, line + 1, sizeof(section) - 1);
            section[strlen(section) - 1] = '\0';
            trim(section);
            continue;
        }

        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = line;
        char *val = eq + 1;
        trim(key);
        trim(val);

        if (strcmp(section, "app") == 0) {
            if (strcmp(key, "id") == 0) strncpy(out_cfg->app_id, val, sizeof(out_cfg->app_id) - 1);
            else if (strcmp(key, "name") == 0) strncpy(out_cfg->app_name, val, sizeof(out_cfg->app_name) - 1);
        } else if (strcmp(section, "server") == 0) {
            if (strcmp(key, "port") == 0) out_cfg->server_port = atoi(val);
            else if (strcmp(key, "bind") == 0) strncpy(out_cfg->server_bind, val, sizeof(out_cfg->server_bind) - 1);
            else if (strcmp(key, "route_prefix") == 0 || strcmp(key, "prefix") == 0) strncpy(out_cfg->route_prefix, val, sizeof(out_cfg->route_prefix) - 1);
        } else if (strcmp(section, "arauth") == 0) {
            if (strcmp(key, "host") == 0) strncpy(out_cfg->arauth_host, val, sizeof(out_cfg->arauth_host) - 1);
            else if (strcmp(key, "port") == 0) out_cfg->arauth_port = atoi(val);
            else if (strcmp(key, "ipc_port") == 0) out_cfg->arauth_ipc_port = atoi(val);
        }
    }

    fclose(f);
    return 0;
}

ArapiauthConfig* arapiauth_config_get(void) {
    return &g_config;
}
