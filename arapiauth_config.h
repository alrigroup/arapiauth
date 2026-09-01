/*
 * Copyright (c) ALRIGROUP and its affiliates.
 *
 * This code is licensed under the ARGLR - ALRI GROUP LICENSE RESERVED
 * found in the LICENSE file in the root directory of this source tree
 * and at: https://github.com/alrigroup/licenses/tree/main
 */

#ifndef ARAPIAUTH_CONFIG_H
#define ARAPIAUTH_CONFIG_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    char app_id[64];
    char app_name[128];
    int server_port;
    char server_bind[64];
    char route_prefix[128];
    char arauth_host[64];
    int arauth_port;
    int arauth_ipc_port;
} ArapiauthConfig;

int arapiauth_config_load(const char *cfg_path, ArapiauthConfig *out_cfg);
ArapiauthConfig* arapiauth_config_get(void);

#endif /* ARAPIAUTH_CONFIG_H */
