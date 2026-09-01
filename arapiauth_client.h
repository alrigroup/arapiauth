/*
 * Copyright (c) ALRIGROUP and its affiliates.
 *
 * This code is licensed under the ARGLR - ALRI GROUP LICENSE RESERVED
 * found in the LICENSE file in the root directory of this source tree
 * and at: https://github.com/alrigroup/licenses/tree/main
 */

#ifndef ARAPIAUTH_CLIENT_H
#define ARAPIAUTH_CLIENT_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    int success;
    int status_code;
    char user[64];
    char tenant[64];
    char role[32];
    char session_token[128];
    char refresh_token[128];
    int expires_in;
    char error_message[256];
} ArapiauthResult;

int arapiauth_client_login(const char *username, const char *password, const char *totp_code,
                           const char *client_ip, ArapiauthResult *out_res);

int arapiauth_client_verify_session(const char *session_token, ArapiauthResult *out_res);

int arapiauth_client_rotate_session(const char *refresh_token, const char *client_ip, ArapiauthResult *out_res);

int arapiauth_client_revoke_session(const char *session_token);

int arapiauth_client_change_password(const char *username, const char *new_password);

#endif /* ARAPIAUTH_CLIENT_H */
