// XOAUTH2 client plugin for libsasl2
// Copyright © 1998-2003 Carnegie Mellon University
// Copyright © 2015 Robert Norris
// MIT license

#include <stdio.h>
#include <string.h>
#include <sasl/sasl.h>
#include <sasl/saslplug.h>

#include "plugin_common.h"

typedef struct client_context {
    int state;
    char *out_buf;
    unsigned out_buf_len;
} client_context_t;

static int xoauth2_client_mech_new(void *glob_context __attribute__((unused)),
                                   sasl_client_params_t *params,
                                   void **conn_context)
{
    client_context_t *text = params->utils->malloc(sizeof(client_context_t));
    if (text == NULL) {
        MEMERROR( params->utils );
        return SASL_NOMEM;
    }
    memset(text, 0, sizeof(client_context_t));

   *conn_context = text;

    return SASL_OK;
}

static int xoauth2_client_mech_step(void *conn_context,
                                    sasl_client_params_t *params,
                                    const char *serverin,
                                    unsigned serverinlen,
                                    sasl_interact_t **prompt_need,
                                    const char **clientout,
                                    unsigned *clientoutlen,
                                    sasl_out_params_t *oparams)
{
    client_context_t *text = (client_context_t *) conn_context;
    int r = SASL_OK;

    if (text->state > 0) {
        static char buf[1024];
        strncpy(buf, serverin, serverinlen);
        buf[serverinlen < 1023 ? serverinlen : 1023] = '\0';

        params->utils->seterror(params->utils->conn, 0, "server rejected XOAUTH2: %s", buf);
        return SASL_BADAUTH;
    }

    /* check if sec layer strong enough */
    if (params->props.min_ssf > params->external_ssf) {
        SETERROR( params->utils, "SSF requested of XOAUTH2 plugin");
        return SASL_TOOWEAK;
    }

    /* try to get the userid */
    /* Note: we want to grab the authname and not the userid, which is
     *       who we AUTHORIZE as, and will be the same as the authname
     *       for the XOAUTH2 mech.
     */
    const char *user = NULL;
    int auth_result = SASL_OK;
    if (oparams->user == NULL) {
        auth_result = _plug_get_authid(params->utils, &user, prompt_need);
        if ((auth_result != SASL_OK) && (auth_result != SASL_INTERACT))
            return auth_result;
    }

    /* try to get the token */
    unsigned int do_free_pass = 0;
    sasl_secret_t *pass = NULL;
    int pass_result = SASL_OK;
    if (pass == NULL) {
        pass_result = _plug_get_password(params->utils, &pass, &do_free_pass, prompt_need);
        if ((pass_result != SASL_OK) && (pass_result != SASL_INTERACT))
            return pass_result;
    }

    /* free prompts we got */
    if (prompt_need && *prompt_need) {
        params->utils->free(*prompt_need);
        *prompt_need = NULL;
    }

    /* if there are prompts not filled in */
    if ((auth_result == SASL_INTERACT) || (pass_result == SASL_INTERACT)) {
        /* make the prompt list */
        int result = _plug_make_prompts(params->utils, prompt_need,
                                        NULL, NULL,
                                        auth_result == SASL_INTERACT ?
                                            "Please enter your user name" : NULL, NULL,
                                        pass_result == SASL_INTERACT ?
                                            "Please enter your OAuth bearer token" : NULL, NULL,
                                        NULL, NULL, NULL,
                                        NULL, NULL, NULL);
        if (result != SASL_OK) goto cleanup;
        return SASL_INTERACT;
    }

    if (!pass) {
        PARAMERROR(params->utils);
        return SASL_BADPARAM;
    }

    r = params->canon_user(params->utils->conn, user, 0, SASL_CU_AUTHID | SASL_CU_AUTHZID, oparams);
    if (r != SASL_OK) goto cleanup;

    // user=someuser@example.com^Aauth=Bearer vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg==^A^A
    *clientoutlen =
        5 +             // user=
        oparams->ulen + // <username>
        13 +            // ^Aauth=Bearer<sp>
        pass->len +     // <token>
        2;              // ^A^A

    // trailing NUL for dumb clients
    r = _plug_buf_alloc(params->utils, &(text->out_buf), &(text->out_buf_len), *clientoutlen + 1);
    if (r != SASL_OK) goto cleanup;

    memset(text->out_buf, 0, text->out_buf_len);
    char *p = text->out_buf;

    memcpy(p, "user=", 5);                   p += 5;
    memcpy(p, oparams->user, oparams->ulen); p += oparams->ulen;
    memcpy(p, "\001auth=Bearer ", 13);       p += 13;
    memcpy(p, pass->data, pass->len);        p += pass->len;
    memcpy(p, "\001\001\0", 3);

    *clientout = text->out_buf;

    /* set oparams */
    oparams->doneflag = 0;
    oparams->mech_ssf = 0;
    oparams->maxoutbuf = 0;
    oparams->encode_context = NULL;
    oparams->encode = NULL;
    oparams->decode_context = NULL;
    oparams->decode = NULL;
    oparams->param_version = 0;

    text->state = 1;

    return SASL_CONTINUE;

cleanup:
    if (do_free_pass) _plug_free_secret(params->utils, &pass);
    return r;
}

static void xoauth2_client_mech_dispose(void *conn_context,
                                        const sasl_utils_t *utils)
{
    client_context_t *text = (client_context_t *) conn_context;

    if (!text) return;
    if (text->out_buf) utils->free(text->out_buf);
    utils->free(text);
}

static sasl_client_plug_t xoauth2_client_plugins[] =
{
    {
        "XOAUTH2",                                            // mech_name
        0,                                                    // max_ssf
        SASL_SEC_NOANONYMOUS | SASL_SEC_PASS_CREDENTIALS,     // security_flags
        SASL_FEAT_WANT_CLIENT_FIRST | SASL_FEAT_ALLOWS_PROXY, // features
        NULL,                                                 // required_prompts
        NULL,                                                 // glob_context
        &xoauth2_client_mech_new,                             // mech_new
        &xoauth2_client_mech_step,                            // mech_step
        &xoauth2_client_mech_dispose,                         // mech_dispose
        NULL,                                                 // mech_free
        NULL,                                                 // idle
        NULL,                                                 // spare
        NULL                                                  // spare
    }
};

int xoauth2_client_plug_init(sasl_utils_t *utils,
                           int maxversion,
                           int *out_version,
                           sasl_client_plug_t **pluglist,
                           int *plugcount)
{
    if (maxversion < SASL_CLIENT_PLUG_VERSION) {
        SETERROR(utils, "XOAUTH2 version mismatch");
        return SASL_BADVERS;
    }

    *out_version = SASL_CLIENT_PLUG_VERSION;
    *pluglist = xoauth2_client_plugins;
    *plugcount = 1;

    return SASL_OK;
}
