/**
 * \file session_server_rc.c
 * \author Alexandru Panoviciu <alexandru.panoviciu@civica.co.uk>
 * \brief libnetconf2 restconf support utilities
 *
 * Copyright (c) 2022 Civica NI Ltd
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */


#define _GNU_SOURCE

#include <errno.h>
#include <ctype.h>

#include "config.h"
#include "session_server.h"
#include "session_p.h"

#define BAIL_OUT(ERR, LBL) do {                 \
        if (ERR) {                              \
            DBG(NULL, "Err %d", ERR);           \
            ret = ERR;                          \
            goto LBL;                           \
        }                                       \
    } while (0)

// Defined in session_server.c
extern struct nc_server_opts server_opts;


/*!
 * @param[in]  r        Fastcgi request handle
 */
static int
nc_fcgi_dump_request (FCGX_Request *r)
{
    extern char **environ;
    
    for (char **p = r->envp; *p; ++p)
        DBG(NULL, "CGI '%s'", *p);
    
    for (char **p = environ; *p; ++p)
        DBG(NULL, "ENV '%s'", *p);
    
    return 0;
}



/* See RFC 8040 Section 7:  Mapping from NETCONF<error-tag> to Status Code
 * and RFC 6241 Appendix A. NETCONF Error list
 */
static int
nc_err_2_http_code (int err)
{
    int code;

    switch (err)
    {
    case NC_ERR_IN_USE:
        code = 409; break;
    case NC_ERR_INVALID_VALUE: /* 400 or 404 or 406 */
        code = 400; break;
    case NC_ERR_TOO_BIG: /* 413 request ; 400 response */
        code = 413; break;
    case NC_ERR_MISSING_ATTR:
        code = 400; break;
    case NC_ERR_BAD_ATTR:
        code = 400; break;
    case NC_ERR_UNKNOWN_ATTR:
        code = 400; break;
    case NC_ERR_MISSING_ELEM:
        code = 400; break;
    case NC_ERR_BAD_ELEM:
        code = 400; break;
    case NC_ERR_UNKNOWN_ELEM:
        code = 400; break;
    case NC_ERR_UNKNOWN_NS:
        code = 400; break;
    case NC_ERR_ACCESS_DENIED: /* 401 or 403 */
        code = 401; break;
    case NC_ERR_LOCK_DENIED:
        code = 409; break;
    case NC_ERR_RES_DENIED:
        code = 409; break;
    case NC_ERR_ROLLBACK_FAILED:
        code = 500; break;
    case NC_ERR_DATA_EXISTS:
        code = 409; break;
    case NC_ERR_DATA_MISSING:
        code = 409; break;
    case NC_ERR_OP_NOT_SUPPORTED: /* 405 or 501 */
        code = 405; break;
    case NC_ERR_OP_FAILED: /* 412 or 500 */
        code = 412; break;
    case NC_ERR_MALFORMED_MSG:
        code = 400; break;
    default:
        code = 400; break;
    }
    return code;
}



/* See 7231 Section 6.1
 */
const char *
nc_http_code_2_str (int http_code)
{
    static struct {
        char *phrase;
        int code;
    } http_reason_phrase_map[] = {
        {"Continue",                      100},
        {"Switching Protocols",           101},
        {"OK",                            200},
        {"Created",                       201},
        {"Accepted",                      202},
        {"Non-Authoritative Information", 203},
        {"No Content",                    204},
        {"Reset Content",                 205},
        {"Partial Content",               206},
        {"Multiple Choices",              300},
        {"Moved Permanently",             301},
        {"Found",                         302},
        {"See Other",                     303},
        {"Not Modified",                  304},
        {"Use Proxy",                     305},
        {"Temporary Redirect",            307},
        {"Bad Request",                   400},
        {"Unauthorized",                  401},
        {"Payment Required",              402},
        {"Forbidden",                     403},
        {"Not Found",                     404},
        {"Method Not Allowed",            405},
        {"Not Acceptable",                406},
        {"Proxy Authentication Required", 407},
        {"Request Timeout",               408},
        {"Conflict",                      409},
        {"Gone",                          410},
        {"Length Required",               411},
        {"Precondition Failed",           412},
        {"Payload Too Large",             413},
        {"URI Too Long",                  414},
        {"Unsupported Media Type",        415},
        {"Range Not Satisfiable",         416},
        {"Expectation Failed",            417},
        {"Upgrade Required",              426},
        {"Internal Server Error",         500},
        {"Not Implemented",               501},
        {"Bad Gateway",                   502},
        {"Service Unavailable",           503},
        {"Gateway Timeout",               504},
        {"HTTP Version Not Supported",    505},
        {NULL,                            -1}
    };
    int i;

    for (i = 0; http_reason_phrase_map[i].code != -1; ++i)
        if (http_code == http_reason_phrase_map[i].code)
            return http_reason_phrase_map[i].phrase;

    return NULL;
}

/**
 * Decodes RFC3986 percent-encoded URI characters, in-place. Returns s, which may be NULL.
 */
static char*
nc_fcgi_percent_decode (char *s)
{
    char *po = s, *pi = s;
    if (!s) return s;

    while (*pi)
    {
        if (*pi == '%' && isxdigit(*(pi + 1)) && isxdigit(*(pi + 2)))
        {
            char hex[3] = {*(pi+1), *(pi+2)};
            *po++ = (char) strtoul(hex, NULL, 16);
            pi += 3;
        }
        else
            *po++ = *pi++;
    }
    
    *po++ = '\0';

    return s;
}

static char*
nc_fcgi_uri_next (char **uri)
{
    char *next;

    if (uri == NULL || *uri == NULL)
    {
        ERRARG("uri");
        return NULL;
    }
    
    next = strtok_r(*uri, "/", uri);
    nc_fcgi_percent_decode(next);

    DBG(NULL, "Next URI atom: '%s'", next);

    return next;
}


static struct nc_server_reply*
nc_fcgi_err_reply (NC_ERR error, NC_ERR_TYPE error_type, char *format, ...)
{
    struct lyd_node *err;
    char *errmsg = NULL;
    va_list ap;

    err = nc_err(server_opts.ctx, error, error_type);

    va_start(ap, format);
    if (vasprintf(&errmsg, format, ap)) {
        nc_err_set_msg(err, errmsg, "en");
        free(errmsg);
    } else {
        DBG(NULL, "Err");
    }
    va_end(ap);

        
    return nc_server_reply_err(err);
}

static LYD_FORMAT
nc_fcgi_get_rq_output_format (FCGX_Request *request)
{
    char *media_accept = NULL;

    media_accept = FCGX_GetParam("HTTP_ACCEPT", request->envp);
    if (media_accept && strcmp(media_accept, "application/yang-data+xml") == 0)
        return LYD_XML;
    
    return LYD_JSON; // Default
}


/**
 * Handles '{+restconf}/yang-library-version - RFC 8040 3.3.3.
 */
static struct nc_server_reply*
nc_fcgi_clb_get_yang_library_version (FCGX_Request *request)
{
    static struct lys_module *yanglib_mod = NULL;
    static struct lys_module *rc_mod = NULL;
    struct lyd_node *reply_data = NULL;
    struct nc_server_reply *reply = NULL;

    (void) request;
    
    yanglib_mod = ly_ctx_get_module_latest(server_opts.ctx, "ietf-yang-library");
    if (!yanglib_mod) {
        ERRINT;
        goto cleanup;
    }

    rc_mod = ly_ctx_get_module_latest(server_opts.ctx, "ietf-restconf");
    if (!rc_mod) {
        ERRINT;
        goto cleanup;
    }

    if (!rc_mod->compiled) {
        ERR(NULL, "Module ietf-restconf not installed, do you need to `sysrepoctl -i ietf-restconf.yang`?");
        goto cleanup;
    }
    
    for (struct lysc_ext_instance *ext = rc_mod->compiled->exts; ext->def; ++ext)
        if (strcmp(ext->argument, "yang-api") == 0)
        {
            //lyd_print_file(stdout, ext->data, LYD_XML, LYD_PRINT_WD_ALL | LYD_PRINT_KEEPEMPTYCONT);
            if (lyd_new_ext_path(NULL, ext,
                                 "/ietf-restconf:restconf/yang-library-version",
                                 yanglib_mod->revision,
                                 0,
                                 &reply_data)) {
                ERRINT;
                goto cleanup;
            }
            
            break;
        }

    if (!reply_data) {
        ERRINT;
        goto cleanup;
    }
 
    reply = nc_server_reply_data(reply_data, NC_WD_ALL, NC_PARAMTYPE_FREE);
    
 cleanup:

    if (!reply) {
        if (reply_data) lyd_free_tree(reply_data);
    }
        
    
    return reply;
}


/**
 * Handles 'GET {+restconf}' - RFC 8040 3.3. It's not clear whether getting this
 * is meant to return the combined content of data, operations etc ?  For now
 * implement as per RFC8040 B1 - returning empty containers for data and
 * operations (seems wasteful to do a full data retrieval for what is
 * likely a discovery 'GET' and also not trivial as we'd need to inject a RPC
 * to simulate a 'GET {+restconf}/data' with no filters).
 */
static struct nc_server_reply*
nc_fcgi_clb_get_restconf (FCGX_Request *request)
{
    static struct lys_module *yanglib_mod = NULL;
    static struct lys_module *rc_mod = NULL;
    struct lyd_node *reply_data = NULL;
    struct nc_server_reply *reply = NULL;

    (void) request;
    
    yanglib_mod = ly_ctx_get_module_latest(server_opts.ctx, "ietf-yang-library");
    if (!yanglib_mod) {
        ERRINT;
        goto cleanup;
    }

    rc_mod = ly_ctx_get_module_latest(server_opts.ctx, "ietf-restconf");
    if (!rc_mod) {
        ERRINT;
        goto cleanup;
    }

    if (!rc_mod->compiled) {
        ERR(NULL, "Module ietf-restconf not installed, do you need to `sysrepoctl -i ietf-restconf.yang`?");
        goto cleanup;
    }
    
    for (struct lysc_ext_instance *ext = rc_mod->compiled->exts; ext->def; ++ext)
        if (strcmp(ext->argument, "yang-api") == 0)
        {
            if (lyd_new_ext_path(NULL, ext,
                                 "/ietf-restconf:restconf/data",
                                 NULL,
                                 0,
                                 &reply_data)) {
                ERRINT;
                goto cleanup;
            }
            
            break;
        }

    if (!reply_data) {
        ERRINT;
        goto cleanup;
    }

    if (lyd_new_path(reply_data, NULL, "operations", NULL, 0, NULL)) {
        ERRINT;
        goto cleanup;
    }

    if (lyd_new_path(reply_data, NULL, "yang-library-version",
                     yanglib_mod->revision, 0, NULL)) {
        ERRINT;
        goto cleanup;
    }
    
    reply = nc_server_reply_data(reply_data, NC_WD_ALL, NC_PARAMTYPE_FREE);
    
 cleanup:

    if (!reply) {
        if (reply_data) lyd_free_tree(reply_data);
    }
        
    
    return reply;
}


static LY_ERR nc_fcgi_collect_operations (struct lysc_node *node, void *data, ly_bool *dfs_continue)
{
    LY_ERR res = 0;
    struct lys_module *mod = node->module;
    struct lyd_node *reply_data = (struct lyd_node*) data;

    (void) dfs_continue;
    
    if (node->nodetype & (LYS_RPC | LYS_ACTION)) {
        _DBG(NULL, "RPC: %s:%s", mod->ns, node->name);
        res = lyd_new_opaq2(reply_data, NULL, node->name, NULL, mod->prefix, mod->ns, NULL);
    }

    return res;
}


/**
 * Handles 'GET {+restconf}/operations' - RFC 8040 3.3.3.
 */
static struct nc_server_reply*
nc_fcgi_clb_get_operations (FCGX_Request *request)
{
    static struct lys_module *rc_mod = NULL;
    struct lyd_node *reply_data = NULL;
    struct lyd_node *operations_data = NULL;
    struct nc_server_reply *reply = NULL;
    static struct lys_module *mod = NULL;
    unsigned int mi = 0;
    

    (void) request;
    
    rc_mod = ly_ctx_get_module_latest(server_opts.ctx, "ietf-restconf");
    if (!rc_mod) {
        ERRINT;
        goto cleanup;
    }

    if (!rc_mod->compiled) {
        ERR(NULL, "Module ietf-restconf not installed, do you need to `sysrepoctl -i ietf-restconf.yang`?");
        goto cleanup;
    }
    
    for (struct lysc_ext_instance *ext = rc_mod->compiled->exts; ext->def; ++ext)
        if (strcmp(ext->argument, "yang-api") == 0)
        {
            //lyd_print_file(stdout, ext->data, LYD_XML, LYD_PRINT_WD_ALL | LYD_PRINT_KEEPEMPTYCONT);
            if (lyd_new_ext_path(NULL, ext,
                                 "/ietf-restconf:restconf/operations",
                                 NULL,
                                 0,
                                 &reply_data)) {
                ERRINT;
                goto cleanup;
            }
            
            break;
        }

    if (!reply_data) {
        ERRINT;
        goto cleanup;
    }

    if (lyd_find_path(reply_data, "operations", 0, &operations_data)) {
        ERRINT;
        goto cleanup;
    }

    while ((mod = ly_ctx_get_module_iter(server_opts.ctx, &mi)) != NULL) {
        DBG(NULL, "Module: %s parsed %p compiled %p", mod->name, mod->parsed, mod->compiled);
        lysc_module_dfs_full(mod, nc_fcgi_collect_operations, operations_data);
    }
 
    reply = nc_server_reply_data(reply_data, NC_WD_ALL, NC_PARAMTYPE_FREE);
    
 cleanup:

    if (!reply) {
        if (reply_data) lyd_free_tree(reply_data);
    }
        
    
    return reply;
}





/**
 * Dispatches to the {+restconf}/ resource-specific handlers, based on
 * method+resource name.
 */
static struct nc_server_reply*
nc_fcgi_clb_uri_restconf (FCGX_Request *request, char *uri_rem)
{
    struct nc_server_reply *reply = NULL;
    char *resource = nc_fcgi_uri_next(&uri_rem);
    char *method = NULL;

    method = FCGX_GetParam("REQUEST_METHOD", request->envp);
    if (!method)
        goto cleanup;

    if (resource == NULL) {
        if (strcmp(method, "GET") == 0) {
            reply = nc_fcgi_clb_get_restconf(request);
        }
    } else if (strcmp(method, "GET") == 0 && strcmp(resource, "yang-library-version") == 0) {
        reply = nc_fcgi_clb_get_yang_library_version(request);
    } else if (strcmp(method, "GET") == 0 && strcmp(resource, "operations") == 0) {
        reply = nc_fcgi_clb_get_operations(request);
    }

 cleanup:

    return reply;
}

/**
 * Handles RPCs that are specifically addressed to the restconf module. Note
 * the rpc argument in this case is a dummy value - the actual request is in
 * the session's request.
 */
static struct nc_server_reply*
nc_fcgi_clb_restconf (struct lyd_node *rpc, struct nc_session *session)
{
    struct nc_server_reply *reply = NULL;
    FCGX_Request *request = NULL;
    char *uri = NULL, *next = NULL, *uri_rem = NULL;

    (void) rpc;

    if (nc_session_2_request(session, &request)) {
        goto cleanup;
    }

    uri_rem = uri = strdup(FCGX_GetParam("REQUEST_URI", request->envp));
    if (uri == NULL) {
        goto cleanup;
    }

    DBG(NULL, "Handling RESTCONF RPC for URI '%s'", uri);

    next = nc_fcgi_uri_next(&uri_rem);
    if (next == NULL || strcmp(next, "restconf")) {
        goto cleanup;
    }

    reply = nc_fcgi_clb_uri_restconf(request, uri_rem);

 cleanup:

    if (!reply) { // Something went wrong - build generic error reply
        reply = nc_fcgi_err_reply(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP,
                                  "Internal error, URI '%s'",
                                  uri ? uri : "<unknown>");
    }

    if (uri) free(uri);
    
    return reply;
}



/**
 * Returns an RPC that eventually invokes nc_fcgi_clb_restconf. This handles
 * all URIs that are restconf-specific and are therefore not served by
 * existing netconf callbacks.
 */
static int
nc_fcgi_restconf_rpc (struct nc_session *session, struct nc_server_rpc **rpc)
{
    int ret = 0;
    static struct lys_module *mod = NULL;
    static struct lysc_node_action *dummy_schema = NULL;

    (void) session;
    
    if (mod == NULL) // HACK ALERT: we create a dummy copy of the get-schema
                     // rpc but fix its private callback to point be
                     // nc_fcgi_clb_restconf. A cleaner solution would be to
                     // have an actual explicit RPC to use, perhaps as an
                     // augmentation of the ietf-restconf module.
        
    {
        if ((mod = ly_ctx_get_module_latest(server_opts.ctx, "ietf-netconf-monitoring")) != NULL) {
            const struct lysc_node *rpc_proto =
                (const struct lysc_node*) lys_find_path(server_opts.ctx, NULL,
                                                        "/ietf-netconf-monitoring:get-schema",
                                                        0);
            
            if (!rpc_proto) {
                BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);
            }
            
            dummy_schema = malloc(sizeof(*dummy_schema));
            memcpy(dummy_schema, rpc_proto, sizeof(*dummy_schema));
            dummy_schema->priv = nc_fcgi_clb_restconf;
        } else {
            BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);
        }
    }

    *rpc = calloc(1, sizeof **rpc);
    if (!*rpc) {
        ERRMEM;
        BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);
    }

    if (lyd_new_inner(NULL, mod, "get-schema", 0, &(*rpc)->rpc)) {
        BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);
    }
    
    if (lyd_new_opaq2(NULL, server_opts.ctx, "rpc", NULL, mod->prefix, mod->ns, &(*rpc)->envp)) {
        BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);
    }

    (*rpc)->rpc->schema = (const struct lysc_node*) dummy_schema;

    DBG(NULL, "RPC is %p", *rpc);
    
 cleanup:
    if (ret && *rpc)
    {
        free(*rpc);
    }
    
    return ret;
}

/**
 * Translates '/restconf/data' to an RPC - in this case the RPC is
 * 'ietf-netconf:get'.
 */
static int
nc_fcgi_uri_data_rpc (struct nc_session *session, struct nc_server_rpc **rpc)
{
    int ret = 0;
    const struct lys_module *mod = NULL;
    (void) session;
    
    DBG(NULL, "URI: /restconf/data");
    ERR(NULL, "XXX");
    if ((mod = ly_ctx_get_module_implemented(server_opts.ctx, "ietf-netconf")) == NULL) {
        BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);
    }

    *rpc = calloc(1, sizeof **rpc);
    if (!*rpc) {
        ERRMEM;
        BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);
    }
    
    if (lyd_new_inner(NULL, mod, "get", 0, &(*rpc)->rpc)) {
        BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);
    }
    
    if (lyd_new_opaq2(NULL, server_opts.ctx, "rpc", NULL, mod->prefix, mod->ns, &(*rpc)->envp)) {
        BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);
    }

 cleanup:
    if (ret && *rpc)
    {
        free(*rpc);
    }
    
    return ret;
}



/**
 * Translates '/restconf/ds/...' to an RPC - in this case the RPC is
 * 'ietf-netconf:'.
 */
static int
nc_fcgi_uri_ds_rpc (struct nc_session *session, char *uri_rem, struct nc_server_rpc **rpc)
{
    int ret = 0;
    const struct lys_module *mod = NULL;
    char *datastore = nc_fcgi_uri_next(&uri_rem);

    (void) session;

    if (!datastore) {
        BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);
    }

    DBG(NULL, "DS: %s", datastore);

    
    if ((mod = ly_ctx_get_module_implemented(server_opts.ctx, "ietf-netconf-nmda")) == NULL) {
        BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);
    }

    *rpc = calloc(1, sizeof **rpc);
    if (!*rpc) {
        ERRMEM;
        BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);
    }
    
    if (lyd_new_inner(NULL, mod, "get-data", 0, &(*rpc)->rpc)) {
        BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);
    }

    if (lyd_new_term((*rpc)->rpc, NULL, "datastore", datastore, 0, NULL)) {
        BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);
    }
    
    if (lyd_new_opaq2(NULL, server_opts.ctx, "rpc", NULL, mod->prefix, mod->ns, &(*rpc)->envp)) {
        BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);
    }

 cleanup:
    if (ret && *rpc)
    {
        free(*rpc);
    }
    
    return ret;
}

/**
 * Reads all of the POST data from the request into one big malloc'd string
 * and returns it into *output (XXX malloc-heavy).
 */
static int
nc_fcgi_read_post_data (FCGX_Request *request, char **output)
{
    int bsz = 0;
    int nread = 0;
    
    *output = NULL;
    
    while (nread == bsz)
    {
        char *buf = realloc(*output, bsz += 1024);
        if (!buf)
        {
            ERRMEM;
            if (*output) free(*output);
            *output = NULL;
            return -1;
        }
        *output = buf;
        nread += FCGX_GetStr(*output + nread, 1024, request->in);
    }

    (*output)[nread++] = '\0';

    return nread;
}

/**
 * Builds a NETCONF serialized RPC for the RPC of the given name, reading the
 * RPC args from the FCGI request's input stream.
 *
 * XXX malloc-heavy
 */
static int
nc_fcgi_build_rpc (FCGX_Request *request, LYD_FORMAT format, char *rpc_fqn, char **rpc)
{
    int ret = 0;
    char *args = "", *inputs = NULL;
    char *rpc_name = NULL, *rpc_ns = NULL;
    int id = time(NULL);

    _DBG(NULL, "RPC FQN '%s'", rpc_fqn);
    
    // split "ns:more_ns:more_ns_stuff:rpc_name" 
    rpc_name = strrchr(rpc_fqn, ':');
    if (!rpc_name) {
        BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);
    }
    rpc_name += 1;
    
    rpc_ns = strndup(rpc_fqn, rpc_name - rpc_fqn - 1);
    if (!rpc_ns) {
        BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);
    }

    _DBG(NULL, "RPC ns '%s' name '%s'", rpc_ns, rpc_name);
    
    // POST data contains the RPC inputs
    if (nc_fcgi_read_post_data(request, &inputs) < 0) {
        BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);
    }

    // Strip <input>...</input> tags from *inputs
    if (strlen(inputs)) {
        int skip;
        char *end;

        if (sscanf(inputs, " <input%*[^>]>%n", &skip) != 0)
        {
            BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);
        }
        
        args = inputs + skip;
        
        end = strrchr(args, '<');
        if (end == NULL || strncmp(end, "</input>", 8)) {
            BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);
        }
        *end = '\0';
    }
    
    _DBG(NULL, "RPC args:\n>>>%s<<<\n", args);

    if (format == LYD_JSON) {
        asprintf(rpc,
                 "{ \"rpc\" : "
                 "     {\"message-id\" : %d,"
                 "      \"xmlns\"      : \"%s\""
                 "      %s : %s"
                 "     }"
                 "}",
                 id, NC_NS_BASE, rpc_fqn, args);
    } else {
        asprintf(rpc,
                 "<rpc message-id=\"%d\" xmlns=\"%s\">"
                 "<%s xmlns=\"%s\">%s</%s>"
                 "</rpc>",
                 id, NC_NS_BASE, rpc_name, rpc_ns, args, rpc_name);
    }

 cleanup:

    if (inputs) free(inputs);
    if (rpc_ns) free(rpc_ns);
        
    return ret;
        
}

/**
 * Translates 'POST /restconf/operations/<rpc> ...' to the actual RPC to be
 * invoked.
 */
static int
nc_fcgi_uri_operations_post_rpc (struct nc_session *session,
                                 char *uri_rem,
                                 struct nc_server_rpc **rpc)
{
    int ret = 0;
    FCGX_Request *request = &session->ti.fcgi.request;
    char *rpc_name = nc_fcgi_uri_next(&uri_rem);
    LYD_FORMAT input_format;
    char *rpc_data = NULL;
    struct ly_in *ly_in = NULL;

    if (!rpc_name)
        BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);

    if (nc_fcgi_get_input_format(session, &input_format)) {
        BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);
    }

    *rpc = calloc(1, sizeof **rpc);
    if (!*rpc) {
        ERRMEM;
        BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);
    }

    if (nc_fcgi_build_rpc(request, input_format, rpc_name, &rpc_data)) {
        BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);
    }

    _DBG(NULL, "RPC data:\n>%s<\n", rpc_data);
    
    if (ly_in_new_memory(rpc_data, &ly_in)) {
        BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);
    }
    
    if (lyd_parse_op(server_opts.ctx, NULL, ly_in, input_format, LYD_TYPE_RPC_NETCONF,
                     &(*rpc)->envp, &(*rpc)->rpc)) {
        if ((*rpc)->envp) lyd_free_tree((*rpc)->envp);
        BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);
    }

 cleanup:

    if (ly_in) ly_in_free(ly_in, 0);
    if (rpc_data) free(rpc_data);
    
    if (ret && *rpc)
    {
        free(*rpc);
    }
    
    return ret;
}


/**
 * Translates '/restconf/operations' to RPC.
 */
static int
nc_fcgi_uri_operations_rpc (struct nc_session *session, char *uri_rem, struct nc_server_rpc **rpc)
{
    FCGX_Request *request = &session->ti.fcgi.request;
    char *method = NULL;
    int ret = 0;
    
    if ((method = FCGX_GetParam("REQUEST_METHOD", request->envp)) == NULL)
    {
        BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);
    }

    DBG(NULL, "URI: %s /restconf/operations", method);

    if (strcmp(method, "GET") == 0) {
        // GET /restconf/operations - RFC 40480 3.3.2
        ret = nc_fcgi_restconf_rpc(session, rpc);
        BAIL_OUT(ret, cleanup);
    } else if (strcmp(method, "POST") == 0) {
        // POST /restconf/operations/<rpc> - RFC4080 3.6
        ret = nc_fcgi_uri_operations_post_rpc(session, uri_rem, rpc);
        BAIL_OUT(ret, cleanup);
    } else {
        BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);
    }


 cleanup:
    return ret;
}


/**
 * Translates URIs of the form  '/restconf...' (aka the root of the REST API) to their
 * equivalent RPC.
 */
static int
nc_fcgi_uri_restconf_rpc (struct nc_session *session, char *uri_rem, struct nc_server_rpc **rpc)
{
    char *resource = nc_fcgi_uri_next(&uri_rem);
    int ret = 0;

    if (!resource) {
        ret = nc_fcgi_restconf_rpc(session, rpc);
    } else if (strcmp(resource, "data") == 0) {
        ret = nc_fcgi_uri_data_rpc(session, rpc);
    } else if (strcmp(resource, "ds") == 0) {
        ret = nc_fcgi_uri_ds_rpc(session, uri_rem, rpc);
    } else if (strcmp(resource, "operations") == 0) {
        ret = nc_fcgi_uri_operations_rpc(session, uri_rem, rpc);
    } else {
        ret = nc_fcgi_restconf_rpc(session, rpc);
    }
        
    return ret;
}

////////////////////////////////////////////////////////////////////////////////
//
// External functions
//
////////////////////////////////////////////////////////////////////////////////


int
nc_fcgi_init (void)
{
    if (FCGX_Init() != 0) {
        ERR(NULL, "FCGI_Init error.");
        return -1;
    }

    return 0;
}

int
nc_fcgi_destroy (void)
{
    FCGX_ShutdownPending();
    
    return 0;
}


int
nc_sock_listen_fcgi(const char *address, const struct nc_server_fcgi_opts *opts)
{
    int sock = -1;
    
    if ((sock = FCGX_OpenSocket(address, opts->backlog)) < 0){
        ERR(NULL, "FCGX_OpenSocket error.");
        return -1;
    }
    
    if (opts->mode != (mode_t)-1) {
        if (chmod(address, opts->mode) < 0) {
            ERR(NULL, "Failed to set unix socket permissions (%s).", strerror(errno));
            goto fail;
        }
    }

    if ((opts->uid != (uid_t)-1) || (opts->gid != (gid_t)-1)) {
        if (chown(address, opts->uid, opts->gid) < 0) {
            ERR(NULL, "Failed to set unix socket uid/gid (%s).", strerror(errno));
            goto fail;
        }
    }


    return sock;

fail:
    if (sock > -1) {
        close(sock);
    }
    return -1;
}


int
nc_accept_fcgi(struct nc_session *session, int sock)
{
    FCGX_Request *request = &session->ti.fcgi.request;
    char *remote_addr = "unknown";
    char *remote_port = "-1";
    char *remote_user = "anonymous";
    char *tmp;

    if (FCGX_InitRequest(request, sock, 0) != 0)
    {
        ERR(NULL, "FCGX_InitRequest error.");
        return -1;
    }

    // Note this is called when we _know_ that sock poll'd so accept will be
    // guaranteed not to block. A better approach may be to refactor the whole
    // bottom half of nc_sock_accept_binds into the TI - specific accept
    // functions.
    if (FCGX_Accept_r(request) < 0) {
        ERR(NULL, "FCGX_Accept_r error.");
        return -1;
    }

    session->ti_type = NC_TI_FCGI;

    if ((tmp = FCGX_GetParam("REMOTE_ADDR", request->envp)) != NULL)
    {
        remote_addr = tmp;
    }
    lydict_insert(server_opts.ctx, remote_addr, 0, &session->host);

    if ((tmp = FCGX_GetParam("REMOTE_PORT", request->envp)) != NULL)
    {
        remote_port = tmp;
    }
    session->port = atoi(remote_port);


    if ((tmp = FCGX_GetParam("REMOTE_USER", request->envp)) != NULL)
    {
        remote_user  = tmp;
    }
    lydict_insert(server_opts.ctx, remote_user, 0, &session->username);

    VRB(NULL, "Accepted an fcgi connection from %s@%s:%s for URI %s.",
        remote_user, remote_addr, remote_port,
        FCGX_GetParam("REQUEST_URI", request->envp));
    DBG(NULL, "Request %p", request);
    
    return 1;
}


int
nc_session_2_request (struct nc_session *session, FCGX_Request **request)
{
    if (!session) {
        ERRARG("session");
        return -1;
    }

    if (session->ti_type != NC_TI_FCGI) {
        ERRARG("session-ti");
        return -1;
    }

    *request = &session->ti.fcgi.request;

    return 0;
}


int
nc_server_recv_rpc_fcgi (struct nc_session *session, int io_timeout, struct nc_server_rpc **rpc)
{
    FCGX_Request *request;
    int ret;
    char *uri = NULL;
    char *next = NULL;
    char *uri_rem = NULL;

    if (nc_session_2_request(session, &request) < 0) {
        ERRARG("session");
        return NC_PSPOLL_ERROR;
    } else if (!rpc) {
        ERRARG("rpc");
        return NC_PSPOLL_ERROR;
    } else if ((session->status != NC_STATUS_RUNNING) ||
               (session->side != NC_SERVER) ||
               (session->ti_type != NC_TI_FCGI)) {
        ERR(session, "Invalid session to receive RPCs.");
        return NC_PSPOLL_ERROR;
    }

    uri_rem = uri = strdup(FCGX_GetParam("REQUEST_URI", request->envp));
    
    if (uri == NULL)
    {
        BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);
    }

    DBG(NULL, "REQUEST_URI '%s' ", uri);

    //nc_fcgi_dump_request(request);

    next = nc_fcgi_uri_next(&uri_rem);
    
    if (next == NULL || strcmp(next, "restconf")) {
        BAIL_OUT(NC_PSPOLL_REPLY_ERROR, cleanup);
    }

    ret = nc_fcgi_uri_restconf_rpc(session, uri_rem, rpc);

 cleanup:

    if (uri) free(uri);
    
    if (ret & NC_PSPOLL_REPLY_ERROR)
    {
        // shouldn't need this but nc_ps_poll has no path to just send a reply
        // in an rcv error case without trying to actually invoke the RPC.
        int r;
        struct lyd_node *e;
        char *errmsg = NULL;
        struct nc_server_reply *reply;
        
        e = nc_err(server_opts.ctx, NC_ERR_INVALID_VALUE, NC_ERR_TYPE_APP);

        if (asprintf(&errmsg,
                     "Invalid '%s' request to uri '%s'.",
                     FCGX_GetParam("REQUEST_METHOD", request->envp),
                     FCGX_GetParam("REQUEST_URI", request->envp)) > 0)
        {
            nc_err_set_msg(e, errmsg, "en");
            free(errmsg);
        }
        else
        {
            DBG(NULL, "Err");
        }
        
        reply = nc_server_reply_err(e);
        
        r = nc_write_msg_io(session, io_timeout, NC_MSG_REPLY, NULL, reply);
        nc_server_reply_free(reply);
        if (r != NC_MSG_REPLY) {
            ERR(session, "Failed to write reply (%s), terminating session.", nc_msgtype2str[r]);
            if (session->status != NC_STATUS_INVALID) {
                session->status = NC_STATUS_INVALID;
                session->term_reason = NC_SESSION_TERM_OTHER;
            }
        }

        ret |= NC_PSPOLL_ERROR; // Tell nc_ps_poll we're not returning an RPC
    }
    
    return ret;
}


int
nc_fcgi_get_output_format (struct nc_session *session, LYD_FORMAT *output_format)
{
    FCGX_Request *request;

    if (nc_session_2_request(session, &request))
        return -1;

    *output_format = nc_fcgi_get_rq_output_format(request);
    
    return 0;
}


int
nc_fcgi_get_input_format (struct nc_session *session, LYD_FORMAT *input_format)
{
    FCGX_Request *request;
    char *media_content_type;

    if (nc_session_2_request(session, &request))
        return -1;

    *input_format = LYD_JSON; // Default

    media_content_type = FCGX_GetParam("HTTP_CONTENT_TYPE", request->envp);
    if (!media_content_type)
        media_content_type = FCGX_GetParam("CONTENT_TYPE", request->envp);

    DBG(NULL, "Content type: %s", media_content_type);
    if (media_content_type && strcmp(media_content_type, "application/yang-data+xml")==0)
        *input_format = LYD_XML;
    
    return 0;
}


int
nc_fcgi_send_headers_ok (struct nc_session *session)
{
    FCGX_Request *request;
    if (nc_session_2_request(session, &request))
        return -1;
    
    FCGX_SetExitStatus(201, request->out); /* Created */
    FCGX_FPrintF(request->out, "Content-Type: text/plain\r\n");
    FCGX_FPrintF(request->out, "\r\n");
    return 0;
}

int
nc_fcgi_send_headers_data (struct nc_session *session)
{
    FCGX_Request *request;
    LYD_FORMAT output_format;

    if (nc_session_2_request(session, &request))
        return -1;
    
    nc_fcgi_get_output_format(session, &output_format);
    
    FCGX_SetExitStatus(200, request->out); /* OK */
    FCGX_FPrintF(request->out, "Content-Type: application/yang-data+%s\r\n",
                 output_format == LYD_XML ? "xml" : "json");
    FCGX_FPrintF(request->out, "\r\n");
    return 0;
}

int
nc_fcgi_send_headers_error(struct nc_session *session, struct lyd_node *err)
{
    FCGX_Request *request;
    int http_code;
    const char *reason_phrase;
    LYD_FORMAT output_format;
    
    if (nc_session_2_request(session, &request))
        return -1;
    
    http_code = nc_err_2_http_code(nc_err_get_tag(err));
    if ((reason_phrase = nc_http_code_2_str(http_code)) == NULL){
        return -1;
    }

    nc_fcgi_get_output_format(session, &output_format);
    
    FCGX_SetExitStatus(http_code, request->out);
    FCGX_FPrintF(request->out, "Status: %d %s\r\n", http_code, reason_phrase);
    FCGX_FPrintF(request->out, "Content-Type: application/yang-data+%s\r\n",
                 output_format == LYD_XML ? "xml" : "json");
    FCGX_FPrintF(request->out, "\r\n");
    return 0;
}
