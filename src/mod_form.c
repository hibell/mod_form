/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <apr_strings.h>
#include <apr_general.h>
#include <apr_buckets.h>
#include <http_request.h>
#include <http_protocol.h>
#include <util_ebcdic.h>
#include <mod_request.h>


#define UNUSED(x) (void) (x)


module AP_MODULE_DECLARE_DATA form_module;


typedef enum {
    form_invalid,
    form_unset,
    form_edit
} form_action;

typedef struct {
    form_action action;
    const char *name;
    const char *value;
    const char *subst;
    ap_regex_t *regex;
} form_entry;

typedef struct {
    apr_array_header_t *fixup_data;
} form_conf;


static void (*ap_request_insert_filter_fn) (request_rec * r) = NULL;
static void (*ap_request_remove_filter_fn) (request_rec * r) = NULL;


static const char *get_form_value(apr_pool_t *pool, ap_form_pair_t *pair);
static const char *process_regexp(request_rec *r, form_entry *entry,
                                  const char *value);


/**
 * Get the form_action.
 * @param action string
 * @return form_action
 */
static form_action parse_action(const char *action)
{
    if (!strcasecmp(action, "unset"))
        return form_unset;
    else if (!strcasecmp(action, "edit"))
        return form_edit;

    return form_invalid;
}


/**
 * Unset a form pair if it is matches the unset rule. Regex is allowed and can
 * be used to unset all form pairs whose name matches the regex.
 * @param r request record
 * @param entry the unset rule to apply
 * @param name the name of pair to check
 * @param value the value of pair
 * @return NULL if pair matched; otherwise the pair's name is returned.
 */
static const char *do_unset(request_rec *r, form_entry *entry,
                            const char *name, const char *value)
{
    if (!ap_regexec(entry->regex, name, 0, NULL, 0)) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, APLOGNO(03492)
                      "Unset rule '%s' matched for form pair '%s'. "
                      "Form pair was unset.",
                      entry->name, name);
        return NULL;
    }

    return value;
}


/**
 * Edit the value of a form pair if it matches the edit rule. Regex is allowed
 * and can be used to
 * @param r
 * @param entry the edit rule to apply
 * @param name the name of pair to check
 * @param value the name of pair to check
 * @return the edited pair's value
 */
static const char *do_edit(request_rec *r, form_entry *entry,
                           const char *name, const char *value)
{
    if (strcmp(entry->name, name) == 0) {
        value = process_regexp(r, entry, value);
        ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, APLOGNO(03493)
                      "Edit rule '%s' matched for form pair '%s'. "
                      "Form pair was edited.",
                      entry->value, name);
    }

    return value;
}

/**
 * Iterate through each rule and apply it.
 * @param r the request record
 * @param name the name of form pair to process
 * @param value the value of form pair to process
 * @param conf the form conf
 * @return NULL if the pair was unset. Otherwise, it returns the new pair's value.
 */
static const char *do_form_fixup(request_rec *r, const char *name,
                                 const char *value, form_conf *conf)
{
    int i;

    for (i = 0; i < conf->fixup_data->nelts; ++i) {
        form_entry *entry = &((form_entry *) (conf->fixup_data->elts))[i];

        switch(entry->action) {
            case form_unset:
                if (do_unset(r, entry, name, value) == NULL)
                    return NULL;
            case form_edit:
                value = do_edit(r, entry, name, value);
            default:
                continue;
        }
    }

    return value;
}


/**
 * Handler that reads and parses the POSTed form data. This depends on the
 * request module so that the body can be read multiple times.
 *
 * This is a handler instead of a fixup because we depend on mod_charset_lite
 * which use filters for translations. Note that the handler returns DECLINED
 * so that other handlers still run.
 *
 * @param r the request record
 * @return handler return code
 */
static int form_data_handler(request_rec *r)
{
    static const char eq = 0x3D;   /* ASCII '=' */
    static const char amp = 0x26;  /* ASCII '&' */

    form_conf *conf = (form_conf *) ap_get_module_config(r->per_dir_config,
                                                         &form_module);
    apr_bucket_brigade *out;
    apr_bucket *b;
    apr_array_header_t *pairs = NULL;
    apr_status_t rv;
    int res, i;
    const char *name;
    const char *value;
    apr_size_t len;

    /* Bail if there are no configured rules or if the handler shouldn't run. */
    if (r->method_number != M_POST || !ap_is_initial_req(r) ||
            conf->fixup_data->nelts <= 0)
        return DECLINED;

    /* Check to make sure its a URL encoded payload. */
    value = apr_table_get(r->headers_in, "Content-Type");
    if (!value || strncasecmp("application/x-www-form-urlencoded", value, 33) != 0)
        return DECLINED;

    /* Parse the form data */
    res = ap_parse_form_data(r, NULL, &pairs, (apr_size_t) -1, HUGE_STRING_LEN);

    if (pairs == NULL || apr_is_empty_array(pairs))
        return DECLINED;

    out = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    for (i = 0; i < pairs->nelts; ++i) {
        ap_form_pair_t *pair = &((ap_form_pair_t *) (pairs->elts))[i];
        name = pair->name;

        ap_log_rerror(APLOG_MARK, APLOG_TRACE8, res, r, APLOGNO(03494)
                "found form data pair -> %s", name);

        /* Read the value of data. */
        value = do_form_fixup(r, name, get_form_value(r->pool, pair), conf);

        if (value == NULL)
            continue;

        /* Special handling for username field */
        if (strncmp(name, "username", 8) == 0) {
            r->user = (char *) value;

            if (r->user && strncmp(r->user, "blocked_user", 12) == 0) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(03491)
                        "Someone tried to login as a blocked user '%s'. "
                        "Forbidding.", r->user);
                return HTTP_FORBIDDEN;
            }
        }

        /* Request body should be translated back to ASCII (if needed). */
        ap_xlate_proto_to_ascii((char *) name, strlen(name));
        ap_xlate_proto_to_ascii((char *) value, strlen(value));

        /* URL-encode data. */
        rv = apr_brigade_printf(out, NULL, NULL, "%s%c%s%c", name, eq, value, amp);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE8, rv, r, APLOGNO(03495)
                    "Unable to write pair. No longer parsing request data.");
            return DECLINED;
        }
    }

    /* Remove the final trailing '&' from the last bucket that was inserted. */
    b = APR_BRIGADE_LAST(out);
    if (apr_bucket_read(b, &value, &len, APR_BLOCK_READ) == APR_SUCCESS) {
        apr_bucket_split(b, len - 1);
        b = APR_BUCKET_NEXT(b);
        APR_BUCKET_REMOVE(b);
    }

    APR_BRIGADE_INSERT_TAIL(out,
                            apr_bucket_eos_create(r->connection->bucket_alloc));
    r->kept_body = out;

    /* Insert kept_body request filter. */
    ap_request_insert_filter_fn(r);

    return DECLINED;
}


/**
 * Get the value from a pair.
 * @param pool the pool to allocate the return value from
 * @param pair form pair
 * @return value as a string
 */
static const char *get_form_value(apr_pool_t *pool, ap_form_pair_t *pair)
{
    apr_off_t len;
    apr_size_t size;
    char *buffer;

    apr_brigade_length(pair->value, 1, &len);
    size = (apr_size_t) len;
    buffer = apr_palloc(pool, size + 1);
    apr_brigade_flatten(pair->value, buffer, &size);
    buffer[len] = '\0';

    return buffer;
}


/**
 * Process a regex and perform substitution as needed.
 * @param r request record
 * @param entry form_entry to process
 * @param value to process
 * @return the substituted string
 */
static const char *process_regexp(request_rec *r, form_entry *entry,
                                  const char *value)
{
    ap_regmatch_t pmatch[AP_MAX_REG_MATCH];
    const char *subs;
    const char *remainder;
    char *ret;
    apr_size_t diffsz;

    if (ap_regexec(entry->regex, value, AP_MAX_REG_MATCH, pmatch, 0)) {
        /* no match, nothing to do */
        return value;
    }

    /* Process tags in the input string rather than the resulting
     * substitution to avoid surprises
     */
    subs = ap_pregsub(r->pool, entry->subst, value, AP_MAX_REG_MATCH, pmatch);
    if (subs == NULL)
        return NULL;

    diffsz = strlen(subs) - (pmatch[0].rm_eo - pmatch[0].rm_so);
    if (entry->action == form_edit) {
        remainder = value + pmatch[0].rm_eo;
    }
    else { /* recurse to edit multiple matches if applicable */
        remainder = process_regexp(r, entry, value + pmatch[0].rm_eo);
        if (remainder == NULL)
            return NULL;
        diffsz += strlen(remainder) - strlen(value + pmatch[0].rm_eo);
    }

    ret = apr_palloc(r->pool, strlen(value) + 1 + diffsz);
    memcpy(ret, value, pmatch[0].rm_so);
    strcpy(ret + pmatch[0].rm_so, subs);
    strcat(ret, remainder);
    return ret;
}


/**
 * Retrieve the mod_request functions to register/remove the request_insert
 * filters
 * @param pconf
 * @param plog
 * @param ptemp
 * @param s
 * @return
 */
static int form_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                            apr_pool_t *ptemp, server_rec *s)
{
    UNUSED(pconf);
    UNUSED(plog);
    UNUSED(ptemp);
    UNUSED(s);

    if (!ap_request_insert_filter_fn || !ap_request_remove_filter_fn) {
        ap_request_insert_filter_fn =
                APR_RETRIEVE_OPTIONAL_FN(ap_request_insert_filter);
        ap_request_remove_filter_fn =
                APR_RETRIEVE_OPTIONAL_FN(ap_request_remove_filter);

        if (!ap_request_insert_filter_fn || !ap_request_remove_filter_fn) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, NULL, APLOGNO(03496)
                    "You must load mod_request to enable the mod_form "
                    "functions");
            return !OK;
        }
    }

    return OK;
}


static void *config_dir_create(apr_pool_t *p, char *d)
{
    form_conf *conf;
    UNUSED(d);

    conf = (form_conf *) apr_pcalloc(p, sizeof(*conf));
    conf->fixup_data = apr_array_make(p, 2, sizeof(form_entry));
    return (void *) conf;
}


static void *config_dir_merge(apr_pool_t *p, void *basev, void *overridesv)
{
    form_conf *new_conf = apr_pcalloc(p, sizeof(*new_conf));
    form_conf *base = basev;
    form_conf *overrides = overridesv;

    new_conf->fixup_data = apr_array_append(p, base->fixup_data,
                                            overrides->fixup_data);

    return (void *) new_conf;
}


static const char *cmd_formdata(cmd_parms *cmd, void *dconf, const char *args)
{
    form_entry *entry;
    const char *action = NULL;
    const char *name = NULL;
    const char *val = NULL;
    const char *subst = NULL;
    form_conf *conf = dconf;

    action = ap_getword_conf(cmd->temp_pool, &args);
    name = ap_getword_conf(cmd->pool, &args);
    val = *args ? ap_getword_conf(cmd->pool, &args) : NULL;
    subst = *args ? ap_getword_conf(cmd->pool, &args) : NULL;

    if (*args) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name, "has too many arguments",
                           NULL);
    }

    entry = (form_entry *) apr_array_push(conf->fixup_data);
    entry->action = parse_action(action);

    if (entry->action == form_invalid)
        return "first argument must be 'unset' or 'edit'";

    if (!*name) {
        return "second argument must be any form data name";
    }

    if (entry->action == form_unset) {
        if (val)
            return "FormData unset only takes 1 argument: name";

        entry->regex = ap_pregcomp(cmd->pool, name, AP_REG_EXTENDED);
        if (entry->regex == NULL)
            return "FormData edit regex could not be compiled";
    }
    else if (entry->action == form_edit) {
        if (!val || !subst)
            return "FormData edit takes 3 arguments: name pattern substitution";

        entry->regex = ap_pregcomp(cmd->pool, val, AP_REG_EXTENDED);
        if (entry->regex == NULL)
            return "FormData edit regex could not be compiled";
    }

    entry->name = name;
    entry->value = val;
    entry->subst = subst;

    ap_log_error(APLOG_MARK, APLOG_TRACE8, 0, cmd->server, APLOGNO(03497)
                 "Adding FormData command {Command: '%s', Name: '%s', Value: "
                 "'%s', Substitution: '%s'}", action, name,
                 val ? val : "None",
                 subst ? subst : "None");

    return NULL;
}


static const command_rec command_table[] = {
    AP_INIT_RAW_ARGS("FormData", cmd_formdata, NULL, ACCESS_CONF,
                     "A pattern and substitution"),
    { NULL }
};


static void register_hooks(apr_pool_t *p)
{
    static const char * const aszSucc[]={ "mod_proxy.c", NULL };

    UNUSED(p);

    /*
     * Retrieve the mod_request functions ap_request_insert_filter
     * and ap_request_remove_filter.
     */
    ap_hook_post_config(form_post_config, NULL, NULL, APR_HOOK_MIDDLE);

    /* Handler to read and parse the POSTed request body. */
    ap_hook_handler(form_data_handler, NULL, aszSucc, APR_HOOK_FIRST);
}


AP_DECLARE_MODULE(form) = {
    STANDARD20_MODULE_STUFF,
    config_dir_create,          /* dir config create   */
    config_dir_merge,           /* dir merger          */
    NULL,                       /* server config       */
    NULL,                       /* merge server config */
    command_table,              /* command table       */
    register_hooks              /* register hooks      */
};
