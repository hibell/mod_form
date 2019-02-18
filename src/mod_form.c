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

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "apr_strings.h"
#include "apr_general.h"
#include "util_filter.h"
#include "apr_buckets.h"
#include "http_request.h"
#include "http_protocol.h"

#include "mod_request.h"


/******************************************************************************
 * DATA TYPES & VARIABLES                                                     *
 *****************************************************************************/
module AP_MODULE_DECLARE_DATA form_module;

static const char *form_filter_name = "form_body";
static ap_filter_rec_t *form_filter_handle;

static void (*ap_request_insert_filter_fn) (request_rec * r) = NULL;
static void (*ap_request_remove_filter_fn) (request_rec * r) = NULL;

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

/******************************************************************************
 * PROTOTYPES                                                                 *
 *****************************************************************************/
static apr_bucket *process_regexp_pair(request_rec *r, form_entry *entry,
                                       ap_form_pair_t *pair);
static char *get_post_form_value(apr_pool_t *pool, ap_form_pair_t *pair);
static int filter_present(request_rec *r, ap_filter_rec_t *fn);
static apr_status_t write_form_pair(apr_bucket_brigade *out,
                                    request_rec *r,
                                    ap_form_pair_t *pair,
                                    int last);


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
 * Example input filter that rejects users trying to authenticate using admin.
 * @param f
 * @param bb
 * @param mode
 * @param block
 * @param readbytes
 * @return
 */
static apr_status_t form_filter(ap_filter_t *f,
                                apr_bucket_brigade *bb,
                                ap_input_mode_t mode,
                                apr_read_type_e block,
                                apr_off_t readbytes)
{
    const char *user = f->r->user;

    ap_remove_input_filter(f);

    if (user && strncmp(user, "blocked_user", 12) == 0) {
        apr_bucket *e;
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, f->r, APLOGNO(03491)
                      "Someone tried to login as a blocked user '%s'."
                      "Forbidding.", user);
        e = ap_bucket_error_create(HTTP_FORBIDDEN, NULL, f->r->pool,
                                   f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, e);
        e = apr_bucket_eos_create(f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, e);
        return ap_pass_brigade(f->r->output_filters, bb);
    }

    return ap_get_brigade(f->next, bb, mode, block, readbytes);
}


/**
 * Unset a form pair if it is matches the unset rule. Regex is allowed and can
 * be used to unset all form pairs whose name matches the regex.
 * @param r request record
 * @param entry the unset rule to apply
 * @param pair the pair to check
 * @return NULL if pair matched; otherwise the pair is returned.
 */
static ap_form_pair_t *do_unset(request_rec *r, form_entry *entry,
                                ap_form_pair_t *pair)
{
    if (!ap_regexec(entry->regex, pair->name, 0, NULL, 0)) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, APLOGNO(03492)
                      "Unset rule '%s' matched for form pair '%s'. "
                      "Form pair was unset.",
                      entry->name, pair->name);
        return NULL;
    }

    return pair;
}


/**
 * Edit the value of a form pair if it matches the edit rule. Regex is allowed
 * and can be used to
 * @param r
 * @param entry the edit rule to apply
 * @param pair the pair to check
 * @return the edited pair
 */
static ap_form_pair_t *do_edit(request_rec *r, form_entry *entry,
                               ap_form_pair_t *pair)
{
    if (strcmp(entry->name, pair->name) == 0) {
        apr_bucket *b = process_regexp_pair(r, entry, pair);

        pair->value = apr_brigade_create(r->pool, r->connection->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(pair->value, b);
        ap_log_rerror(APLOG_MARK, APLOG_TRACE8, 0, r, APLOGNO(03493)
                      "Edit rule '%s' matched for form pair '%s'. "
                      "Form pair was edited.",
                      entry->value, pair->name);
    }

    return pair;
}

/**
 * Iterate through each rule and apply it.
 * @param r the request record
 * @param pair the form pair to process
 * @param conf the form conf
 * @return the new pair
 */
static ap_form_pair_t *do_form_body_fixup(request_rec *r, ap_form_pair_t *pair,
                                          form_conf *conf)
{
    int i;

    for (i = 0; i < conf->fixup_data->nelts; ++i) {
        form_entry *entry = &((form_entry *) (conf->fixup_data->elts))[i];

        switch(entry->action) {
            case form_unset:
                return do_unset(r, entry, pair);
            case form_edit:
                pair = do_edit(r, entry, pair);
                break;
            default:
                break;
        }
    }

    return pair;
}


/**
 * Fixup hook that reads and parses the POSTed form data. This depends on the
 * request module so that the body can be read multiple times.
 * @param r the request record
 * @return fixup return code
 */
static int parse_form_data_fixup(request_rec *r)
{
    apr_array_header_t *pairs = NULL;
    apr_off_t len;
    apr_size_t size;
    int res = OK;
    char *buffer;
    apr_status_t rv;
    form_conf *conf = (form_conf *) ap_get_module_config(r->per_dir_config,
                                                         &form_module);
    apr_bucket_brigade *out;
    int i = 0;

    /* Insert request filter to read the request body */
    ap_request_insert_filter_fn(r);

    if (r->method_number == M_POST && ap_is_initial_req(r)) {
        res = ap_parse_form_data(r, NULL, &pairs, -1, HUGE_STRING_LEN);
        out = apr_brigade_create(r->pool, r->connection->bucket_alloc);

        if (pairs == NULL)
            return OK;

        for (i = 0; i < pairs->nelts; ++i) {
            apr_bucket *b;
            ap_form_pair_t *pair =
                    (ap_form_pair_t *) &((ap_form_pair_t *) (pairs->elts))[i];
            ap_log_rerror(APLOG_MARK, APLOG_TRACE8, res, r, APLOGNO(03494)
                          "found form data pair -> %s", pair->name);

            pair = do_form_body_fixup(r, pair, conf);

            if (pair == NULL)
                continue;

            if (strncmp(pair->name, "username", 8) == 0) {
                r->user = get_post_form_value(r->pool, pair);
            }


            rv = write_form_pair(out, r, pair, i >= pairs->nelts - 1);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE8, rv, r, APLOGNO(03495)
                              "Unable to write pair. No longer parsing request "
                              "data.");
                return OK;
            }
        }

        APR_BRIGADE_INSERT_TAIL(out,
                apr_bucket_eos_create(r->connection->bucket_alloc));
        r->kept_body = out;
    }

    return OK;
}


static apr_status_t write_form_pair(apr_bucket_brigade *out,
                                    request_rec *r,
                                    ap_form_pair_t *pair,
                                    int last)
{
    static const char *eq = "=";
    static const char *amp = "&";

    apr_bucket_alloc_t *alloc = r->connection->bucket_alloc;

    APR_BRIGADE_INSERT_TAIL(out,
            apr_bucket_pool_create(pair->name, strlen(pair->name),
            r->pool, alloc));
    APR_BRIGADE_INSERT_TAIL(out,
            apr_bucket_immortal_create(eq, 1, alloc));
    APR_BRIGADE_CONCAT(out, pair->value);

    if (!last)
        APR_BRIGADE_INSERT_TAIL(out,
                apr_bucket_immortal_create(amp, 1, alloc));

    return APR_SUCCESS;
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
    if (!ap_request_insert_filter_fn || !ap_request_remove_filter_fn) {
        ap_request_insert_filter_fn =
                APR_RETRIEVE_OPTIONAL_FN(ap_request_insert_filter);
        ap_request_remove_filter_fn =
                APR_RETRIEVE_OPTIONAL_FN(ap_request_remove_filter);

        if (!ap_request_insert_filter_fn || !ap_request_remove_filter_fn) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, 0, NULL, APLOGNO(03496)
                    "You must load mod_request to enable the mod_auth_form "
                    "functions");
            return !OK;
        }
    }

    return OK;
}




static void *config_dir_create(apr_pool_t *p, char *d)
{
    form_conf *conf = (form_conf *) apr_pcalloc(p, sizeof(*conf));
    conf->fixup_data = apr_array_make(p, 2, sizeof(form_entry));
    return (void *) conf;
}


static void *config_dir_merge(apr_pool_t *p, void *basev, void *overridesv)
{
    form_conf *newconf = apr_pcalloc(p, sizeof(*newconf));
    form_conf *base = basev;
    form_conf *overrides = overridesv;

    newconf->fixup_data = apr_array_append(p, base->fixup_data,
                                           overrides->fixup_data);

    return (void *) newconf;
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


/**
 * Insert filter hook. Add the form_filter if it is not already added.
 * @param r The request
 */
static void insert_filter(request_rec * r)
{
    if (!filter_present(r, form_filter_handle)) {
        ap_add_input_filter_handle(form_filter_handle, NULL, r,
                                   r->connection);
    }
}

static void register_hooks(apr_pool_t *p)
{
    /*
     * Retrieve the mod_request functions ap_request_insert_filter
     * and ap_request_remove_filter.
     */
    ap_hook_post_config(form_post_config, NULL, NULL, APR_HOOK_MIDDLE);

    /* Register the input filter to deny admin users. */
    form_filter_handle = ap_register_input_filter(form_filter_name,
                                                  form_filter,
                                                  NULL,
                                                  AP_FTYPE_RESOURCE);

    /* Insert our form_filter if it is not already set. */
    ap_hook_insert_filter(insert_filter, NULL, NULL, APR_HOOK_MIDDLE);

    /* Fixup to read and parse the POSTed request body. */
    ap_hook_fixups(parse_form_data_fixup, NULL, NULL, APR_HOOK_LAST);
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


/******************************************************************************
 * HELPER FUNCTIONS                                                           *
 *****************************************************************************/

/**
 * Get the value from a pair.
 * @param pool the pool to allocate the return value from
 * @param pair form pair
 * @return value as a string
 */
static char *get_post_form_value(apr_pool_t *pool, ap_form_pair_t *pair)
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
    int diffsz;

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
 * Process a regex and perform substitution as needed.
 * @param r request record
 * @param entry form_entry to process
 * @param pair form pair to process
 * @return a bucket containing the substituted value
 */
static apr_bucket *process_regexp_pair(request_rec *r, form_entry *entry,
                                       ap_form_pair_t *pair)
{
    const char *value = get_post_form_value(r->pool, pair);
    value = process_regexp(r, entry, value);
    return apr_bucket_pool_create(value, strlen(value), r->pool,
                                  r->connection->bucket_alloc);
}

/**
 * Check whether an input filter is present in the input filter chain already or
 * not.
 * @param r request record
 * @param fn filter record
 * @return TRUE or FALSE depending on if filter is present or not
 */
static int filter_present(request_rec * r, ap_filter_rec_t *fn)
{
    ap_filter_t * f = r->input_filters;
    while (f) {
        if (f->frec == fn) {
            return TRUE;
        }
        f = f->next;
    }
    return FALSE;
}
