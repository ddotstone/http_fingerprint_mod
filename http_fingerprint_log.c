/*
**  mod_http_fingerprint_log_module_mod.c -- Apache sample http_fingerprint_log_module_mod module
**  [Autogenerated via ``apxs -n http_fingerprint_log_module_mod -g'']
**
**  To play with this sample module first compile it into a
**  DSO file and install it into Apache's modules directory
**  by running:
**
**    $ apxs -c -i mod_http_fingerprint_log_module_mod.c
**
**  Then activate it in Apache's apache2.conf file for instance
**  for the URL /http_fingerprint_log_module_mod in as follows:
**
**    #   apache2.conf
**    LoadModule http_fingerprint_log_module_mod_module modules/mod_http_fingerprint_log_module_mod.so
**    <Location /http_fingerprint_log_module_mod>
**    SetHandler http_fingerprint_log_module_mod
**    </Location>
**
**  Then after restarting Apache via
**
**    $ apachectl restart
**
**  you immediately can request the URL /http_fingerprint_log_module_mod and watch for the
**  output of this module. This can be achieved for instance via:
**
**    $ lynx -mime_header http://localhost/http_fingerprint_log_module_mod
**
**  The output should be similar to the following one:
**
**    HTTP/1.1 200 OK
**    Date: Tue, 31 Mar 1998 14:42:22 GMT
**    Server: Apache/1.3.4 (Unix)
**    Connection: close
**    Content-Type: text/html
**
**    The sample page from mod_http_fingerprint_log_module_mod.c
*/

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "apr_strings.h"
#include "apr_atomic.h"
#include "http_protocol.h"
#include "mod_ssl.h"
#include <json-c/json.h>
#include "test_char.h"
#include <stdbool.h>
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

module AP_MODULE_DECLARE_DATA http_fingerprint_log_module;

typedef struct fcfg
{
    const char *logname;
    apr_file_t *fd;
    bool opened;
} fcfg;

static apr_uint32_t next_id;

static void *make_fingerprint_log_scfg(apr_pool_t *p, server_rec *s)
{
    fcfg *cfg = apr_pcalloc(p, sizeof *cfg);
    cfg->logname = NULL;
    cfg->fd = NULL;
    cfg->opened = false;
    fprintf(stderr, "cfg->fd: %ld\n", (long int)cfg->fd);
    return cfg;
}

static void *merge_fingerprint_log_scfg(apr_pool_t *p, void *parent, void *new)
{
    fcfg *cfg = apr_pcalloc(p, sizeof *cfg);
    fprintf(stderr, "cfg->fd: %ld\n", (long int)cfg->fd);
    fcfg *pc = parent;
    fcfg *nc = new;

    cfg->logname = apr_pstrdup(p, nc->logname ? nc->logname : pc->logname);
    cfg->fd = NULL;
    cfg->opened = false;

    return cfg;
}

static int open_log(server_rec *s, apr_pool_t *p)
{
    fcfg *cfg = ap_get_module_config(s->module_config, &http_fingerprint_log_module);

    ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(00650) "bool %s", cfg->opened ? "true" : "false");
    if (!cfg->logname || cfg->opened)
    {
        return 1;
    }

    if (*cfg->logname == '|')
    {
        piped_log *pl;
        const char *pname = ap_server_root_relative(p, cfg->logname + 1);

        pl = ap_open_piped_log(p, pname);
        if (pl == NULL)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(00650) "couldn't spawn fingerprint log pipe %s", cfg->logname);
            return 0;
        }
        cfg->fd = ap_piped_log_write_fd(pl);
        cfg->opened = false;
    }
    else
    {
        const char *fname = ap_server_root_relative(p, cfg->logname);
        apr_status_t rv;
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, APLOGNO(00651) "file %s.", fname);

        if ((rv = apr_file_open(&cfg->fd, fname,
                                APR_WRITE | APR_APPEND | APR_CREATE,
                                APR_OS_DEFAULT, p)) != APR_SUCCESS)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(00651) "could not open fingerprint log file %s.", fname);
            return 0;
        }
        cfg->opened = false;
    }

    return 1;
}

static int log_init(apr_pool_t *pc, apr_pool_t *p, apr_pool_t *pt,
                    server_rec *s)
{
    for (; s; s = s->next)
    {
        if (!open_log(s, p))
        {

            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return OK;
}

/* e is the first _invalid_ location in q
   N.B. returns the terminating NUL.
 */
static char *log_escape(char *q, const char *e, const char *p)
{
    for (; *p; ++p)
    {
        ap_assert(q < e);
        if (test_char_table[*(unsigned char *)p] & T_ESCAPE_FORENSIC)
        {
            ap_assert(q + 2 < e);
            *q++ = '%';
            sprintf(q, "%02x", *(unsigned char *)p);
            q += 2;
        }
        else
            *q++ = *p;
    }
    ap_assert(q < e);
    *q = '\0';

    return q;
}

typedef struct hlog
{
    char *log;
    char *pos;
    char *end;
    apr_pool_t *p;
    apr_size_t count;
} hlog;

static int count_string(const char *p)
{
    int n;

    for (n = 0; *p; ++p, ++n)
        if (test_char_table[*(unsigned char *)p] & T_ESCAPE_FORENSIC)
            n += 2;
    return n;
}

static int count_headers(void *h_, const char *key, const char *value)
{
    hlog *h = h_;

    h->count += count_string(key) + count_string(value) + 2;

    return 1;
}

static int log_headers(void *h_, const char *key, const char *value)
{
    hlog *h = h_;

    /* note that we don't have to check h->pos here, coz its been done
       for us by log_escape */
    *h->pos++ = '|';
    h->pos = log_escape(h->pos, h->end, key);
    *h->pos++ = ':';
    h->pos = log_escape(h->pos, h->end, value);

    return 1;
}

static int log_before(request_rec *r)
{

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "enter before");
    fcfg *cfg = ap_get_module_config(r->server->module_config,
                                     &http_fingerprint_log_module);
    fprintf(stderr, "cfg->fd: %ld\n", (long int)cfg->fd);
    const char *id;
    hlog h;
    apr_size_t n;
    apr_status_t rv;

    if (!cfg->fd || r->prev)
    {
        return DECLINED;
    }

    if (!(id = apr_table_get(r->subprocess_env, "UNIQUE_ID")))
    {
        /* we make the assumption that we can't go through all the PIDs in
           under 1 second */
        id = apr_psprintf(r->pool, "%" APR_PID_T_FMT ":%lx:%x", getpid(),
                          time(NULL), apr_atomic_inc32(&next_id));
    }
    ap_set_module_config(r->request_config, &http_fingerprint_log_module, (char *)id);

    h.p = r->pool;
    h.count = 0;

    apr_table_do(count_headers, &h, r->headers_in, NULL);

    h.count += 1 + strlen(id) + 1 + count_string(r->the_request) + 1 + 1;
    h.log = apr_palloc(r->pool, h.count);
    h.pos = h.log;
    h.end = h.log + h.count;

    *h.pos++ = '+';
    strcpy(h.pos, id);
    h.pos += strlen(h.pos);
    *h.pos++ = '|';
    h.pos = log_escape(h.pos, h.end, r->the_request);

    apr_table_do(log_headers, &h, r->headers_in, NULL);

    ap_assert(h.pos != NULL && h.end != NULL);
    ap_assert(h.pos < h.end);
    *h.pos++ = '\n';

    n = h.count - 1;
    rv = apr_file_write(cfg->fd, h.log, &n);
    ap_assert(rv == APR_SUCCESS && n == h.count - 1);

    apr_table_setn(r->notes, "fingerprint-id", id);

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "exit before");
    return OK;
}

static int log_after(request_rec *r)
{
    fcfg *cfg = ap_get_module_config(r->server->module_config,
                                     &http_fingerprint_log_module);
    fprintf(stderr, "cfg->fd: %ld\n", (long int)cfg->fd);
    const char *id = ap_get_module_config(r->request_config,
                                          &http_fingerprint_log_module);
    char *s;
    apr_size_t l, n;
    apr_status_t rv;

    if (!cfg->fd || id == NULL)
    {
        return DECLINED;
    }

    s = apr_pstrcat(r->pool, "-", id, "\n", NULL);
    l = n = strlen(s);
    rv = apr_file_write(cfg->fd, s, &n);
    ap_assert(rv == APR_SUCCESS && n == l);

    return OK;
}

static const char *set_fingerprint_log(cmd_parms *cmd, void *dummy, const char *fn)
{

    fcfg *cfg = ap_get_module_config(cmd->server->module_config,
                                     &http_fingerprint_log_module);
    cfg->logname = fn;
    return NULL;
}

static const command_rec fingerprint_log_cmds[] =
    {
        AP_INIT_TAKE1("FingerprintLog", set_fingerprint_log, NULL, RSRC_CONF,
                      "the filename of the fingerprint log"),
        {NULL}};

static void register_hooks_fingerprint(apr_pool_t *p)
{

    static const char *const pre[] = {"mod_unique_id.c", NULL};

    ap_hook_open_logs(log_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(log_before, pre, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_log_transaction(log_after, NULL, NULL, APR_HOOK_REALLY_LAST);
    return;
}

AP_DECLARE_MODULE(http_fingerprint_log_module) =
    {
        STANDARD20_MODULE_STUFF,
        NULL,                      /* create per-dir config */
        NULL,                      /* merge per-dir config */
        make_fingerprint_log_scfg, /* server config */
        NULL,                      /* merge server config */
        fingerprint_log_cmds,      /* command apr_table_t */
        register_hooks_fingerprint /* register hooks */
};
