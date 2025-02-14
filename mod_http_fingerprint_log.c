/*
**  mod_http_fingerprint_log.c -- Fingerprinting for http requests
*/

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "apr_strings.h"
#include "apr_atomic.h"
#include "http_protocol.h"
#include "mod_ssl.h"
#include "http_ssl.h"
#include "apr_time.h"
#include "test_char.h"
#include <stdbool.h>
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#define META_DATA_SPACE 2048
#define TIMEZONE_OFFSET (-7 * 3600) // UTC-7 (Eastern Standard Time)

module AP_MODULE_DECLARE_DATA http_fingerprint_log_module;

typedef struct fingerprint_cfg
{
    const char *logname;
    apr_file_t *fd;
} fingerprint_cfg;

static apr_uint32_t next_id;

static void *make_fingerprint_log_scfg(apr_pool_t *p, server_rec *s)
{
    fingerprint_cfg *cfg = (fingerprint_cfg *)apr_pcalloc(p, sizeof(fingerprint_cfg));
    if (cfg)
    {
        cfg->logname = NULL;
        cfg->fd = NULL;
    }
    return cfg;
}

static void *merge_fingerprint_log_scfg(apr_pool_t *p, void *parent, void *new)
{
    fingerprint_cfg *cfg = (fingerprint_cfg *)apr_pcalloc(p, sizeof(fingerprint_cfg));
    if (cfg)
    {
        fingerprint_cfg *pc = parent;
        fingerprint_cfg *nc = new;

        cfg->logname = apr_pstrdup(p, nc->logname ? nc->logname : pc->logname);
        cfg->fd = NULL;
    }
    return cfg;
}

static int open_log(server_rec *s, apr_pool_t *p)
{
    fingerprint_cfg *cfg = ap_get_module_config(s->module_config, &http_fingerprint_log_module);

    if (!cfg->logname || cfg->fd)
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
    }
    else
    {
        const char *fname = ap_server_root_relative(p, cfg->logname);
        apr_status_t rv;

        if ((rv = apr_file_open(&cfg->fd, fname,
                                APR_WRITE | APR_APPEND | APR_CREATE,
                                APR_OS_DEFAULT, p)) != APR_SUCCESS)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(00651) "could not open fingerprint log file %s.", fname);
            return 0;
        }
        else
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(00650) "opened fd: %ld", (long int)cfg->fd);
            ap_log_error(APLOG_MARK, APLOG_ERR, rv, s, APLOGNO(00651) "openened fingerprint log file %s.", fname);
        }
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
        else if (*p == '"')
        {
            *q++ = '\\';
        }
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

static apr_size_t count_string(const char *p)
{
    apr_size_t n;

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
    *h->pos++ = '\\';
    *h->pos++ = 'n';
    *h->pos++ = '\\';
    *h->pos++ = 'r';
    h->pos = log_escape(h->pos, h->end, key);
    *h->pos++ = ':';
    h->pos = log_escape(h->pos, h->end, value);

    return 1;
}

static int log_before(request_rec *r)
{
    fingerprint_cfg *cfg = ap_get_module_config(r->server->module_config,
                                                &http_fingerprint_log_module);
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
    h.count += META_DATA_SPACE;
    h.log = apr_palloc(r->pool, h.count);
    h.pos = h.log;
    h.end = h.log + h.count;

    *h.pos++ = '+';
    *h.pos++ = '\n';

    strcpy(h.pos, "{\"id\":\"");
    h.pos += strlen(h.pos);

    strcpy(h.pos, id);
    h.pos += strlen(h.pos);

    strcpy(h.pos, "\",\n\"time\":\"");
    h.pos += strlen(h.pos);

    // Get request timestamp
    apr_time_t request_time = r->request_time;

    // Get time
    apr_time_exp_t time_exp;
    apr_time_exp_gmt(&time_exp, request_time);

    // Apply the timezone offset (handling overflow cases)
    int total_seconds = time_exp.tm_hour * 3600 + time_exp.tm_min * 60 + time_exp.tm_sec;

    // Adjust hours, minutes, and seconds properly
    time_exp.tm_hour = (total_seconds / 3600) % 24;
    time_exp.tm_min = (total_seconds / 60) % 60;
    time_exp.tm_sec = total_seconds % 60;

    // Adjust for mst
    time_exp.tm_hour -= 7;

    // Handle negative hour wrap-around (previous day)
    if (time_exp.tm_hour < 0)
    {
        time_exp.tm_hour += 24;
        time_exp.tm_mday -= 1;
    }

    // Handle positive overflow (next day)
    if (time_exp.tm_hour >= 24)
    {
        time_exp.tm_hour -= 24;
        time_exp.tm_mday += 1;
    }

    // Format the final timestamp string
    char timestr[128];
    snprintf(timestr, sizeof(timestr), "%04d-%02d-%02d %02d:%02d:%02d:%06d",
             time_exp.tm_year + 1900, time_exp.tm_mon + 1, time_exp.tm_mday,
             time_exp.tm_hour, time_exp.tm_min, time_exp.tm_sec, time_exp.tm_usec);
    // YYYY-MM-DD HH:MI:SS

    strcpy(h.pos, timestr);
    h.pos += strlen(h.pos);

    strcpy(h.pos, "\",\n\"ip\":\"");
    h.pos += strlen(h.pos);

    strcpy(h.pos, r->connection->client_ip);
    h.pos += strlen(h.pos);

    strcpy(h.pos, "\",\n\"ssl_clienthello_version\":\"");
    h.pos += strlen(h.pos);

    strcpy(h.pos, ap_ssl_var_lookup(r->pool, r->server, r->connection, r, "SSL_CLIENTHELLO_VERSION"));
    h.pos += strlen(h.pos);

    strcpy(h.pos, "\",\n\"ssl_clienthello_ciphers\":\"");
    h.pos += strlen(h.pos);

    strcpy(h.pos, ap_ssl_var_lookup(r->pool, r->server, r->connection, r, "SSL_CLIENTHELLO_CIPHERS"));
    h.pos += strlen(h.pos);

    strcpy(h.pos, "\",\n\"ssl_clienthello_sig_algos\":\"");
    h.pos += strlen(h.pos);

    strcpy(h.pos, ap_ssl_var_lookup(r->pool, r->server, r->connection, r, "SSL_CLIENTHELLO_SIG_ALGOS"));
    h.pos += strlen(h.pos);

    strcpy(h.pos, "\",\n\"ssl_clienthello_groups\":\"");
    h.pos += strlen(h.pos);

    strcpy(h.pos, ap_ssl_var_lookup(r->pool, r->server, r->connection, r, "SSL_CLIENTHELLO_GROUPS"));
    h.pos += strlen(h.pos);

    strcpy(h.pos, "\",\n\"ssl_clienthello_ec_formats\":\"");
    h.pos += strlen(h.pos);

    strcpy(h.pos, ap_ssl_var_lookup(r->pool, r->server, r->connection, r, "SSL_CLIENTHELLO_EC_FORMATS"));
    h.pos += strlen(h.pos);

    strcpy(h.pos, "\",\n\"ssl_clienthello_alpn\":\"");
    h.pos += strlen(h.pos);

    strcpy(h.pos, ap_ssl_var_lookup(r->pool, r->server, r->connection, r, "SSL_CLIENTHELLO_ALPN"));
    h.pos += strlen(h.pos);

    strcpy(h.pos, "\",\n\"ssl_clienthello_versions\":\"");
    h.pos += strlen(h.pos);

    strcpy(h.pos, ap_ssl_var_lookup(r->pool, r->server, r->connection, r, "SSL_CLIENTHELLO_VERSIONS"));
    h.pos += strlen(h.pos);

    strcpy(h.pos, "\",\n\"ssl_clienthello_extensions\":\"");
    h.pos += strlen(h.pos);

    strcpy(h.pos, ap_ssl_var_lookup(r->pool, r->server, r->connection, r, "SSL_CLIENTHELLO_EXTENSIONS"));
    h.pos += strlen(h.pos);

    strcpy(h.pos, "\",\n\"ssl_handshake_rtt\":\"");
    h.pos += strlen(h.pos);

    strcpy(h.pos, ap_ssl_var_lookup(r->pool, r->server, r->connection, r, "SSL_HANDSHAKE_RTT"));
    h.pos += strlen(h.pos);

    strcpy(h.pos, "\",\n\"headers\":\"");
    h.pos += strlen(h.pos);

    h.pos = log_escape(h.pos, h.end, r->the_request);

    apr_table_do(log_headers, &h, r->headers_in, NULL);
    strcpy(h.pos, "\"\n}\n");
    h.pos += strlen(h.pos);

    strcpy(h.pos, "-");
    h.pos += strlen(h.pos);

    ap_assert(h.pos != NULL && h.end != NULL);
    ap_assert(h.pos < h.end);

    *h.pos++ = '\n';
    n = h.pos - h.log;

    rv = apr_file_write_full(cfg->fd, h.log, n, NULL);
    ap_assert(rv == APR_SUCCESS);

    apr_table_setn(r->notes, "fingerprint-id", id);
    return OK;
}

static const char *set_fingerprint_log(cmd_parms *cmd, void *dummy, const char *fn)
{
    fingerprint_cfg *cfg = ap_get_module_config(cmd->server->module_config,
                                                &http_fingerprint_log_module);
    cfg->logname = fn;
    cfg->fd = 0;
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
    return;
}

AP_DECLARE_MODULE(http_fingerprint_log) =
    {
        STANDARD20_MODULE_STUFF,
        NULL,                       /* create per-dir config */
        NULL,                       /* merge per-dir config */
        make_fingerprint_log_scfg,  /* server config */
        merge_fingerprint_log_scfg, /* merge server config */
        fingerprint_log_cmds,       /* command apr_table_t */
        register_hooks_fingerprint  /* register hooks */
};