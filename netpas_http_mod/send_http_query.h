#ifndef NP_HTTP_MOD_NP_SEND_HTTP_QUERY_H
#define NP_HTTP_MOD_NP_SEND_HTTP_QUERY_H

#include "netpas_http_mod/np_common.h"

struct outbound_entry;
struct serviced_query;
struct query_info;
struct module_qstate;

struct np_http_query_st {
    struct query_info *qinfo;               // dns query info
    uint8_t np_http_url[NP_COMMON_HTTP_URL_LEN];    // http query addr
    int np_http_timeout;                    // query timeout
    uint64_t np_http_ttl;                   // Query the survival time of the record
    struct np_mtr_input_st *mtr_input;      // mtr query format
    struct np_outside_http_list_st *np_http_list;   // thread pool info
};

struct outbound_entry*
np_worker_send_query(struct query_info* qinfo, uint16_t flags, int dnssec,
	int want_dnssec, int nocaps, struct sockaddr_storage* addr,
	socklen_t addrlen, uint8_t* zone, size_t zonelen, int ssl_upstream,
	char* tls_auth_name, struct module_qstate* q, 
    struct np_http_query_st *np_http_query);

/** callback for pending udp connections */
int np_outnet_udp_cb(struct comm_point* c, void* arg, int error,
	struct comm_reply *reply_info);

/** callback for udp timeout */
void 
np_pending_udp_timer_cb(void *arg);
int 
np_serviced_udp_callback(struct comm_point* c, void* arg, int error,
        struct comm_reply* rep);

// list

void 
np_outbound_list_insert(struct outbound_list* list, struct outbound_entry* e);
void 
np_outbound_list_remove(struct outbound_list* list, struct outbound_entry* e);
void 
np_outbound_list_clear(struct outbound_list* list);
void 
np_outbound_list_init(struct outbound_list* list);

#endif
