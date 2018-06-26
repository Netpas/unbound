
#include "config.h"
#include <ctype.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <sys/time.h>
#include "services/outside_network.h"
#include "services/listen_dnsport.h"
#include "services/cache/infra.h"
#include "util/data/msgparse.h"
#include "util/data/msgreply.h"
#include "util/data/msgencode.h"
#include "util/data/dname.h"
#include "util/netevent.h"
#include "util/log.h"
#include "util/net_help.h"
#include "util/random.h"
#include "util/fptr_wlist.h"
#include "sldns/sbuffer.h"
#include "dnstap/dnstap.h"
#ifdef HAVE_OPENSSL_SSL_H
#include <openssl/ssl.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#include <fcntl.h>
// 
#include "services/outbound_list.h"

#include "daemon/worker.h"
#include "util/config_file.h"
#include "util/regional.h"
// socketpair handle
#include <sys/types.h>
#include <sys/socket.h>
// netpas mod
#include "netpas_http_mod/outside_http.h"
#include "netpas_http_mod/send_http_query.h"
#include "netpas_http_mod/C-Thread-Pool/thpool.h"

/** number of times to retry making a random ID that is unique. */
#define MAX_ID_RETRY 1000
/** number of times to retry finding interface, port that can be opened. */
#define MAX_PORT_RETRY 10000
/** number of retries on outgoing UDP queries */
#define OUTBOUND_UDP_RETRY 1

static void
np_serviced_perturb_qname(struct ub_randstate* rnd, uint8_t* qbuf, size_t len);

static void
portcomm_loweruse(struct outside_network* outnet, struct port_comm* pc);
static void
np_outnet_send_wait_udp(struct outside_network* outnet);
static int
randomize_and_send_udp(struct pending* pend, sldns_buffer* packet, int timeout, void *http_data);
static int8_t np_get_free_outside_http_list(void *data, struct outside_network* outnet);

static struct serviced_query* 
np_outnet_serviced_query(struct outside_network* outnet,
	struct query_info* qinfo, uint16_t flags, int dnssec, int want_dnssec,
	int nocaps, int tcp_upstream, int ssl_upstream, char* tls_auth_name,
	struct sockaddr_storage* addr, socklen_t addrlen, uint8_t* zone,
	size_t zonelen, struct module_qstate* qstate,
	comm_point_callback_type* callback, void* callback_arg, sldns_buffer* buff,
	struct module_env* env, void *http_data);

static struct serviced_query*
np_serviced_create(struct outside_network* outnet, sldns_buffer* buff, int dnssec,
	int want_dnssec, int nocaps, int tcp_upstream, int ssl_upstream,
	char* tls_auth_name, struct sockaddr_storage* addr, socklen_t addrlen,
	uint8_t* zone, size_t zonelen, int qtype, struct edns_option* opt_list);

static struct serviced_query*
np_lookup_serviced(struct outside_network* outnet, sldns_buffer* buff, int dnssec,
	struct sockaddr_storage* addr, socklen_t addrlen,
	struct edns_option* opt_list);

static void
np_serviced_gen_query(sldns_buffer* buff, uint8_t* qname, size_t qnamelen, 
	uint16_t qtype, uint16_t qclass, uint16_t flags);

struct outbound_entry*
np_worker_send_query(struct query_info* qinfo, uint16_t flags, int dnssec,
	int want_dnssec, int nocaps, struct sockaddr_storage* addr,
	socklen_t addrlen, uint8_t* zone, size_t zonelen, int ssl_upstream,
	char* tls_auth_name, struct module_qstate* q,
    struct np_http_query_st *np_http_query)
{
	struct worker* worker = q->env->worker;
	struct outbound_entry* e = (struct outbound_entry*)regional_alloc(
		q->region, sizeof(*e));
	if(!e) 
		return NULL;
	e->qstate = q;

	e->qsent = np_outnet_serviced_query(worker->back, qinfo, flags, dnssec,
		want_dnssec, nocaps, q->env->cfg->tcp_upstream,
		ssl_upstream, tls_auth_name, addr, addrlen, zone, zonelen, q,
		worker_handle_service_reply, e, worker->back->udp_buff,
        q->env, np_http_query);

	if(!e->qsent) {
		return NULL;
	}
	return e;
}

/** put serviced query into a buffer */
static void
serviced_encode(struct serviced_query* sq, sldns_buffer* buff, int with_edns)
{
	/* if we are using 0x20 bits for ID randomness, perturb them */
	if(sq->outnet->use_caps_for_id && !sq->nocaps) {
		np_serviced_perturb_qname(sq->outnet->rnd, sq->qbuf, sq->qbuflen);
	}
	/* generate query */
	sldns_buffer_clear(buff);
	sldns_buffer_write_u16(buff, 0); /* id placeholder */
	sldns_buffer_write(buff, sq->qbuf, sq->qbuflen);
	sldns_buffer_flip(buff);
	if(with_edns) {
		/* add edns section */
		struct edns_data edns;
		edns.edns_present = 1;
		edns.ext_rcode = 0;
		edns.edns_version = EDNS_ADVERTISED_VERSION;
		edns.opt_list = sq->opt_list;
		if(sq->status == serviced_query_UDP_EDNS_FRAG) {
			if(addr_is_ip6(&sq->addr, sq->addrlen)) {
				if(EDNS_FRAG_SIZE_IP6 < EDNS_ADVERTISED_SIZE)
					edns.udp_size = EDNS_FRAG_SIZE_IP6;
				else	edns.udp_size = EDNS_ADVERTISED_SIZE;
			} else {
				if(EDNS_FRAG_SIZE_IP4 < EDNS_ADVERTISED_SIZE)
					edns.udp_size = EDNS_FRAG_SIZE_IP4;
				else	edns.udp_size = EDNS_ADVERTISED_SIZE;
			}
		} else {
			edns.udp_size = EDNS_ADVERTISED_SIZE;
		}
		edns.bits = 0;
		if(sq->dnssec & EDNS_DO)
			edns.bits = EDNS_DO;
		if(sq->dnssec & BIT_CD)
			LDNS_CD_SET(sldns_buffer_begin(buff));
		attach_edns_record(buff, &edns);
	}
}

static struct pending* 
np_pending_udp_query(struct serviced_query* sq, struct sldns_buffer* packet,
	int timeout, comm_point_callback_type* cb, void* cb_arg, void *http_data)
{
	struct pending* pend = (struct pending*)calloc(1, sizeof(*pend));
	if(!pend) return NULL;
	pend->outnet = sq->outnet;
	pend->sq = sq;

	pend->addrlen = sq->addrlen;
	memmove(&pend->addr, &sq->addr, sq->addrlen);
	pend->cb = cb;
	pend->cb_arg = cb_arg;
	pend->node.key = pend;
	pend->timer = comm_timer_create(sq->outnet->base, np_pending_udp_timer_cb,
		pend);
	if(!pend->timer) {
		free(pend);
		return NULL;
	}

	if(sq->outnet->unused_fds == NULL || 
            ((sq->outnet->unused_fds != NULL) && np_get_free_outside_http_list(http_data, sq->outnet) < 0)) {
		/* no unused fd, cannot create a new port (randomly) */
        // log_err("no fds avilable, udp query waiting, timeout: %d", timeout);
		verbose(VERB_ALGO, "no fds available, udp query waiting");
		pend->timeout = timeout;
		pend->pkt_len = sldns_buffer_limit(packet);
	    pend->pkt = (uint8_t *)malloc(pend->pkt_len + 
                sizeof(struct np_http_query_st));
		memmove(pend->pkt, sldns_buffer_begin(packet), pend->pkt_len);
		//pend->pkt = (uint8_t*)memdup(sldns_buffer_begin(packet),
		//	pend->pkt_len);
        // save http info
        memcpy(pend->pkt+pend->pkt_len, http_data, 
                sizeof(struct np_http_query_st));
		if(!pend->pkt) {
			comm_timer_delete(pend->timer);
			free(pend);
			return NULL;
		}
		/* put at end of waiting list */
		if(sq->outnet->udp_wait_last)
			sq->outnet->udp_wait_last->next_waiting = pend;
		else 
			sq->outnet->udp_wait_first = pend;
		sq->outnet->udp_wait_last = pend;
		return pend;
	}

	if(!randomize_and_send_udp(pend, packet, timeout, http_data)) {
		pending_delete(sq->outnet, pend);
		return NULL;
	}
	return pend;
}


/**
 * Perform serviced query UDP sending operation.
 * Sends UDP with EDNS, unless infra host marked non EDNS.
 * @param sq: query to send.
 * @param buff: buffer scratch space.
 * @return 0 on error.
 */
static int
serviced_udp_send(struct serviced_query* sq, sldns_buffer* buff, void *http_data)
{
	int rtt, vs;
	uint8_t edns_lame_known;
	time_t now = *sq->outnet->now_secs;

    if(http_data == NULL) {
        return 0;
    }

	if(!infra_host(sq->outnet->infra, &sq->addr, sq->addrlen, sq->zone,
		sq->zonelen, now, &vs, &edns_lame_known, &rtt))
		return 0;
	sq->last_rtt = rtt;
	verbose(VERB_ALGO, "EDNS lookup known=%d vs=%d", edns_lame_known, vs);
	if(sq->status == serviced_initial) {
		if(edns_lame_known == 0 && rtt > 5000 && rtt < 10001) {
			/* perform EDNS lame probe - check if server is
			 * EDNS lame (EDNS queries to it are dropped) */
			verbose(VERB_ALGO, "serviced query: send probe to see "
				" if use of EDNS causes timeouts");
			/* even 700 msec may be too small */
			rtt = 1000;
			sq->status = serviced_query_PROBE_EDNS;
		} else if(vs != -1) {
			sq->status = serviced_query_UDP_EDNS;
		} else { 	
			sq->status = serviced_query_UDP; 
		}
	}
	serviced_encode(sq, buff, (sq->status == serviced_query_UDP_EDNS) ||
		(sq->status == serviced_query_UDP_EDNS_FRAG));
	sq->last_sent_time = *sq->outnet->now_tv;
	sq->edns_lame_known = (int)edns_lame_known;
	verbose(VERB_ALGO, "serviced query UDP timeout=%d msec", 
            rtt+TCP_AUTH_QUERY_TIMEOUT*1000);
	sq->pending = np_pending_udp_query(sq, buff,
            rtt + TCP_AUTH_QUERY_TIMEOUT*1000,
		np_serviced_udp_callback, sq, http_data);
	if(!sq->pending)
		return 0;
	return 1;
}

static struct serviced_query* 
np_outnet_serviced_query(struct outside_network* outnet,
	struct query_info* qinfo, uint16_t flags, int dnssec, int want_dnssec,
	int nocaps, int tcp_upstream, int ssl_upstream, char* tls_auth_name,
	struct sockaddr_storage* addr, socklen_t addrlen, uint8_t* zone,
	size_t zonelen, struct module_qstate* qstate,
	comm_point_callback_type* callback, void* callback_arg, sldns_buffer* buff,
	struct module_env* env, void *http_data)
{
	struct serviced_query* sq;
	struct service_callback* cb;

	if(!inplace_cb_query_call(env, qinfo, flags, addr, addrlen, zone, zonelen,
		qstate, qstate->region))
			return NULL;
	np_serviced_gen_query(buff, qinfo->qname, qinfo->qname_len, qinfo->qtype,
		qinfo->qclass, flags);
	sq = np_lookup_serviced(outnet, buff, dnssec, addr, addrlen,
		qstate->edns_opts_back_out);
	/* duplicate entries are included in the callback list, because
	 * there is a counterpart registration by our caller that needs to
	 * be doubly-removed (with callbacks perhaps). */
	if(!(cb = (struct service_callback*)malloc(sizeof(*cb))))
		return NULL;
	if(!sq) {
		/* make new serviced query entry */
		sq = np_serviced_create(outnet, buff, dnssec, want_dnssec, nocaps,
			tcp_upstream, ssl_upstream, tls_auth_name, addr,
			addrlen, zone, zonelen, (int)qinfo->qtype,
			qstate->edns_opts_back_out);
		if(!sq) {
			free(cb);
			return NULL;
        }
        /* perform first network action */
        if(outnet->do_udp && !(tcp_upstream || ssl_upstream)) {
            if(!serviced_udp_send(sq, buff, http_data)) {
                (void)rbtree_delete(outnet->serviced, sq);
                free(sq->qbuf);
                free(sq->zone);
                free(sq);
                free(cb);
                return NULL;
            }
        } else 
        {
           // if(!np_serviced_tcp_send(sq, buff, http_data)) {
           if(1) {
                (void)rbtree_delete(outnet->serviced, sq);
                free(sq->qbuf);
                free(sq->zone);
                free(sq);
                free(cb);
                return NULL;
            }
        }
    }
	/* add callback to list of callbacks */
	cb->cb = callback;
	cb->cb_arg = callback_arg;
	cb->next = sq->cblist;
	sq->cblist = cb;
	return sq;
}
/** Create new serviced entry */
static struct serviced_query*
np_serviced_create(struct outside_network* outnet, sldns_buffer* buff, int dnssec,
	int want_dnssec, int nocaps, int tcp_upstream, int ssl_upstream,
	char* tls_auth_name, struct sockaddr_storage* addr, socklen_t addrlen,
	uint8_t* zone, size_t zonelen, int qtype, struct edns_option* opt_list)
{
	struct serviced_query* sq = (struct serviced_query*)malloc(sizeof(*sq));
#ifdef UNBOUND_DEBUG
	rbnode_type* ins;
#endif
	if(!sq) 
		return NULL;
	sq->node.key = sq;
	sq->qbuf = memdup(sldns_buffer_begin(buff), sldns_buffer_limit(buff));
	if(!sq->qbuf) {
		free(sq);
		return NULL;
	}
	sq->qbuflen = sldns_buffer_limit(buff);
	sq->zone = memdup(zone, zonelen);
	if(!sq->zone) {
		free(sq->qbuf);
		free(sq);
		return NULL;
	}
	sq->zonelen = zonelen;
	sq->qtype = qtype;
	sq->dnssec = dnssec;
	sq->want_dnssec = want_dnssec;
	sq->nocaps = nocaps;
	sq->tcp_upstream = tcp_upstream;
	sq->ssl_upstream = ssl_upstream;
	if(tls_auth_name) {
		sq->tls_auth_name = strdup(tls_auth_name);
		if(!sq->tls_auth_name) {
			free(sq->zone);
			free(sq->qbuf);
			free(sq);
			return NULL;
		}
	} else {
		sq->tls_auth_name = NULL;
	}
	memcpy(&sq->addr, addr, addrlen);
	sq->addrlen = addrlen;
	sq->opt_list = NULL;
	if(opt_list) {
		sq->opt_list = edns_opt_copy_alloc(opt_list);
		if(!sq->opt_list) {
			free(sq->tls_auth_name);
			free(sq->zone);
			free(sq->qbuf);
			free(sq);
			return NULL;
		}
	}
	sq->outnet = outnet;
	sq->cblist = NULL;
	sq->pending = NULL;
	sq->status = serviced_initial;
	sq->retry = 0;
	sq->to_be_deleted = 0;
#ifdef UNBOUND_DEBUG
	ins = 
#else
	(void)
#endif
	rbtree_insert(outnet->serviced, &sq->node);
	log_assert(ins != NULL); /* must not be already present */
	return sq;
}

static struct serviced_query*
np_lookup_serviced(struct outside_network* outnet, sldns_buffer* buff, int dnssec,
	struct sockaddr_storage* addr, socklen_t addrlen,
	struct edns_option* opt_list)
{
	struct serviced_query key;
	key.node.key = &key;
	key.qbuf = sldns_buffer_begin(buff);
	key.qbuflen = sldns_buffer_limit(buff);
	key.dnssec = dnssec;
	memcpy(&key.addr, addr, addrlen);
	key.addrlen = addrlen;
	key.outnet = outnet;
	key.opt_list = opt_list;
	return (struct serviced_query*)rbtree_search(outnet->serviced, &key);
}

/** create query for serviced queries */
static void
np_serviced_gen_query(sldns_buffer* buff, uint8_t* qname, size_t qnamelen, 
	uint16_t qtype, uint16_t qclass, uint16_t flags)
{
	sldns_buffer_clear(buff);
	/* skip id */
	sldns_buffer_write_u16(buff, flags);
	sldns_buffer_write_u16(buff, 1); /* qdcount */
	sldns_buffer_write_u16(buff, 0); /* ancount */
	sldns_buffer_write_u16(buff, 0); /* nscount */
	sldns_buffer_write_u16(buff, 0); /* arcount */
	sldns_buffer_write(buff, qname, qnamelen);
	sldns_buffer_write_u16(buff, qtype);
	sldns_buffer_write_u16(buff, qclass);
	sldns_buffer_flip(buff);
}
#if 0
/** Send serviced query over TCP return false on initial failure */
static int
np_serviced_tcp_send(struct serviced_query* sq, sldns_buffer* buff, void *http_data)
{
	int vs, rtt;
	uint8_t edns_lame_known;
	if(!infra_host(sq->outnet->infra, &sq->addr, sq->addrlen, sq->zone,
		sq->zonelen, *sq->outnet->now_secs, &vs, &edns_lame_known,
		&rtt))
		return 0;
	if(vs != -1)
		sq->status = serviced_query_TCP_EDNS;
	else 	sq->status = serviced_query_TCP;
	np_serviced_encode(sq, buff, sq->status == serviced_query_TCP_EDNS);
	sq->last_sent_time = *sq->outnet->now_tv;
	sq->pending = np_pending_tcp_query(sq, buff, TCP_AUTH_QUERY_TIMEOUT,
		serviced_tcp_callback, sq, http_data);
	return sq->pending != NULL;
}
#endif
static int8_t np_get_free_outside_http_list(void *data, struct outside_network* outnet)
{
    struct np_http_query_st *query_data = (struct np_http_query_st *)data;
    struct outside_http_data_st *working_prev = &(query_data->np_http_list->working);
    struct np_outside_http_list_st *http_list = (query_data->np_http_list);
    struct outside_http_data_st *working = NULL;
	struct pending key;
	struct pending* p;
    uint8_t status = 0;

    if(http_list->queue_len > 0) {
        // log_err("queue_len_free");
        return 0;
    }

    if(http_list->use_socket > 0 ) {
        // log_err("1 use_socket <= 0\n");
        return 0;
    }

    working = working_prev->next;
    while(working) {
        pthread_mutex_lock(&(working->use_mutex));
        status = working->use;
        pthread_mutex_unlock(&(working->use_mutex));
        if(status == 0 ) {
            key.id = working->query_id;
            ((struct sockaddr_in*)&(key.addr))->sin_family = AF_INET;
            ((struct sockaddr_in*)&(key.addr))->sin_port = htons(53);
            ((struct sockaddr_in*)&(key.addr))->sin_addr.s_addr = 
                inet_addr("127.0.0.1");
            key.addrlen = sizeof(struct sockaddr_in);
            p = (struct pending*)rbtree_search(outnet->pending, &key);
            if(!p) {
                //pthread_mutex_lock(&http_list->rw_mutex);
                working_prev->next = working->next;
                working->next = http_list->free.next;
                http_list->use_socket ++;
                http_list->free.next = working;

                working = working_prev->next;
                //pthread_mutex_unlock(&(http_list->rw_mutex));
                continue;
            }
        }
        working_prev = working_prev->next;
        working = working->next;

        if(http_list->use_socket <= 0) {
            // log_err("2 use_socket <= 0\n");
            return -1;
        }
    }
    // log_err("http_list->use_socket: %d", http_list->use_socket);

    return 0;
}

struct outside_http_data_st 
*np_find_free_http_list(struct np_outside_http_list_st *http_list,
        struct outside_network* outnet)
{
    struct outside_http_data_st *free = NULL;
    struct outside_http_data_st *tmp = NULL;
    int flag = 0;
    uint8_t status = 0;
    struct outside_http_data_st *working = NULL;
    struct outside_http_data_st *working_next = NULL;
    struct outside_http_data_st *working_prev = &(http_list->working);
	struct pending key;
	struct pending* p;

start:
    flag = 0;
    if(http_list->free.next) {
        free = http_list->free.next;
        http_list->free.next = free->next;
        free->use = 0;

        free->next = http_list->working.next;
        http_list->working.next = free;
        return free;
    }
    else {
        // new struct outside_http_data_st
        working = working_prev->next;
        while(working) {
            pthread_mutex_lock(&(working->use_mutex));
            status = working->use;
            pthread_mutex_unlock(&(working->use_mutex));
            if(status == 0 ) {
                key.id = working->query_id;
                ((struct sockaddr_in*)&(key.addr))->sin_family = AF_INET;
                ((struct sockaddr_in*)&(key.addr))->sin_port = htons(53);
                ((struct sockaddr_in*)&(key.addr))->sin_addr.s_addr = 
                    inet_addr("127.0.0.1");
                key.addrlen = sizeof(struct sockaddr_in);
                p = (struct pending*)rbtree_search(outnet->pending, &key);
                if(!p) {
                    flag = 1;
                    working_prev->next = working->next;
                    working->next = http_list->free.next;
                    http_list->free.next = working;
                    http_list->use_socket ++;

                    working = working_prev->next;
                    continue;
                }
            }
            working_prev = working_prev->next;
            working = working->next;
        }
        if(flag) {
            goto start;
        }
        else {
            if(http_list->queue_len < 0) {
                log_err("np_fined_free_http_list(): Excessive queue creation!");
            }
            free = calloc(1, sizeof(struct outside_http_data_st));
            if(free == NULL) {
                log_err("np_find_free_http_list() calloc fialed!");
                return NULL;
            }
            free->fd[0] = -1;
            free->fd[1] = -1;
            free->use = 0;
            if(socketpair(AF_UNIX, SOCK_DGRAM, 0, free->fd) < 0) {
                log_err("socketpair() failed!");
                return 0;
            }
            fd_set_nonblock(free->fd[0]);
            fd_set_nonblock(free->fd[1]);

            pthread_mutex_init(&(free->use_mutex), NULL);
            //pthread_mutex_lock(&http_list->rw_mutex);
            free->next = http_list->working.next;
            http_list->working.next = free;
            http_list->queue_len --;
            http_list->use_socket ++;
            //pthread_mutex_unlock(&(http_list->rw_mutex));
            return free;
        }
    }

    return NULL;
}
#if 0
struct waiting_tcp*
np_pending_tcp_query(struct serviced_query* sq, sldns_buffer* packet,
	int timeout, comm_point_callback_type* callback, void* callback_arg,\
    void *http_data)
{
	struct pending_tcp* pend = sq->outnet->tcp_free;
	struct waiting_tcp* w;
	struct timeval tv;
	uint16_t id;

    if(pend != NULL && np_get_free_outside_http_list(http_data, sq->outnet) < 0) {
        pend = NULL;
    }
    // struct np_http_query_st *query_data = (struct np_http_query_st *)http_data;
	/* if no buffer is free allocate space to store query */
	w = (struct waiting_tcp*)malloc(sizeof(struct waiting_tcp) 
		+ (pend?0:(sldns_buffer_limit(packet) + 
                sizeof(struct np_http_query_st))));
	if(!w) {
		return NULL;
	}
	if(!(w->timer = comm_timer_create(sq->outnet->base, np_outnet_tcptimer, w))) {
		free(w);
		return NULL;
	}
	w->pkt = NULL;
	w->pkt_len = 0;
	id = ((unsigned)ub_random(sq->outnet->rnd)>>8) & 0xffff;
	LDNS_ID_SET(sldns_buffer_begin(packet), id);
	memcpy(&w->addr, &sq->addr, sq->addrlen);
	w->addrlen = sq->addrlen;
	w->outnet = sq->outnet;
	w->cb = callback;
	w->cb_arg = callback_arg;
	w->ssl_upstream = sq->ssl_upstream;
	w->tls_auth_name = sq->tls_auth_name;
#ifndef S_SPLINT_S
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
#endif
	comm_timer_set(w->timer, &tv);
	if(pend) {
		/* we have a buffer available right now */
		if(!np_outnet_tcp_take_into_use(w, sldns_buffer_begin(packet),
			sldns_buffer_limit(packet), http_data)) {
			waiting_tcp_delete(w);
			return NULL;
		}
#if 0
#ifdef USE_DNSTAP
		if(sq->outnet->dtenv &&
		   (sq->outnet->dtenv->log_resolver_query_messages ||
		    sq->outnet->dtenv->log_forwarder_query_messages))
		dt_msg_send_outside_query(sq->outnet->dtenv, &sq->addr,
		comm_tcp, sq->zone, sq->zonelen, packet);
#endif
#endif
	} else {
		/* queue up */
		w->pkt = (uint8_t*)w + sizeof(struct waiting_tcp);
		w->pkt_len = sldns_buffer_limit(packet);
		memmove(w->pkt, sldns_buffer_begin(packet), w->pkt_len);
        // 
        memcpy(w->pkt + w->pkt_len, http_data, 
                sizeof(struct np_http_query_st));
		w->next_waiting = NULL;
		if(sq->outnet->tcp_wait_last)
			sq->outnet->tcp_wait_last->next_waiting = w;
		else	sq->outnet->tcp_wait_first = w;
		sq->outnet->tcp_wait_last = w;
	}
	return w;
}
/** use next free buffer to service a tcp query */
static int
np_outnet_tcp_take_into_use(struct waiting_tcp* w, uint8_t* pkt, size_t pkt_len, void *http_data)
{
	struct pending_tcp* pend = w->outnet->tcp_free;
	int s;
    int srv[2] = {};
    struct np_http_query_st *query_data = (struct np_http_query_st *)http_data;
    //struct outside_http_data_st *outside_data = 
    //    (struct outside_http_data_st *)http_data;
	log_assert(pend);
	log_assert(pkt);
	log_assert(w->addrlen > 0);
#if 0
	/* open socket */
	s = outnet_get_tcp_fd(&w->addr, w->addrlen, w->outnet->tcp_mss);

	if(!pick_outgoing_tcp(w, s))
		return 0;

	fd_set_nonblock(s);
#ifdef USE_OSX_MSG_FASTOPEN
	/* API for fast open is different here. We use a connectx() function and 
	   then writes can happen as normal even using SSL.*/
	/* connectx requires that the len be set in the sockaddr struct*/
	struct sockaddr_in *addr_in = (struct sockaddr_in *)&w->addr;
	addr_in->sin_len = w->addrlen;
	sa_endpoints_t endpoints;
	endpoints.sae_srcif = 0;
	endpoints.sae_srcaddr = NULL;
	endpoints.sae_srcaddrlen = 0;
	endpoints.sae_dstaddr = (struct sockaddr *)&w->addr;
	endpoints.sae_dstaddrlen = w->addrlen;
	if (connectx(s, &endpoints, SAE_ASSOCID_ANY,  
	             CONNECT_DATA_IDEMPOTENT | CONNECT_RESUME_ON_READ_WRITE,
	             NULL, 0, NULL, NULL) == -1) {
		/* if fails, failover to connect for OSX 10.10 */
#ifdef EINPROGRESS
		if(errno != EINPROGRESS) {
#else
		if(1) {
#endif
			if(connect(s, (struct sockaddr*)&w->addr, w->addrlen) == -1) {
#else /* USE_OSX_MSG_FASTOPEN*/
#ifdef USE_MSG_FASTOPEN
	pend->c->tcp_do_fastopen = 1;
	/* Only do TFO for TCP in which case no connect() is required here.
	   Don't combine client TFO with SSL, since OpenSSL can't 
	   currently support doing a handshake on fd that already isn't connected*/
	if (w->outnet->sslctx && w->ssl_upstream) {
		if(connect(s, (struct sockaddr*)&w->addr, w->addrlen) == -1) {
#else /* USE_MSG_FASTOPEN*/
	if(connect(s, (struct sockaddr*)&w->addr, w->addrlen) == -1) {
#endif /* USE_MSG_FASTOPEN*/
#endif /* USE_OSX_MSG_FASTOPEN*/
#ifndef USE_WINSOCK
#ifdef EINPROGRESS
		if(errno != EINPROGRESS) {
#else
		if(1) {
#endif
			if(tcp_connect_errno_needs_log(
				(struct sockaddr*)&w->addr, w->addrlen))
				log_err_addr("outgoing tcp: connect",
					strerror(errno), &w->addr, w->addrlen);
			close(s);
#else /* USE_WINSOCK */
		if(WSAGetLastError() != WSAEINPROGRESS &&
			WSAGetLastError() != WSAEWOULDBLOCK) {
			closesocket(s);
#endif
			return 0;
		}
	}
#ifdef USE_MSG_FASTOPEN
	}
#endif /* USE_MSG_FASTOPEN */
#ifdef USE_OSX_MSG_FASTOPEN
		}
	}
#endif /* USE_OSX_MSG_FASTOPEN */
	if(w->outnet->sslctx && w->ssl_upstream) {
		pend->c->ssl = outgoing_ssl_fd(w->outnet->sslctx, s);
		if(!pend->c->ssl) {
			pend->c->fd = s;
			comm_point_close(pend->c);
			return 0;
		}
#ifdef USE_WINSOCK
		comm_point_tcp_win_bio_cb(pend->c, pend->c->ssl);
#endif
		pend->c->ssl_shake_state = comm_ssl_shake_write;
#ifdef HAVE_SSL_SET1_HOST
		if(w->tls_auth_name) {
			SSL_set_verify(pend->c->ssl, SSL_VERIFY_PEER, NULL);
			/* setting the hostname makes openssl verify the
                         * host name in the x509 certificate in the
                         * SSL connection*/
                        if(!SSL_set1_host(pend->c->ssl, w->tls_auth_name)) {
                                log_err("SSL_set1_host failed");
				pend->c->fd = s;
				comm_point_close(pend->c);
				return 0;
			}
		}
#endif /* HAVE_SSL_SET1_HOST */
	}
    else 
#endif 
    {
        verbose(VERB_ALGO, "pthread poll find outside_http_data ....");
        struct outside_http_data_st *outside_data = 
            np_find_free_http_list(query_data->np_http_list, NULL);
        //  struct outside_http_data_st outside_data;
        if(outside_data->fd[0] == -1 || outside_data->fd[1] == -1) {
            log_err("outside->fd error");
            return 0;
        }
        query_data->np_http_list->use_socket --;
        verbose(VERB_ALGO, "pthread poll start ....");
        //verbose(VERB_ALGO, "qinfo: %*s",
        // query_data->qinfo->qname_len,query_data->qinfo->qname);
        // start thread, http query
        pend->c->type = comm_tcp;
        pend->c->callback = np_outnet_tcp_cb;
        s = outside_data->fd[0];
        outside_data->socket_mode = query_data->np_http_list->socket_mode;

        //memset(&outside_data, 0, sizeof(outside_data));

        // http info
        memcpy(outside_data->http_query_url, query_data->np_http_url, 
                strlen(query_data->np_http_url));
        outside_data->http_timeout = query_data->np_http_timeout;
        outside_data->http_ttl = query_data->np_http_ttl;
        // verbose(VERB_ALGO, "http_info: %s, %d",
        //         outside_data.http_query_url, outside_data.http_timeout);
        // cname 
        memcpy(outside_data->qname, query_data->qinfo->qname, 
                query_data->qinfo->qname_len);
        outside_data->qname_len = query_data->qinfo->qname_len;
        outside_data->query_id = LDNS_ID_WIRE(pkt);
        memcpy(&(outside_data->mtr_input),
                query_data->mtr_input, sizeof(struct np_mtr_input_st));
        // test
        // create_http_pth((void *)(outside_data));
        thpool_add_work(query_data->np_http_list->pool,
                (void*)np_add_http_query_work,outside_data);
    }
	w->pkt = NULL;
	w->next_waiting = (void*)pend;
	pend->id = LDNS_ID_WIRE(pkt);
	w->outnet->num_tcp_outgoing++;
	w->outnet->tcp_free = pend->next_free;
	pend->next_free = NULL;
	pend->query = w;
	pend->c->repinfo.addrlen = w->addrlen;
	memcpy(&pend->c->repinfo.addr, &w->addr, w->addrlen);
	sldns_buffer_clear(pend->c->buffer);
	sldns_buffer_write(pend->c->buffer, pkt, pkt_len);
	sldns_buffer_flip(pend->c->buffer);
	pend->c->tcp_is_reading = 1;
	pend->c->tcp_byte_count = 0;
	comm_point_start_listening(pend->c, s, -1);
	return 1;
}
/** put serviced query into a buffer */
static void
np_serviced_encode(struct serviced_query* sq, sldns_buffer* buff, int with_edns)
{
	/* if we are using 0x20 bits for ID randomness, perturb them */
	if(sq->outnet->use_caps_for_id && !sq->nocaps) {
		np_serviced_perturb_qname(sq->outnet->rnd, sq->qbuf, sq->qbuflen);
	}
	/* generate query */
	sldns_buffer_clear(buff);
	sldns_buffer_write_u16(buff, 0); /* id placeholder */
	sldns_buffer_write(buff, sq->qbuf, sq->qbuflen);
	sldns_buffer_flip(buff);
	if(with_edns) {
		/* add edns section */
		struct edns_data edns;
		edns.edns_present = 1;
		edns.ext_rcode = 0;
		edns.edns_version = EDNS_ADVERTISED_VERSION;
		edns.opt_list = sq->opt_list;
		if(sq->status == serviced_query_UDP_EDNS_FRAG) {
			if(addr_is_ip6(&sq->addr, sq->addrlen)) {
				if(EDNS_FRAG_SIZE_IP6 < EDNS_ADVERTISED_SIZE)
					edns.udp_size = EDNS_FRAG_SIZE_IP6;
				else	edns.udp_size = EDNS_ADVERTISED_SIZE;
			} else {
				if(EDNS_FRAG_SIZE_IP4 < EDNS_ADVERTISED_SIZE)
					edns.udp_size = EDNS_FRAG_SIZE_IP4;
				else	edns.udp_size = EDNS_ADVERTISED_SIZE;
			}
		} else {
			edns.udp_size = EDNS_ADVERTISED_SIZE;
		}
		edns.bits = 0;
		if(sq->dnssec & EDNS_DO)
			edns.bits = EDNS_DO;
		if(sq->dnssec & BIT_CD)
			LDNS_CD_SET(sldns_buffer_begin(buff));
		attach_edns_record(buff, &edns);
	}
}
#endif
/** perturb a dname capitalization randomly */
static void
np_serviced_perturb_qname(struct ub_randstate* rnd, uint8_t* qbuf, size_t len)
{
	uint8_t lablen;
	uint8_t* d = qbuf + 10;
	long int random = 0;
	int bits = 0;
	log_assert(len >= 10 + 5 /* offset qname, root, qtype, qclass */);
	(void)len;
	lablen = *d++;
	while(lablen) {
		while(lablen--) {
			/* only perturb A-Z, a-z */
			if(isalpha((unsigned char)*d)) {
				/* get a random bit */	
				if(bits == 0) {
					random = ub_random(rnd);
					bits = 30;
				}
				if(random & 0x1) {
					*d = (uint8_t)toupper((unsigned char)*d);
				} else {
					*d = (uint8_t)tolower((unsigned char)*d);
				}
				random >>= 1;
				bits--;
			}
			d++;
		}
		lablen = *d++;
	}
	if(verbosity >= VERB_ALGO) {
		char buf[LDNS_MAX_DOMAINLEN+1];
		dname_str(qbuf+10, buf);
		verbose(VERB_ALGO, "qname perturbed to %s", buf);
	}
}
#if 0
/** delete waiting_tcp entry. Does not unlink from waiting list. 
 * @param w: to delete.
 */
static void
waiting_tcp_delete(struct waiting_tcp* w)
{
	if(!w) return;
	if(w->timer)
		comm_timer_delete(w->timer);
	free(w);
}
#endif

/** remove waiting tcp from the outnet waiting list */
static void
waiting_list_remove(struct outside_network* outnet, struct waiting_tcp* w)
{
	struct waiting_tcp* p = outnet->tcp_wait_first, *prev = NULL;
	while(p) {
		if(p == w) {
			/* remove w */
			if(prev)
				prev->next_waiting = w->next_waiting;
			else	outnet->tcp_wait_first = w->next_waiting;
			if(outnet->tcp_wait_last == w)
				outnet->tcp_wait_last = prev;
			return;
		}
		prev = p;
		p = p->next_waiting;
	}
}
#if 0
/** see if buffers can be used to service TCP queries */
static void
use_free_buffer(struct outside_network* outnet)
{
	struct waiting_tcp* w;
    w = outnet->tcp_wait_first;
    while(outnet->tcp_free && outnet->tcp_wait_first 
            && !outnet->want_to_quit) {
        w = outnet->tcp_wait_first;
        if(w && np_get_free_outside_http_list(w->pkt+w->pkt_len, outnet) < 0) {
            return ;
        }
        outnet->tcp_wait_first = w->next_waiting;
        if(outnet->tcp_wait_last == w)
            outnet->tcp_wait_last = NULL;
        if(!np_outnet_tcp_take_into_use(w, w->pkt, w->pkt_len, (w->pkt+w->pkt_len))) {
			comm_point_callback_type* cb = w->cb;
			void* cb_arg = w->cb_arg;
			waiting_tcp_delete(w);
            log_err("netpas_module--use_free_buffer---->cb");
			// fptr_ok(fptr_whitelist_pending_tcp(cb));
			(void)(*cb)(NULL, cb_arg, NETEVENT_CLOSED, NULL);
		}
	}
}
#endif
/** check that perturbed qname is identical */
static int
serviced_check_qname(sldns_buffer* pkt, uint8_t* qbuf, size_t qbuflen)
{
	uint8_t* d1 = sldns_buffer_begin(pkt)+12;
	uint8_t* d2 = qbuf+10;
	uint8_t len1, len2;
	int count = 0;
	if(sldns_buffer_limit(pkt) < 12+1+4) /* packet too small for qname */
		return 0;
	log_assert(qbuflen >= 15 /* 10 header, root, type, class */);
	len1 = *d1++;
	len2 = *d2++;
	while(len1 != 0 || len2 != 0) {
		if(LABEL_IS_PTR(len1)) {
			/* check if we can read *d1 with compression ptr rest */
			if(d1 >= sldns_buffer_at(pkt, sldns_buffer_limit(pkt)))
				return 0;
			d1 = sldns_buffer_begin(pkt)+PTR_OFFSET(len1, *d1);
			/* check if we can read the destination *d1 */
			if(d1 >= sldns_buffer_at(pkt, sldns_buffer_limit(pkt)))
				return 0;
			len1 = *d1++;
			if(count++ > MAX_COMPRESS_PTRS)
				return 0;
			continue;
		}
		if(d2 > qbuf+qbuflen)
			return 0;
		if(len1 != len2)
			return 0;
		if(len1 > LDNS_MAX_LABELLEN)
			return 0;
		/* check len1 + 1(next length) are okay to read */
		if(d1+len1 >= sldns_buffer_at(pkt, sldns_buffer_limit(pkt)))
			return 0;
		log_assert(len1 <= LDNS_MAX_LABELLEN);
		log_assert(len2 <= LDNS_MAX_LABELLEN);
		log_assert(len1 == len2 && len1 != 0);
		/* compare the labels - bitwise identical */
		if(memcmp(d1, d2, len1) != 0)
			return 0;
		d1 += len1;
		d2 += len2;
		len1 = *d1++;
		len2 = *d2++;
	}
	return 1;
}

/** helper serviced delete */
static void
serviced_node_del(rbnode_type* node, void* ATTR_UNUSED(arg))
{
	struct serviced_query* sq = (struct serviced_query*)node;
	struct service_callback* p = sq->cblist, *np;
	free(sq->qbuf);
	free(sq->zone);
	free(sq->tls_auth_name);
	edns_opt_list_free(sq->opt_list);
	while(p) {
		np = p->next;
		free(p);
		p = np;
	}
	free(sq);
}

/** cleanup serviced query entry */
static void
serviced_delete(struct serviced_query* sq)
{
	if(sq->pending) {
		/* clear up the pending query */
		if(sq->status == serviced_query_UDP_EDNS ||
			sq->status == serviced_query_UDP ||
			sq->status == serviced_query_PROBE_EDNS ||
			sq->status == serviced_query_UDP_EDNS_FRAG ||
			sq->status == serviced_query_UDP_EDNS_fallback) {
			struct pending* p = (struct pending*)sq->pending;
			if(p->pc)
				portcomm_loweruse(sq->outnet, p->pc);
			pending_delete(sq->outnet, p);
			/* this call can cause reentrant calls back into the
			 * mesh */
			np_outnet_send_wait_udp(sq->outnet);
		} else {
            /*
			struct waiting_tcp* p = (struct waiting_tcp*)
				sq->pending;
			if(p->pkt == NULL) {
				decommission_pending_tcp(sq->outnet, 
					(struct pending_tcp*)p->next_waiting);
			} else {
				waiting_list_remove(sq->outnet, p);
				waiting_tcp_delete(p);
			}
            */
		}
	}
	/* does not delete from tree, caller has to do that */
	serviced_node_del(&sq->node, NULL);
}
/** call the callbacks for a serviced query */
static void
serviced_callbacks(struct serviced_query* sq, int error, struct comm_point* c,
	struct comm_reply* rep)
{
	struct service_callback* p;
	int dobackup = (sq->cblist && sq->cblist->next); /* >1 cb*/
	uint8_t *backup_p = NULL;
	size_t backlen = 0;
#ifdef UNBOUND_DEBUG
	rbnode_type* rem =
#else
	(void)
#endif
	/* remove from tree, and schedule for deletion, so that callbacks
	 * can safely deregister themselves and even create new serviced
	 * queries that are identical to this one. */
	rbtree_delete(sq->outnet->serviced, sq);
	log_assert(rem); /* should have been present */
	sq->to_be_deleted = 1; 
	verbose(VERB_ALGO, "svcd callbacks start");
	if(sq->outnet->use_caps_for_id && error == NETEVENT_NOERROR && c &&
		!sq->nocaps && sq->qtype != LDNS_RR_TYPE_PTR) {
		/* for type PTR do not check perturbed name in answer,
		 * compatibility with cisco dns guard boxes that mess up
		 * reverse queries 0x20 contents */
		/* noerror and nxdomain must have a qname in reply */
		if(sldns_buffer_read_u16_at(c->buffer, 4) == 0 &&
			(LDNS_RCODE_WIRE(sldns_buffer_begin(c->buffer))
				== LDNS_RCODE_NOERROR || 
			 LDNS_RCODE_WIRE(sldns_buffer_begin(c->buffer))
				== LDNS_RCODE_NXDOMAIN)) {
			verbose(VERB_DETAIL, "no qname in reply to check 0x20ID");
			log_addr(VERB_DETAIL, "from server", 
				&sq->addr, sq->addrlen);
			log_buf(VERB_DETAIL, "for packet", c->buffer);
			error = NETEVENT_CLOSED;
			c = NULL;
		} else if(sldns_buffer_read_u16_at(c->buffer, 4) > 0 &&
			!serviced_check_qname(c->buffer, sq->qbuf, 
			sq->qbuflen)) {
			verbose(VERB_DETAIL, "wrong 0x20-ID in reply qname");
			log_addr(VERB_DETAIL, "from server", 
				&sq->addr, sq->addrlen);
			log_buf(VERB_DETAIL, "for packet", c->buffer);
			error = NETEVENT_CAPSFAIL;
			/* and cleanup too */
			pkt_dname_tolower(c->buffer, 
				sldns_buffer_at(c->buffer, 12));
		} else {
			verbose(VERB_ALGO, "good 0x20-ID in reply qname");
			/* cleanup caps, prettier cache contents. */
			pkt_dname_tolower(c->buffer, 
				sldns_buffer_at(c->buffer, 12));
		}
	}
	if(dobackup && c) {
		/* make a backup of the query, since the querystate processing
		 * may send outgoing queries that overwrite the buffer.
		 * use secondary buffer to store the query.
		 * This is a data copy, but faster than packet to server */
		backlen = sldns_buffer_limit(c->buffer);
		backup_p = memdup(sldns_buffer_begin(c->buffer), backlen);
		if(!backup_p) {
			log_err("malloc failure in serviced query callbacks");
			error = NETEVENT_CLOSED;
			c = NULL;
		}
		sq->outnet->svcd_overhead = backlen;
	}
	/* test the actual sq->cblist, because the next elem could be deleted*/
	while((p=sq->cblist) != NULL) {
		sq->cblist = p->next; /* remove this element */
		if(dobackup && c) {
			sldns_buffer_clear(c->buffer);
			sldns_buffer_write(c->buffer, backup_p, backlen);
			sldns_buffer_flip(c->buffer);
		}
		fptr_ok(fptr_whitelist_serviced_query(p->cb));
		(void)(*p->cb)(c, p->cb_arg, error, rep);
		free(p);
	}
	if(backup_p) {
		free(backup_p);
		sq->outnet->svcd_overhead = 0;
	}
	verbose(VERB_ALGO, "svcd callbacks end");
	log_assert(sq->cblist == NULL);
	serviced_delete(sq);
}
static void
serviced_tcp_initiate(struct serviced_query* sq, sldns_buffer* buff)
{
	verbose(VERB_ALGO, "initiate TCP query %s", 
		sq->status==serviced_query_TCP_EDNS?"EDNS":"");
	serviced_encode(sq, buff, sq->status == serviced_query_TCP_EDNS);
	sq->last_sent_time = *sq->outnet->now_tv;
	sq->pending = pending_tcp_query(sq, buff, TCP_AUTH_QUERY_TIMEOUT,
		serviced_tcp_callback, sq);
	if(!sq->pending) {
		/* delete from tree so that a retry by above layer does not
		 * clash with this entry */
		log_err("serviced_tcp_initiate: failed to send tcp query");
		serviced_callbacks(sq, NETEVENT_CLOSED, NULL, NULL);
	}
}

#if 0
int 
np_serviced_tcp_callback(struct comm_point* c, void* arg, int error,
        struct comm_reply* rep)
{
	struct serviced_query* sq = (struct serviced_query*)arg;
	struct comm_reply r2;
	sq->pending = NULL; /* removed after this callback */
	if(error != NETEVENT_NOERROR)
		log_addr(VERB_QUERY, "tcp error for address", 
			&sq->addr, sq->addrlen);
	if(error==NETEVENT_NOERROR)
		infra_update_tcp_works(sq->outnet->infra, &sq->addr,
			sq->addrlen, sq->zone, sq->zonelen);
#ifdef USE_DNSTAP
	if(error==NETEVENT_NOERROR && sq->outnet->dtenv &&
	   (sq->outnet->dtenv->log_resolver_response_messages ||
	    sq->outnet->dtenv->log_forwarder_response_messages))
		dt_msg_send_outside_response(sq->outnet->dtenv, &sq->addr,
		c->type, sq->zone, sq->zonelen, sq->qbuf, sq->qbuflen,
		&sq->last_sent_time, sq->outnet->now_tv, c->buffer);
#endif
	if(error==NETEVENT_NOERROR && sq->status == serviced_query_TCP_EDNS &&
		(LDNS_RCODE_WIRE(sldns_buffer_begin(c->buffer)) == 
		LDNS_RCODE_FORMERR || LDNS_RCODE_WIRE(sldns_buffer_begin(
		c->buffer)) == LDNS_RCODE_NOTIMPL) ) {
		/* attempt to fallback to nonEDNS */
		sq->status = serviced_query_TCP_EDNS_fallback;
		serviced_tcp_initiate(sq, c->buffer);
		return 0;
	} else if(error==NETEVENT_NOERROR && 
		sq->status == serviced_query_TCP_EDNS_fallback &&
			(LDNS_RCODE_WIRE(sldns_buffer_begin(c->buffer)) == 
			LDNS_RCODE_NOERROR || LDNS_RCODE_WIRE(
			sldns_buffer_begin(c->buffer)) == LDNS_RCODE_NXDOMAIN 
			|| LDNS_RCODE_WIRE(sldns_buffer_begin(c->buffer)) 
			== LDNS_RCODE_YXDOMAIN)) {
		/* the fallback produced a result that looks promising, note
		 * that this server should be approached without EDNS */
		/* only store noEDNS in cache if domain is noDNSSEC */
		if(!sq->want_dnssec)
		  if(!infra_edns_update(sq->outnet->infra, &sq->addr, 
			sq->addrlen, sq->zone, sq->zonelen, -1,
			*sq->outnet->now_secs))
			log_err("Out of memory caching no edns for host");
		sq->status = serviced_query_TCP;
	}
	if(sq->tcp_upstream || sq->ssl_upstream) {
	    struct timeval now = *sq->outnet->now_tv;
	    if(now.tv_sec > sq->last_sent_time.tv_sec ||
		(now.tv_sec == sq->last_sent_time.tv_sec &&
		now.tv_usec > sq->last_sent_time.tv_usec)) {
		/* convert from microseconds to milliseconds */
		int roundtime = ((int)(now.tv_sec - sq->last_sent_time.tv_sec))*1000
		  + ((int)now.tv_usec - (int)sq->last_sent_time.tv_usec)/1000;
		verbose(VERB_ALGO, "measured TCP-time at %d msec", roundtime);
		log_assert(roundtime >= 0);
		/* only store if less then AUTH_TIMEOUT seconds, it could be
		 * huge due to system-hibernated and we woke up */
		if(roundtime < TCP_AUTH_QUERY_TIMEOUT*1000) {
		    if(!infra_rtt_update(sq->outnet->infra, &sq->addr,
			sq->addrlen, sq->zone, sq->zonelen, sq->qtype,
			roundtime, sq->last_rtt, (time_t)now.tv_sec))
			log_err("out of memory noting rtt.");
		}
	    }
	}
	/* insert address into reply info */
	if(!rep) {
		/* create one if there isn't (on errors) */
		rep = &r2;
		r2.c = c;
	}
	memcpy(&rep->addr, &sq->addr, sq->addrlen);
	rep->addrlen = sq->addrlen;
	serviced_callbacks(sq, error, c, rep);
	return 0;
}

void
np_outnet_tcptimer(void* arg)
{
	struct waiting_tcp* w = (struct waiting_tcp*)arg;
	struct outside_network* outnet = w->outnet;
	comm_point_callback_type* cb;
	void* cb_arg;
	if(w->pkt) {
		/* it is on the waiting list */
		waiting_list_remove(outnet, w);
	} else {
		/* it was in use */
        struct pending_tcp* pend=(struct pending_tcp*)w->next_waiting;
        comm_point_close(pend->c);
        pend->query = NULL;
        pend->next_free = outnet->tcp_free;
		outnet->tcp_free = pend;
	}
	cb = w->cb;
	cb_arg = w->cb_arg;
	waiting_tcp_delete(w);
	// fptr_ok(fptr_whitelist_pending_tcp(cb));
    log_err("netpas_module: ==> np_outnet_tcptimer()");
	(void)(*cb)(NULL, cb_arg, NETEVENT_TIMEOUT, NULL);
	use_free_buffer(outnet);
}
/** decommission a tcp buffer, closes commpoint and frees waiting_tcp entry */
static void
decommission_pending_tcp(struct outside_network* outnet, 
	struct pending_tcp* pend)
{
	if(pend->c->ssl) {
#ifdef HAVE_SSL
		SSL_shutdown(pend->c->ssl);
		SSL_free(pend->c->ssl);
		pend->c->ssl = NULL;
#endif
	}
    pend->c->callback = outnet_tcp_cb;
    pend->c->do_not_close = 1;
	comm_point_close(pend->c);
    pend->c->do_not_close = 0;
	pend->next_free = outnet->tcp_free;
	outnet->tcp_free = pend;
	waiting_tcp_delete(pend->query);
	pend->query = NULL;
	use_free_buffer(outnet);
}
#endif
/** Select random ID */
static int
select_id(struct outside_network* outnet, struct pending* pend,
	sldns_buffer* packet)
{
	int id_tries = 0;
	pend->id = ((unsigned)ub_random(outnet->rnd)>>8) & 0xffff;
	LDNS_ID_SET(sldns_buffer_begin(packet), pend->id);

	/* insert in tree */
	pend->node.key = pend;
	while(!rbtree_insert(outnet->pending, &pend->node)) {
		/* change ID to avoid collision */
		pend->id = ((unsigned)ub_random(outnet->rnd)>>8) & 0xffff;
		LDNS_ID_SET(sldns_buffer_begin(packet), pend->id);
		id_tries++;
		if(id_tries == MAX_ID_RETRY) {
			pend->id=99999; /* non existant ID */
			log_err("failed to generate unique ID, drop msg");
			return 0;
		}
	}
	verbose(VERB_ALGO, "inserted new pending reply id=%4.4x", pend->id);
	return 1;
}

static void
sai6_putrandom(struct sockaddr_in6 *sa, int pfxlen, struct ub_randstate *rnd)
{
	int i, last;
	if(!(pfxlen > 0 && pfxlen < 128))
		return;
	for(i = 0; i < (128 - pfxlen) / 8; i++) {
		sa->sin6_addr.s6_addr[15-i] = (uint8_t)ub_random_max(rnd, 256);
	}
	last = pfxlen & 7;
	if(last != 0) {
		sa->sin6_addr.s6_addr[15-i] |=
			((0xFF >> last) & ub_random_max(rnd, 256));
	}
}
#if 0
/**
 * Try to open a UDP socket for outgoing communication.
 * Sets sockets options as needed.
 * @param addr: socket address.
 * @param addrlen: length of address.
 * @param pfxlen: length of network prefix (for address randomisation).
 * @param port: port override for addr.
 * @param inuse: if -1 is returned, this bool means the port was in use.
 * @param rnd: random state (for address randomisation).
 * @return fd or -1
 */
static int
udp_sockport(struct sockaddr_storage* addr, socklen_t addrlen, int pfxlen,
	int port, int* inuse, struct ub_randstate* rnd)
{
	int fd, noproto;
	if(addr_is_ip6(addr, addrlen)) {
		int freebind = 0;
		struct sockaddr_in6 sa = *(struct sockaddr_in6*)addr;
		sa.sin6_port = (in_port_t)htons((uint16_t)port);
		if(pfxlen != 0) {
			freebind = 1;
			sai6_putrandom(&sa, pfxlen, rnd);
		}
		fd = create_udp_sock(AF_INET6, SOCK_DGRAM, 
			(struct sockaddr*)&sa, addrlen, 1, inuse, &noproto,
			0, 0, 0, NULL, 0, freebind, 0);
	} else {
		struct sockaddr_in* sa = (struct sockaddr_in*)addr;
		sa->sin_port = (in_port_t)htons((uint16_t)port);
		fd = create_udp_sock(AF_INET, SOCK_DGRAM, 
			(struct sockaddr*)addr, addrlen, 1, inuse, &noproto,
			0, 0, 0, NULL, 0, 0, 0);
	}
	return fd;
}
#endif
/** Select random interface and port */
static int
select_ifport(struct outside_network* outnet, struct pending* pend,
	int num_if, struct port_if* ifs, int socket_pair)
{
	int my_if, my_port, fd, portno, inuse, tries=0;
	struct port_if* pif;
    int ret = 0;
	/* randomly select interface and port */
	if(num_if == 0) {
		verbose(VERB_QUERY, "Need to send query but have no "
			"outgoing interfaces of that family");
		return 0;
	}
	log_assert(outnet->unused_fds);
#if 0
	tries = 0;
    while(1) {
        my_if = ub_random_max(outnet->rnd, num_if);
        pif = &ifs[my_if];
        my_port = ub_random_max(outnet->rnd, pif->avail_total);
        verbose(VERB_ALGO, "my_port: %d", my_port);
        if(my_port < pif->inuse) {
            /* port already open */
            pend->pc = pif->out[my_port];
            verbose(VERB_ALGO, "using UDP if=%d port=%d", 
                    my_if, pend->pc->number);
            verbose(VERB_ALGO, "TEST UDP 1451");
            log_err("test_udp_1451");
            ret = 2;
            break;
        }
        /* try to open new port, if fails, loop to try again */
        log_assert(pif->inuse < pif->maxout);
        portno = pif->avail_ports[my_port - pif->inuse];
        if(socket_pair < 0) {
            fd = udp_sockport(&pif->addr, pif->addrlen, pif->pfxlen,
                    portno, &inuse, outnet->rnd);
            if(fd == -1 && !inuse) {
                /* nonrecoverable error making socket */
                return 0;
            }
        }
        else {
            fd = socket_pair;
        }
		if(fd != -1) {
			verbose(VERB_ALGO, "opened UDP if=%d port=%d", 
				my_if, portno);
			/* grab fd */
			pend->pc = outnet->unused_fds;
			outnet->unused_fds = pend->pc->next;

			/* setup portcomm */
			pend->pc->next = NULL;
			pend->pc->number = portno;
			pend->pc->pif = pif;
			pend->pc->index = pif->inuse;
			pend->pc->num_outstanding = 0;
			comm_point_start_listening(pend->pc->cp, fd, -1);

			/* grab port in interface */
			pif->out[pif->inuse] = pend->pc;
			pif->avail_ports[my_port - pif->inuse] =
				pif->avail_ports[pif->avail_total-pif->inuse-1];
			pif->inuse++;
            ret = 1;
			break;
		}
		/* failed, already in use */
		verbose(VERB_QUERY, "port %d in use, trying another", portno);
		tries++;
		if(tries == MAX_PORT_RETRY) {
			log_err("failed to find an open port, drop msg");
			return 0;
		}
    }
#endif
#if 1
    /* grab fd */
    fd = socket_pair;
    if(fd == -1) {
        return 0;
    }
    pend->pc = outnet->unused_fds;
    outnet->unused_fds = pend->pc->next;
    /* setup portcomm */
    pend->pc->next = NULL;
    pend->pc->number = 0;
    pend->pc->pif = NULL;
    pend->pc->index = 0;
    pend->pc->num_outstanding = 0;
    comm_point_start_listening(pend->pc->cp, fd, -1);
    // pend->pc->cp->do_not_close = 1;
#endif
	log_assert(pend->pc);
	pend->pc->num_outstanding++;

	return 1;
}

static int
randomize_and_send_udp(struct pending* pend, sldns_buffer* packet, int timeout, void *http_data)
{
	struct timeval tv;
	struct outside_network* outnet = pend->sq->outnet;
    struct np_http_query_st *query_data = (struct np_http_query_st *)http_data;
    int fd_use = 0;

    struct outside_http_data_st *outside_data = 
        np_find_free_http_list(query_data->np_http_list, outnet);

	/* select id */
	if(!select_id(outnet, pend, packet)) {
		return 0;
	}
    // Add tasks to the thread pool
    verbose(VERB_ALGO, "pthread poll find outside_http_data ....");
    //  struct outside_http_data_st outside_data;
    if(outside_data->fd[0] == -1) {
        log_err("outside_data->fd : -1");
        return 0;
    }
    query_data->np_http_list->use_socket --;
    verbose(VERB_ALGO, "pthread poll start ....");
    outside_data->socket_mode = query_data->np_http_list->socket_mode;
    // http info
    memset(outside_data->http_query_url, 0, sizeof(outside_data->http_query_url));
    memcpy(outside_data->http_query_url, query_data->np_http_url, 
            strlen(query_data->np_http_url));
    outside_data->http_timeout = query_data->np_http_timeout;
    outside_data->http_ttl = query_data->np_http_ttl;
    // cname 
    memset(outside_data->qname, 0, sizeof(outside_data->qname));
    memcpy(outside_data->qname, query_data->qinfo->qname, 
            query_data->qinfo->qname_len);
    outside_data->qname_len = query_data->qinfo->qname_len;
    outside_data->query_id = pend->id;
    verbose(VERB_ALGO, "outside_data->query_id: %x, pend->id: %x", 
            outside_data->query_id, pend->id);
    memset(&(outside_data->mtr_input), 0, sizeof(struct np_mtr_input_st));
    memcpy(&(outside_data->mtr_input),
            query_data->mtr_input, sizeof(struct np_mtr_input_st));

	/* select src_if, port */
    /*
	if(addr_is_ip6(&pend->addr, pend->addrlen)) {
		if(!select_ifport(outnet, pend, 
			outnet->num_ip6, outnet->ip6_ifs,query_data->np_http_list->socket_pair[1]))
			return 0;
	} else 
    */
    {
		if(!(fd_use = select_ifport(outnet, pend, 
			outnet->num_ip4, outnet->ip4_ifs, outside_data->fd[0]))) {
            log_err("select_ifport() failed\n");
            outside_data->use = 0;
			return 0;
        }
	}
    // udp reuse
    if((!(pend->pc)) || (!(pend->pc->cp))) {
        outside_data->use = 0;
        return 0;
    }

    log_assert(pend->pc && pend->pc->cp);
    pend->pc->cp->callback = np_outnet_udp_cb;
    outside_data->use = 1;
    // test
    // create_http_pth((void *)(outside_data));
    if(thpool_add_work(query_data->np_http_list->pool,
            (void*)np_add_http_query_work,outside_data) < 0) {
        log_err("thpool_add_work() failed");
    }
    //log_err("add_work: id: %x, fd: %d, fd_1: %d",
      //      pend->id, outside_data->fd[0],
        //    outside_data->fd[1]);

#if 0
	/* send it over the commlink */
	if(!comm_point_send_udp_msg(pend->pc->cp, packet, 
		(struct sockaddr*)&pend->addr, pend->addrlen)) {
		portcomm_loweruse(outnet, pend->pc);
		return 0;
	}
#endif
	/* system calls to set timeout after sending UDP to make roundtrip
	   smaller. */
//#ifndef S_SPLINT_S
	tv.tv_sec = timeout/1000;
	tv.tv_usec = (timeout%1000)*1000;
//#endif
	comm_timer_set(pend->timer, &tv);

#ifdef USE_DNSTAP
	if(outnet->dtenv &&
	   (outnet->dtenv->log_resolver_query_messages ||
	    outnet->dtenv->log_forwarder_query_messages))
		dt_msg_send_outside_query(outnet->dtenv, &pend->addr, comm_udp,
		pend->sq->zone, pend->sq->zonelen, packet);
#endif
	return 1;
}

/** lower use count on pc, see if it can be closed */
static void
portcomm_loweruse(struct outside_network* outnet, struct port_comm* pc)
{
	struct port_if* pif;
	pc->num_outstanding--;
	if(pc->num_outstanding > 0) {
		return;
	}
	/* close it and replace in unused list */
	verbose(VERB_ALGO, "close of port %d", pc->number);
    /* not close fd for socketpair*/
    pc->cp->callback = outnet_udp_cb;
    pc->cp->do_not_close = 1;
	comm_point_close(pc->cp);
    pc->cp->do_not_close = 0;
#if 0
	pif = pc->pif;
	log_assert(pif->inuse > 0);
	pif->avail_ports[pif->avail_total - pif->inuse] = pc->number;
	pif->inuse--;
	pif->out[pc->index] = pif->out[pif->inuse];
	pif->out[pc->index]->index = pc->index;
#endif
	pc->next = outnet->unused_fds;
	outnet->unused_fds = pc;
}

/** try to send waiting UDP queries */
static void
np_outnet_send_wait_udp(struct outside_network* outnet)
{
	struct pending* pend;
	/* process waiting queries */
	while(outnet->udp_wait_first && outnet->unused_fds 
		&& !outnet->want_to_quit) {
		pend = outnet->udp_wait_first;
        if(pend && np_get_free_outside_http_list(pend->pkt+pend->pkt_len, outnet) < 0) {
            return ;
        }
		outnet->udp_wait_first = pend->next_waiting;
		if(!pend->next_waiting) outnet->udp_wait_last = NULL;
		sldns_buffer_clear(outnet->udp_buff);
		sldns_buffer_write(outnet->udp_buff, pend->pkt, pend->pkt_len);
		sldns_buffer_flip(outnet->udp_buff);

		if(!randomize_and_send_udp(pend, outnet->udp_buff,
			pend->timeout, pend->pkt+pend->pkt_len)) {
			/* callback error on pending */
			if(pend->cb) {
				fptr_ok(fptr_whitelist_pending_udp(pend->cb));
				(void)(*pend->cb)(outnet->unused_fds->cp, pend->cb_arg, 
					NETEVENT_CLOSED, NULL);
			}
			pending_delete(outnet, pend);
		}
		free(pend->pkt); /* freeing now makes get_mem correct */
		pend->pkt = NULL; 
		pend->pkt_len = 0;
	}
}
#if 0
void
pending_udp_timer_delay_cb(void* arg)
{
	struct pending* p = (struct pending*)arg;
	struct outside_network* outnet = p->outnet;
	verbose(VERB_ALGO, "timeout udp with delay");
	portcomm_loweruse(outnet, p->pc);
	pending_delete(outnet, p);
	outnet_send_wait_udp(outnet);
}
#endif
void 
np_pending_udp_timer_cb(void *arg)
{
	struct pending* p = (struct pending*)arg;
	struct outside_network* outnet = p->outnet;
	/* it timed out */
	verbose(VERB_ALGO, "np timeout udp");
    log_err("udp_timer_timeout: fd: %d, id: %x", p->pc->cp->fd, p->id);
    if(p->sq->qbuf) {
        log_err("udp_content: %*s", p->sq->qbuflen, p->sq->qbuf);
    }
	if(p->cb) {
		fptr_ok(fptr_whitelist_pending_udp(p->cb));
		(void)(*p->cb)(p->pc->cp, p->cb_arg, NETEVENT_TIMEOUT, NULL);
	}
#if 0
	/* if delayclose, keep port open for a longer time.
	 * But if the udpwaitlist exists, then we are struggling to
	 * keep up with demand for sockets, so do not wait, but service
	 * the customer (customer service more important than portICMPs) */
	if(outnet->delayclose && !outnet->udp_wait_first) {
		p->cb = NULL;
        log_err("pending_udp_timer_delaly_cb() ...");
		p->timer->callback = &pending_udp_timer_delay_cb;
		comm_timer_set(p->timer, &outnet->delay_tv);
		return;
	}
#endif
	portcomm_loweruse(outnet, p->pc);
	pending_delete(outnet, p);
	np_outnet_send_wait_udp(outnet);
}

int 
np_outnet_udp_cb(struct comm_point* c, void* arg, int error,
	struct comm_reply *reply_info)
{
	struct outside_network* outnet = (struct outside_network*)arg;
	struct pending key;
	struct pending* p;
	verbose(VERB_ALGO, "netpas answer cb");

	if(error != NETEVENT_NOERROR) {
		verbose(VERB_QUERY, "outnetudp got udp error %d", error);
		return 0;
	}
	if(sldns_buffer_limit(c->buffer) < LDNS_HEADER_SIZE) {
		verbose(VERB_QUERY, "outnetudp udp too short");
		return 0;
	}
	log_assert(reply_info);

	/* setup lookup key */
	key.id = (unsigned)LDNS_ID_WIRE(sldns_buffer_begin(c->buffer));
	((struct sockaddr_in*)&(key.addr))->sin_family = AF_INET;

	((struct sockaddr_in*)&(key.addr))->sin_port = htons(53);
	((struct sockaddr_in*)&(key.addr))->sin_addr.s_addr = inet_addr("127.0.0.1");

	// memcpy(&key.addr, &reply_info->addr, reply_info->addrlen);
	key.addrlen = sizeof(struct sockaddr_in);
	verbose(VERB_ALGO, "Incoming reply id = %4.4x", key.id);
    /*
	log_addr(VERB_ALGO, "Incoming reply addr =", 
		&reply_info->addr, reply_info->addrlen);*/

	/* find it, see if this thing is a valid query response */
	verbose(VERB_ALGO, "lookup size is %d entries", (int)outnet->pending->count);
	p = (struct pending*)rbtree_search(outnet->pending, &key);
    // log_err("p->id: %x,key.id: %x", p->id, key.id);
	if(!p) {
		verbose(VERB_QUERY, "received unwanted or unsolicited udp reply dropped.");
		log_buf(VERB_ALGO, "dropped message", c->buffer);
		outnet->unwanted_replies++;
		if(outnet->unwanted_threshold && ++outnet->unwanted_total 
			>= outnet->unwanted_threshold) {
			log_warn("unwanted reply total reached threshold (%u)"
				" you may be under attack."
				" defensive action: clearing the cache",
				(unsigned)outnet->unwanted_threshold);
			fptr_ok(fptr_whitelist_alloc_cleanup(
				outnet->unwanted_action));
			(*outnet->unwanted_action)(outnet->unwanted_param);
			outnet->unwanted_total = 0;
		}
		return 0;
	}

	verbose(VERB_ALGO, "received udp reply.");
	log_buf(VERB_ALGO, "udp message", c->buffer);
	if(p->pc->cp != c) {
        log_err("p->pc->cp != c error");
		verbose(VERB_QUERY, "received reply id,addr on wrong port. "
			"dropped.");
		outnet->unwanted_replies++;
		if(outnet->unwanted_threshold && ++outnet->unwanted_total 
			>= outnet->unwanted_threshold) {
			log_warn("unwanted reply total reached threshold (%u)"
				" you may be under attack."
				" defensive action: clearing the cache",
				(unsigned)outnet->unwanted_threshold);
			fptr_ok(fptr_whitelist_alloc_cleanup(
				outnet->unwanted_action));
			(*outnet->unwanted_action)(outnet->unwanted_param);
			outnet->unwanted_total = 0;
		}
		return 0;
	}
	comm_timer_disable(p->timer);
	verbose(VERB_ALGO, "outnet handle udp reply");
	/* delete from tree first in case callback creates a retry */
	(void)rbtree_delete(outnet->pending, p->node.key);
	if(p->cb) {
		fptr_ok(fptr_whitelist_pending_udp(p->cb));
		(void)(*p->cb)(p->pc->cp, p->cb_arg, NETEVENT_NOERROR, reply_info);
	}
	portcomm_loweruse(outnet, p->pc);
	pending_delete(NULL, p);
	np_outnet_send_wait_udp(outnet);
    //log_err("udp_recvied test result");
	return 0;
}
#if 0
int 
np_outnet_tcp_cb(struct comm_point* c, void* arg, int error,
	struct comm_reply *reply_info)
{
	struct pending_tcp* pend = (struct pending_tcp*)arg;
	struct outside_network* outnet = pend->query->outnet;
	verbose(VERB_ALGO, "netpas outnettcp cb");
	if(error != NETEVENT_NOERROR) {
		verbose(VERB_QUERY, "outnettcp got tcp error %d", error);
		/* pass error below and exit */
	} else {
		/* check ID */
		if(sldns_buffer_limit(c->buffer) < sizeof(uint16_t) ||
			LDNS_ID_WIRE(sldns_buffer_begin(c->buffer))!=pend->id) {
			log_addr(VERB_QUERY, 
				"outnettcp: bad ID in reply, from:",
				&pend->query->addr, pend->query->addrlen);
			error = NETEVENT_CLOSED;
		}
	}
	// fptr_ok(fptr_whitelist_pending_tcp(pend->query->cb));
	(void)(*pend->query->cb)(c, pend->query->cb_arg, error, reply_info);
	decommission_pending_tcp(outnet, pend);
	return 0;
}
#endif
/* see if packet is edns malformed; got zeroes at start.
 * This is from servers that return malformed packets to EDNS0 queries,
 * but they return good packets for nonEDNS0 queries.
 * We try to detect their output; without resorting to a full parse or
 * check for too many bytes after the end of the packet. */
static int
packet_edns_malformed(struct sldns_buffer* buf, int qtype)
{
	size_t len;
	if(sldns_buffer_limit(buf) < LDNS_HEADER_SIZE)
		return 1; /* malformed */
	/* they have NOERROR rcode, 1 answer. */
	if(LDNS_RCODE_WIRE(sldns_buffer_begin(buf)) != LDNS_RCODE_NOERROR)
		return 0;
	/* one query (to skip) and answer records */
	if(LDNS_QDCOUNT(sldns_buffer_begin(buf)) != 1 ||
		LDNS_ANCOUNT(sldns_buffer_begin(buf)) == 0)
		return 0;
	/* skip qname */
	len = dname_valid(sldns_buffer_at(buf, LDNS_HEADER_SIZE),
		sldns_buffer_limit(buf)-LDNS_HEADER_SIZE);
	if(len == 0)
		return 0;
	if(len == 1 && qtype == 0)
		return 0; /* we asked for '.' and type 0 */
	/* and then 4 bytes (type and class of query) */
	if(sldns_buffer_limit(buf) < LDNS_HEADER_SIZE + len + 4 + 3)
		return 0;

	/* and start with 11 zeroes as the answer RR */
	/* so check the qtype of the answer record, qname=0, type=0 */
	if(sldns_buffer_at(buf, LDNS_HEADER_SIZE+len+4)[0] == 0 &&
	   sldns_buffer_at(buf, LDNS_HEADER_SIZE+len+4)[1] == 0 &&
	   sldns_buffer_at(buf, LDNS_HEADER_SIZE+len+4)[2] == 0)
		return 1;
	return 0;
}

int 
np_serviced_udp_callback(struct comm_point* c, void* arg, int error,
        struct comm_reply* rep)
{
	struct serviced_query* sq = (struct serviced_query*)arg;
	struct outside_network* outnet = sq->outnet;
	struct timeval now = *sq->outnet->now_tv;
	int fallback_tcp = 0;
    if(error == NETEVENT_TIMEOUT)
        log_err("np_serviced_udp_callback() error: %d\n", error);
	sq->pending = NULL; /* removed after callback */
	if(error == NETEVENT_TIMEOUT) {
		int rto = 0;
		if(sq->status == serviced_query_PROBE_EDNS) {
			/* non-EDNS probe failed; we do not know its status,
			 * keep trying with EDNS, timeout may not be caused
			 * by EDNS. */
			sq->status = serviced_query_UDP_EDNS;
		}
		if(sq->status == serviced_query_UDP_EDNS && sq->last_rtt < 5000) {
			/* fallback to 1480/1280 */
			sq->status = serviced_query_UDP_EDNS_FRAG;
			log_name_addr(VERB_ALGO, "try edns1xx0", sq->qbuf+10,
				&sq->addr, sq->addrlen);
			if(!serviced_udp_send(sq, c->buffer, NULL)) { // todo
				serviced_callbacks(sq, NETEVENT_CLOSED, c, rep);
			}
			return 0;
		}
		if(sq->status == serviced_query_UDP_EDNS_FRAG) {
			/* fragmentation size did not fix it */
			sq->status = serviced_query_UDP_EDNS;
		}
		sq->retry++;
		if(!(rto=infra_rtt_update(outnet->infra, &sq->addr, sq->addrlen,
			sq->zone, sq->zonelen, sq->qtype, -1, sq->last_rtt,
			(time_t)now.tv_sec)))
			log_err("out of memory in UDP exponential backoff");
		if(sq->retry < OUTBOUND_UDP_RETRY) {
			log_name_addr(VERB_ALGO, "retry query", sq->qbuf+10,
				&sq->addr, sq->addrlen);
			if(!serviced_udp_send(sq, c->buffer, NULL)) { //todo
				serviced_callbacks(sq, NETEVENT_CLOSED, c, rep);
			}
			return 0;
		}
		if(rto >= RTT_MAX_TIMEOUT) {
			fallback_tcp = 1;
			/* UDP does not work, fallback to TCP below */
		} else {
			serviced_callbacks(sq, NETEVENT_TIMEOUT, c, rep);
			return 0;
		}
	} else if(error != NETEVENT_NOERROR) {
		/* udp returns error (due to no ID or interface available) */
		serviced_callbacks(sq, error, c, rep);
		return 0;
	}
#ifdef USE_DNSTAP
	if(error == NETEVENT_NOERROR && outnet->dtenv &&
	   (outnet->dtenv->log_resolver_response_messages ||
	    outnet->dtenv->log_forwarder_response_messages))
		dt_msg_send_outside_response(outnet->dtenv, &sq->addr, c->type,
		sq->zone, sq->zonelen, sq->qbuf, sq->qbuflen,
		&sq->last_sent_time, sq->outnet->now_tv, c->buffer);
#endif
	if(!fallback_tcp) {
	    if( (sq->status == serviced_query_UDP_EDNS 
	        ||sq->status == serviced_query_UDP_EDNS_FRAG)
		&& (LDNS_RCODE_WIRE(sldns_buffer_begin(c->buffer)) 
			== LDNS_RCODE_FORMERR || LDNS_RCODE_WIRE(
			sldns_buffer_begin(c->buffer)) == LDNS_RCODE_NOTIMPL
		    || packet_edns_malformed(c->buffer, sq->qtype)
			)) {
		/* try to get an answer by falling back without EDNS */
		verbose(VERB_ALGO, "serviced query: attempt without EDNS");
		sq->status = serviced_query_UDP_EDNS_fallback;
		sq->retry = 0;
		if(!serviced_udp_send(sq, c->buffer, NULL)) {
			serviced_callbacks(sq, NETEVENT_CLOSED, c, rep);
		}
		return 0;
	    } else if(sq->status == serviced_query_PROBE_EDNS) {
		/* probe without EDNS succeeds, so we conclude that this
		 * host likely has EDNS packets dropped */
		log_addr(VERB_DETAIL, "timeouts, concluded that connection to "
			"host drops EDNS packets", &sq->addr, sq->addrlen);
		/* only store noEDNS in cache if domain is noDNSSEC */
		if(!sq->want_dnssec)
		  if(!infra_edns_update(outnet->infra, &sq->addr, sq->addrlen,
			sq->zone, sq->zonelen, -1, (time_t)now.tv_sec)) {
			log_err("Out of memory caching no edns for host");
		  }
		sq->status = serviced_query_UDP;
	    } else if(sq->status == serviced_query_UDP_EDNS && 
		!sq->edns_lame_known) {
		/* now we know that edns queries received answers store that */
		log_addr(VERB_ALGO, "serviced query: EDNS works for",
			&sq->addr, sq->addrlen);
		if(!infra_edns_update(outnet->infra, &sq->addr, sq->addrlen, 
			sq->zone, sq->zonelen, 0, (time_t)now.tv_sec)) {
			log_err("Out of memory caching edns works");
		}
		sq->edns_lame_known = 1;
	    } else if(sq->status == serviced_query_UDP_EDNS_fallback &&
		!sq->edns_lame_known && (LDNS_RCODE_WIRE(
		sldns_buffer_begin(c->buffer)) == LDNS_RCODE_NOERROR || 
		LDNS_RCODE_WIRE(sldns_buffer_begin(c->buffer)) == 
		LDNS_RCODE_NXDOMAIN || LDNS_RCODE_WIRE(sldns_buffer_begin(
		c->buffer)) == LDNS_RCODE_YXDOMAIN)) {
		/* the fallback produced a result that looks promising, note
		 * that this server should be approached without EDNS */
		/* only store noEDNS in cache if domain is noDNSSEC */
		if(!sq->want_dnssec) {
		  log_addr(VERB_ALGO, "serviced query: EDNS fails for",
			&sq->addr, sq->addrlen);
		  if(!infra_edns_update(outnet->infra, &sq->addr, sq->addrlen,
			sq->zone, sq->zonelen, -1, (time_t)now.tv_sec)) {
			log_err("Out of memory caching no edns for host");
		  }
		} else {
		  log_addr(VERB_ALGO, "serviced query: EDNS fails, but "
		  	"not stored because need DNSSEC for", &sq->addr,
			sq->addrlen);
		}
		sq->status = serviced_query_UDP;
	    }
	    if(now.tv_sec > sq->last_sent_time.tv_sec ||
		(now.tv_sec == sq->last_sent_time.tv_sec &&
		now.tv_usec > sq->last_sent_time.tv_usec)) {
		/* convert from microseconds to milliseconds */
		int roundtime = ((int)(now.tv_sec - sq->last_sent_time.tv_sec))*1000
		  + ((int)now.tv_usec - (int)sq->last_sent_time.tv_usec)/1000;
		verbose(VERB_ALGO, "measured roundtrip at %d msec", roundtime);
		log_assert(roundtime >= 0);
		/* in case the system hibernated, do not enter a huge value,
		 * above this value gives trouble with server selection */
		if(roundtime < 60000) {
		    if(!infra_rtt_update(outnet->infra, &sq->addr, sq->addrlen, 
			sq->zone, sq->zonelen, sq->qtype, roundtime,
			sq->last_rtt, (time_t)now.tv_sec))
			log_err("out of memory noting rtt.");
		}
	    }
	} /* end of if_!fallback_tcp */
	/* perform TC flag check and TCP fallback after updating our
	 * cache entries for EDNS status and RTT times */
	if(LDNS_TC_WIRE(sldns_buffer_begin(c->buffer)) || fallback_tcp) {
		/* fallback to TCP */
		/* this discards partial UDP contents */
		if(sq->status == serviced_query_UDP_EDNS ||
			sq->status == serviced_query_UDP_EDNS_FRAG ||
			sq->status == serviced_query_UDP_EDNS_fallback)
			/* if we have unfinished EDNS_fallback, start again */
			sq->status = serviced_query_TCP_EDNS;
		else	sq->status = serviced_query_TCP;
		serviced_tcp_initiate(sq, c->buffer);
		return 0;
	}
	/* yay! an answer */
	serviced_callbacks(sq, error, c, rep);
	return 0;
}

/** remove callback from list */
static void
callback_list_remove(struct serviced_query* sq, void* cb_arg)
{
	struct service_callback** pp = &sq->cblist;
	while(*pp) {
		if((*pp)->cb_arg == cb_arg) {
			struct service_callback* del = *pp;
			*pp = del->next;
			free(del);
			return;
		}
		pp = &(*pp)->next;
	}
}

static void 
np_outnet_serviced_query_stop(struct serviced_query* sq, void* cb_arg)
{
	if(!sq) 
		return;
	callback_list_remove(sq, cb_arg);
	/* if callbacks() routine scheduled deletion, let it do that */
	if(!sq->cblist && !sq->to_be_deleted) {
		(void)rbtree_delete(sq->outnet->serviced, sq);
		serviced_delete(sq); 
	}
}

void 
np_outbound_list_init(struct outbound_list* list)
{
	list->first = NULL;
}

void 
np_outbound_list_clear(struct outbound_list* list)
{
	struct outbound_entry *p, *np;
	p = list->first;
	while(p) {
		np = p->next;
		np_outnet_serviced_query_stop(p->qsent, p);
		/* in region, no free needed */
		p = np;
	}
	outbound_list_init(list);
}

void 
np_outbound_list_insert(struct outbound_list* list, struct outbound_entry* e)
{
	if(list->first)
		list->first->prev = e;
	e->next = list->first;
	e->prev = NULL;
	list->first = e;
}

void 
np_outbound_list_remove(struct outbound_list* list, struct outbound_entry* e)
{
	if(!e)
		return;
	np_outnet_serviced_query_stop(e->qsent, e);
	if(e->next)
		e->next->prev = e->prev;
	if(e->prev)
		e->prev->next = e->next;
	else	list->first = e->next;
	/* in region, no free needed */
}

