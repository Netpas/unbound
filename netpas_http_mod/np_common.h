#ifndef _NP_HTTP_MOD_NP_COMMON_H
#define _NP_HTTP_MOD_NP_COMMON_H

#include <stdint.h>
#define NP_COMMON_IP_LEN 32
#define NP_COMMON_QUERY_FROM_LEN 20
#define NP_COMMON_HTTP_URL_LEN 255
#define NP_COMMON_QNAME_LEN 512

#define NP_COMMON_MAX_THREAD_POOL 1000
#define NP_COMMON_DEFAULT_THREAD_POOL 50

#include "netpas_http_mod/C-Thread-Pool/thpool.h"

struct np_mtr_input_st{
    char ip[NP_COMMON_IP_LEN];
    char from[NP_COMMON_QUERY_FROM_LEN];
    int32_t hop;
};

struct outside_http_data_st {
    struct outside_http_data_st *next;
    pthread_mutex_t use_mutex;
    uint8_t use;
    // reply pkg content
    uint16_t query_id;
    uint8_t qname[NP_COMMON_QNAME_LEN];
    uint16_t qname_len;
    // socket pair
    int32_t cur_fd;
    int8_t socket_mode;
    int32_t fd[2];
    // http param
    char http_query_url[NP_COMMON_HTTP_URL_LEN];
    int http_timeout;
    uint32_t http_ttl; // set every dns pack ttl
    // http query pararm
    struct np_mtr_input_st mtr_input;

    void *unused_fds;
};

// Prevent reuse of malloc and improve performance
struct np_outside_http_list_st {
    //pthread_mutex_t rw_mutex;
    struct outside_http_data_st free;   // free struct
    struct outside_http_data_st working; // is using
    // udp mode
    int8_t socket_mode;
    int32_t use_socket;
    int32_t queue_len;
    threadpool pool;
};


#endif

