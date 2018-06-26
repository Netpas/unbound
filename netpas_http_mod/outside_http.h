#ifndef NP_HTTP_MOD_OUTSIDE_HTTP_H
#define NP_HTTP_MOD_OUTSIDE_HTTP_H

#define NP_OUTSIDE_HTTP_FLAGS 0x8180
#define NP_OUTSIDE_HTTP_TYPE_TXT 16
#define NP_OUTSIDE_HTTP_CNAME 0xc00c
#define NP_OUTSIDE_HTTP_CLASS 1
#define NP_OUTSIDE_HTTP_QUERY_TTL 604800

/**
 * @brief Every http query task callback
 * @param [in] void *arg Can be any data
 * @return void * Can be any data
 */
void *np_add_http_query_work(void *arg);
// test
// int create_http_pth(void *arg);

#endif
