#ifndef NP_HTTP_MOD_NP_HTTP_H
#define NP_HTTP_MOD_NP_HTTP_H

#include "netpas_http_mod/np_common.h"
#include <stdint.h>

#define NP_HTTP_ASN_LEN 20
#define NP_HTTP_COUNTRY_NAME_LEN 20
#define NP_HTTP_CITY_NAME_LEN 20
#define NP_HTTP_CARRIER_NAME_LEN 20


struct np_mtr_geo_st {
    double lot;
    double lon;
};

struct np_mtr_output_st {
    uint8_t ip[NP_COMMON_IP_LEN];           // ip addr
    uint8_t asn[NP_HTTP_ASN_LEN];           // ASN info
    uint8_t country[NP_HTTP_COUNTRY_NAME_LEN];      // country info
    uint8_t city[NP_HTTP_CITY_NAME_LEN];            // city info
    uint8_t carrier[NP_HTTP_CARRIER_NAME_LEN];      // Operator info
    struct np_mtr_geo_st mtr_geo;                   // geo info
};

typedef struct
{
    unsigned char *data;
    size_t len;
    size_t size;
} np_string;

typedef enum http_method {
    GET = 1,
    POST
}method;

/**
 * @brief Perform curl transfer tasks
 * @param [in] const char *url      url addr
 * @param [in] np_string *mydata    Contains transmission data
 * @param [in] unsigned int timeout Execution timeout time
 * @param [in] method post          http query method(post or get)
 * @return int 0 success -1 failure
 */
int np_curl (const char *url,
    np_string *mydata,
    unsigned int timeout,
    method post);

/**
 * @brief Convert mtr data to json format
 * @param [in] struct np_mtr_input_st *mtr_data Enter mtr data
 * @return char * success:Return json string.failure:NULL
 */
char *np_str2json(struct np_mtr_input_st *mtr_data);

/**
 * @brief Json data is converted to 'struct np_mtr_output_st' format
 * @param [in] const char *mtr_data     Json format string
 * @param [out] struct np_mtr_output_st *mtr_out Query result conversion
 * @return int8_t 0 success ,-1 failure
 */
int8_t np_json2str(const char *mtr_data, struct np_mtr_output_st *mtr_out);

#endif
