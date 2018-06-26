#include <pthread.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "netpas_http_mod/outside_http.h"
#include "netpas_http_mod/np_http.h"
#include "netpas_http_mod/np_common.h"
// test
/*
#include "np_http.h"
#include "outside_http.h"
*/
#define MYDATA_SIZE 1024

static int8_t np_rep_dns_pkg(int32_t fd, const char *buff, int32_t len);
static uint8_t build_dns_rep_pkg(struct outside_http_data_st *http_data, \
        struct np_mtr_output_st *mtr_output, \
        char *buff, uint32_t ttl, int8_t mode, int8_t socket_mode);

void *np_add_http_query_work(void *arg)
{
    struct outside_http_data_st *http_data = (struct outside_http_data_st *)arg;
    char *json_data = NULL;
    np_string mydata;
    int ret = 0;
    uint8_t  buff[4096] = {};
    struct np_mtr_output_st mtr_output;
    int32_t w_len = 0;
    int8_t status = 0;
    uint8_t curl_data[MYDATA_SIZE] = {};

    mydata.data = curl_data;
    mydata.size = MYDATA_SIZE;
    bzero(buff, sizeof(buff));

    json_data = np_str2json(&(http_data->mtr_input));
    if(json_data == NULL) {
        status = 1;
        goto end;
    }

    if(strlen(json_data) < mydata.size) {
        strncpy(mydata.data, json_data, strlen(json_data));
        mydata.len = strlen(json_data);
    }
    else {
        status = 1;
        goto end;
    }
    // http query
    //printf("http_data->http_query_url: %s\n",
    //        http_data->http_query_url);
    ret = np_curl(http_data->http_query_url, &mydata,
            http_data->http_timeout, POST);
    if(ret != 0) {
        // printf("np_curl() ret: %d\n", ret);
        status = 1;
        goto end;
    }

    // pase json data
    if(np_json2str(mydata.data, &mtr_output) < 0) {
        status = 1;
        goto end;
    }
    w_len = build_dns_rep_pkg(http_data, &mtr_output, buff,
            http_data->http_ttl, 0, http_data->socket_mode);
    if(w_len == 0) {
        status = 1;
        goto end;
    }
end:
    if(status == 1) {
        w_len = build_dns_rep_pkg(http_data, &mtr_output, buff,
            0, 1, http_data->socket_mode);
    }

    if(json_data != NULL) {
        free(json_data);
    }

    if(np_rep_dns_pkg(http_data->fd[1], buff, w_len) < 0) {
        // printf("write() failed\n");
    }
    pthread_mutex_lock(&(http_data->use_mutex));
    http_data->use = 0;
    pthread_mutex_unlock(&(http_data->use_mutex));

    return NULL;
}


static int8_t np_rep_dns_pkg(int32_t fd, const char *buff, int32_t len)
{
    int32_t ret = 0;
    int32_t w_len = 0;

    if(fd < 0 && len <= 0) {
        return -1;
    }

    while(1) {
        ret = write(fd, buff+w_len, len);
        if(ret < 0) {
            return -1;
        }
        if(len - ret <= 0) {
            break;
        }
        w_len += ret;
        len -= ret;
    }

    return 0;
}

static uint8_t build_dns_rep_pkg(struct outside_http_data_st *http_data, \
        struct np_mtr_output_st *mtr_output, \
        char *buff, uint32_t ttl, int8_t mode, int8_t socket_mode)
{
    int len = 0;
    uint16_t tmp = 0;
    uint32_t tmp_ttl = 0;
    char txt_data[255] = {};
    uint8_t txt_len = 0;

    if(http_data == NULL || mtr_output == NULL || buff == NULL) {
        return 0;
    }
    // ASN | IP-Prefix | Country-Code | Register | 
    // Allocation-Date | City | Carrier | Geo
    if(mode == 0) {
        sprintf(txt_data, "%s||%s||%s||%s|%lf,%lf", \
                mtr_output->asn, mtr_output->country,\
                mtr_output->city, \
                mtr_output->carrier, \
                mtr_output->mtr_geo.lot, \
                mtr_output->mtr_geo.lon);
        txt_len = strlen(txt_data);

        if(txt_len > 255) {
            return 0;
        }
    }

    if(socket_mode > 0) {
        len += 2;
    }
    // id
    tmp = htons(http_data->query_id);
    memcpy(buff+len,(void *)&(tmp), 2);
    len += 2;
    // flags
    tmp = htons(NP_OUTSIDE_HTTP_FLAGS);
    memcpy(buff+len,(void *)&(tmp), 2);
    len += 2;

    // questions
    tmp = htons(1);
    memcpy(buff+len,(void *)&(tmp), 2);
    len += 2;
    // answer
    if(mode == 1) {
        tmp = htons(0);
    }
    memcpy(buff+len,(void *)&(tmp), 2);
    len += 2;

    // authority
    tmp = htons(0);
    memcpy(buff+len,(void *)&(tmp), 2);
    len += 2;
    // additional
    memcpy(buff+len,(void *)&(tmp), 2);
    len += 2;
    // question start 
    // name
    memcpy(buff+len,(void *)(http_data->qname), http_data->qname_len);
    len += http_data->qname_len;

    // type
    tmp = htons(NP_OUTSIDE_HTTP_TYPE_TXT);
    memcpy(buff+len,(void *)&(tmp), 2);
    len += 2;
    // class
    tmp = htons(NP_OUTSIDE_HTTP_CLASS);
    memcpy(buff+len,(void *)&(tmp), 2);
    len += 2;

    // answer
    // name
    if(mode == 0) {
        tmp = htons(0xc00c);
        memcpy(buff+len,(void *)&(tmp), 2);
        len += 2;
        // type
        tmp = htons(NP_OUTSIDE_HTTP_TYPE_TXT);
        memcpy(buff+len,(void *)&(tmp), 2);
        len += 2;
        // class
        tmp = htons(NP_OUTSIDE_HTTP_CLASS);
        memcpy(buff+len,(void *)&(tmp), 2);
        len += 2;
        // ttl
        if(ttl == 0) {
            tmp_ttl = htonl(NP_OUTSIDE_HTTP_QUERY_TTL);
        }
        else {
            tmp_ttl = htonl(ttl);
        }
        memcpy(buff+len,(void *)&(tmp_ttl), 4);
        len += 4;
        // data_len
        tmp = htons(txt_len + 1);
        memcpy(buff+len,(void *)&(tmp), 2);
        len += 2;
        // txt_len
        memcpy(buff+len,(void *)&(txt_len), 1);
        len += 1;
        // txt_data
        memcpy(buff+len,(void *)txt_data, txt_len);
        len += txt_len;
    }
    // tcp set package length
    if(socket_mode > 0) {
        tmp = htons(len-2);
        memcpy(buff, (void *)&tmp, 2);
    }

    return len;
}

#if 0
int create_http_pth(void *arg)
{
    pthread_t thread;
    pthread_create(&thread, NULL, np_add_http_query_work, arg);
    pthread_detach(thread);

    return 0;
}

void *thread_function(void *arg)
{
    int32_t w_len = 0;
    int32_t ret = 0;
    struct outside_http_data_st *http_data = (struct outside_http_data_st *)arg;
    char *json_data = NULL;
    np_string mydata;
    uint8_t  buff[4096] = {};

    mydata.data = calloc(1, 1024);
    mydata.size = 1024;
	// verbose(VERB_ALGO, "thread_function start ...........");

    struct np_mtr_input_st mtr_input;
    struct np_mtr_output_st mtr_output;

    bzero(buff, sizeof(buff));
    // 产生 mtr_input 结构体
    // fprintf(stdout, "test start ....\n");
    ret = parse_query_answer(http_data, &mtr_input);
    if(ret == -1) {
        // fprintf(stdout, "parse_query_answer() failed\n");
        goto end;
    }
    // 生成json数据
    json_data = np_str2json(&mtr_input);
    if(json_data == NULL) {
        goto end;
       //  printf("np_str2json() failed \n");
    }

    //fprintf(stdout, "json_data: %s, len: %d\n", json_data, strlen(json_data));
    // fprintf(stdout, "http_url: %s\n", http_data->http_query_url);

    strncpy(mydata.data, json_data, strlen(json_data));
    mydata.len = strlen(json_data);
    // send http
    // ret = np_curl("http://127.0.0.1:80/hello", &mydata, 2, POST);
    ret = np_curl(http_data->http_query_url, &mydata,
            http_data->http_timeout, POST);
    if(ret != 0) {
        // fprintf(stdout, "np_curl() ret: %d\n", ret);
        goto end;
    }
    fprintf(stdout, "mydata: %s\n", mydata.data);

    free(json_data);

    // 解析数据
    np_json2str(mydata.data, &mtr_output);    
    
    // printf("http data: %s\n", mydata.data);
    // reply socket
#if 1
    w_len = build_dns_rep_pkg(http_data, &mtr_output, buff);
    if(w_len == 0) {
        // 容错
    }
    np_rep_dns_pkg(http_data->fd, buff, w_len);
#endif
    free(mydata.data);
end:
    close(http_data->fd);

    return NULL;
}


int main(void)
{
    char tmp[512] = { 0x01, '3',
        0x03 , 'm' , 't' , 'r',
        0x02 , '7' , '8',
        0x02 , '5' , '6',
        0x02 , '3' , '4',
        0x02 , '1' , '2',
        0x02 , 'i' , 'p',
        0x10 , 'x' , 'e', 'l' , 'e' , 'r' , 'a' , 't' , 'e',
        0x02 , 'a' , 'i', 0x00

    };
    char domain[20] = {
        0x02 , 'i' , 'p',
        0x10 , 'x' , 'e', 'l' , 'e' , 'r' , 'a' , 't' , 'e',
        0x02 , 'a' , 'i', 0x00
    };
    struct outside_http_data_st http_data;

    strncpy((http_data.auth_domain), domain, 16);
    strncpy((http_data.url), tmp, 34);
    http_data.url_len = 34;
    http_data.id = 0x2345;
    http_data.fd = 1;
    
    create_http_pth((void *) &http_data);

    sleep(5);

    return 0;
}

#endif

