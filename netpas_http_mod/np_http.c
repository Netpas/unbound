#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>

#include "netpas_http_mod/cJSON/cJSON.h"
#include "netpas_http_mod/np_http.h"
#if 0
#include "cJSON/cJSON.h"
#include "np_http.h"
#endif


/**
 * @brief Curl data processing callback function
 * @param [in] char *ptr Point to received data，data size:(size*nmemb)
 * @param [in] size_t size  
 * @param [in] size_t nmemb 
 * @param [in] void *stream     User parameters
 * @return size_t recvived data size
 */
static size_t writefunc (char *ptr, size_t size, size_t nmemb, void *stream)
{
    np_string *mydata  = (np_string *)stream;
    size_t     new_len = mydata->len + size * nmemb;
    // fprintf(stdout, "%s", ptr);
    if (new_len >= mydata->size) {
        return 0;
    }
    memcpy(mydata->data + (mydata->len), ptr, size * nmemb);
    mydata->data[new_len] = '\0';
    mydata->len           = new_len;

    return (size * nmemb);
}

/**
 * @brief Perform curl transfer tasks
 * @param [in] const char *url      url addr
 * @param [in] np_string *mydata    Contains transmission data
 * @param [in] unsigned int timeout Execution timeout time
 * @param [in] method post          http method(post or get)
 * @return int 0 success -1 failure
 */
int np_curl (const char *url,
    np_string *mydata,
    unsigned int timeout,
    method post)
{
    CURL *curl;
    CURLcode res;
    size_t   datalen = 0;
    char     get_url[255];
    char    *esc_data  = NULL;
    char    *esc_param = NULL;  // http post operate string
    // struct curl_slist *headers = NULL;

    curl = curl_easy_init();
    //fprintf(stdout, "curl_easy_init() \n");
    if (curl) {
        snprintf(get_url, sizeof(get_url), "%s", url);

        // http get method
        switch(post) {
            case GET:
                if (mydata->len != 0) {
                    esc_data = curl_easy_escape(curl, mydata->data, 0);

                    if (esc_data) {
                        datalen = strlen(esc_data);
                    }
                    else {
                        curl_easy_cleanup(curl);
                        //fprintf(stdout, "curl_easy_cleanup() \n");
                        return -1;
                    }
                }

                strcat(get_url, "?o=");
                strcat(get_url, esc_data);
                break;
            case POST:
                //fprintf(stdout, "POST start ... \n");
                datalen = mydata->len;
                esc_param = (char *)malloc(datalen + 1);

                if (!esc_param) {
                    curl_easy_cleanup(curl);
                    //fprintf(stdout, "curl_easy_init()  post\n");
                    return -1;
                }
                sprintf(esc_param, "%s", mydata->data);
                break;
            default:
                break;
        }

        if (esc_data)
            curl_free(esc_data);

        // Empty the cache
        memset(mydata->data, 0, mydata->size);
        mydata->len = 0;

        // set curl pararms
        // headers = curl_slist_append(headers, "User-Agent: LetsVPN");
        //debug
        //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl, CURLOPT_URL, get_url);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, mydata);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        // curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        if (post) {
            curl_easy_setopt(curl, CURLOPT_POST, 1);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, esc_param);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, datalen);
        }

        // Execute curl
        res = curl_easy_perform(curl);

        free(esc_param);
        // curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        if (res != CURLE_OK) {
            // fprintf(stdout, "curl_easy_cleanup() .....res: %d\n", res);
            return -1;
        }
        return 0;
    }

    //fprintf(stdout, "curl_easy_init() failed\n");
    return -1;
}

char *np_str2json(struct np_mtr_input_st *mtr_data)
{
    /*
     * generate json format
     *{
     * "ip": "1.1.1.1",
     * "from": "mtr",
     * "hop": 3
     *}
     */
    cJSON *root = NULL;

    cJSON *ip = NULL;
    cJSON *from = NULL;
    cJSON *hop = NULL;
    char *string = NULL;

    if(mtr_data == NULL) {
        return NULL;
    }

    root = cJSON_CreateObject();
    if(root == NULL) {
        goto END;
    }
    ip = cJSON_CreateString(mtr_data->ip);
    cJSON_AddItemToObject(root, "ip", ip);
    from = cJSON_CreateString(mtr_data->from);
    cJSON_AddItemToObject(root, "from", from);
    hop = cJSON_CreateNumber(mtr_data->hop);
    cJSON_AddItemToObject(root, "hop", hop);

    string = cJSON_Print(root);
    if(string == NULL) {
        goto END;
    }

END:
    cJSON_Delete(root);
    return string;
}

int8_t np_json2str(const char *mtr_data, struct np_mtr_output_st *mtr_out)
{
    const cJSON *ip = NULL;
    const cJSON *asn = NULL;
    const cJSON *country = NULL;
    const cJSON *city = NULL;
    const cJSON *carrier = NULL;
    const cJSON *geo = NULL;
    const cJSON *lot = NULL;
    const cJSON *lon = NULL;
    int status = 0;

    if(mtr_out == NULL || mtr_data == NULL) {
        return -1;
    }

    cJSON *root_json = cJSON_Parse(mtr_data);
    if(root_json == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            //fprintf(stderr, "Error before: %s\n", error_ptr);
        }
        return -1;
    }

    // ip parse
    ip = cJSON_GetObjectItemCaseSensitive(root_json, "ip");
    if (cJSON_IsString(ip) && (ip->valuestring != NULL)) {
        memcpy(mtr_out->ip,ip->valuestring, strlen(ip->valuestring));
        // printf("Checking monitor \"%s\"\n", ip->valuestring);
    }
    else {
        status = -1;
        goto end;
    }
    // asn parse
    asn = cJSON_GetObjectItemCaseSensitive(root_json, "asn");
    if (cJSON_IsString(asn) && (asn->valuestring != NULL)) {
        memcpy(mtr_out->asn,asn->valuestring, \
                strlen(asn->valuestring));
        // printf("Checking monitor \"%s\"\n", asn->valuestring);
    }
    else {
        status = -1;
        goto end;
    }
    
    // country
    country = cJSON_GetObjectItemCaseSensitive(root_json, "country");
    if (cJSON_IsString(country) && (country->valuestring != NULL)) {
        memcpy(mtr_out->country,country->valuestring, \
                strlen(country->valuestring));
        // printf("Checking monitor \"%s\"\n", country->valuestring);
    }
    else {
        status = -1;
        goto end;
    }
    // city
    city = cJSON_GetObjectItemCaseSensitive(root_json, "city");
    if (cJSON_IsString(city) && (city->valuestring != NULL)) {
        memcpy(mtr_out->city,city->valuestring, \
                strlen(city->valuestring));
        // printf("Checking monitor \"%s\"\n", city->valuestring);
    }
    else {
        status = -1;
        goto end;
    }
    // carrier
    carrier = cJSON_GetObjectItemCaseSensitive(root_json, "carrier");
    if (cJSON_IsString(carrier) && (carrier->valuestring != NULL)) {
        memcpy(mtr_out->carrier,carrier->valuestring, \
                strlen(carrier->valuestring));
        // printf("Checking monitor \"%s\"\n", carrier->valuestring);
    }
    else {
        status = -1;
        goto end;
    }
    // geo
    geo = cJSON_GetObjectItemCaseSensitive(root_json, "geo");
    if(cJSON_IsObject(geo)) {
        // parse geo
        // printf("geo is object \n");
        lot = cJSON_GetObjectItemCaseSensitive(geo, "lot");
        if (cJSON_IsNumber(lot)) {
            mtr_out->mtr_geo.lot = lot->valuedouble;
            // printf("Checking monitor \"%s\"\n", lot->valuestring);
        }
        else {
            status = -1;
            goto end;
        }
        lon = cJSON_GetObjectItemCaseSensitive(geo, "lon");
        if (cJSON_IsNumber(lon)) {
            mtr_out->mtr_geo.lon = lon->valuedouble;
            // printf("Checking monitor \"%s\"\n", lon->valuestring);
        }
        else {
            status = -1;
            goto end;
        }
    }
    else {
        status = -1;
    }
end:
    cJSON_Delete(root_json);
    return status;
}


#if 0
// test
char *test_json_data(void)
{
    char *string = NULL;
    cJSON *root = NULL;

    root = cJSON_CreateObject();

    if (cJSON_AddStringToObject(root, "ip", "2.3.4.5") == NULL) {
        goto END;
    }

    if (cJSON_AddStringToObject(root, "asn", "ASN404") == NULL) {
        goto END;
    }

    if (cJSON_AddStringToObject(root, "country", "cn") == NULL) {
        goto END;
    }

    if (cJSON_AddStringToObject(root, "city", "BeiJing") == NULL) {
        goto END;
    }
    
    if (cJSON_AddStringToObject(root, "carrier", "CNTel") == NULL) {
        goto END;
    }

    cJSON *geo = NULL;
    geo = cJSON_CreateObject();

    cJSON_AddItemToObject(root,"geo", geo);
    if (cJSON_AddStringToObject(geo, "lot", "39.990751") == NULL) {
        goto END;
    }
    if (cJSON_AddStringToObject(geo, "lon", "116.423826") == NULL) {
        goto END;
    }

    string = cJSON_Print(root);
END:
    cJSON_Delete(root);
    return string;
}

int main(int argc, char **argv)
{
    // test curl
#if 0
    np_string str;

    str.data = calloc(1,1024*1024);
    str.size = 1024*1024;

    np_curl(argv[1], &str, 60, 0);


    fprintf(stdout, "%s\n", str.data);
    free(str.data);
#endif
    // test np_str2json
#if 0
    struct np_mtr_input_st mtr_data;
    strcpy(mtr_data.ip, "1.1.1.1");
    strcpy(mtr_data.from, "mtr");
    mtr_data.hop = 3;
    printf("str--->json: \n");
    printf("%s\n", np_str2json(&mtr_data));
#endif
    struct np_mtr_output_st mtr_out;
#if 0
    printf("str--->json: \n");
    char *json = test_json_data();
    if(json == NULL) {
        printf("json is NULL\n");
    }
    else
        printf("%s\n", test_json_data());
    printf("******************************\n");
#endif
    // np_json2str(json, &mtr_out);
  
    // free(json);

    return 0;
    
}

#endif

