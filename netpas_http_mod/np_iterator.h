/*
 * iterator/iterator.h - iterative resolver DNS query response module
 *
 * Copyright (c) 2007, NLnet Labs. All rights reserved.
 *
 * This software is open source.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *
 * This file contains a module that performs recursive iterative DNS query
 * processing.
 */

#ifndef NP_HTTP_MOD_NP_ITERATOR_ITERATOR_H
#define NP_HTTP_MOD_NP_ITERATOR_ITERATOR_H
#include "services/outbound_list.h"
#include "util/data/msgreply.h"
#include "util/module.h"
#include "netpas_http_mod/np_common.h"
struct delegpt;
struct iter_hints;
struct iter_forwards;
struct iter_donotq;
struct iter_prep_list;
struct iter_priv;
struct rbtree_type;
struct iter_env;
struct iter_qstate;
struct np_mtr_input_st;

// http mod config info(There can be multiple groups,cannot exceed 255)
struct np_iter_http_st {
    struct np_iter_http_st *next;
    char *np_auth_domain;
    uint32_t np_auth_domain_len;
    char *np_http_url;
    int np_http_timeout;
    uint32_t np_http_ttl;

    uint8_t id;
    uint32_t size;
};

struct np_iter_env_st {
    struct iter_env iter;
    struct np_iter_http_st np_iter_http;
    int32_t num_threads; // Unbound main thread number
    void *http_thpool;
};

struct np_iter_qstate_st {
    struct iter_qstate iq;
    struct np_mtr_input_st mtr_input;
    uint8_t auth_id;
};


/**
 * Get the iterator function block.
 * @return: function block with function pointers to iterator methods.
 */
struct module_func_block* np_iter_get_funcblock(void);


/** iterator init */
int np_iter_init(struct module_env* env, int id);

/** iterator deinit */
void np_iter_deinit(struct module_env* env, int id);

/** iterator operate on a query */
void np_iter_operate(struct module_qstate* qstate, enum module_ev event, int id,
	struct outbound_entry* outbound);

/**
 * Return priming query results to interested super querystates.
 * 
 * Sets the delegation point and delegation message (not nonRD queries).
 * This is a callback from walk_supers.
 *
 * @param qstate: query state that finished.
 * @param id: module id.
 * @param super: the qstate to inform.
 */
void np_iter_inform_super(struct module_qstate* qstate, int id, 
	struct module_qstate* super);

/** iterator cleanup query state */
void np_iter_clear(struct module_qstate* qstate, int id);

/** iterator alloc size routine */
size_t np_iter_get_mem(struct module_env* env, int id);

#endif /* ITERATOR_ITERATOR_H */
