/* A Bison parser, made by GNU Bison 3.0.4.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

#ifndef YY_YY_UTIL_CONFIGPARSER_H_INCLUDED
# define YY_YY_UTIL_CONFIGPARSER_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    SPACE = 258,
    LETTER = 259,
    NEWLINE = 260,
    COMMENT = 261,
    COLON = 262,
    ANY = 263,
    ZONESTR = 264,
    STRING_ARG = 265,
    VAR_SERVER = 266,
    VAR_VERBOSITY = 267,
    VAR_NUM_THREADS = 268,
    VAR_PORT = 269,
    VAR_OUTGOING_RANGE = 270,
    VAR_INTERFACE = 271,
    VAR_DO_IP4 = 272,
    VAR_DO_IP6 = 273,
    VAR_PREFER_IP6 = 274,
    VAR_DO_UDP = 275,
    VAR_DO_TCP = 276,
    VAR_TCP_MSS = 277,
    VAR_OUTGOING_TCP_MSS = 278,
    VAR_CHROOT = 279,
    VAR_USERNAME = 280,
    VAR_DIRECTORY = 281,
    VAR_LOGFILE = 282,
    VAR_PIDFILE = 283,
    VAR_MSG_CACHE_SIZE = 284,
    VAR_MSG_CACHE_SLABS = 285,
    VAR_NUM_QUERIES_PER_THREAD = 286,
    VAR_RRSET_CACHE_SIZE = 287,
    VAR_RRSET_CACHE_SLABS = 288,
    VAR_OUTGOING_NUM_TCP = 289,
    VAR_INFRA_HOST_TTL = 290,
    VAR_INFRA_LAME_TTL = 291,
    VAR_INFRA_CACHE_SLABS = 292,
    VAR_INFRA_CACHE_NUMHOSTS = 293,
    VAR_INFRA_CACHE_LAME_SIZE = 294,
    VAR_NAME = 295,
    VAR_STUB_ZONE = 296,
    VAR_STUB_HOST = 297,
    VAR_STUB_ADDR = 298,
    VAR_TARGET_FETCH_POLICY = 299,
    VAR_HARDEN_SHORT_BUFSIZE = 300,
    VAR_HARDEN_LARGE_QUERIES = 301,
    VAR_FORWARD_ZONE = 302,
    VAR_FORWARD_HOST = 303,
    VAR_FORWARD_ADDR = 304,
    VAR_DO_NOT_QUERY_ADDRESS = 305,
    VAR_HIDE_IDENTITY = 306,
    VAR_HIDE_VERSION = 307,
    VAR_IDENTITY = 308,
    VAR_VERSION = 309,
    VAR_HARDEN_GLUE = 310,
    VAR_MODULE_CONF = 311,
    VAR_TRUST_ANCHOR_FILE = 312,
    VAR_TRUST_ANCHOR = 313,
    VAR_VAL_OVERRIDE_DATE = 314,
    VAR_BOGUS_TTL = 315,
    VAR_VAL_CLEAN_ADDITIONAL = 316,
    VAR_VAL_PERMISSIVE_MODE = 317,
    VAR_INCOMING_NUM_TCP = 318,
    VAR_MSG_BUFFER_SIZE = 319,
    VAR_KEY_CACHE_SIZE = 320,
    VAR_KEY_CACHE_SLABS = 321,
    VAR_TRUSTED_KEYS_FILE = 322,
    VAR_VAL_NSEC3_KEYSIZE_ITERATIONS = 323,
    VAR_USE_SYSLOG = 324,
    VAR_OUTGOING_INTERFACE = 325,
    VAR_ROOT_HINTS = 326,
    VAR_DO_NOT_QUERY_LOCALHOST = 327,
    VAR_CACHE_MAX_TTL = 328,
    VAR_HARDEN_DNSSEC_STRIPPED = 329,
    VAR_ACCESS_CONTROL = 330,
    VAR_LOCAL_ZONE = 331,
    VAR_LOCAL_DATA = 332,
    VAR_INTERFACE_AUTOMATIC = 333,
    VAR_STATISTICS_INTERVAL = 334,
    VAR_DO_DAEMONIZE = 335,
    VAR_USE_CAPS_FOR_ID = 336,
    VAR_STATISTICS_CUMULATIVE = 337,
    VAR_OUTGOING_PORT_PERMIT = 338,
    VAR_OUTGOING_PORT_AVOID = 339,
    VAR_DLV_ANCHOR_FILE = 340,
    VAR_DLV_ANCHOR = 341,
    VAR_NEG_CACHE_SIZE = 342,
    VAR_HARDEN_REFERRAL_PATH = 343,
    VAR_PRIVATE_ADDRESS = 344,
    VAR_PRIVATE_DOMAIN = 345,
    VAR_REMOTE_CONTROL = 346,
    VAR_CONTROL_ENABLE = 347,
    VAR_CONTROL_INTERFACE = 348,
    VAR_CONTROL_PORT = 349,
    VAR_SERVER_KEY_FILE = 350,
    VAR_SERVER_CERT_FILE = 351,
    VAR_CONTROL_KEY_FILE = 352,
    VAR_CONTROL_CERT_FILE = 353,
    VAR_CONTROL_USE_CERT = 354,
    VAR_EXTENDED_STATISTICS = 355,
    VAR_LOCAL_DATA_PTR = 356,
    VAR_JOSTLE_TIMEOUT = 357,
    VAR_STUB_PRIME = 358,
    VAR_UNWANTED_REPLY_THRESHOLD = 359,
    VAR_LOG_TIME_ASCII = 360,
    VAR_DOMAIN_INSECURE = 361,
    VAR_PYTHON = 362,
    VAR_PYTHON_SCRIPT = 363,
    VAR_VAL_SIG_SKEW_MIN = 364,
    VAR_VAL_SIG_SKEW_MAX = 365,
    VAR_CACHE_MIN_TTL = 366,
    VAR_VAL_LOG_LEVEL = 367,
    VAR_AUTO_TRUST_ANCHOR_FILE = 368,
    VAR_KEEP_MISSING = 369,
    VAR_ADD_HOLDDOWN = 370,
    VAR_DEL_HOLDDOWN = 371,
    VAR_SO_RCVBUF = 372,
    VAR_EDNS_BUFFER_SIZE = 373,
    VAR_PREFETCH = 374,
    VAR_PREFETCH_KEY = 375,
    VAR_SO_SNDBUF = 376,
    VAR_SO_REUSEPORT = 377,
    VAR_HARDEN_BELOW_NXDOMAIN = 378,
    VAR_IGNORE_CD_FLAG = 379,
    VAR_LOG_QUERIES = 380,
    VAR_LOG_REPLIES = 381,
    VAR_TCP_UPSTREAM = 382,
    VAR_SSL_UPSTREAM = 383,
    VAR_SSL_SERVICE_KEY = 384,
    VAR_SSL_SERVICE_PEM = 385,
    VAR_SSL_PORT = 386,
    VAR_FORWARD_FIRST = 387,
    VAR_STUB_SSL_UPSTREAM = 388,
    VAR_FORWARD_SSL_UPSTREAM = 389,
    VAR_TLS_CERT_BUNDLE = 390,
    VAR_STUB_FIRST = 391,
    VAR_MINIMAL_RESPONSES = 392,
    VAR_RRSET_ROUNDROBIN = 393,
    VAR_MAX_UDP_SIZE = 394,
    VAR_DELAY_CLOSE = 395,
    VAR_UNBLOCK_LAN_ZONES = 396,
    VAR_INSECURE_LAN_ZONES = 397,
    VAR_INFRA_CACHE_MIN_RTT = 398,
    VAR_DNS64_PREFIX = 399,
    VAR_DNS64_SYNTHALL = 400,
    VAR_DNSTAP = 401,
    VAR_DNSTAP_ENABLE = 402,
    VAR_DNSTAP_SOCKET_PATH = 403,
    VAR_DNSTAP_SEND_IDENTITY = 404,
    VAR_DNSTAP_SEND_VERSION = 405,
    VAR_DNSTAP_IDENTITY = 406,
    VAR_DNSTAP_VERSION = 407,
    VAR_DNSTAP_LOG_RESOLVER_QUERY_MESSAGES = 408,
    VAR_DNSTAP_LOG_RESOLVER_RESPONSE_MESSAGES = 409,
    VAR_DNSTAP_LOG_CLIENT_QUERY_MESSAGES = 410,
    VAR_DNSTAP_LOG_CLIENT_RESPONSE_MESSAGES = 411,
    VAR_DNSTAP_LOG_FORWARDER_QUERY_MESSAGES = 412,
    VAR_DNSTAP_LOG_FORWARDER_RESPONSE_MESSAGES = 413,
    VAR_RESPONSE_IP_TAG = 414,
    VAR_RESPONSE_IP = 415,
    VAR_RESPONSE_IP_DATA = 416,
    VAR_HARDEN_ALGO_DOWNGRADE = 417,
    VAR_IP_TRANSPARENT = 418,
    VAR_DISABLE_DNSSEC_LAME_CHECK = 419,
    VAR_IP_RATELIMIT = 420,
    VAR_IP_RATELIMIT_SLABS = 421,
    VAR_IP_RATELIMIT_SIZE = 422,
    VAR_RATELIMIT = 423,
    VAR_RATELIMIT_SLABS = 424,
    VAR_RATELIMIT_SIZE = 425,
    VAR_RATELIMIT_FOR_DOMAIN = 426,
    VAR_RATELIMIT_BELOW_DOMAIN = 427,
    VAR_IP_RATELIMIT_FACTOR = 428,
    VAR_RATELIMIT_FACTOR = 429,
    VAR_SEND_CLIENT_SUBNET = 430,
    VAR_CLIENT_SUBNET_ZONE = 431,
    VAR_CLIENT_SUBNET_ALWAYS_FORWARD = 432,
    VAR_CLIENT_SUBNET_OPCODE = 433,
    VAR_MAX_CLIENT_SUBNET_IPV4 = 434,
    VAR_MAX_CLIENT_SUBNET_IPV6 = 435,
    VAR_CAPS_WHITELIST = 436,
    VAR_CACHE_MAX_NEGATIVE_TTL = 437,
    VAR_PERMIT_SMALL_HOLDDOWN = 438,
    VAR_QNAME_MINIMISATION = 439,
    VAR_QNAME_MINIMISATION_STRICT = 440,
    VAR_IP_FREEBIND = 441,
    VAR_DEFINE_TAG = 442,
    VAR_LOCAL_ZONE_TAG = 443,
    VAR_ACCESS_CONTROL_TAG = 444,
    VAR_LOCAL_ZONE_OVERRIDE = 445,
    VAR_ACCESS_CONTROL_TAG_ACTION = 446,
    VAR_ACCESS_CONTROL_TAG_DATA = 447,
    VAR_VIEW = 448,
    VAR_ACCESS_CONTROL_VIEW = 449,
    VAR_VIEW_FIRST = 450,
    VAR_SERVE_EXPIRED = 451,
    VAR_FAKE_DSA = 452,
    VAR_FAKE_SHA1 = 453,
    VAR_LOG_IDENTITY = 454,
    VAR_HIDE_TRUSTANCHOR = 455,
    VAR_TRUST_ANCHOR_SIGNALING = 456,
    VAR_AGGRESSIVE_NSEC = 457,
    VAR_USE_SYSTEMD = 458,
    VAR_SHM_ENABLE = 459,
    VAR_SHM_KEY = 460,
    VAR_ROOT_KEY_SENTINEL = 461,
    VAR_DNSCRYPT = 462,
    VAR_DNSCRYPT_ENABLE = 463,
    VAR_DNSCRYPT_PORT = 464,
    VAR_DNSCRYPT_PROVIDER = 465,
    VAR_DNSCRYPT_SECRET_KEY = 466,
    VAR_DNSCRYPT_PROVIDER_CERT = 467,
    VAR_DNSCRYPT_PROVIDER_CERT_ROTATED = 468,
    VAR_DNSCRYPT_SHARED_SECRET_CACHE_SIZE = 469,
    VAR_DNSCRYPT_SHARED_SECRET_CACHE_SLABS = 470,
    VAR_DNSCRYPT_NONCE_CACHE_SIZE = 471,
    VAR_DNSCRYPT_NONCE_CACHE_SLABS = 472,
    VAR_IPSECMOD_ENABLED = 473,
    VAR_IPSECMOD_HOOK = 474,
    VAR_IPSECMOD_IGNORE_BOGUS = 475,
    VAR_IPSECMOD_MAX_TTL = 476,
    VAR_IPSECMOD_WHITELIST = 477,
    VAR_IPSECMOD_STRICT = 478,
    VAR_CACHEDB = 479,
    VAR_CACHEDB_BACKEND = 480,
    VAR_CACHEDB_SECRETSEED = 481,
    VAR_CACHEDB_REDISHOST = 482,
    VAR_CACHEDB_REDISPORT = 483,
    VAR_CACHEDB_REDISTIMEOUT = 484,
    VAR_UDP_UPSTREAM_WITHOUT_DOWNSTREAM = 485,
    VAR_FOR_UPSTREAM = 486,
    VAR_AUTH_ZONE = 487,
    VAR_ZONEFILE = 488,
    VAR_MASTER = 489,
    VAR_URL = 490,
    VAR_FOR_DOWNSTREAM = 491,
    VAR_FALLBACK_ENABLED = 492,
    VAR_ADDITIONAL_TLS_PORT = 493,
    VAR_LOW_RTT = 494,

    VAR_NP_HTTP = 1000,
    VAR_NP_HTTP_URL = 1001,
    VAR_NP_HTTP_TIMEOUT = 1002,
    VAR_NP_AUTH_DOMAIN = 1003,
    VAR_NP_HTTP_TTL = 1004,
    VAR_NP_POOL = 1005,
    VAR_NP_THREADS_POOL_NUM = 1006,

    VAR_LOW_RTT_PERMIL = 495,
    VAR_ALLOW_NOTIFY = 496
  };
#endif
/* Tokens.  */
#define SPACE 258
#define LETTER 259
#define NEWLINE 260
#define COMMENT 261
#define COLON 262
#define ANY 263
#define ZONESTR 264
#define STRING_ARG 265
#define VAR_SERVER 266
#define VAR_VERBOSITY 267
#define VAR_NUM_THREADS 268
#define VAR_PORT 269
#define VAR_OUTGOING_RANGE 270
#define VAR_INTERFACE 271
#define VAR_DO_IP4 272
#define VAR_DO_IP6 273
#define VAR_PREFER_IP6 274
#define VAR_DO_UDP 275
#define VAR_DO_TCP 276
#define VAR_TCP_MSS 277
#define VAR_OUTGOING_TCP_MSS 278
#define VAR_CHROOT 279
#define VAR_USERNAME 280
#define VAR_DIRECTORY 281
#define VAR_LOGFILE 282
#define VAR_PIDFILE 283
#define VAR_MSG_CACHE_SIZE 284
#define VAR_MSG_CACHE_SLABS 285
#define VAR_NUM_QUERIES_PER_THREAD 286
#define VAR_RRSET_CACHE_SIZE 287
#define VAR_RRSET_CACHE_SLABS 288
#define VAR_OUTGOING_NUM_TCP 289
#define VAR_INFRA_HOST_TTL 290
#define VAR_INFRA_LAME_TTL 291
#define VAR_INFRA_CACHE_SLABS 292
#define VAR_INFRA_CACHE_NUMHOSTS 293
#define VAR_INFRA_CACHE_LAME_SIZE 294
#define VAR_NAME 295
#define VAR_STUB_ZONE 296
#define VAR_STUB_HOST 297
#define VAR_STUB_ADDR 298
#define VAR_TARGET_FETCH_POLICY 299
#define VAR_HARDEN_SHORT_BUFSIZE 300
#define VAR_HARDEN_LARGE_QUERIES 301
#define VAR_FORWARD_ZONE 302
#define VAR_FORWARD_HOST 303
#define VAR_FORWARD_ADDR 304
#define VAR_DO_NOT_QUERY_ADDRESS 305
#define VAR_HIDE_IDENTITY 306
#define VAR_HIDE_VERSION 307
#define VAR_IDENTITY 308
#define VAR_VERSION 309
#define VAR_HARDEN_GLUE 310
#define VAR_MODULE_CONF 311
#define VAR_TRUST_ANCHOR_FILE 312
#define VAR_TRUST_ANCHOR 313
#define VAR_VAL_OVERRIDE_DATE 314
#define VAR_BOGUS_TTL 315
#define VAR_VAL_CLEAN_ADDITIONAL 316
#define VAR_VAL_PERMISSIVE_MODE 317
#define VAR_INCOMING_NUM_TCP 318
#define VAR_MSG_BUFFER_SIZE 319
#define VAR_KEY_CACHE_SIZE 320
#define VAR_KEY_CACHE_SLABS 321
#define VAR_TRUSTED_KEYS_FILE 322
#define VAR_VAL_NSEC3_KEYSIZE_ITERATIONS 323
#define VAR_USE_SYSLOG 324
#define VAR_OUTGOING_INTERFACE 325
#define VAR_ROOT_HINTS 326
#define VAR_DO_NOT_QUERY_LOCALHOST 327
#define VAR_CACHE_MAX_TTL 328
#define VAR_HARDEN_DNSSEC_STRIPPED 329
#define VAR_ACCESS_CONTROL 330
#define VAR_LOCAL_ZONE 331
#define VAR_LOCAL_DATA 332
#define VAR_INTERFACE_AUTOMATIC 333
#define VAR_STATISTICS_INTERVAL 334
#define VAR_DO_DAEMONIZE 335
#define VAR_USE_CAPS_FOR_ID 336
#define VAR_STATISTICS_CUMULATIVE 337
#define VAR_OUTGOING_PORT_PERMIT 338
#define VAR_OUTGOING_PORT_AVOID 339
#define VAR_DLV_ANCHOR_FILE 340
#define VAR_DLV_ANCHOR 341
#define VAR_NEG_CACHE_SIZE 342
#define VAR_HARDEN_REFERRAL_PATH 343
#define VAR_PRIVATE_ADDRESS 344
#define VAR_PRIVATE_DOMAIN 345
#define VAR_REMOTE_CONTROL 346
#define VAR_CONTROL_ENABLE 347
#define VAR_CONTROL_INTERFACE 348
#define VAR_CONTROL_PORT 349
#define VAR_SERVER_KEY_FILE 350
#define VAR_SERVER_CERT_FILE 351
#define VAR_CONTROL_KEY_FILE 352
#define VAR_CONTROL_CERT_FILE 353
#define VAR_CONTROL_USE_CERT 354
#define VAR_EXTENDED_STATISTICS 355
#define VAR_LOCAL_DATA_PTR 356
#define VAR_JOSTLE_TIMEOUT 357
#define VAR_STUB_PRIME 358
#define VAR_UNWANTED_REPLY_THRESHOLD 359
#define VAR_LOG_TIME_ASCII 360
#define VAR_DOMAIN_INSECURE 361
#define VAR_PYTHON 362
#define VAR_PYTHON_SCRIPT 363
#define VAR_VAL_SIG_SKEW_MIN 364
#define VAR_VAL_SIG_SKEW_MAX 365
#define VAR_CACHE_MIN_TTL 366
#define VAR_VAL_LOG_LEVEL 367
#define VAR_AUTO_TRUST_ANCHOR_FILE 368
#define VAR_KEEP_MISSING 369
#define VAR_ADD_HOLDDOWN 370
#define VAR_DEL_HOLDDOWN 371
#define VAR_SO_RCVBUF 372
#define VAR_EDNS_BUFFER_SIZE 373
#define VAR_PREFETCH 374
#define VAR_PREFETCH_KEY 375
#define VAR_SO_SNDBUF 376
#define VAR_SO_REUSEPORT 377
#define VAR_HARDEN_BELOW_NXDOMAIN 378
#define VAR_IGNORE_CD_FLAG 379
#define VAR_LOG_QUERIES 380
#define VAR_LOG_REPLIES 381
#define VAR_TCP_UPSTREAM 382
#define VAR_SSL_UPSTREAM 383
#define VAR_SSL_SERVICE_KEY 384
#define VAR_SSL_SERVICE_PEM 385
#define VAR_SSL_PORT 386
#define VAR_FORWARD_FIRST 387
#define VAR_STUB_SSL_UPSTREAM 388
#define VAR_FORWARD_SSL_UPSTREAM 389
#define VAR_TLS_CERT_BUNDLE 390
#define VAR_STUB_FIRST 391
#define VAR_MINIMAL_RESPONSES 392
#define VAR_RRSET_ROUNDROBIN 393
#define VAR_MAX_UDP_SIZE 394
#define VAR_DELAY_CLOSE 395
#define VAR_UNBLOCK_LAN_ZONES 396
#define VAR_INSECURE_LAN_ZONES 397
#define VAR_INFRA_CACHE_MIN_RTT 398
#define VAR_DNS64_PREFIX 399
#define VAR_DNS64_SYNTHALL 400
#define VAR_DNSTAP 401
#define VAR_DNSTAP_ENABLE 402
#define VAR_DNSTAP_SOCKET_PATH 403
#define VAR_DNSTAP_SEND_IDENTITY 404
#define VAR_DNSTAP_SEND_VERSION 405
#define VAR_DNSTAP_IDENTITY 406
#define VAR_DNSTAP_VERSION 407
#define VAR_DNSTAP_LOG_RESOLVER_QUERY_MESSAGES 408
#define VAR_DNSTAP_LOG_RESOLVER_RESPONSE_MESSAGES 409
#define VAR_DNSTAP_LOG_CLIENT_QUERY_MESSAGES 410
#define VAR_DNSTAP_LOG_CLIENT_RESPONSE_MESSAGES 411
#define VAR_DNSTAP_LOG_FORWARDER_QUERY_MESSAGES 412
#define VAR_DNSTAP_LOG_FORWARDER_RESPONSE_MESSAGES 413
#define VAR_RESPONSE_IP_TAG 414
#define VAR_RESPONSE_IP 415
#define VAR_RESPONSE_IP_DATA 416
#define VAR_HARDEN_ALGO_DOWNGRADE 417
#define VAR_IP_TRANSPARENT 418
#define VAR_DISABLE_DNSSEC_LAME_CHECK 419
#define VAR_IP_RATELIMIT 420
#define VAR_IP_RATELIMIT_SLABS 421
#define VAR_IP_RATELIMIT_SIZE 422
#define VAR_RATELIMIT 423
#define VAR_RATELIMIT_SLABS 424
#define VAR_RATELIMIT_SIZE 425
#define VAR_RATELIMIT_FOR_DOMAIN 426
#define VAR_RATELIMIT_BELOW_DOMAIN 427
#define VAR_IP_RATELIMIT_FACTOR 428
#define VAR_RATELIMIT_FACTOR 429
#define VAR_SEND_CLIENT_SUBNET 430
#define VAR_CLIENT_SUBNET_ZONE 431
#define VAR_CLIENT_SUBNET_ALWAYS_FORWARD 432
#define VAR_CLIENT_SUBNET_OPCODE 433
#define VAR_MAX_CLIENT_SUBNET_IPV4 434
#define VAR_MAX_CLIENT_SUBNET_IPV6 435
#define VAR_CAPS_WHITELIST 436
#define VAR_CACHE_MAX_NEGATIVE_TTL 437
#define VAR_PERMIT_SMALL_HOLDDOWN 438
#define VAR_QNAME_MINIMISATION 439
#define VAR_QNAME_MINIMISATION_STRICT 440
#define VAR_IP_FREEBIND 441
#define VAR_DEFINE_TAG 442
#define VAR_LOCAL_ZONE_TAG 443
#define VAR_ACCESS_CONTROL_TAG 444
#define VAR_LOCAL_ZONE_OVERRIDE 445
#define VAR_ACCESS_CONTROL_TAG_ACTION 446
#define VAR_ACCESS_CONTROL_TAG_DATA 447
#define VAR_VIEW 448
#define VAR_ACCESS_CONTROL_VIEW 449
#define VAR_VIEW_FIRST 450
#define VAR_SERVE_EXPIRED 451
#define VAR_FAKE_DSA 452
#define VAR_FAKE_SHA1 453
#define VAR_LOG_IDENTITY 454
#define VAR_HIDE_TRUSTANCHOR 455
#define VAR_TRUST_ANCHOR_SIGNALING 456
#define VAR_AGGRESSIVE_NSEC 457
#define VAR_USE_SYSTEMD 458
#define VAR_SHM_ENABLE 459
#define VAR_SHM_KEY 460
#define VAR_ROOT_KEY_SENTINEL 461
#define VAR_DNSCRYPT 462
#define VAR_DNSCRYPT_ENABLE 463
#define VAR_DNSCRYPT_PORT 464
#define VAR_DNSCRYPT_PROVIDER 465
#define VAR_DNSCRYPT_SECRET_KEY 466
#define VAR_DNSCRYPT_PROVIDER_CERT 467
#define VAR_DNSCRYPT_PROVIDER_CERT_ROTATED 468
#define VAR_DNSCRYPT_SHARED_SECRET_CACHE_SIZE 469
#define VAR_DNSCRYPT_SHARED_SECRET_CACHE_SLABS 470
#define VAR_DNSCRYPT_NONCE_CACHE_SIZE 471
#define VAR_DNSCRYPT_NONCE_CACHE_SLABS 472
#define VAR_IPSECMOD_ENABLED 473
#define VAR_IPSECMOD_HOOK 474
#define VAR_IPSECMOD_IGNORE_BOGUS 475
#define VAR_IPSECMOD_MAX_TTL 476
#define VAR_IPSECMOD_WHITELIST 477
#define VAR_IPSECMOD_STRICT 478
#define VAR_CACHEDB 479
#define VAR_CACHEDB_BACKEND 480
#define VAR_CACHEDB_SECRETSEED 481
#define VAR_CACHEDB_REDISHOST 482
#define VAR_CACHEDB_REDISPORT 483
#define VAR_CACHEDB_REDISTIMEOUT 484
#define VAR_UDP_UPSTREAM_WITHOUT_DOWNSTREAM 485
#define VAR_FOR_UPSTREAM 486
#define VAR_AUTH_ZONE 487
#define VAR_ZONEFILE 488
#define VAR_MASTER 489
#define VAR_URL 490
#define VAR_FOR_DOWNSTREAM 491
#define VAR_FALLBACK_ENABLED 492
#define VAR_ADDITIONAL_TLS_PORT 493
#define VAR_LOW_RTT 494
#define VAR_LOW_RTT_PERMIL 495
#define VAR_ALLOW_NOTIFY 496

#define VAR_NP_HTTP 1000
#define VAR_NP_HTTP_URL 1001
#define VAR_NP_HTTP_TIMEOUT 1002
#define VAR_NP_AUTH_DOMAIN 1003
#define VAR_NP_HTTP_TTL 1004
#define VAR_NP_POOL 1005
#define VAR_NP_THREADS_POOL_NUM 1006

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED

union YYSTYPE
{
#line 66 "./util/configparser.y" /* yacc.c:1909  */

	char*	str;

#line 540 "util/configparser.h" /* yacc.c:1909  */
};

typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE yylval;

int yyparse (void);

#endif /* !YY_YY_UTIL_CONFIGPARSER_H_INCLUDED  */
