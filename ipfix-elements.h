/**
 * \file ipfix-elements.h
 * \brief List of IPFIX elements and templates
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \date 2017
 * \date 2020
 */
/*
 * Copyright (C) 2020 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
 */

#ifndef IPFIX_ELEMENTS_H
#define IPFIX_ELEMENTS_H


/**
 * Each IPFIX element is defined as a C-preprocessor macro expecting
 * one argument - macro function that is used to pass 4 arguments (info about an element).
 *
 * The IPFIX element has 4 "attributes" in the following order:
 *   1. Enterprise number,
 *   2. Element ID,
 *   3. Data type length (in bytes),
 *   4. Source memory pointer (to copy value from)
 */


/**
 * Difference between NTP and UNIX epoch in number of seconds.
 */
#define EPOCH_DIFF 2208988800ULL

/**
 * Conversion from microseconds to NTP fraction (resolution 1/(2^32)s,  ~233 picoseconds).
 * Division by 1000000 would lead to wrong value when converting fraction back to microseconds, so 999999 is used.
 */
#define NTP_USEC_TO_FRAC(usec) (uint32_t)(((uint64_t) usec << 32) / 999999)

/**
 * Create 64 bit NTP timestamp which consist of 32 bit seconds part and 32 bit fraction part.
 */
#define MK_NTP_TS(ts) (((uint64_t) (ts.tv_sec + EPOCH_DIFF) << 32) | (uint64_t) NTP_USEC_TO_FRAC(ts.tv_usec))

/**
 * Convert FIELD to its "attributes", i.e. BYTES(FIELD) used in the source code produces
 *    0, 1, 8, &flow.octet_total_length
 * when it is substituted by C-preprocessor.
 */
#define FIELD(EN, ID, LEN, SRC) EN, ID, LEN, SRC

/* The list of known IPFIX elements: */
#define BYTES(F)                      F(0,        1,    8,   &flow.src_octet_total_length)
#define BYTES_REV(F)                  F(29305,    1,    8,   &flow.dst_octet_total_length)
#define PACKETS(F)                    F(0,        2,    8,   (temp = (uint64_t) flow.src_pkt_total_cnt, &temp))
#define PACKETS_REV(F)                F(29305,    2,    8,   (temp = (uint64_t) flow.dst_pkt_total_cnt, &temp))
#define FLOW_START_USEC(F)            F(0,      154,    8,   (temp = MK_NTP_TS(flow.time_first), &temp))
#define FLOW_END_USEC(F)              F(0,      155,    8,   (temp = MK_NTP_TS(flow.time_last), &temp))
#define OBSERVATION_MSEC(F)           F(0,      323,    8,   NULL)
#define INPUT_INTERFACE(F)            F(0,       10,    2,   &this->dir_bit_field)
#define OUTPUT_INTERFACE(F)           F(0,       14,    2,   NULL)
#define FLOW_END_REASON(F)            F(0,      136,    1,   &flow.end_reason)

#define ETHERTYPE(F)                  F(0,      256,    2,   NULL)

#define L2_SRC_MAC(F)                 F(0,       56,    6,   flow.src_mac)
#define L2_DST_MAC(F)                 F(0,       80,    6,   flow.dst_mac)

#define L3_PROTO(F)                   F(0,       60,    1,   &flow.ip_version)
#define L3_IPV4_ADDR_SRC(F)           F(0,        8,    4,   &flow.src_ip.v4)
#define L3_IPV4_ADDR_DST(F)           F(0,       12,    4,   &flow.dst_ip.v4)
#define L3_IPV4_TOS(F)                F(0,        5,    1,   NULL)
#define L3_IPV6_ADDR_SRC(F)           F(0,       27,   16,   &flow.src_ip.v6)
#define L3_IPV6_ADDR_DST(F)           F(0,       28,   16,   &flow.dst_ip.v6)
#define L3_IPV4_IDENTIFICATION(F)     F(0,       54,    2,   NULL)
#define L3_IPV4_FRAGMENT(F)           F(0,       88,    2,   NULL)
#define L3_IPV4_TTL(F)                F(0,      192,    1,   NULL)
#define L3_IPV6_TTL(F)                F(0,      192,    1,   NULL)
#define L3_TTL(F)                     F(0,      192,    1,   NULL)
#define L3_TTL_REV(F)                 F(29305,  192,    1,   NULL)
#define L3_FLAGS(F)                   F(0,      197,    1,   NULL)
#define L3_FLAGS_REV(F)               F(29305,  197,    1,   NULL)

#define L4_PROTO(F)                   F(0,        4,    1,   &flow.ip_proto)
#define L4_TCP_FLAGS(F)               F(0,        6,    1,   &flow.src_tcp_control_bits)
#define L4_TCP_FLAGS_REV(F)           F(29305,    6,    1,   &flow.dst_tcp_control_bits)
#define L4_PORT_SRC(F)                F(0,        7,    2,   &flow.src_port)
#define L4_PORT_DST(F)                F(0,       11,    2,   &flow.dst_port)
#define L4_ICMP_TYPE_CODE(F)          F(0,       32,    2,   NULL)
#define L4_TCP_WIN(F)                 F(0,       186,   2,   NULL)
#define L4_TCP_WIN_REV(F)             F(29305,   186,   2,   NULL)
#define L4_TCP_OPTIONS(F)             F(0,       209,   8,   NULL)
#define L4_TCP_OPTIONS_REV(F)         F(29305,   209,   8,   NULL)


#define L4_TCP_MSS(F)                 F(8057,   900,   4,   NULL)
#define L4_TCP_MSS_REV(F)             F(8057,   901,   4,   NULL)
#define L4_TCP_SYN_SIZE(F)            F(8057,   902,   2,   NULL)

#define HTTP_DOMAIN(F)                F(39499,    1,   -1,   NULL)
#define HTTP_REFERER(F)               F(39499,    3,   -1,   NULL)
#define HTTP_URI(F)                   F(39499,    2,   -1,   NULL)
#define HTTP_CONTENT_TYPE(F)          F(39499,   10,   -1,   NULL)
#define HTTP_STATUS(F)                F(39499,   12,    2,   NULL)
#define HTTP_USERAGENT(F)             F(39499,   20,   -1,   NULL)
#define HTTP_METHOD(F)                F(8057,   200,   -1,   NULL)

#define RTSP_METHOD(F)                F(16982,  600,   -1,   NULL)
#define RTSP_USERAGENT(F)             F(16982,  601,   -1,   NULL)
#define RTSP_URI(F)                   F(16982,  602,   -1,   NULL)
#define RTSP_STATUS(F)                F(16982,  603,    2,   NULL)
#define RTSP_CONTENT_TYPE(F)          F(16982,  604,   -1,   NULL)
#define RTSP_SERVER(F)                F(16982,  605,   -1,   NULL)

#define DNS_RCODE(F)                  F(8057,     1,    1,   NULL)
#define DNS_NAME(F)                   F(8057,     2,   -1,   NULL)
#define DNS_QTYPE(F)                  F(8057,     3,    2,   NULL)
#define DNS_CLASS(F)                  F(8057,     4,    2,   NULL)
#define DNS_RR_TTL(F)                 F(8057,     5,    4,   NULL)
#define DNS_RLENGTH(F)                F(8057,     6,    2,   NULL)
#define DNS_RDATA(F)                  F(8057,     7,   -1,   NULL)
#define DNS_PSIZE(F)                  F(8057,     8,    2,   NULL)
#define DNS_DO(F)                     F(8057,     9,    1,   NULL)
#define DNS_ID(F)                     F(8057,    10,    2,   NULL)
#define DNS_ATYPE(F)                  F(8057,    11,    2,   NULL)
#define DNS_ANSWERS(F)                F(8057,    14,    2,   NULL)

#define SIP_MSG_TYPE(F)               F(8057,   100,    2,   NULL)
#define SIP_STATUS_CODE(F)            F(8057,   101,    2,   NULL)
#define SIP_CALL_ID(F)                F(8057,   102,   -1,   NULL)
#define SIP_CALLING_PARTY(F)          F(8057,   103,   -1,   NULL)
#define SIP_CALLED_PARTY(F)           F(8057,   104,   -1,   NULL)
#define SIP_VIA(F)                    F(8057,   105,   -1,   NULL)
#define SIP_USER_AGENT(F)             F(8057,   106,   -1,   NULL)
#define SIP_REQUEST_URI(F)            F(8057,   107,   -1,   NULL)
#define SIP_CSEQ(F)                   F(8057,   108,   -1,   NULL)

#define NTP_LEAP(F)                   F(8057,    18,    1,   NULL)
#define NTP_VERSION(F)                F(8057,    19,    1,   NULL)
#define NTP_MODE(F)                   F(8057,    20,    1,   NULL)
#define NTP_STRATUM(F)                F(8057,    21,    1,   NULL)
#define NTP_POLL(F)                   F(8057,    22,    1,   NULL)
#define NTP_PRECISION(F)              F(8057,    23,    1,   NULL)
#define NTP_DELAY(F)                  F(8057,    24,    4,   NULL)
#define NTP_DISPERSION(F)             F(8057,    25,    4,   NULL)
#define NTP_REF_ID(F)                 F(8057,    26,   -1,   NULL)
#define NTP_REF(F)                    F(8057,    27,   -1,   NULL)
#define NTP_ORIG(F)                   F(8057,    28,   -1,   NULL)
#define NTP_RECV(F)                   F(8057,    29,   -1,   NULL)
#define NTP_SENT(F)                   F(8057,    30,   -1,   NULL)

#define ARP_HA_FORMAT(F)              F(8057,    31,    2,   NULL)
#define ARP_PA_FORMAT(F)              F(8057,    32,    2,   NULL)
#define ARP_OPCODE(F)                 F(8057,    33,    2,   NULL)
#define ARP_SRC_HA(F)                 F(8057,    34,   -1,   NULL)
#define ARP_SRC_PA(F)                 F(8057,    35,   -1,   NULL)
#define ARP_DST_HA(F)                 F(8057,    36,   -1,   NULL)
#define ARP_DST_PA(F)                 F(8057,    37,   -1,   NULL)

#define TLS_SNI(F)                    F(8057,   808,   -1,   NULL)
#define TLS_ALPN(F)                   F(8057,   809,   -1,   NULL)
#define TLS_JA3(F)                    F(8057,   830,   -1,   NULL)

#define SMTP_COMMANDS(F)              F(8057,    810,   4,   NULL)
#define SMTP_MAIL_COUNT(F)            F(8057,    811,   4,   NULL)
#define SMTP_RCPT_COUNT(F)            F(8057,    812,   4,   NULL)
#define SMTP_SENDER(F)                F(8057,    813,  -1,   NULL)
#define SMTP_RECIPIENT(F)             F(8057,    814,  -1,   NULL)
#define SMTP_STATUS_CODES(F)          F(8057,    815,   4,   NULL)
#define SMTP_CODE_2XX_COUNT(F)        F(8057,    816,   4,   NULL)
#define SMTP_CODE_3XX_COUNT(F)        F(8057,    817,   4,   NULL)
#define SMTP_CODE_4XX_COUNT(F)        F(8057,    818,   4,   NULL)
#define SMTP_CODE_5XX_COUNT(F)        F(8057,    819,   4,   NULL)
#define SMTP_DOMAIN(F)                F(8057,    820,  -1,   NULL)

#define SSDP_LOCATION_PORT(F)         F(8057,    821,   2,   NULL)
#define SSDP_SERVER(F)                F(8057,    822,  -1,   NULL)
#define SSDP_USER_AGENT(F)            F(8057,    823,  -1,   NULL)
#define SSDP_NT(F)                    F(8057,    824,  -1,   NULL)
#define SSDP_ST(F)                    F(8057,    825,  -1,   NULL)

#define DNSSD_QUERIES(F)              F(8057,    826,  -1,   NULL)
#define DNSSD_RESPONSES(F)            F(8057,    827,  -1,   NULL)

#define OVPN_CONF_LEVEL(F)            F(8057,    828,   1,   NULL)

#define NB_NAME(F)                    F(8057,    831,  -1,   NULL)
#define NB_SUFFIX(F)                  F(8057,    832,   1,   NULL)


#define IDP_CONTENT(F)                F(8057,   850,   -1,   NULL)
#define IDP_CONTENT_REV(F)            F(8057,   851,   -1,   NULL)

#define STATS_PCKT_SIZES(F)           F(0,       291,  -1,   NULL) // BASIC LIST -- FIELD IS e8057id1013 (uint16*)
#define STATS_PCKT_TIMESTAMPS(F)      F(0,       291,  -1,   NULL) // BASIC LIST -- FIELD IS e8057id1014 (time*)
#define STATS_PCKT_TCPFLGS(F)         F(0,       291,  -1,   NULL) // BASIC LIST -- FIELD IS e8057id1015 (uint8*)
#define STATS_PCKT_DIRECTIONS(F)      F(0,       291,  -1,   NULL) // BASIC LIST -- FIELD IS e8057id1016 (int8*)


#define SBI_BRST_PACKETS(F)           F(0,       291,  -1,   NULL) // BASIC LIST -- FIELD IS e8057id1050 (uint16*)
#define SBI_BRST_BYTES(F)             F(0,       291,  -1,   NULL) // BASIC LIST -- FIELD IS e8057id1051 (uint16*)
#define SBI_BRST_TIME_START(F)        F(0,       291,  -1,   NULL) // BASIC LIST -- FIELD IS e8057id1052 (time*)
#define SBI_BRST_TIME_STOP(F)         F(0,       291,  -1,   NULL) // BASIC LIST -- FIELD IS e8057id1053 (time*)
#define DBI_BRST_PACKETS(F)           F(0,       291,  -1,   NULL) // BASIC LIST -- FIELD IS e8057id1054 (uint16*)
#define DBI_BRST_BYTES(F)             F(0,       291,  -1,   NULL) // BASIC LIST -- FIELD IS e8057id1055 (uint16*)
#define DBI_BRST_TIME_START(F)        F(0,       291,  -1,   NULL) // BASIC LIST -- FIELD IS e8057id1056 (time*)
#define DBI_BRST_TIME_STOP(F)         F(0,       291,  -1,   NULL) // BASIC LIST -- FIELD IS e8057id1057 (time*)

#define D_PHISTS_IPT(F)               F(0,       291,  -1,   NULL) // BASIC LIST -- FIELD IS e8057id1063 (uint16*)
#define D_PHISTS_SIZES(F)             F(0,       291,  -1,   NULL) // BASIC LIST -- FIELD IS e8057id1062 (uint16*)
#define S_PHISTS_SIZES(F)             F(0,       291,  -1,   NULL) // BASIC LIST -- FIELD IS e8057id1060 (uint16*)
#define S_PHISTS_IPT(F)               F(0,       291,  -1,   NULL) // BASIC LIST -- FIELD IS e8057id1061 (uint16*)

#define WG_CONF_LEVEL(F)              F(8057,    861,   1,   NULL)
#define WG_SRC_PEER(F)                F(8057,    862,   4,   NULL)
#define WG_DST_PEER(F)                F(8057,    863,   4,   NULL)

/**
 * IPFIX Templates - list of elements
 *
 * Each template is defined as a macro function expecting one argument F.
 * This argument must be a macro function which is substituted with every
 * specified element of the template.
 *
 * For instance, BASIC_TMPLT_V4 contains FLOW_END_REASON, BYTES, BYTES_REV, PACKETS,...
 * all of them defined above.
 */

#define BASIC_TMPLT_V4(F) \
   F(FLOW_END_REASON) \
   F(BYTES) \
   F(BYTES_REV) \
   F(PACKETS) \
   F(PACKETS_REV) \
   F(FLOW_START_USEC) \
   F(FLOW_END_USEC) \
   F(L3_PROTO) \
   F(L4_PROTO) \
   F(L4_TCP_FLAGS) \
   F(L4_TCP_FLAGS_REV) \
   F(L4_PORT_SRC) \
   F(L4_PORT_DST) \
   F(INPUT_INTERFACE) \
   F(L3_IPV4_ADDR_SRC) \
   F(L3_IPV4_ADDR_DST) \
   F(L2_SRC_MAC) \
   F(L2_DST_MAC)

#define BASIC_TMPLT_V6(F) \
   F(FLOW_END_REASON) \
   F(BYTES) \
   F(BYTES_REV) \
   F(PACKETS) \
   F(PACKETS_REV) \
   F(FLOW_START_USEC) \
   F(FLOW_END_USEC) \
   F(L3_PROTO) \
   F(L4_PROTO) \
   F(L4_TCP_FLAGS) \
   F(L4_TCP_FLAGS_REV) \
   F(L4_PORT_SRC) \
   F(L4_PORT_DST) \
   F(INPUT_INTERFACE) \
   F(L3_IPV6_ADDR_SRC) \
   F(L3_IPV6_ADDR_DST) \
   F(L2_SRC_MAC) \
   F(L2_DST_MAC)

#define IPFIX_HTTP_TEMPLATE(F) \
   F(HTTP_USERAGENT) \
   F(HTTP_METHOD) \
   F(HTTP_DOMAIN) \
   F(HTTP_REFERER) \
   F(HTTP_URI) \
   F(HTTP_CONTENT_TYPE) \
   F(HTTP_STATUS)

#define IPFIX_RTSP_TEMPLATE(F) \
   F(RTSP_METHOD) \
   F(RTSP_USERAGENT) \
   F(RTSP_URI) \
   F(RTSP_STATUS)\
   F(RTSP_SERVER) \
   F(RTSP_CONTENT_TYPE)

#define IPFIX_TLS_TEMPLATE(F) \
   F(TLS_SNI)\
   F(TLS_ALPN)\
   F(TLS_JA3)

#define IPFIX_NTP_TEMPLATE(F) \
   F(NTP_LEAP) \
   F(NTP_VERSION) \
   F(NTP_MODE) \
   F(NTP_STRATUM) \
   F(NTP_POLL) \
   F(NTP_PRECISION) \
   F(NTP_DELAY) \
   F(NTP_DISPERSION) \
   F(NTP_REF_ID) \
   F(NTP_REF) \
   F(NTP_ORIG) \
   F(NTP_RECV) \
   F(NTP_SENT)

#define IPFIX_DNS_TEMPLATE(F) \
   F(DNS_ANSWERS) \
   F(DNS_RCODE) \
   F(DNS_QTYPE) \
   F(DNS_CLASS) \
   F(DNS_RR_TTL) \
   F(DNS_RLENGTH) \
   F(DNS_PSIZE) \
   F(DNS_DO) \
   F(DNS_ID) \
   F(DNS_NAME) \
   F(DNS_RDATA)

#define IPFIX_PASSIVEDNS_TEMPLATE(F) \
   F(DNS_ID) \
   F(DNS_RR_TTL) \
   F(DNS_ATYPE) \
   F(DNS_RDATA) \
   F(DNS_NAME)

#define IPFIX_SMTP_TEMPLATE(F) \
   F(SMTP_COMMANDS) \
   F(SMTP_MAIL_COUNT) \
   F(SMTP_RCPT_COUNT) \
   F(SMTP_STATUS_CODES) \
   F(SMTP_CODE_2XX_COUNT) \
   F(SMTP_CODE_3XX_COUNT) \
   F(SMTP_CODE_4XX_COUNT) \
   F(SMTP_CODE_5XX_COUNT) \
   F(SMTP_DOMAIN) \
   F(SMTP_SENDER) \
   F(SMTP_RECIPIENT)

#define IPFIX_SIP_TEMPLATE(F) \
   F(SIP_MSG_TYPE) \
   F(SIP_STATUS_CODE) \
   F(SIP_CSEQ) \
   F(SIP_CALLING_PARTY) \
   F(SIP_CALLED_PARTY) \
   F(SIP_CALL_ID) \
   F(SIP_USER_AGENT) \
   F(SIP_REQUEST_URI) \
   F(SIP_VIA)

#define IPFIX_PSTATS_TEMPLATE(F) \
   F(STATS_PCKT_SIZES) \
   F(STATS_PCKT_TIMESTAMPS) \
   F(STATS_PCKT_TCPFLGS) \
   F(STATS_PCKT_DIRECTIONS)

#define IPFIX_OVPN_TEMPLATE(F) \
   F(OVPN_CONF_LEVEL)

#define IPFIX_SSDP_TEMPLATE(F) \
   F(SSDP_LOCATION_PORT) \
   F(SSDP_NT) \
   F(SSDP_USER_AGENT)\
   F(SSDP_ST) \
   F(SSDP_SERVER)

#define IPFIX_DNSSD_TEMPLATE(F) \
   F(DNSSD_QUERIES) \
   F(DNSSD_RESPONSES)

#define IPFIX_IDPCONTENT_TEMPLATE(F) \
  F(IDP_CONTENT) \
  F(IDP_CONTENT_REV)

#define IPFIX_BSTATS_TEMPLATE(F) \
  F(SBI_BRST_PACKETS) \
  F(SBI_BRST_BYTES) \
  F(SBI_BRST_TIME_START) \
  F(SBI_BRST_TIME_STOP) \
  F(DBI_BRST_PACKETS) \
  F(DBI_BRST_BYTES) \
  F(DBI_BRST_TIME_START) \
  F(DBI_BRST_TIME_STOP)

#define IPFIX_NETBIOS_TEMPLATE(F) \
   F(NB_SUFFIX) \
   F(NB_NAME)

#define IPFIX_NETBIOS_TEMPLATE(F) \
   F(NB_SUFFIX) \
   F(NB_NAME)

#define IPFIX_BASICPLUS_TEMPLATE(F) \
   F(L3_TTL) \
   F(L3_TTL_REV) \
   F(L3_FLAGS) \
   F(L3_FLAGS_REV) \
   F(L4_TCP_WIN) \
   F(L4_TCP_WIN_REV) \
   F(L4_TCP_OPTIONS) \
   F(L4_TCP_OPTIONS_REV) \
   F(L4_TCP_MSS) \
   F(L4_TCP_MSS_REV) \
   F(L4_TCP_SYN_SIZE)

#define IPFIX_PHISTS_TEMPLATE(F) \
  F(S_PHISTS_SIZES) \
  F(S_PHISTS_IPT) \
  F(D_PHISTS_SIZES) \
  F(D_PHISTS_IPT)

#define IPFIX_WG_TEMPLATE(F) \
  F(WG_CONF_LEVEL) \
  F(WG_SRC_PEER) \
  F(WG_DST_PEER)

/**
 * List of all known templated.
 *
 * This macro is define in order to use all elements of all defined
 * templates at once.
 */
#define IPFIX_ENABLED_TEMPLATES(F) \
   BASIC_TMPLT_V4(F) \
   BASIC_TMPLT_V6(F) \
   IPFIX_HTTP_TEMPLATE(F) \
   IPFIX_RTSP_TEMPLATE(F) \
   IPFIX_TLS_TEMPLATE(F) \
   IPFIX_NTP_TEMPLATE(F) \
   IPFIX_SIP_TEMPLATE(F) \
   IPFIX_DNS_TEMPLATE(F) \
   IPFIX_PASSIVEDNS_TEMPLATE(F) \
   IPFIX_PSTATS_TEMPLATE(F) \
   IPFIX_OVPN_TEMPLATE(F) \
   IPFIX_SMTP_TEMPLATE(F) \
   IPFIX_SSDP_TEMPLATE(F) \
   IPFIX_DNSSD_TEMPLATE(F) \
   IPFIX_IDPCONTENT_TEMPLATE(F) \
   IPFIX_NETBIOS_TEMPLATE(F) \
   IPFIX_BASICPLUS_TEMPLATE(F) \
   IPFIX_BSTATS_TEMPLATE(F) \
   IPFIX_PHISTS_TEMPLATE(F) \
   IPFIX_WG_TEMPLATE(F)



/**
 * Helper macro, convert FIELD into its name as a C literal.
 *
 * For instance, processing: IPFIX_FIELD_NAMES(BYTES) with C-preprocessor
 * produces "BYTES".
 */
#define IPFIX_FIELD_NAMES(F) #F,

#endif
