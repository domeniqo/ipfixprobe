/**
 * \file kubernetesplugin.cpp
 * \brief Plugin for parsing kubernetes traffic.
 * \author Dominik Mlynka dominik.mlynka@gmail.com
 * \date 2021
 */
/*
 * Copyright (C) 2021 CESNET
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
 * This software is provided as is'', and any express or implied
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

#include <iostream>

#include "kubernetesplugin.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"
#include "ipfix-elements.h"

using namespace std;

//#define DEBUG_K8S

// Print debug message if debugging is allowed.
#ifdef DEBUG_K8S
#define DEBUG_MSG(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define DEBUG_MSG(format, ...)
#endif

// Process code if debugging is allowed.
#ifdef DEBUG_K8S
#define DEBUG_CODE(code) code
#else
#define DEBUG_CODE(code)
#endif

#define KUBERNETES_UNIREC_TEMPLATE "K8S_APP_NAME" /* TODO: unirec template */

UR_FIELDS (
   /* TODO: unirec fields definition */
   string K8S_APP_NAME
)

KUBERNETESPlugin::KUBERNETESPlugin(const options_t &module_options)
{
   print_stats = module_options.print_stats;
}

KUBERNETESPlugin::KUBERNETESPlugin(const options_t &module_options, vector<plugin_opt> plugin_options) : FlowCachePlugin(plugin_options)
{
   print_stats = module_options.print_stats;
   for(auto i : plugin_options) {
      printf("%s", i.params);
   }
}

FlowCachePlugin *KUBERNETESPlugin::copy()
{
   return new KUBERNETESPlugin(*this);
}

int KUBERNETESPlugin::pre_create(Packet &pkt)
{
   return 0;
}

int KUBERNETESPlugin::post_create(Flow &rec, const Packet &pkt)
{
   return 0;
}

int KUBERNETESPlugin::pre_update(Flow &rec, Packet &pkt)
{
   return 0;
}

int KUBERNETESPlugin::post_update(Flow &rec, const Packet &pkt)
{
   return 0;
}

void KUBERNETESPlugin::pre_export(Flow &rec)
{
   if (recPrealloc == NULL) {
      recPrealloc = new RecordExtKUBERNETES();
   }
   rec.addExtension(recPrealloc);
   recPrealloc = NULL;
}

void KUBERNETESPlugin::finish()
{
   if (print_stats) {
      cout << "KUBERNETES plugin stats: finished" << endl;
   }
}

const char *ipfix_kubernetes_template[] = {
   IPFIX_KUBERNETES_TEMPLATE(IPFIX_FIELD_NAMES)
   NULL
};

const char **KUBERNETESPlugin::get_ipfix_string()
{
   return ipfix_kubernetes_template;
}

string KUBERNETESPlugin::get_unirec_field_string()
{
   return KUBERNETES_UNIREC_TEMPLATE;
}


