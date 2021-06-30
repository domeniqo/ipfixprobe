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
#include <sstream>

#include "kubernetesplugin.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"
#include "ipfix-elements.h"

using namespace std;

#define DEBUG_K8S

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

#define KUBERNETES_UNIREC_TEMPLATE "K8S_APP_NAME,K8S_NODE_NAME,K8S_POD_NAME,K8S_CONTAINER_IDS,K8S_CONTAINER_IMAGES,K8S_CONTAINER_IMAGE_IDS,K8S_PORTS_CONTAINER,K8S_PORTS_EXPOSED" /* TODO: unirec template */

UR_FIELDS (
   /* TODO: unirec fields definition */
   string K8S_APP_NAME
   string K8S_NODE_NAME
   string K8S_POD_NAME
   string K8S_CONTAINER_IDS
   string K8S_CONTAINER_IMAGES
   string K8S_CONTAINER_IMAGE_IDS
   string K8S_PORTS_CONTAINER
   string K8S_PORTS_EXPOSED
)

KUBERNETESPlugin::KUBERNETESPlugin(const options_t &module_options)
{
   print_stats = module_options.print_stats;
}

KUBERNETESPlugin::KUBERNETESPlugin(const options_t &module_options, vector<plugin_opt> plugin_options) : FlowCachePlugin(plugin_options)
{
   print_stats = module_options.print_stats;
   string& params = plugin_options[0].params;
   string filename;
   if (parse_filename(params, filename)) {
      parse_params_from_file(filename);
   }
   parse_params(params);
}

bool KUBERNETESPlugin::parse_filename(const string& params, string& filename) {
   size_t pos_end, pos_begin = params.find("file-name=");
   if(pos_begin != string::npos) {
      //filename included in params
      pos_begin += strlen("file-name=");
      pos_end = params.find(':', pos_begin);
      if (pos_end == string::npos) {
         pos_end = params.length();
      }
      filename = params.substr(pos_begin, pos_end - pos_begin);
      DEBUG_MSG("Filename extracted: %s\n", filename.c_str());
      return true;
   }
   return false;
}

void KUBERNETESPlugin::parse_params_from_file(const string& filename) {
   DEBUG_MSG("Trying to parse file: %s\n", filename.c_str());
}

bool KUBERNETESPlugin::parse_params(const string& params)
{
   DEBUG_MSG("Recieved parameters: %s\n", params.c_str());
   stringstream param_stream (params);
   vector<string> param_pairs;
   size_t sep = 0;
   string key, val;

   for (auto key : known_parameter_keys) {
      //fill in known parameters to map
      user_parameters[key] = "";
   }

   while (param_stream.good()) {
      string param_pair;
      getline(param_stream, param_pair, ':');
      param_pairs.push_back(param_pair);
   }

   for (auto param_pair : param_pairs) {
      sep = param_pair.find("=", 0);
      if(sep == string::npos) {
         sep = param_pair.length() - 1;
         key = param_pair.substr(0, sep + 1);
      }  else {
         key = param_pair.substr(0, sep);
      }
      val = param_pair.substr(sep + 1, param_pair.length() - 1);
      try {
         //check whether parameter is known or not
         user_parameters.at(key) = val;
         DEBUG_MSG("Importing parameter key(length): %s(%lu) with value(length): %s(%lu)\n", key.c_str(), key.length(), val.c_str(), val.length());
      } catch (out_of_range) {
         cerr << "ipfixprobe: kubernetes: Unexpected paramater key: " << key << " with value: " << val << endl;
      }
   }
   
   return true;
}

FlowCachePlugin *KUBERNETESPlugin::copy()
{
   return new KUBERNETESPlugin(*this);
}

void KUBERNETESPlugin::pre_export(Flow &rec)
{
   if (recPrealloc == NULL) {
      recPrealloc = new RecordExtKUBERNETES();
   }

   //filling up structure fields
   recPrealloc->app_name = user_parameters["app-name"];
   recPrealloc->node_name = user_parameters["node-name"];
   recPrealloc->pod_name = user_parameters["pod-name"];
   recPrealloc->container_ids = user_parameters["container-ids"];
   recPrealloc->container_images = user_parameters["container-images"];
   recPrealloc->container_image_ids = user_parameters["container-image-ids"];
   recPrealloc->ports_container = user_parameters["ports-container"];
   recPrealloc->ports_exposed = user_parameters["ports-exposed"];

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


