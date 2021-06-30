/**
 * \file kubernetesplugin.h
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

#ifndef KUBERNETESPLUGIN_H
#define KUBERNETESPLUGIN_H

#include <map>
#include <string>
#include <string.h>

#ifdef WITH_NEMEA
  #include "fields.h"
#endif

#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"

using namespace std;

/**
 * \brief Flow record extension header for storing parsed KUBERNETES packets.
 */
struct RecordExtKUBERNETES : RecordExt {

   char app_name[32];
   char node_name[32];
   char pod_name[32];
   char container_ids[256];
   char container_images[256];
   char container_image_ids[256];
   char ports_container[32];
   char ports_exposed[32];
   string app_name_s;

   RecordExtKUBERNETES() : RecordExt(kubernetes)
   {
   }

#ifdef WITH_NEMEA
   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
   }
#endif

   virtual int fillIPFIX(uint8_t *buffer, int size)
   {
      int length, total_length = 0;

      //app name
      /*
      length = strlen(app_name);
      if (length + 1 > size) {
         return -1;
      }
      buffer[0] = length;
      memcpy(buffer + 1, app_name, length);
      total_length = length + 1;
      */
      app_name_s = app_name_s.substr(32);
      length = app_name_s.length();
      if (length + 1 > size) {
         return -1
      }
      buffer[0] = length;
      memcpy(buffer + 1, app_name_s.c_str(), length);
      total_length = length + 1;

      //node name
      length = strlen(node_name);
      if (total_length + length + 1 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, node_name, length);
      total_length += length + 1;
      
      //pod name
      length = strlen(pod_name);
      if (total_length + length + 1 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, pod_name, length);
      total_length += length + 1;
      
      //container ids
      length = strlen(container_ids);
      if (total_length + length + 1 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, container_ids, length);
      total_length += length + 1;
      
      //container images
      length = strlen(container_images);
      if (total_length + length + 1 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, container_images, length);
      total_length += length + 1;
      
      //container image ids
      length = strlen(container_image_ids);
      if (total_length + length + 1 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, container_image_ids, length);
      total_length += length + 1;
      
      //container ports
      length = strlen(ports_container);
      if (total_length + length + 1 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, ports_container, length);
      total_length += length + 1;
      
      //exposed ports
      length = strlen(ports_exposed);
      if (total_length + length + 1 > size) {
         return -1;
      }
      buffer[total_length] = length;
      memcpy(buffer + total_length + 1, ports_exposed, length);
      total_length += length + 1;

      return total_length;
   }
};

/**
 * \brief Flow cache plugin for parsing KUBERNETES packets.
 */
class KUBERNETESPlugin : public FlowCachePlugin
{
public:
   KUBERNETESPlugin(const options_t &module_options);
   KUBERNETESPlugin(const options_t &module_options, vector<plugin_opt> plugin_options);
   FlowCachePlugin *copy();
   void pre_export(Flow &rec);
   void finish();
   const char **get_ipfix_string();
   string get_unirec_field_string();

private:
   bool print_stats;       /**< Print stats when flow cache finish. */
   RecordExtKUBERNETES *recPrealloc; /**< Preallocated instance of record to use. */

   std::vector<string> known_parameter_keys {"app-name", "file-name", "node-name", "pod-name", "container-ids", "container-images", "container-image-ids", "ports-container", "ports-exposed"}; /**< Used to inform user in case no valid paramter passed to plugin. */
   std::map<string,string> user_parameters; /**< Map of given parameters by user. */

   bool parse_params(const string &params);
};

#endif

