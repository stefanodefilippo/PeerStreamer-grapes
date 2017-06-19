/*
 *  Copyright (c) 2010 Luca Abeni
 *
 *  This is free software; see lgpl-2.1.txt
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "net_helper.h"
#include "topocache.h"
#include "proto.h"
#include "topo_proto.h"
#include "grapes_msg_types.h"
#define NODE_STR_LENGTH 120
#define SESSION_ID_SIZE 32

struct topo_context{
 struct peer_cache *myEntry;
 uint8_t *pkt;
 int pkt_size;
};

static int topo_payload_fill(struct topo_context *context, uint8_t *payload, int size, const struct peer_cache *c, const struct nodeID *snot, int max_peers, int include_me)
{
  int i;
  uint8_t *p = payload;

  if (!max_peers) max_peers = 1000; // FIXME: just to be sure to dump the whole cache...
  p += cache_header_dump(p, c, include_me);
  if (include_me) {
    p += entry_dump(p, context->myEntry, 0, size - (p - payload));
    max_peers--;
  }
  for (i = 0; nodeid(c, i) && max_peers; i++) {
    if (!nodeid_equal(nodeid(c, i), snot)) {
      int res;
      res = entry_dump(p, c, i, size - (p - payload));
      if (res < 0) {
        fprintf(stderr, "too many entries!\n");
        return -1;
      }
      p += res;
      --max_peers;
    }
  }

  return p - payload;
}

int topo_reply_header(struct topo_context *context, const struct peer_cache *c, const struct peer_cache *local_cache, int protocol,
                      int type, uint8_t *header, int header_len, int max_peers, int include_me)
{
     
   fprintf(stderr, "topo_reply_header: RECUPERO IL SESSION_ID_SET LOCALE PER SPEDIRLO\n");
   
   int num_sessions = get_num_flows_request(context->myEntry);
   fprintf(stderr, "topo_reply_header: NUMERO SESSIONI: %d\n", num_sessions);
   char **local_id_set = (char **)malloc(MAX_SESSION_IDS * sizeof(char*));
   uint8_t * distributed = (uint8_t *)malloc(num_sessions * sizeof(uint8_t));
   for(int i = 0; i < num_sessions; i++){
       local_id_set[i] = (char *)malloc(SESSION_ID_SIZE * sizeof(char));
       memcpy(local_id_set[i], get_session_id_request(i, context->myEntry), SESSION_ID_SIZE);
       fprintf(stderr, "topo_reply_header: RECUPERATO ID: %s\n", local_id_set[i]);
   }
   
   /*int *local_id_set = (int *)malloc(2 * num_sessions * sizeof(int));*/
   for(int i = 0; i < num_sessions; i++){
       distributed[i] = 0;
   }
   struct topo_header *h = (struct topo_header *)context->pkt;
  int len, res, shift;
  struct nodeID *dst;

  shift = sizeof(struct topo_header);
  if (header_len > 0) {
    if (header_len > context->pkt_size - shift) return -1;

    memcpy(context->pkt + shift, header, header_len);
    shift += sizeof(uint8_t) * header_len;
  }

#if 0
  n = psize / sizeof(struct cache_entry);
  if (n * sizeof(struct cache_entry) != psize) {
    fprintf(stderr, "Wrong number of elems %d (%d / %d)!!!\n", n, psize, sizeof(struct cache_entry));
    return -1;
  }
#endif
  dst = nodeid(c, 0);
  h->protocol = protocol;
  h->type = type;
  h->num_sessions = num_sessions;
  len = topo_payload_fill(context, context->pkt + shift, context->pkt_size - shift, local_cache, dst, max_peers, include_me);
  char ** id_set;
  id_set = local_id_set;//context->id_set;
  uint8_t *pkt;
  char str[NODE_STR_LENGTH];
  node_addr(dst, str, NODE_STR_LENGTH);
  fprintf(stderr, "topo_reply_header: NODO A CUI MANDARE: %s\n", str);
  if(get_last_node_recieved(context->myEntry) != NULL){
      fprintf(stderr, "topo_reply_header\n");
    //node_addr(get_last_node_recieved(context->myEntry), str, NODE_STR_LENGTH);
    fprintf(stderr, "topo_reply_header\n");
    fprintf(stderr, "topo_reply_header: NODO ULTIMO RICEVUTO: %s\n", str);
    fprintf(stderr, "topo_reply_header\n");
  }
  fprintf(stderr, "topo_reply_header\n");
  if(!is_time_to_send_id_set_request(context->myEntry)){
      fprintf(stderr, "topo_reply_header\n");
      if(is_time_to_send_id_set_no_change(context->myEntry)){
          h->subtype = SESSION_ID_NO_CHANGE;
          fprintf(stderr, "topo_reply_header: SPEDITO MESSAGGIO DI TOPOLOGIA SESSION_ID_NO_CHANGE\n");
      }else{
          h->subtype = WITHOUT_SESSION_ID_SET;
          fprintf(stderr, "topo_reply_header: SPEDITO MESSAGGIO DI TOPOLOGIA WITHOUT_SESSION_ID_SET\n");
      }
    //set_sending_id_set_cycles(context->myEntry, get_sending_id_set_cycles(context->myEntry) + 1);
    return len > 0 ? send_to_peer(nodeid(context->myEntry, 0), dst, context->pkt, shift + len) : len;
  
  }else{
    
      h->subtype = WITH_SESSION_IDS_REQUEST;
    pkt = (uint8_t*)malloc(shift + len + num_sessions*SESSION_ID_SIZE*sizeof(char) + num_sessions*sizeof(uint8_t));
    memcpy(pkt, context->pkt, shift + len);
    for(int i = 0; i < num_sessions; i++){
        memcpy(pkt + shift + len + i*num_sessions*SESSION_ID_SIZE*sizeof(char), id_set[i], SESSION_ID_SIZE*sizeof(char));
    }
    memcpy(pkt + shift + len + num_sessions*SESSION_ID_SIZE*sizeof(char), distributed, num_sessions*sizeof(uint8_t));
    //set_sending_id_set_cycles(context->myEntry, 0);
    set_time_to_send_id_set_request(context->myEntry, false);
    fprintf(stderr, "topo_reply_header: SPEDITO MESSAGGIO DI TOPOLOGIA CON SESSION_ID_SET REQUEST\n");
    return len > 0 ? send_to_peer(nodeid(context->myEntry, 0), dst, pkt, shift + len + num_sessions*SESSION_ID_SIZE*sizeof(char) + num_sessions*sizeof(uint8_t)) : len;
  
  }
  
}

int topo_reply(struct topo_context *context, const struct peer_cache *c, const struct peer_cache *local_cache, int protocol, int type, int max_peers, int include_me)
{
  return topo_reply_header(context, c, local_cache, protocol, type, NULL, 0, max_peers, include_me);
}

void topo_proto_send_SDP(struct topo_context *context, const struct peer_cache *remote_cache)
{
    fprintf(stderr, "topo_proto_send_SDP: RECUPERO GLI SDP RICHIESTI..\n");
    struct nodeID *dst;
    uint8_t *pkt;
    dst = nodeid(remote_cache, 0);
    uint8_t num_sessions = (uint8_t)get_num_flows(remote_cache);
    fprintf(stderr, "topo_proto_send_SDP: NUMERO DI SDP RICHIESTI: %d..\nGLI ID RICHIESTI SONO:\n", num_sessions);
    int *dim_array = (int *)malloc(num_sessions * sizeof(int));
    char ** requested_SDP = (char **)malloc(num_sessions * sizeof(char*));
    FILE **f = (FILE **)malloc(num_sessions * sizeof(FILE*));
    int payload_size = 0;
    for(int i = 0; i < num_sessions; i++){
        fprintf(stderr, "%d\n", get_session_id(i, remote_cache));
        //dim_array[i] = get_session_id(i, remote_cache);
        char s[64];
        strcpy(s, "SDP");
        strcat(s, get_session_id(i, remote_cache));
        f[i] = fopen(s, "r");
        fseek(f[i], 0, SEEK_END);
        int lengthOfFile = (int)ftell(f[i]);
        payload_size += lengthOfFile;
        dim_array[i] = lengthOfFile;
        requested_SDP[i] = (char *)malloc(SESSION_ID_SIZE * sizeof(char));
        requested_SDP[i] = get_session_id(i, remote_cache);
        fprintf(stderr, "MESSO NEL VETTORE: %s\n", requested_SDP[i]);
        fprintf(stderr, "topo_proto_send_SDP: DIMENSIONE DEL RELATIVO FILE SDP: %d\n", lengthOfFile);
        rewind(f[i]);
        //fclose(f[i]);
    }
    char *buffer = (char *)malloc(payload_size * sizeof(char));
    for(int i = 0; i < num_sessions; i++){
        if(i == 0)
            fread(buffer, dim_array[i], 1 , f[i]);
        else
            fread(buffer + dim_array[i - 1], dim_array[i], 1 , f[i]);
        fclose(f[i]);
    }
    char str[NODE_STR_LENGTH];
    node_addr(nodeid(context->myEntry, 0), str, NODE_STR_LENGTH);
    fprintf(stderr, "topo_proto_send_SDP: MIO INDIRIZZO: %s\n", str);
    node_addr(dst, str, NODE_STR_LENGTH);
    fprintf(stderr, "topo_proto_send_SDP: NODO A CUI MANDARE: %s\n", str);
    pkt = (uint8_t*)malloc(sizeof(uint8_t) + sizeof(int) + num_sessions * SESSION_ID_SIZE * sizeof(char) + num_sessions * sizeof(int) + payload_size * sizeof(char));
    pkt[0] = MSG_TYPE_SDP;
    pkt[1] = num_sessions;
    //pkt[2] = dim_array;
    for(int i = 0; i < num_sessions; i++){
        memcpy(pkt + 2 + i * SESSION_ID_SIZE * sizeof(char), requested_SDP[i], SESSION_ID_SIZE * sizeof(char));
    }
    memcpy(pkt + 2 + SESSION_ID_SIZE * sizeof(char) * num_sessions, dim_array, num_sessions * sizeof(int));
    memcpy(pkt + 2 + SESSION_ID_SIZE * sizeof(char) * num_sessions + num_sessions * sizeof(int), buffer, payload_size);
    send_to_peer(nodeid(context->myEntry, 0), dst, pkt, sizeof(uint8_t) + sizeof(uint8_t) + num_sessions * SESSION_ID_SIZE * sizeof(char) + num_sessions * sizeof(int) + payload_size * sizeof(char));
    fprintf(stderr, "topo_proto_send_SDP: SPEDITO MESSAGGIO DI TIPO MSG_TYPE_SDP\n");
}

int topo_query_peer_header(struct topo_context *context, const struct peer_cache *local_cache, struct nodeID *dst, int protocol, int type,
                           uint8_t *header, int header_len, int max_peers)
{
    
   fprintf(stderr, "topo_query_peer_header: RECUPERO IL SESSION_ID_SET LOCALE PER SPEDIRLO\n");
      
   int num_sessions = get_num_flows_request(context->myEntry);
   fprintf(stderr, "topo_query_peer_header: NUMERO SESSIONI: %d\n", num_sessions);
   char **local_id_set = (char **)malloc(MAX_SESSION_IDS * sizeof(char*));
   uint8_t * distributed = (uint8_t *)malloc(num_sessions * sizeof(uint8_t));
   for(int i = 0; i < num_sessions; i++){
       local_id_set[i] = (char *)malloc(SESSION_ID_SIZE * sizeof(char));
       memcpy(local_id_set[i], get_session_id(i, context->myEntry), SESSION_ID_SIZE);
       fprintf(stderr, "topo_reply_header: RECUPERATO ID: %s\n", local_id_set[i]);
   }
   
   for(int i = 0; i < num_sessions; i++){
       distributed[i] = get_distributed(i, context->myEntry);
   }
            
   
  struct topo_header *h = (struct topo_header *)context->pkt;
  int len, shift;

  shift = sizeof(struct topo_header);
  if (header_len > 0) {
    if (header_len > context->pkt_size - shift) return -1;

    memcpy(context->pkt + shift, header, header_len);
    shift += sizeof(uint8_t) * header_len;
  }

  h->protocol = protocol;
  h->type = type;
  len = topo_payload_fill(context, context->pkt + shift, context->pkt_size - shift, local_cache, dst, max_peers, 1);
  //fprintf(stderr,"[DEBUG] sending TOPO to peer \n");
  topo_proto_set_time_to_send_session_id_set(context->myEntry, true);
  char **id_set;
  id_set = local_id_set;//context->id_set;
  uint8_t *pkt;
  char str[NODE_STR_LENGTH];
  node_addr(dst, str, NODE_STR_LENGTH);
  fprintf(stderr, "NODO A CUI MANDARE: %s\n", str);
  if(get_last_node_recieved(context->myEntry) != NULL){
  //node_addr(get_last_node_recieved(context->myEntry), str, NODE_STR_LENGTH);
  fprintf(stderr, "NODO ULTIMO RICEVUTO: %s\n", str);
  }
  if(!is_time_to_send_id_set(context->myEntry) /*(get_last_node_recieved(context->myEntry) != NULL && nodeid_equal(get_last_node_recieved(context->myEntry), dst))*/){
    
    h->subtype = WITHOUT_SESSION_ID_SET;
    h->num_sessions = 0;
    //set_sending_id_set_cycles(context->myEntry, get_sending_id_set_cycles(context->myEntry) + 1);
    fprintf(stderr, "topo_query_peer_header: SPEDITO MESSAGGIO DI TOPOLOGIA SENZA SESSION_ID_SET\n");
    return len > 0 ? send_to_peer(nodeid(context->myEntry, 0), dst, context->pkt, shift + len) : len;
  
  }else{
    
    h->subtype = WITH_SESSION_IDS_OFFER;
    h->num_sessions = num_sessions;
    pkt = (uint8_t*)malloc(shift + len + num_sessions*SESSION_ID_SIZE*sizeof(char) + num_sessions*sizeof(uint8_t));
    memcpy(pkt, context->pkt, shift + len);
    for(int i = 0; i < num_sessions; i++){
        memcpy(pkt + shift + len + i*num_sessions*SESSION_ID_SIZE*sizeof(char), id_set[i], SESSION_ID_SIZE*sizeof(char));
    }
    memcpy(pkt + shift + len + num_sessions*SESSION_ID_SIZE*sizeof(char), distributed, num_sessions*sizeof(uint8_t));
    //set_sending_id_set_cycles(context->myEntry, 0);
    set_time_to_send_id_set(context->myEntry, false);
    fprintf(stderr, "topo_query_peer_header: SPEDITO MESSAGGIO DI TOPOLOGIA CON SESSION_ID_SET\n");
    return len > 0 ? send_to_peer(nodeid(context->myEntry, 0), dst, pkt, shift + len + num_sessions*SESSION_ID_SIZE*sizeof(char) + num_sessions*sizeof(uint8_t)) : len;
  
  }
  
}
int topo_update_random_session_id_set(struct topo_context *context)
{
    return update_random_session_id_set(context->myEntry);
}

void topo_proto_add_session_id(struct topo_context *context, char * session_id)
{
    return topo_add_session_id_int(context->myEntry, session_id);
}

bool topo_proto_update_session_id_set(struct topo_context *local, struct peer_cache *remote)
{
    return topo_update_session_id_set(local->myEntry, remote);
}

void topo_proto_set_time_to_send_session_id_set(struct topo_context *context, bool value)
{
    return topo_set_time_to_send_session_id_set(context->myEntry, value);
}

void topo_proto_set_time_to_send_id_set_no_change(struct topo_context *context, bool value)
{
    return topo_set_time_to_send_id_set_no_change(context->myEntry, value);
}

void topo_proto_set_distributed(struct topo_context *context, char * session_id, bool value)
{
    return topo_set_distributed(context->myEntry, session_id, value);
}

void topo_proto_set_time_to_send_id_set_request(struct topo_context *context, bool value)
{
    return topo_set_time_to_send_id_set_request(context->myEntry, value);
}

void topo_proto_set_SDP_policy(struct topo_context *context, int * SDP_policy)
{
    return topo_set_SDP_policy(context->myEntry, SDP_policy);
}

int topo_query_peer(struct topo_context *context, const struct peer_cache *local_cache, struct nodeID *dst, int protocol, int type, int max_peers)
{
  return topo_query_peer_header(context, local_cache, dst, protocol, type, NULL, 0, max_peers);
}

int topo_proto_myentry_update(struct topo_context *context, struct nodeID *s, int dts, const void *meta, int meta_size)
{
  int ret = 1;

  if (s && !nodeid_equal(nodeid(context->myEntry, 0), s)) {
    fprintf(stderr, "ERROR: myEntry change not implemented!\n");	//TODO
    exit(1);
  }

  if (dts) {
    cache_delay(context->myEntry, dts);
  }

  if (meta) {
    if (cache_metadata_update(context->myEntry, nodeid(context->myEntry, 0), meta, meta_size) <= 0) {
      ret = -1;
    }
  }

  return ret;
}

int topo_proto_metadata_update(struct topo_context *context, const void *meta, int meta_size)
{
  return topo_proto_myentry_update(context, nodeid(context->myEntry, 0), 0 , meta, meta_size);
}

struct topo_context* topo_proto_init(struct nodeID *s, const void *meta, int meta_size)
{
  struct topo_context* con;

  con = malloc(sizeof(struct topo_context));
  if (!con) return NULL;
  con->pkt_size = 60 * 1024;   // FIXME: Do something smarter, here!
  con->pkt = malloc(con->pkt_size);
  if (!con->pkt) {
    free(con);

    return NULL;
  }
  
  con->myEntry = cache_init(1, meta_size, 0);
  cache_add(con->myEntry, s, meta, meta_size);

  return con;
}