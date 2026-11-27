/*
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain this list of conditions
 *    and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE SOFTWARE PROVIDER OR DEVELOPERS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/************************************************************************/
/* attack-one.c : Initially, the node is part of the network and after  */
/* ATTACK_TRIGGER seconds, it starts to send data packets with unknown  */
/* flows to their neighbors.                                            */
/************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include "contiki.h"
#include "sdn-core.h"
#include "flow-table-tests.h"
#include "src-route-tests.h"
#include "sdn-debug.h"
#include "string.h"
#include "lib/random.h"
#include "collect-nd.h"
#include "net/netstack.h"
#include "sdn-process-packets.h"
#include "sdn-common-send.h"
#include "sdn-packetbuf.h"
#include "sdn-queue.h"
#include "sdn-send.h"
#include "sdn-neighbor-table.h"
#include "sdn-send-packet.h"

#ifdef DEMO
#include "leds.h"
#endif

#include "sys/etimer.h"

#ifndef SDN_SIMULATION_N_SINKS
#define SDN_SIMULATION_N_SINKS 1
#endif

#ifndef SENSING_AT_SECONDS
#define SENSING_AT_SECONDS 60
#endif
#define IDS_TIMER 120
#ifndef ATTACK_TRIGGER
#define ATTACK_TRIGGER 7000
#endif
#ifndef RANDOM_TRIGGER
#define RANDOM_TRIGGER 1200
#endif
// #define ATTACK_TRIGGER 30600
// #define RANDOM_TRIGGER 72
#ifdef ATTACK_SIXTY
#define ATTACK_PERIOD 60
#endif
#ifdef ATTACK_THIRTY
#define ATTACK_PERIOD 30
#endif
#ifdef ATTACK_TEN
#define ATTACK_PERIOD 10
#endif
#ifdef ATTACK_ONE
#define ATTACK_PERIOD 1
#endif
#ifndef ATTACK_PERIOD
#define ATTACK_PERIOD 60
#endif

#ifdef MONETWSEC
#define CP_TIMER 120
#endif
#ifdef MSIXTYSEC
#define CP_TIMER 60
#endif
#ifdef MTHIRSEC
#define CP_TIMER 30
#endif
#ifdef MTENSEC
#define CP_TIMER 10
#endif
#ifndef CP_TIMER
#define CP_TIMER 60
#endif

uint8_t attack;

/*---------------------------------------------------------------------------*/
PROCESS(sdn_test_process, "Contiki SDN example process");
AUTOSTART_PROCESSES(&sdn_test_process);


uint16_t temp_flowid[8];


uint8_t flag[4];
static uint8_t neighbor_buf[4][SDN_MAX_PACKET_SIZE];
uint8_t* neighbor[4];

uint16_t len_neighbor[4];

/*---------------------------------------------------------------------------*/
static void
receiver(uint8_t *data, uint16_t len, sdnaddr_t *source_addr, uint16_t flowId) {

  SDN_DEBUG("Receiving message from ");
  sdnaddr_print(source_addr);
  SDN_DEBUG(" of len %d: %s\n", len, (char*) data);

  /* Put your code here to get data received from application. */
}
/*-----------------------------------------------------------------------------*/
/* Use to defines either node is a sensor node and sends packets to sink or only router node and forward packets. */
static uint8_t isSensing() {

  uint8_t sensing = 0;

  sensing = 1;

  return sensing;
}

static uint8_t forged_seq_offset = 1;

void create_false_neighbor_information(uint8_t * packet, uint16_t len);

void create_false_neighbor_information(uint8_t * packet, uint16_t len) {
    if (packet == NULL || len < sizeof(sdn_neighbor_report_t) || len > SDN_MAX_PACKET_SIZE) {
      return;
    }
    uint8_t *forged = (uint8_t *)sdn_packetbuf_pool_get();
    if (forged == NULL) {
      SDN_DEBUG_ERROR("SDN packetbuf pool is empty.\n");
      return;
    }
    memcpy(forged, packet, len);
    SDN_HEADER(forged)->thl = SDN_DEFAULT_TTL;
    SDN_HEADER(forged)->seq_no = (uint8_t)(SDN_HEADER(packet)->seq_no + forged_seq_offset++);

 /*We count the number of neighbors and do a random from 0 to # of neigbors*/
/*The random result is the number of neighbors that will be remove (or modified) from the table*/  
    #ifdef ETX_MODIF 
    uint8_t n_neighbors;
    memcpy(&n_neighbors, forged + 8, sizeof(n_neighbors));

    uint8_t i;
    for (i = 11; i < len; i=i+4) {
      uint16_t temp_etx;
      uint16_t new_etx;
      memcpy(&temp_etx, forged + i, sizeof(temp_etx));
      new_etx = 8 + (random_rand() % 100);
      memcpy(forged + i, &new_etx, sizeof(new_etx));
    }
    #endif
    
    #ifdef ADDR_MODIF
    uint8_t a;
    for (a = 9; a < len; a=a+4) {
      sdnaddr_t fake_addr;
      memset(&fake_addr, 0, sizeof(fake_addr));
      fake_addr.u8[0] = (uint8_t)(20 + (random_rand() % 40));
      memcpy(forged + a, &fake_addr, sizeof(fake_addr));
    }
    #endif

    printf("Injecting false neighbor report for source ");
    sdnaddr_print_nodebug(&SDN_HEADER(forged)->source);
    printf(" len=%u\n", len);

    if (sdn_send_queue_enqueue(forged, len, 0) != SDN_SUCCESS) {
      sdn_packetbuf_pool_put((struct sdn_packetbuf *)forged);
      SDN_DEBUG_ERROR("Error on packet enqueue.\n");
    } else {
      SDN_METRIC_TX(forged);
      sdn_send_down_once();
    }
}

static void inject_synthesized_false_nr_for_addr(sdnaddr_t *target) {
  if (target == NULL) {
    return;
  }
  uint8_t *forged = (uint8_t *)sdn_packetbuf_pool_get();
  if (forged == NULL) {
    SDN_DEBUG_ERROR("SDN packetbuf pool is empty.\n");
    return;
  }
  sdn_neighbor_report_t *nr = (sdn_neighbor_report_t *)forged;
  nr->header.type = SDN_PACKET_NEIGHBOR_REPORT;
  nr->header.reserved = 0xFF;
  nr->header.thl = SDN_DEFAULT_TTL;
  nr->header.seq_no = (uint8_t)(200 + forged_seq_offset++);
  sdnaddr_copy(&nr->header.source, target);
  nr->flowid = SDN_CONTROLLER_FLOW;
  nr->num_of_neighbors = 2;
  uint16_t pkt_len = sizeof(sdn_neighbor_report_t);
  uint8_t k;
  for (k = 0; k < 2; k++) {
    sdn_neighbor_report_list_t nrl;
    memset(&nrl, 0, sizeof(nrl));
    nrl.neighbor.u8[0] = (uint8_t)(20 + (random_rand() % 40));
    nrl.etx = (uint16_t)(8 + (random_rand() % 100));
    memcpy(forged + pkt_len, &nrl, sizeof(nrl));
    pkt_len += sizeof(nrl);
  }
  printf("Injecting synthesized false neighbor report for source ");
  sdnaddr_print_nodebug(&nr->header.source);
  printf(" len=%u\n", pkt_len);
  if (sdn_send_queue_enqueue(forged, pkt_len, 0) != SDN_SUCCESS) {
    sdn_packetbuf_pool_put((struct sdn_packetbuf *)forged);
    SDN_DEBUG_ERROR("Error on synthesized packet enqueue.\n");
  } else {
    SDN_METRIC_TX(forged);
    sdn_send_down_once();
  }
}

static void inject_synthesized_false_nr(void) {
  struct sdn_neighbor_entry *sne = sdn_neighbor_table_head();
  if (sne == NULL) {
    return;
  }
  inject_synthesized_false_nr_for_addr(&sne->neighbor_addr);
}

void copy_neighbor_packet(uint8_t * packet, uint16_t len) {
  uint8_t slot;
  if (packet == NULL || len == 0 || len > SDN_MAX_PACKET_SIZE) {
    return;
  }
  printf("Copying neighbor reports\n");
  for (slot = 0; slot < 4; slot++) {
    if (flag[slot] == 0) {
      neighbor[slot] = neighbor_buf[slot];
      memcpy(neighbor[slot], packet, len);
      len_neighbor[slot] = len;
      flag[slot] = 1;
      return;
    }
  }
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(sdn_test_process, ev, data)
{
  PROCESS_BEGIN();

/*
  NETSTACK_RADIO.off();

  static struct etimer sdn_timer;
  etimer_set(&sdn_timer, (600 + random_rand() % 300) * CLOCK_SECOND);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&sdn_timer));

  NETSTACK_RADIO.on();
*/

  printf("SENSING AT SECONDS = %i\n", SENSING_AT_SECONDS);

  sdn_init(receiver);

  static flowid_t sink;

  sink = 2017 + (sdn_node_addr.u8[0] % SDN_SIMULATION_N_SINKS);

  printf("SDN_SIMULATION_N_SINKS %d\n", SDN_SIMULATION_N_SINKS);

  static struct etimer periodic_timer;
  static struct etimer ids_timer;
  static struct etimer attack_timer;
  #ifdef CP_DETECT
  static struct etimer ts_timer;
  #endif

  if(isSensing() == 1) {
    printf("Sensing data node.\n");
    printf("#A color=GREEN\n");
  } else {
    printf("#A color=BLUE\n");
  }

  etimer_set(&periodic_timer, (120 + random_rand() % SENSING_AT_SECONDS) * CLOCK_SECOND) ;

  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));

  if(isSensing() == 1) {
    etimer_set(&periodic_timer, SENSING_AT_SECONDS * CLOCK_SECOND);
  }

  etimer_set(&ids_timer, IDS_TIMER * CLOCK_SECOND);
  etimer_set(&attack_timer, (ATTACK_TRIGGER +  random_rand() % RANDOM_TRIGGER) * CLOCK_SECOND);
  #ifdef CP_DETECT
  etimer_set(&ts_timer, CP_TIMER * CLOCK_SECOND);
  #endif
  //ctimer_set(&attack_timer, ATTACK_TRIGGER * CLOCK_SECOND, create_false_flows, NULL);
  //printf("Flag timer = %u\n", ATTACK_TRIGGER +  random_rand() % RANDOM_TRIGGER);

  static char data[10];
  static uint8_t i = 0;
  static uint8_t counter = 0;

  while(1) {
    PROCESS_WAIT_EVENT();

    if (etimer_expired(&periodic_timer)) {

      sprintf(data, "teste %d", i++);

      SDN_DEBUG("Sending data to flow %d\n", sink);

      sdn_send((uint8_t*) data, 10, sink);

      etimer_restart(&periodic_timer);
      counter++;
    }

/*
    if (counter == 3) {
      etimer_set(&ids_timer, 2 * CLOCK_SECOND);
      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&ids_timer));
      counter = 0;
      printf("Sending IDS data to Management server\n");
      uint16_t mngt_metrics;
      mngt_metrics = 26;
      sdn_send_data_management(mngt_metrics);
      //printf("Energy consumption = %lu\n", consumed_energy());
      etimer_reset(&ids_timer);

    } 
*/
    if (etimer_expired(&attack_timer)) {
      attack = 1;
#ifdef FNI_BROAD_POISON
      static uint8_t poison_cursor = 0;
      sdnaddr_t victims[8];
      int8_t victim_slot[8];
      uint8_t victim_count = 0;
      uint8_t s, v;

      for (s = 0; s < 4 && victim_count < 8; s++) {
        if (flag[s] == 1 && len_neighbor[s] >= sizeof(sdn_neighbor_report_t)) {
          sdnaddr_t *src = &SDN_HEADER(neighbor[s])->source;
          if (src->u8[0] > 3) {
            uint8_t exists = 0;
            for (v = 0; v < victim_count; v++) {
              if (sdnaddr_cmp(&victims[v], src) == SDN_EQUAL) {
                exists = 1;
                break;
              }
            }
            if (!exists) {
              sdnaddr_copy(&victims[victim_count], src);
              victim_slot[victim_count] = (int8_t)s;
              victim_count++;
            }
          }
        }
      }

      struct sdn_neighbor_entry *sne;
      for (sne = sdn_neighbor_table_head(); sne != NULL && victim_count < 8;
           sne = sdn_neighbor_table_next(sne->neighbor_addr)) {
        if (sne->neighbor_addr.u8[0] > 3) {
          uint8_t exists = 0;
          for (v = 0; v < victim_count; v++) {
            if (sdnaddr_cmp(&victims[v], &sne->neighbor_addr) == SDN_EQUAL) {
              exists = 1;
              break;
            }
          }
          if (!exists) {
            sdnaddr_copy(&victims[victim_count], &sne->neighbor_addr);
            victim_slot[victim_count] = -1;
            victim_count++;
          }
        }
      }

      if (victim_count > 0) {
        uint8_t idx = (uint8_t)(poison_cursor % victim_count);
        poison_cursor++;
        if (victim_slot[idx] >= 0) {
          uint8_t slot = (uint8_t)victim_slot[idx];
          create_false_neighbor_information(neighbor[slot], len_neighbor[slot]);
        } else {
          inject_synthesized_false_nr_for_addr(&victims[idx]);
        }
      } else {
        inject_synthesized_false_nr();
      }
#else
      uint8_t n_random;
      n_random = random_rand() % 4;
      if (flag[n_random] == 1) {
        create_false_neighbor_information(neighbor[n_random], len_neighbor[n_random]);
      }else if (flag[0] == 1) {
        n_random = 0;
        create_false_neighbor_information(neighbor[n_random], len_neighbor[n_random]);
      } else {
        inject_synthesized_false_nr();
      }
#endif
      etimer_set(&attack_timer, ATTACK_PERIOD * CLOCK_SECOND);
    }

    #if defined (CP_DETECT) && defined (CENTR_DETECT)
    if (etimer_expired(&ts_timer)){
      uint16_t mngt_metrics;
      mngt_metrics = SDN_MNGT_METRIC_QTY_DATA + SDN_MNGT_CTRL_PCKT_TX;
      sdn_send_data_management(mngt_metrics, 1);
      etimer_reset(&ts_timer);
    }
    #endif
/*
    if (etimer_expired(&ids_timer)) {
      
      printf("Sending IDS data to controller\n");
      uint16_t mngt_metrics;
      mngt_metrics = 24;
      sdn_send_data_management(mngt_metrics, 2);
      etimer_reset(&ids_timer);
    }
*/
  }

  PROCESS_END();
}
