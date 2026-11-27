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

#include <math.h>
#include <stdio.h>
#include "contiki.h"
#include <inttypes.h>
#include "manage-info.h"
#include "sys/etimer.h"
#include "sdn-node-security-module.h"
#include "sdn-constants.h"
#include "sdn-send-packet.h"

// #define m_win 201 // number of samples for the training process. It starts in 201 to discard the first sample
#ifndef DIST_M_WIN
#define DIST_M_WIN 201
#endif
#define m_win DIST_M_WIN
#ifndef DIST_INIT_DELAY
#define DIST_INIT_DELAY 720
#endif
#ifndef DIST_D_WIN
#define DIST_D_WIN 50
#endif
#define d_win DIST_D_WIN
#ifndef DIST_CA
#define DIST_CA 2.82f
#endif
#ifndef ALARM_MAX_RETRIES
#define ALARM_MAX_RETRIES 5
#endif
#define sus_buff 10 // the buffer on the suspects list

#ifdef SONETWSEC
#define SAMPLING_TIME 120
#endif
#ifdef SSIXTYSEC
#define SAMPLING_TIME 60
#endif
#ifdef STHIRSEC
#define SAMPLING_TIME 30
#endif
#ifdef STENSEC
#define SAMPLING_TIME 10
#endif


#if defined (CP_DETECT) && defined (DIST_DETECT)
unsigned long last_tx;
unsigned long diff_tx;
unsigned long last_cpu;
unsigned long diff_cpu;
unsigned long last_lpm;
unsigned long diff_lpm;
unsigned long last_listen;
unsigned long diff_listen;
unsigned long ticks_tx;
unsigned long ticks_cpu;
unsigned long ticks_lpm;
unsigned long ticks_listen;
unsigned long energy;

// DT is the parameter that will be compared against the critical value (ca)
double DT;
float ca = DIST_CA;
float Var;
float g = 0;

// unsigned long training[m_win];
// unsigned long monitoring[d_win];
uint16_t training[m_win];
uint16_t monitoring[d_win];

uint16_t CPA;
unsigned long sum_tot_q1 = 0;
unsigned long sum_tot_q2 = 0;

#if defined(ENERGY) && (defined(TRANS_TS) || defined(RX_CTRL_PCKT))
static unsigned long energy_sum_tot_q1 = 0;
static unsigned long energy_sum_tot_q2 = 0;
static float energy_mean = 0.0f;
static float energy_m2 = 0.0f;
static uint16_t energy_train_count = 0;
static float energy_Var = 0.0f;
#endif

static uint8_t alarm_pending = 0;
static uint8_t alarm_acked = 0;
static uint8_t alarm_retries = 0;

sdnaddr_t suspects_list[sus_buff];
uint8_t add_counter = 0;


PROCESS(security_node_process, "Security process");

void security_node_init(){
  process_start(&security_node_process, NULL);
}

unsigned long security_node_transmitting_time(){
  energest_flush();
  diff_tx = energest_type_time(ENERGEST_TYPE_TRANSMIT) - last_tx;
  last_tx = energest_type_time(ENERGEST_TYPE_TRANSMIT);
  //printf("Transmitting time: %lu\n", diff_tx);
  return diff_tx;
}

unsigned long security_node_lpm_time(){
  energest_flush();
  diff_lpm = energest_type_time(ENERGEST_TYPE_LPM) - last_lpm;
  last_lpm = energest_type_time(ENERGEST_TYPE_LPM);
  //printf("LPM time: %lu\n", diff_lpm);
  return diff_lpm;
}

unsigned long security_node_listening_time(){
  energest_flush();
  diff_listen = energest_type_time(ENERGEST_TYPE_LISTEN) - last_listen;
  last_listen = energest_type_time(ENERGEST_TYPE_LISTEN);
  //printf("Listening time: %lu\n", diff_listen);
  return diff_listen;
}

unsigned long security_node_processing_time(){
  energest_flush();
  diff_cpu = energest_type_time(ENERGEST_TYPE_CPU) - last_cpu;
  last_cpu = energest_type_time(ENERGEST_TYPE_CPU);
  //printf("Processing time: %lu\n", diff_cpu);
  return diff_cpu;
}

static unsigned long security_node_consumption_mJ_from_tx(unsigned long tx_ticks){
  ticks_tx = tx_ticks;
  ticks_lpm = security_node_lpm_time();
  ticks_listen = security_node_listening_time();
  ticks_cpu = security_node_processing_time();

  energy = 3.3 * (ticks_tx * 17.4 + ticks_lpm * 0.023 + ticks_listen * 18.8 + ticks_cpu * 10) / 32768;
  //printf("Energy (mJ): %lu\n", energy);

  return energy;
}

unsigned long security_node_consumption_mJ(){
  return security_node_consumption_mJ_from_tx(security_node_transmitting_time());
}
// create time series for training

void security_node_ts_training(uint16_t metric, uint16_t train_counter){
  if (train_counter < m_win) {
    training[train_counter] = metric;
  }
}

// include a sample into the monitoring ts
void security_node_ts_monitoring(uint16_t metric, uint16_t monitor_counter){
  if (monitor_counter < d_win) {
    monitoring[monitor_counter] = metric;
  }
}

// summatory of training time series
void security_node_sum_q1(uint16_t k_counter){
  uint16_t k;
  sum_tot_q1 = 0;
  // start in k = 1 to discard the first sample because it represents the total time of 1 hour
  for(k = 1; k <= k_counter && k < m_win; k++){
    sum_tot_q1 += (unsigned long)training[k];
  }
  //printf("Summatory Q1: %lu\n", sum_tot_q1);
}

// summatory of monitoring window

void security_node_sum_q2(unsigned long metric){
  sum_tot_q2 += (unsigned long)metric;
}

// Calculate the variance of the time series

void security_node_variance_ts(unsigned long tot_q1, int v_counter){
  if (v_counter <= 1) {
    Var = 0.0f;
    return;
  }
  float average = (float)tot_q1/(float)v_counter;
  //printf("Average = %lu\n", (uint32_t)average);
  float sum_var = 0.0;
  int v;
  // start in v = 1 to discard the first sample because it represents the total time of 1 hour
  for(v = 1; v <= v_counter && v < m_win; v++){
    sum_var += (float)(pow((training[v] - average), 2));
  }
  Var = sum_var/(v_counter-1);
  //printf("Variance Q1: %lu\n", (uint32_t)Var);
}

// Determine if there is a change point

uint16_t security_node_cp_detector(uint16_t i_s, uint16_t M){
  if (M == 0) {
    return 0;
  }
  double numerator = fabs((double)(sum_tot_q2-((i_s/(double)M)*sum_tot_q1)));
  double denominator = sqrt((double)M*(double)Var)*(1+((double)i_s/(double)M))*(powf((double)i_s/(double)(i_s+M),(double)g));
  if (denominator <= 0.0) {
    DT = 0.0;
    return 0;
  }
  DT = numerator/denominator;
  //printf("Summatory Q1: %lu, Summatory Q2: %lu, M: %u, i_s: %u\n", sum_tot_q1, sum_tot_q2, M, i_s);
  // printf("%s\n", );
  // printf("Summatory Q2: %lu\n", sum_tot_q2);
  //printf("Numerator %ld\n", (signed long)numerator);
  //printf("Denominator %ld\n", (signed long)denominator);
  if(DT >= ca){
    return(m_win + i_s);
  }
  else{
    return(0);
  }
}

#if defined(ENERGY) && (defined(TRANS_TS) || defined(RX_CTRL_PCKT))
static void security_node_energy_training_sample(uint16_t e_sample, uint16_t train_counter){
  if (train_counter == 0) {
    return;
  }
  energy_sum_tot_q1 += (unsigned long)e_sample;
  energy_train_count++;
  float delta = (float)e_sample - energy_mean;
  energy_mean += delta / (float)energy_train_count;
  energy_m2 += delta * ((float)e_sample - energy_mean);
}

static uint16_t security_node_energy_cp_detector(uint16_t i_s, uint16_t M){
  if (M == 0) {
    return 0;
  }
  double numerator = fabs((double)(energy_sum_tot_q2-((i_s/(double)M)*energy_sum_tot_q1)));
  double denominator = sqrt((double)M*(double)energy_Var)*(1+((double)i_s/(double)M))*(powf((double)i_s/(double)(i_s+M),(double)g));
  if (denominator <= 0.0) {
    return 0;
  }
  if ((numerator/denominator) >= ca) {
    return (m_win + i_s);
  }
  return 0;
}
#endif

void security_node_add_suspect(sdnaddr_t suspect){
  if(add_counter >= sus_buff){
  	add_counter = 0;
  }
  suspects_list[add_counter] = suspect;
  printf("Adding suspect: ");
  sdnaddr_print_nodebug(&suspect);
  printf("\n");
  add_counter++;
}

sdnaddr_t *security_node_choose_suspect(){
  uint8_t max_count = 0;
  uint8_t max_value = 0;
  uint8_t i, j;

  for(i = 0; i < sus_buff; i++){
    if(sdnaddr_cmp(&suspects_list[i], &sdnaddr_null) == SDN_EQUAL){
      if(i == 0){
      	return NULL;
      }else{
        return &suspects_list[max_value];
      }
    }
    uint8_t count_sus = 0;
	  for(j = 0; j < sus_buff; j++){
	    if(sdnaddr_cmp(&suspects_list[j], &suspects_list[i]) == SDN_EQUAL){
	      count_sus++;
	    }
	  }
	  if(count_sus > max_count){
	    max_count = count_sus;
	    max_value = i;
	  }
  }
  return &suspects_list[max_value];
}

void security_node_send_alarm(){
  sdn_send_data_management(SDN_SEC_CP_DETECT_ALARM, 1);
  //printf("Sending alarm\n");
}

void security_node_alarm_acked(void){
  if (alarm_pending && !alarm_acked) {
    alarm_acked = 1;
    alarm_pending = 0;
    printf("CP alarm acknowledged\n");
  }
}

void security_new_period(){
  int samp_counter;
  if (m_win > d_win) {
    // Discard first d_win samples and move the rest to the start to free space
    for(samp_counter = 1; samp_counter < (m_win-d_win); samp_counter++){
      training[samp_counter] =  training[samp_counter+d_win];
    }
    // Moves monitoring samples to the last d_win samples in the training time series
    for(samp_counter = 0; samp_counter < d_win; samp_counter++){
      training[samp_counter+m_win-d_win] = monitoring[samp_counter];
      monitoring[samp_counter] = 0;
    }
  } else {
    int keep = m_win - 1;
    int start_idx = d_win - keep;
    for(samp_counter = 0; samp_counter < keep; samp_counter++){
      training[1 + samp_counter] = monitoring[start_idx + samp_counter];
    }
    for(samp_counter = 0; samp_counter < d_win; samp_counter++){
      monitoring[samp_counter] = 0;
    }
  }
  //printf("Checking new period: ");
  for(samp_counter = 0; samp_counter < m_win; samp_counter++){
    printf("%u, ", training[samp_counter]);
  }
  printf("\n");
  // restart cusum
  sum_tot_q1 = 0;
  sum_tot_q2 = 0;
}

PROCESS_THREAD(security_node_process, ev, data){

  PROCESS_BEGIN();

  static struct etimer ts_timer;
  static uint16_t ts_counter = 0;
  // sets the timer to start the period previous initiate the metric monitoring
  // etimer_set(&ts_timer, 3600 * CLOCK_SECOND);
  etimer_set(&ts_timer, DIST_INIT_DELAY * CLOCK_SECOND);
  // when the ts_timer expires the time series construction starts
  // we defined the monitoring window (traning) with m_win, when the counter surpass this value,
  // the detection window starts

  printf("Sampling time: %u\n", SAMPLING_TIME);

  while(1){
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&ts_timer));
    if (etimer_expired(&ts_timer)){
	// time series construction
	// ts_counter < 2000 is hard code, just for these simulations. It's a method to stop the security process
  	  if(ts_counter < 2000){
  	    if(ts_counter <= (m_win-1)){
  	      #if defined(TRANS_TS)
          unsigned long tx_ticks_sample = security_node_transmitting_time();
  	      security_node_ts_training((uint16_t)tx_ticks_sample, ts_counter);
  	      printf("Sample: %u, Transmitting time: %u\n", (ts_counter), training[ts_counter]);
          #ifdef ENERGY
          uint16_t e_sample = (uint16_t)security_node_consumption_mJ_from_tx(tx_ticks_sample);
          security_node_energy_training_sample(e_sample, ts_counter);
          printf("Sample: %u, Consumption (mJ): %u\n", (ts_counter), e_sample);
          #endif
  	      #elif defined(RX_CTRL_PCKT)
  	      security_node_ts_training((uint16_t)manag_get_info(64), ts_counter);
  	      printf("Sample: %u, Control packets received: %u\n", (ts_counter), training[ts_counter]);
          #ifdef ENERGY
          uint16_t e_sample = (uint16_t)security_node_consumption_mJ();
          security_node_energy_training_sample(e_sample, ts_counter);
          printf("Sample: %u, Consumption (mJ): %u\n", (ts_counter), e_sample);
          #endif
          #elif defined(ENERGY)
          security_node_ts_training((uint16_t)security_node_consumption_mJ(), ts_counter);
  	      printf("Sample: %u, Consumption (mJ): %u\n", (ts_counter), training[ts_counter]);
          #endif
  	    }

  	    if(ts_counter == (m_win-1)){
  	      security_node_sum_q1(ts_counter);
  	      security_node_variance_ts(sum_tot_q1, ts_counter);
          #if defined(ENERGY) && (defined(TRANS_TS) || defined(RX_CTRL_PCKT))
          energy_Var = (energy_train_count > 1) ? (energy_m2 / (float)(energy_train_count - 1)) : 0.0f;
          #endif
  	    }

  	    if(ts_counter >= (m_win)){
          #if defined(ENERGY) && (defined(TRANS_TS) || defined(RX_CTRL_PCKT))
          uint16_t e_sample = 0;
          #endif
  	      #if defined(TRANS_TS)
          unsigned long tx_ticks_sample = security_node_transmitting_time();
  	      security_node_ts_monitoring((uint16_t)tx_ticks_sample, ts_counter-m_win);
  	      printf("Sample: %u, Transmitting time: %u\n", (ts_counter), monitoring[ts_counter-m_win]);
          #ifdef ENERGY
          e_sample = (uint16_t)security_node_consumption_mJ_from_tx(tx_ticks_sample);
          printf("Sample: %u, Consumption (mJ): %u\n", (ts_counter), e_sample);
          #endif
  	      #elif defined(RX_CTRL_PCKT)
  	      security_node_ts_monitoring((uint16_t)manag_get_info(64), ts_counter-m_win);
  	      printf("Sample: %u, Control packets received: %u\n", (ts_counter), monitoring[ts_counter-m_win]);
          #ifdef ENERGY
          e_sample = (uint16_t)security_node_consumption_mJ();
          printf("Sample: %u, Consumption (mJ): %u\n", (ts_counter), e_sample);
          #endif
          #elif defined(ENERGY)
          security_node_ts_monitoring((uint16_t)security_node_consumption_mJ(), ts_counter-m_win);
  	      printf("Sample: %u, Consumption (mJ): %u\n", (ts_counter), monitoring[ts_counter-m_win]);
          #endif

  	      security_node_sum_q2(monitoring[ts_counter-m_win]);
  	      CPA = security_node_cp_detector(ts_counter-(m_win-1), m_win-1);
          #if defined(ENERGY) && (defined(TRANS_TS) || defined(RX_CTRL_PCKT))
          energy_sum_tot_q2 += (unsigned long)e_sample;
          if (CPA == 0) {
            CPA = security_node_energy_cp_detector(ts_counter-(m_win-1), m_win-1);
          }
          #endif
  	      if(CPA != 0){
            alarm_pending = 1;
            alarm_acked = 0;
            alarm_retries = 1;
  	        security_node_send_alarm();
  	        printf("CP detected in %u\n", CPA);
  	        ts_counter = 2000;
  	      }
          if((ts_counter >= m_win + d_win - 1) && ts_counter != 2000){
            // ts_counter = 2000;
            security_new_period();
            ts_counter = m_win-1;
            security_node_sum_q1(ts_counter);
            security_node_variance_ts(sum_tot_q1, ts_counter);
            #if defined(ENERGY) && (defined(TRANS_TS) || defined(RX_CTRL_PCKT))
            energy_sum_tot_q2 = 0;
            #endif
          }
  	    }
        if (ts_counter < 2000) {
	        ts_counter++;
        }
	      // etimer_set(&ts_timer, 120 * CLOCK_SECOND);
        etimer_set(&ts_timer, SAMPLING_TIME * CLOCK_SECOND);
  	  } else {
        if (alarm_pending && !alarm_acked && alarm_retries < ALARM_MAX_RETRIES) {
          alarm_retries++;
          printf("Retrying CP detection alarm (%u/%u)\n", alarm_retries, ALARM_MAX_RETRIES);
          security_node_send_alarm();
          etimer_set(&ts_timer, SAMPLING_TIME * CLOCK_SECOND);
        } else {
  	      printf("CP already detected\n");
  	      etimer_reset(&ts_timer);
  	      etimer_stop(&ts_timer);
        }
  	  }
	  }
  }
  PROCESS_END();
}
#endif
