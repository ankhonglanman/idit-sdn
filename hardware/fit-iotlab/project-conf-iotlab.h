#ifndef PROJECT_CONF_IOTLAB_H_
#define PROJECT_CONF_IOTLAB_H_

/* Match controller-pc SDNADDR_SIZE=2 on FIT IoT-LAB hardware */
#ifdef LINKADDR_CONF_SIZE
#undef LINKADDR_CONF_SIZE
#endif
#define LINKADDR_CONF_SIZE 2

/* Disable unused process names and uIPv6 TCP to keep firmware compact */
#define PROCESS_CONF_NO_PROCESS_NAMES 1
#define UIP_CONF_TCP 0

/* Isolate experiment on dedicated IEEE 802.15.4 channel & PAN ID */
#ifndef IOTLAB_RF_CHANNEL
#define IOTLAB_RF_CHANNEL 22
#endif

#ifndef IOTLAB_PAN_ID
#define IOTLAB_PAN_ID 0x1D17
#endif

#ifdef RF_CHANNEL
#undef RF_CHANNEL
#endif
#define RF_CHANNEL IOTLAB_RF_CHANNEL

#ifdef CC2538_RF_CONF_CHANNEL
#undef CC2538_RF_CONF_CHANNEL
#endif
#define CC2538_RF_CONF_CHANNEL IOTLAB_RF_CHANNEL

#ifdef CC2420_CONF_CHANNEL
#undef CC2420_CONF_CHANNEL
#endif
#define CC2420_CONF_CHANNEL IOTLAB_RF_CHANNEL

#ifdef IEEE802154_CONF_PANID
#undef IEEE802154_CONF_PANID
#endif
#define IEEE802154_CONF_PANID IOTLAB_PAN_ID

/* Optional reduced TX power for multi-hop topologies in dense testbeds */
#ifdef IOTLAB_TX_POWER
#ifdef CC2538_RF_CONF_TX_POWER
#undef CC2538_RF_CONF_TX_POWER
#endif
#define CC2538_RF_CONF_TX_POWER IOTLAB_TX_POWER
#ifdef CC2420_CONF_TXPOWER
#undef CC2420_CONF_TXPOWER
#endif
#define CC2420_CONF_TXPOWER IOTLAB_TX_POWER
#endif

/* SDN neighbor & controller discovery drivers */
#define SDN_CONF_ND collect_sdn_nd
#define SDN_CONF_CD null_sdn_cd

/* RDC selection: ContikiMAC by default, or NullRDC with -DIOTLAB_USE_NULLRDC */
#ifdef NETSTACK_CONF_RDC
#undef NETSTACK_CONF_RDC
#endif
#ifdef IOTLAB_USE_NULLRDC
#define NETSTACK_CONF_RDC nullrdc_driver
#else
#define NETSTACK_CONF_RDC contikimac_driver
#endif

#define SDN_CONF_TX_RELIABILITY 1
#define SDN_CONF_1HOP_RELIABILITY 0

#define NETSTACK_CONF_LLSEC commutator_protocol_driver

/* Larger packet/queue buffers for real wireless interference */
#define SDN_PACKETBUF_POOL_SIZE 16
#define SDN_SEND_QUEUE_SIZE 12
#define SDN_RECV_QUEUE_SIZE 12

#define SDN_MAX_PACKET_SIZE (127 - 11)

#endif /* PROJECT_CONF_IOTLAB_H_ */
