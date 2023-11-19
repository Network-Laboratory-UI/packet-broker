#ifndef CONFIG_H
#define CONFIG_H
// C library
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <time.h>
#include <sched.h>

// DPDK library
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>
#include <rte_pdump.h>

// Threading library
#include <pthread.h>
#include <unistd.h>

// ======================================================= THE DEFINE =======================================================

// Define the limit of
#define MAX_PACKET_LEN 1500
#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define MAX_TCP_PAYLOAD_LEN 1024

// Define the dump file name
#define PCAP_FILE "packet_forwarded.txt"

// Define the statistics file name
#define STAT_FILE "statistics.csv"

// Define period to print stats

// Define the type of filter
#define HTTP_GET 112
#define TLS_CLIENT_HELLO 212

// Define HTTP GET and TLS CLIENT HELLO Pattern
// add MAGIC for the pattern and MAGIC_LEN for the byte length on variable name
#define HTTP_GET_MAGIC "GET /"
#define HTTP_GET_MAGIC_LEN 5
#define TLS_MAGIC "\x16\x03\x01"
#define TLS_MAGIC_LEN 3
#define TLS_CLIENT_HELLO_MAGIC "\x01"
#define TLS_CLIENT_HELLO_MAGIC_LEN 1

// Define the number of threads and tasks
#define MAX_THREADS 4
#define MAX_TASKS 1000000

// Force quit variable
static volatile bool force_quit;

// Timer period for statistics
static uint16_t timer_period = 100;		// 100 Cycle
static uint16_t timer_period_stats = 1; // 1 minutes
static uint16_t timer_period_send = 10; // 10 minutes

// Define fixed character for screen control
const char clr[] = {27, '[', '2', 'J', '\0'};
const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};

// TDOO: Create struct for packet broker identifier

// Port statistic struct
struct port_statistics_data
{
	uint64_t tx_count;
	uint64_t rx_count;
	uint64_t tx_size;
	uint64_t rx_size;
	uint64_t dropped;
	uint64_t httpMatch;
	uint64_t httpsMatch;
    pthread_mutex_t mutex;
	// TODO: add size of packet, throughpout.
} __rte_cache_aligned;
struct port_statistics_data port_statistics[RTE_MAX_ETHPORTS];

struct StatsThreadData {
    FILE *dumpFile;
    FILE *statFile;
    pthread_mutex_t mutex;
};

// End if define
#endif