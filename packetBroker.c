// ======================================================= THE LIBRARY =======================================================

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
#include <unistd.h>
#include <curl/curl.h>
#include <jansson.h>
#include <pthread.h>

// DPDK library
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>
#include <rte_pdump.h>

// Hyperscan library
#include <hs/hs.h>

// ======================================================= THE DEFINE =======================================================

// Define the limit of
uint32_t MAX_PACKET_LEN;
uint32_t RX_RING_SIZE;
uint32_t TX_RING_SIZE;
uint32_t NUM_MBUFS;
uint32_t MBUF_CACHE_SIZE;
uint32_t BURST_SIZE;
uint32_t MAX_TCP_PAYLOAD_LEN;
char NPB_ID[200];

// Define the statistics file name
char STAT_FILE[100];
char STAT_FILE_EXT[100];
char HOSTNAME[100];

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

// Hyperscan setup
hs_database_t *database;
hs_compile_error_t *compile_err;
hs_scratch_t *scratch = NULL;

const char *patterns[] = {"GET /", "\x16\x03\x01.{2}\x01"}; // Add your patterns
const int ids[2] = {0, 1};
unsigned flags[] = {HS_FLAG_SINGLEMATCH,HS_FLAG_SINGLEMATCH};

// Force quit variable
static volatile bool force_quit;

// Timer period for statistics
static uint32_t TIMER_PERIOD_STATS; // 1 second
static uint32_t TIMER_PERIOD_SEND;	// 10 minutes

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
	long int throughput;
	uint64_t noMatch;
	uint64_t err_rx;
	uint64_t err_tx;
	uint64_t mbuf_err;
} __rte_cache_aligned;
struct port_statistics_data port_statistics[RTE_MAX_ETHPORTS];
struct rte_eth_stats stats_0;
struct rte_eth_stats stats_1;
uint64_t httpMatch = 0;
uint64_t httpsMatch = 0;

// Service Time
clock_t start, end;
double service_time = 0, avg_service_time = 0;
int count_service_time = 0;

/*
 * The log message function
 * Log the message to the log file
 * @param filename
 * 	the name of the file
 * @param line
 * 	the line of the file
 * @param format
 * 	the format of the message
 */
typedef enum {
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR
} LogLevel;

const char* getLogLevelString(LogLevel level) {
    switch(level) {
        case LOG_LEVEL_INFO: return "INFO";
        case LOG_LEVEL_WARNING: return "WARNING";
        case LOG_LEVEL_ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

void logMessage(LogLevel level, const char *filename, int line, const char *format, ...)
{
    // Open the log file in append mode
    FILE *file = fopen("logs/log.txt", "a");
    if (file == NULL)
    {
        logMessage(LOG_LEVEL_ERROR, __FILE__, __LINE__, "Error opening file %s\n", filename);
        return;
    }

    // Get the current time
    time_t rawtime;
    struct tm *timeinfo;
    char timestamp[20];
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);

    // Write the timestamp and log level to the file
    fprintf(file, "[%s] [%s] [%s:%d] - ", timestamp, getLogLevelString(level), filename, line);

    // Write the formatted message to the file
    va_list args;
    va_start(args, format);
    vfprintf(file, format, args);
    va_end(args);

    // Close the file
    fclose(file);
}

/*
 * The clear statistics function
 * Clear the statistics
 */
static void clear_stats(void)
{
	memset(port_statistics, 0, RTE_MAX_ETHPORTS * sizeof(struct port_statistics_data));
}

/*
 * The port initialization function
 * Initialize the port with the given port number and mbuf pool
 * @param port
 * 	the port number
 * @param mbuf_pool
 * 	pointer to a memory pool of mbufs (memory buffers)
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	// Declaration
	struct rte_eth_conf port_conf;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	// Check port validity
	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	// Set memory for port configuration
	memset(&port_conf, 0, sizeof(struct rte_eth_conf));

	// Get the port info
	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0)
	{
		logMessage(LOG_LEVEL_ERROR,__FILE__, __LINE__, "Error during getting device (port %u) info: %s\n",
				   port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	// Configure the Ethernet device
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	// Allocate 1 Rx queue for each port
	for (q = 0; q < rx_rings; q++)
	{
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
										rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;

	// Allocate 1 Tx queue for each port
	for (q = 0; q < tx_rings; q++)
	{
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
										rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	// Starting the ethernet port
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	// Display the MAC Addresses
	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	logMessage(LOG_LEVEL_INFO, __FILE__, __LINE__, "Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			   port, RTE_ETHER_ADDR_BYTES(&addr));

	// SET THE PORT TO PROMOCIOUS
	retval = rte_eth_promiscuous_enable(port);
	if (retval != 0)
		return retval;

	return 0;
}

/*
 * The open file function
 * Open the file with the given filename
 * @param filename
 * 	the name of the file
 */
static FILE *open_file(const char *filename)
{
	logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "Opening file %s\n", filename);
	FILE *f = fopen(filename, "a+");
	if (f == NULL)
	{
		logMessage(LOG_LEVEL_ERROR,__FILE__, __LINE__, "Error opening file %s\n", filename);
		rte_exit(EXIT_FAILURE, "Error opening file %s\n", filename);
	}
	return f;
}

/*
 * The print statistics function
 * Print the statistics to the console
 */
static void
print_stats(int *last_run_print)
{
	unsigned int portid;

	const char clr[] = {27, '[', '2', 'J', '\0'};
	const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};

	// set timer
	time_t rawtime;
	struct tm *timeinfo;
	time(&rawtime);
	timeinfo = localtime(&rawtime);

	if (timeinfo->tm_sec % TIMER_PERIOD_STATS == 0 && timeinfo->tm_sec != *last_run_print)
	{
		// Clear screen and move to top left
		printf("%s%s", clr, topLeft);
		printf("PACKET BORKER\n");
		printf("\nRefreshed every %d seconds. "
			   "Send every %d minutes.\n",
			   TIMER_PERIOD_STATS, TIMER_PERIOD_SEND);
		printf("\nPort statistics ====================================");

		for (portid = 0; portid < 2; portid++)
		{
			printf("\nStatistics for port %u ------------------------------"
				   "\nPackets sent count: %18" PRIu64
				   "\nPackets sent size: %19" PRIu64
				   "\nPackets received count: %14" PRIu64
				   "\nPackets received size: %15" PRIu64
				   "\nPackets dropped: %21" PRIu64
				   "\nHTTP GET match: %22" PRIu64
				   "\nTLS CLIENT HELLO match: %14" PRIu64
				   "\nNo match: %28" PRIu64
				   "\nThroughput: %26" PRId64
				   "\nPacket errors rx: %20" PRIu64
				   "\nPacket errors tx: %20" PRIu64
				   "\nPacket mbuf errors: %18" PRIu64,
				   portid,
				   port_statistics[portid].tx_count,
				   port_statistics[portid].tx_size,
				   port_statistics[portid].rx_count,
				   port_statistics[portid].rx_size,
				   port_statistics[portid].dropped,
				   port_statistics[portid].httpMatch,
				   port_statistics[portid].httpsMatch,
				   port_statistics[portid].noMatch,
				   port_statistics[portid].throughput,
				   port_statistics[portid].err_rx,
				   port_statistics[portid].err_tx,
				   port_statistics[portid].mbuf_err);
		}
		printf("\n=====================================================");

		fflush(stdout);

		// clear the stats
		clear_stats();
		*last_run_print = timeinfo->tm_sec;
	}
}

/*
 * The print statistics csv header function
 * Print the header of the statistics to the csv file
 * @param f
 * 	the file pointer
 */
static void print_stats_csv_header(FILE *f)
{
	fprintf(f, "npb_id,http_count,https_count,no_match,rx_0_count,tx_0_count,rx_0_size,tx_0_size,rx_0_drop,rx_0_error,tx_0_error,rx_0_mbuf,rx_1_count,tx_1_count,rx_1_size,tx_1_size,rx_1_drop,rx_1_error,tx_1_error,rx_1_mbuf,time,throughput,service_time\n"); // Header row
}

/*
 * The print statistics csv function
 * Print the statistics to the csv file
 * @param f
 * 	the file pointer
 */
static void print_stats_csv(FILE *f, char *timestamp)
{
	// Write data to the CSV file
	fprintf(f, "%s,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%s,%ld,%f\n", NPB_ID, port_statistics[0].httpMatch, port_statistics[0].httpsMatch, port_statistics[0].noMatch, port_statistics[0].rx_count, port_statistics[0].tx_count, port_statistics[0].rx_size, port_statistics[0].tx_size, port_statistics[0].dropped, port_statistics[0].err_rx, port_statistics[0].err_tx, port_statistics[0].mbuf_err, port_statistics[1].rx_count, port_statistics[1].tx_count, port_statistics[1].rx_size, port_statistics[1].tx_size, port_statistics[1].dropped, port_statistics[1].err_rx, port_statistics[1].err_tx, port_statistics[1].mbuf_err, timestamp, port_statistics[1].throughput, avg_service_time);
}

/*
 * The load configuration file function
 * Load the configuration file
 */
int load_config_file()
{
	FILE *configFile = fopen("config/config.cfg", "r");
	if (configFile == NULL)
	{
		logMessage(LOG_LEVEL_ERROR,__FILE__, __LINE__, "Cannot open the config file\n");
		return 1;
	}

	char line[256];
	char key[256];
	char value[256];

	while (fgets(line, sizeof(line), configFile))
	{
		if (sscanf(line, "%255[^=]= %255[^\n]", key, value) == 2)
		{
			if (strcmp(key, "MAX_PACKET_LEN") == 0)
			{
				MAX_PACKET_LEN = atoi(value);
				logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "MAX_PACKET_LEN: %d\n", MAX_PACKET_LEN);
			}
			else if (strcmp(key, "RX_RING_SIZE") == 0)
			{
				RX_RING_SIZE = atoi(value);
				logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "RX_RING_SIZE: %d\n", RX_RING_SIZE);
			}
			else if (strcmp(key, "TX_RING_SIZE") == 0)
			{
				TX_RING_SIZE = atoi(value);
				logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "TX_RING_SIZE: %d\n", TX_RING_SIZE);
			}
			else if (strcmp(key, "NUM_MBUFS") == 0)
			{
				NUM_MBUFS = atoi(value);
				logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "NUM_MBUFS: %d\n", NUM_MBUFS);
			}
			else if (strcmp(key, "MBUF_CACHE_SIZE") == 0)
			{
				MBUF_CACHE_SIZE = atoi(value);
				logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "MBUF_CACHE_SIZE: %d\n", MBUF_CACHE_SIZE);
			}
			else if (strcmp(key, "BURST_SIZE") == 0)
			{
				BURST_SIZE = atoi(value);
				logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "BURST_SIZE: %d\n", BURST_SIZE);
			}
			else if (strcmp(key, "MAX_TCP_PAYLOAD_LEN") == 0)
			{
				MAX_TCP_PAYLOAD_LEN = atoi(value);
				logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "MAX_TCP_PAYLOAD_LEN: %d\n", MAX_TCP_PAYLOAD_LEN);
			}
			else if (strcmp(key, "STAT_FILE") == 0)
			{
				strcpy(STAT_FILE, value);
				logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "STAT_FILE: %s\n", STAT_FILE);
			}
			else if (strcmp(key, "STAT_FILE_EXT") == 0)
			{
				strcpy(STAT_FILE_EXT, value);
				logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "STAT_FILE_EXT: %s\n", STAT_FILE_EXT);
			}
			else if (strcmp(key, "TIMER_PERIOD_STATS") == 0)
			{
				TIMER_PERIOD_STATS = atoi(value);
				logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "TIMER_PERIOD_STATS: %d\n", TIMER_PERIOD_STATS);
			}
			else if (strcmp(key, "TIMER_PERIOD_SEND") == 0)
			{
				TIMER_PERIOD_SEND = atoi(value);
				logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "TIMER_PERIOD_SEND: %d\n", TIMER_PERIOD_SEND);
			}
			else if (strcmp(key, "ID_NPB") == 0)
			{
				strcpy(NPB_ID, value);
				logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "NPB ID: %s\n", NPB_ID);
			}
			else if (strcmp(key, "HOSTNAME") == 0)
			{
				strcpy(HOSTNAME, value);
				logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "HOSTNAME: %s\n", HOSTNAME);
			}
		}
	}

	fclose(configFile);
	return 0;
}

typedef struct {
    unsigned int id;
} MatchContext;

static int eventHandler(unsigned int id, unsigned long long from,
                        unsigned long long to, unsigned int flags, void *ctx) {
	// printf("id: %d, from: %llu, to: %llu\n", id, from, to);
    // printf("Match for pattern \"%s\" at offset %llu\n", patterns[id], to);
	MatchContext *matchCtx = (MatchContext *)ctx;
	matchCtx->id = id+1;
	// free(matchCtx);
    return 0;
}

/*
 * The packet checker function
 * Check the packet type
 * @param pkt
 * 	the packet
 * @param nb_rx
 * 	the number of packets
 */
static int packet_checker(struct rte_mbuf **pkt)
{
	// // Define Variable
	// int sent;

	// // Parse Ethernet header
	// struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(*pkt, struct rte_ether_hdr *);

	// // Check if it's an IP packet
	// if (eth_hdr->ether_type == rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4))
	// {
	// 	// Parse IP header
	// 	struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

	// 	// Check if it's a TCP packet
	// 	if (ip_hdr->next_proto_id == IPPROTO_TCP)
	// 	{
	// 		// Parse TCP header
	// 		struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)((char *)ip_hdr + sizeof(struct rte_ipv4_hdr));

	// 		// Calculate TCP payload length
	// 		uint16_t tcp_payload_len = rte_be_to_cpu_16(ip_hdr->total_length) - sizeof(struct rte_ipv4_hdr) - sizeof(struct rte_tcp_hdr);

	// 		// Point to the TCP payload data
	// 		char *tcp_payload = (char *)tcp_hdr + sizeof(struct rte_tcp_hdr);

	// 		// Convert the TCP payload to a string (char array)
	// 		char tcp_payload_str[MAX_TCP_PAYLOAD_LEN + 1]; // +1 for null-terminator
	// 		// Copy the TCP payload into the string
	// 		// Limit the copy to avoid buffer overflow
	// 		snprintf(tcp_payload_str, sizeof(tcp_payload_str), "%.*s", tcp_payload_len, tcp_payload);

	// 		if (strncmp(tcp_payload_str, HTTP_GET_MAGIC, HTTP_GET_MAGIC_LEN) == 0)
	// 		{
	// 			return HTTP_GET;
	// 		}

	// 		// Check if the payload contains a TLS handshake message
	// 		if (strncmp(tcp_payload, TLS_MAGIC, TLS_MAGIC_LEN) == 0)
	// 		{
	// 			if (tcp_payload[5] == 1)
	// 			{
	// 				return TLS_CLIENT_HELLO;
	// 			}
	// 		}

	// 		// return if there is no payload
	// 		return 0;
	// 	}

	// 	// return if there is no TCP packet
	// 	return 0;
	// }

	// // return if there is no IP packet
	// return 0;

	char *payload = rte_pktmbuf_mtod(*pkt, char *);
    uint16_t payload_len = rte_pktmbuf_pkt_len(*pkt);
	unsigned int id;

	MatchContext *matchCtx = (MatchContext *)malloc(sizeof(MatchContext));
	if (matchCtx == NULL) {
			logMessage(LOG_LEVEL_ERROR,__FILE__, __LINE__, "Unable to allocating MatchContext\n");
            hs_free_scratch(scratch);
            hs_free_database(database);
            return EXIT_FAILURE;
    }
	int ret = hs_scan(database, payload, payload_len, 0, scratch, eventHandler, matchCtx);
	if (ret != HS_SUCCESS) {
		logMessage(LOG_LEVEL_ERROR,__FILE__, __LINE__, "Unable to scan input buffer. Exiting. (%d)\n",ret);
        hs_free_scratch(scratch);
        hs_free_database(database);
        return -1;
    }

	if(matchCtx->id == 1)
	{
		// printf("HTTP GET\n");
		return HTTP_GET;
	}
	else if(matchCtx->id == 2)
	{
		// printf("TLS CLIENT HELLO\n");
		return TLS_CLIENT_HELLO;
	}
	else
	{
		// printf("matchCtx.id: %d\n", matchCtx->id);
		return 0;
	}

	free(matchCtx);
}

/*
 * The termination signal handler
 * Handle the termination signal
 * @param signum
 * 	the signal number
 */
static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM)
	{
		hs_free_scratch(scratch);
        hs_free_database(database);
		printf("\nSignal %d received, preparing to exit...\n", signum);
		logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "Signal %d received, preparing to exit...\n", signum);
		force_quit = true;
	}
}

static void
populate_json_array(json_t *jsonArray, char *timestamp)
{
	// Create object for the statistics
	json_t *jsonObject = json_object();

	// Populate the JSON object
	json_object_set(jsonObject, "npb_id", json_string(NPB_ID));
	json_object_set(jsonObject, "http_count", json_integer(port_statistics[0].httpMatch));
	json_object_set(jsonObject, "https_count", json_integer(port_statistics[0].httpsMatch));
	json_object_set(jsonObject, "no_match", json_integer(port_statistics[0].noMatch));
	json_object_set(jsonObject, "rx_0_count", json_integer(port_statistics[0].rx_count));
	json_object_set(jsonObject, "tx_0_count", json_integer(port_statistics[0].tx_count));
	json_object_set(jsonObject, "rx_0_size", json_integer(port_statistics[0].rx_size));
	json_object_set(jsonObject, "tx_0_size", json_integer(port_statistics[0].tx_size));
	json_object_set(jsonObject, "rx_0_drop", json_integer(port_statistics[0].dropped));
	json_object_set(jsonObject, "rx_0_error", json_integer(port_statistics[0].err_rx));
	json_object_set(jsonObject, "tx_0_error", json_integer(port_statistics[0].err_tx));
	json_object_set(jsonObject, "rx_0_mbuf", json_integer(port_statistics[0].mbuf_err));
	json_object_set(jsonObject, "rx_1_count", json_integer(port_statistics[1].rx_count));
	json_object_set(jsonObject, "tx_1_count", json_integer(port_statistics[1].tx_count));
	json_object_set(jsonObject, "rx_1_size", json_integer(port_statistics[1].rx_size));
	json_object_set(jsonObject, "tx_1_size", json_integer(port_statistics[1].tx_size));
	json_object_set(jsonObject, "rx_1_drop", json_integer(port_statistics[1].dropped));
	json_object_set(jsonObject, "rx_1_error", json_integer(port_statistics[1].err_rx));
	json_object_set(jsonObject, "tx_1_error", json_integer(port_statistics[1].err_tx));
	json_object_set(jsonObject, "rx_1_mbuf", json_integer(port_statistics[1].mbuf_err));
	json_object_set(jsonObject, "time", json_string(timestamp));
	json_object_set(jsonObject, "throughput", json_integer(port_statistics[1].throughput));

	// Append the JSON object to the JSON array
	json_array_append(jsonArray, jsonObject);
}

static void
collect_stats()
{
	// Get the statistics
	rte_eth_stats_get(1, &stats_1);
	rte_eth_stats_get(0, &stats_0);

	// Update the statistics
	port_statistics[1].rx_count = stats_1.ipackets;
	port_statistics[1].tx_count = stats_1.opackets;
	port_statistics[1].rx_size = stats_1.ibytes;
	port_statistics[1].tx_size = stats_1.obytes;
	port_statistics[1].dropped = stats_1.imissed;
	port_statistics[1].err_rx = stats_1.ierrors;
	port_statistics[1].err_tx = stats_1.oerrors;
	port_statistics[1].mbuf_err = stats_1.rx_nombuf;
	port_statistics[0].rx_count = stats_0.ipackets;
	port_statistics[0].tx_count = stats_0.opackets;
	port_statistics[0].rx_size = stats_0.ibytes;
	port_statistics[0].tx_size = stats_0.obytes;
	port_statistics[0].dropped = stats_0.imissed;
	port_statistics[0].err_rx = stats_0.ierrors;
	port_statistics[0].err_tx = stats_0.oerrors;
	port_statistics[0].mbuf_err = stats_0.rx_nombuf;
	port_statistics[0].httpMatch = httpMatch;
	port_statistics[0].httpsMatch = httpsMatch;

	// Clear the statistics
	rte_eth_stats_reset(0);
	rte_eth_stats_reset(1);
	httpMatch = 0;
	httpsMatch = 0;

	// Calculate the throughput
	port_statistics[1].throughput = port_statistics[1].rx_size / TIMER_PERIOD_STATS;
	port_statistics[0].throughput = port_statistics[0].tx_size / TIMER_PERIOD_STATS;
}

/*
 * The print statistics file function
 * Print the statistics to the file
 * @param last_run_stat
 * 	the last run statistics
 * @param last_run_file
 * 	the last run file
 * @param f_stat
 * 	the file pointer
 */
static void print_stats_file(int *last_run_stat, int *last_run_file, FILE **f_stat, json_t *jsonArray)
{
	int current_sec;
	char time_str[80];
	char time_str_utc[80];
	char time_str_file[80];
	const char *format = "%Y-%m-%dT%H:%M:%S";
	struct tm *tm_info, *tm_rounded, *tm_info_utc;
	time_t now, rounded;

	time(&now);
	tm_info = localtime(&now);
	current_sec = tm_info->tm_sec;
	if (current_sec % TIMER_PERIOD_STATS == 0 && current_sec != *last_run_stat)
	{
		char *filename = (char *)calloc(100, 100);

		// get the current minute
		int current_min = tm_info->tm_min;

		// check file
		if (!*f_stat)
		{
			// get the rounded time
			int remaining_seconds = current_min % TIMER_PERIOD_SEND * 60 + current_sec;
			rounded = now - remaining_seconds;
			tm_rounded = localtime(&rounded);

			// convert the time to string
			strftime(time_str_file, sizeof(time_str_file), format, tm_rounded);

			// create the filename
			strcat(filename, STAT_FILE);
			strcat(filename, time_str_file);
			strcat(filename, STAT_FILE_EXT);
			*f_stat = open_file(filename);

			// print the header of the statistics file
			print_stats_csv_header(*f_stat);

			// free the string
			free(filename);
			*last_run_file = tm_rounded->tm_min;

			// Set the time to now
			tm_info = localtime(&now);
		}

		// Collcet stats
		collect_stats();

		// convert the time to string
		strftime(time_str, sizeof(time_str), format, tm_info);

		// convert the time to string
		tm_info = gmtime(&now);
		strftime(time_str_utc, sizeof(time_str_utc), format, tm_info);

		// get avg service time
		if (count_service_time > 0)
		{
			avg_service_time = service_time / count_service_time;
			service_time = 0;
			count_service_time = 0;
			logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "AVG Service Time: %f\n", avg_service_time);
		}

		// print out the stats to csv
		print_stats_csv(*f_stat, time_str);

		// flush the file
		fflush(*f_stat);

		// populate the stats to json array
		populate_json_array(jsonArray, time_str_utc);

		if (current_min % TIMER_PERIOD_SEND == 0 && current_min != *last_run_file)
		{
			// create the filename
			strcat(filename, STAT_FILE);
			strcat(filename, time_str);
			strcat(filename, STAT_FILE_EXT);
			*f_stat = open_file(filename);

			// print the header of the statistics file
			print_stats_csv_header(*f_stat);

			// free the string
			free(filename);

			// set the last run file
			*last_run_file = current_min;
		}

		// Set the last run time
		*last_run_stat = current_sec;
	}
}

static void
send_stats_to_server(json_t *jsonArray)
{
	CURL *curl;
	CURLcode res;
	struct curl_slist *headers = curl_slist_append(headers, "Content-Type: application/json");
	;
	char *jsonString = json_dumps(jsonArray, 0);
	char url[256];
	size_t size = json_array_size(jsonArray);

	sprintf(url, "%s/npb/npb-packet", HOSTNAME);

	curl_global_init(CURL_GLOBAL_DEFAULT);
	curl = curl_easy_init();

	if (curl)
	{
		headers = curl_slist_append(headers, "Content-Type: application/json");

		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonString);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		res = curl_easy_perform(curl);

		if (res != CURLE_OK)
		{
			fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
			logMessage(LOG_LEVEL_ERROR,__FILE__, __LINE__, "Send %d Stats failed: %s\n", size, curl_easy_strerror(res));
		} else {
			if (size < (60 * TIMER_PERIOD_SEND)){
				logMessage(LOG_LEVEL_WARNING,__FILE__, __LINE__, "Stats data is not normal\n");
			}
			logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "Send %d Stats success\n", size);
		}

		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);
		free(jsonString);
		json_array_clear(jsonArray);
	}

	curl_global_cleanup();
}

static void
send_stats(json_t *jsonArray, int *last_run_send)
{

	// Get the current time
	time_t rawtime;
	struct tm *timeinfo;
	char timestamp[20];
	time(&rawtime);
	timeinfo = localtime(&rawtime);

	int current_min = timeinfo->tm_min;
	if (current_min % TIMER_PERIOD_SEND == 0 && current_min != *last_run_send)
	{
		// send the statistics to the server
		logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "Start sending statistics to server\n");
		send_stats_to_server(jsonArray);
		*last_run_send = current_min;
	}
}

/*
 * The lcore stast process
 * Running all the stats process including
 * - Get the statistics
 * - Update the statistics
 * - Calculate the throughput
 * - Print the statistics
 * - Print the statistics to file
 * - Reset the timer
 */
static inline void
lcore_stats_process(void)
{
	// Variable declaration
	int last_run_stat = 0;							 // lastime statistics printed
	int last_run_file = 0;							 // lastime statistics printed to file
	int last_run_send = 0;							 // lastime statistics sent to server
	int last_run_print = 0;							 // lastime statistics printed to console
	uint64_t start_tx_size_0 = 0, end_tx_size_0 = 0; // For throughput calculation
	uint64_t start_rx_size_1 = 0, end_rx_size_1 = 0; // For throughput calculation
	double throughput_0 = 0.0, throughput_1 = 0.0;	 // For throughput calculation
	FILE *f_stat = NULL;							 // File pointer for statistics
	json_t *jsonArray = json_array();				 // JSON array for statistics

	logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "Starting stats process in %d\n", rte_lcore_id());

	while (!force_quit)
	{
		// Print Statistcs to file
		print_stats_file(&last_run_stat, &last_run_file, &f_stat, jsonArray);

		// Print the statistics
		// print_stats(&last_run_print);

		// Send stats
		send_stats(jsonArray, &last_run_send);

		usleep(10000);
	}
}

/*
 * The lcore main process
 * Running all the forwarding process including
 * - Get the burst of RX packets
 * - Check the packet type (HTTP or HTTPS)
 * - Send the packet to the right port
 * - Update the statistics
 * - Free up the buffer
 */
static inline void
lcore_main_process(void)
{
	// initialization
	uint16_t port;
	uint64_t timer_tsc = 0;
	uint64_t packet_type;
	uint16_t sent;

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
		   rte_lcore_id());
	logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "Starting main process in %d\n", rte_lcore_id());

	// Main work of application loop
	while (!force_quit)
	{
		// get time for start service time
		start = clock();

		// Get burst of RX packets, from first port of pair
		struct rte_mbuf *bufs[BURST_SIZE];
		
		const uint16_t nb_rx = rte_eth_rx_burst(1, 0,
												bufs, BURST_SIZE);

		// if there is no packet, continue
		if (unlikely(nb_rx == 0))
			continue;

		// process the packet
		for (int i = 0; i < nb_rx; i++)
		{

			// check the packet type
			packet_type = packet_checker(&bufs[i]);

			// function to check the packet type and send it to the right port
			if (packet_type == HTTP_GET)
			{
				// send the packet to port 0 if HTTP GET
				sent = rte_eth_tx_burst(0, 0, &bufs[i], 1);

				// update the statistics
				if (sent)
				{
					httpMatch += sent;
					
					// get end time to count service time
					end = clock();
				}
			}
			else if (packet_type == TLS_CLIENT_HELLO)
			{
				// send the packet to port 0 if TLS CLIENT HELLO
				sent = rte_eth_tx_burst(0, 0, &bufs[i], 1);

				// update the statistics
				if (sent)
				{
					httpsMatch += sent;
					
					// get end time to count service time
					end = clock();
				}
			}
			else
			{
				// no match
				port_statistics[0].noMatch += 1;

				// free up the buffer
				rte_pktmbuf_free(bufs[i]);

				// get end time to count service time
				end = clock();
			}
		}

		// free up the buffer
		rte_pktmbuf_free(*bufs);

		// get the service time
		service_time += (double)(end - start) / CLOCKS_PER_SEC;
		count_service_time += 1;
	}
}

/*
 * The write callback function
 * Write the callback function for the heartbeat
 * @param contents
 * 	the contents
 * @param size
 * 	the size
 * @param nmemb
 * 	the nmemb
 * @param userp
 * 	the userp
 */
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t real_size = size * nmemb;
	logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "Heartbeat Response: %.*s \n", (int)real_size, (char *)contents);
	return real_size;
}

/*
 * The lcore heartbeat process
 * Running the heartbeat process
 * - Send the heartbeat to the server
 * - Sleep for 5 seconds
 */
static inline void
lcore_heartbeat_process()
{
	CURL *curl;
	CURLcode res;
	char post_fields[256];
	char url[256];
	char timestamp_str[25];
	time_t timestamp;
	struct tm *tm_info;
	struct curl_slist *headers = NULL;

	sprintf(url, "%s/npb/heartbeat", HOSTNAME);

	curl_global_init(CURL_GLOBAL_DEFAULT);
	curl = curl_easy_init();

	if (curl)
	{
		headers = curl_slist_append(headers, "Content-Type: application/json");

		while (!force_quit)
		{
			timestamp = time(NULL);
			tm_info = gmtime(&timestamp);
			strftime(timestamp_str, 25, "%Y-%m-%dT%H:%M:%S.000Z", tm_info);

			sprintf(post_fields, "[{\"npb_id\": \"%s\", \"time\": \"%s\"}]", NPB_ID, timestamp_str);

			curl_easy_setopt(curl, CURLOPT_URL, url);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields);
			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

			res = curl_easy_perform(curl);

			if (res != CURLE_OK)
			{
				logMessage(LOG_LEVEL_ERROR,__FILE__, __LINE__, "Heartbeat failed: %s\n", curl_easy_strerror(res));
			}
			sleep(5);
		}

		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);
	}

	curl_global_cleanup();
}

/*
 * The main function
 * entry point of the application
 * - Load the configuration file
 * - Initialize the EAL
 * - Initialize the ports
 * - Assign the lcore
 * - Run the lcore main function
 * - Run the stats
 * - Wait all lcore stopped
 * - Clean up the EAL
 * - Exit the application
 */
int main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;
	unsigned lcore_id, lcore_main = 0, lcore_stats = 0;

	// log the starting of the application
	logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "Starting the application\n");

	// load the config file
	if (load_config_file())
	{
		logMessage(LOG_LEVEL_ERROR,__FILE__, __LINE__, "Cannot load the config file\n");
		rte_exit(EXIT_FAILURE, "Cannot load the config file\n");
	}
	logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "Load config done\n");

	// Initializion the Environment Abstraction Layer (EAL)
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
	{
		logMessage(LOG_LEVEL_ERROR,__FILE__, __LINE__, "Error with EAL initialization\n");
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	}

	argc -= ret;
	argv += ret;

	// force quit handler
	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	// clean the data
	memset(port_statistics, 0, 32 * sizeof(struct port_statistics_data));
	logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "Clean the statistics data\n");

	// count the number of ports to send and receive
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < 2 || (nb_ports & 1))
	{
		logMessage(LOG_LEVEL_ERROR,__FILE__, __LINE__, "Error: number of ports must be even\n");
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");
	}

	// allocates the mempool to hold the mbufs
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
										MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	// check the mempool allocation
	if (mbuf_pool == NULL)
	{
		logMessage(LOG_LEVEL_ERROR,__FILE__, __LINE__, "Cannot create mbuf pool\n");
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");
	}
	logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "Create mbuf pool done\n");

	// initializing ports
	RTE_ETH_FOREACH_DEV(portid)
	if (port_init(portid, mbuf_pool) != 0)
	{
		logMessage(LOG_LEVEL_ERROR,__FILE__, __LINE__, "Cannot init port %" PRIu16 "\n", portid);
		rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);
	}

	// count the number of lcore
	if (rte_lcore_count() < 3)
	{
		logMessage(LOG_LEVEL_ERROR,__FILE__, __LINE__, "lcore must be more than equal 3\n");
		rte_exit(EXIT_FAILURE, "lcore must be more than equal 3\n");
	}

	// compile hyperscan database
	if(hs_compile_multi(patterns, flags, ids, 2, HS_MODE_BLOCK, NULL, &database, &compile_err))
	{
		logMessage(LOG_LEVEL_ERROR,__FILE__, __LINE__, "Unable to compile pattern : %s\n", compile_err->message);
		hs_free_compile_error(compile_err);
		rte_exit(EXIT_FAILURE, "Cannot compile pattern\n");
	}

	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		if (lcore_id == (unsigned int)lcore_main ||
			lcore_id == (unsigned int)lcore_stats)
		{
			continue;
		}
		if (lcore_main == 0)
		{
			lcore_main = lcore_id;
			logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "Main on core %u\n", lcore_id);
			continue;
		}
		if (lcore_stats == 0)
		{
			lcore_stats = lcore_id;
			logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "Stats on core %u\n", lcore_id);
			continue;
		}
	}

	// run the lcore main function
	logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "Run the lcore main function\n");
	rte_eal_remote_launch((lcore_function_t *)lcore_main_process,
						  NULL, lcore_main);

	// run the stats
	logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "Run the stats\n");
	rte_eal_remote_launch((lcore_function_t *)lcore_stats_process,
						  NULL, lcore_stats);

	// run the heartbeat
	logMessage(LOG_LEVEL_INFO,__FILE__, __LINE__, "Run the heartbeat\n");
	lcore_heartbeat_process();

	// wait all lcore stopped
	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}
	// clean up the EAL
	rte_eal_cleanup();
}