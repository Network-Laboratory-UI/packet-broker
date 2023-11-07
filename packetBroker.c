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

// DPDK library
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>
#include <rte_pdump.h>

// ======================================================= THE DEFINE =======================================================

// Define the limit of
// #define MAX_PACKET_LEN 1500
// #define RX_RING_SIZE 1024
// #define TX_RING_SIZE 1024
// #define NUM_MBUFS 8191
// #define MBUF_CACHE_SIZE 250
// #define BURST_SIZE 32
// #define MAX_TCP_PAYLOAD_LEN 1024
uint32_t MAX_PACKET_LEN;
uint32_t RX_RING_SIZE;
uint32_t TX_RING_SIZE;
uint32_t NUM_MBUFS;
uint32_t MBUF_CACHE_SIZE;
uint32_t BURST_SIZE;
uint32_t MAX_TCP_PAYLOAD_LEN;

// Define the statistics file name
// #define STAT_FILE "stats/stats"
// #define STAT_FILE_EXT ".csv"
char STAT_FILE[100];
char STAT_FILE_EXT[100];

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

// Force quit variable
static volatile bool force_quit;

// Timer period for statistics
static uint16_t TIMER_PERIOD;			// 100 Cycle
static uint16_t TIMER_PERIOD_STATS; 	// 1 second
static uint16_t TIMER_PERIOD_SEND; 		// 10 minutes

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
	// TODO: add size of packet, throughpout.
} __rte_cache_aligned;
struct port_statistics_data port_statistics[RTE_MAX_ETHPORTS];

// ======================================================= THE FUNCTIONS =======================================================

// PORT INITIALIZATION
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
		printf("Error during getting device (port %u) info: %s\n",
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

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
		   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
		   port, RTE_ETHER_ADDR_BYTES(&addr));

	// SET THE PORT TO PROMOCIOUS
	retval = rte_eth_promiscuous_enable(port);
	if (retval != 0)
		return retval;

	return 0;
}
// END OF PORT INITIALIZATION

// OPEN FILE
static FILE *open_file(const char *filename)
{
	FILE *f = fopen(filename, "w");
	if (f == NULL)
	{
		printf("Error opening file!\n");
		exit(1);
	}
	return f;
}

// PRINT OUT STATISTICS
static void
print_stats(void)
{
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
	unsigned int portid;

	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;

	const char clr[] = {27, '[', '2', 'J', '\0'};
	const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};

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
			   "\nHTTP GET MATCH: %22" PRIu64
			   "\nTLS CLIENT HELLO MATCH: %14" PRIu64,
			   portid,
			   port_statistics[portid].tx_count,
			   port_statistics[portid].tx_size,
			   port_statistics[portid].rx_count,
			   port_statistics[portid].rx_size,
			   port_statistics[portid].dropped,
			   port_statistics[portid].httpMatch,
			   port_statistics[portid].httpsMatch);

		total_packets_dropped += port_statistics[portid].dropped;
		total_packets_tx += port_statistics[portid].tx_count;
		total_packets_rx += port_statistics[portid].rx_count;
	}
	printf("\nAggregate statistics ==============================="
		   "\nTotal packets sent: %18" PRIu64
		   "\nTotal packets received: %14" PRIu64
		   "\nTotal packets dropped: %15" PRIu64,
		   total_packets_tx,
		   total_packets_rx,
		   total_packets_dropped);
	printf("\n====================================================\n");

	fflush(stdout);
}

// PRINT STATISTICS HEADER INTO CSV FILE
static void print_stats_csv_header(FILE *f)
{
	fprintf(f, "npb_id,http_count,https_count,rx_count,tx_count,rx_size,tx_size,time,throughput\n"); // Header row
}

// PRINT STATISTICS INTO CSV FILE
static void print_stats_csv(FILE *f, char *timestamp)
{
	// Write data to the CSV file
	fprintf(f, "%d,%ld,%ld,%ld,%ld,%ld,%ld,%s,%d\n", 1, port_statistics[0].httpMatch, port_statistics[0].httpsMatch, port_statistics[1].rx_count, port_statistics[0].tx_count, port_statistics[1].rx_size, port_statistics[0].tx_size, timestamp, 0);
}

// CLEAR THE STATS STRUCT
static void clear_stats(void)
{
	memset(port_statistics, 0, RTE_MAX_ETHPORTS * sizeof(struct port_statistics_data));
}

// CONFIG FILE LOADER
int load_config_file()
{
	FILE *configFile = fopen("config/packetBroker.cfg", "r");
	if (!configFile) {
        perror("Error opening configuration file");
        return 1;
    }

	char line[256];
    char key[256];
    char value[256];

	while (fgets(line, sizeof(line), configFile)) {
        if (sscanf(line, "%255[^=]= %255[^\n]", key, value) == 2) {
            if (strcmp(key, "db_host") == 0) {
                printf("Database Host: %s\n", value);
            } else if (strcmp(key, "db_port") == 0) {
                printf("Database Port: %s\n", value);
            } else if (strcmp(key, "db_name") == 0) {
                printf("Database Name: %s\n", value);
            } else if (strcmp(key, "db_user") == 0) {
                printf("Database User: %s\n", value);
            } else if (strcmp(key, "db_password") == 0) {
                printf("Database Password: %s\n", value);
            } else if (strcmp(key, "debug_mode") == 0) {
                printf("Debug Mode: %s\n", value);
            } else if (strcmp(key, "log_file") == 0) {
                printf("Log File: %s\n", value);
            }
        }
    }

	fclose(configFile);
    return 0;
}


// PACKET PROCESSING AND CHECKING
static int packet_checker(struct rte_mbuf **pkt, uint16_t nb_rx)
{
	// Define Variable
	int sent;

	// Parse Ethernet header
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(*pkt, struct rte_ether_hdr *);

	// Check if it's an IP packet
	if (eth_hdr->ether_type == rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4))
	{
		// Parse IP header
		struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

		// Check if it's a TCP packet
		if (ip_hdr->next_proto_id == IPPROTO_TCP)
		{
			// Parse TCP header
			struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)((char *)ip_hdr + sizeof(struct rte_ipv4_hdr));

			// Calculate TCP payload length
			uint16_t tcp_payload_len = rte_be_to_cpu_16(ip_hdr->total_length) - sizeof(struct rte_ipv4_hdr) - sizeof(struct rte_tcp_hdr);

			// Point to the TCP payload data
			char *tcp_payload = (char *)tcp_hdr + sizeof(struct rte_tcp_hdr);

			// Convert the TCP payload to a string (char array)
			char tcp_payload_str[MAX_TCP_PAYLOAD_LEN + 1]; // +1 for null-terminator
			if (tcp_hdr->tcp_flags == (RTE_TCP_PSH_FLAG | RTE_TCP_ACK_FLAG) && tcp_payload_len > 0)
			{
				// Copy the TCP payload into the string
				// Limit the copy to avoid buffer overflow
				snprintf(tcp_payload_str, sizeof(tcp_payload_str), "%.*s", tcp_payload_len, tcp_payload);

				if (strncmp(tcp_payload_str, HTTP_GET_MAGIC, HTTP_GET_MAGIC_LEN) == 0)
				{
					return HTTP_GET;
				}

				// Check if the payload contains a TLS handshake message
				if (strncmp(tcp_payload, TLS_MAGIC, TLS_MAGIC_LEN) == 0)
				{
					if (tcp_payload[5] == 1)
					{
						return TLS_CLIENT_HELLO;
					}
				}

				// return if there is no match
				return 0;
			}

			// return if there is no payload
			return 0;
		}

		// return if there is no TCP packet
		return 0;
	}

	// return if there is no IP packet
	return 0;
}
// END OF PACKET PROCESSING AND CHECKING

// TERMINATION SIGNAL HANDLER
static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM)
	{
		printf("\n\nSignal %d received, preparing to exit...\n",
			   signum);
		force_quit = true;
	}
}
// END OF TERMINATION SIGNAL HANDLER

// ======================================================= THE LCORE FUNCTION =======================================================
static inline void
lcore_main(void)
{
	// initialization
	uint16_t port;
	uint64_t timer_tsc = 0;
	uint64_t packet_type;
	uint16_t sent;
	int last_run_stat = 0;
	int last_run_file = 0;
	int current_sec;
	char time_str[80];
	char time_str_file[80];
	const char *format = "%Y-%m-%dT%H:%M:%S";
	FILE *f_stat = NULL;
	struct tm *tm_info, *tm_rounded;
	time_t now, rounded;

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	RTE_ETH_FOREACH_DEV(port)
	if (rte_eth_dev_socket_id(port) >= 0 &&
		rte_eth_dev_socket_id(port) !=
			(int)rte_socket_id())
		printf("WARNING, port %u is on remote NUMA node to "
			   "polling thread.\n\tPerformance will "
			   "not be optimal.\n",
			   port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
		   rte_lcore_id());

	// Main work of application loop
	while (!force_quit)
	{

		// Get burst of RX packets, from first port of pair
		struct rte_mbuf *bufs[BURST_SIZE];
		// TODO: get the portId from options
		const uint16_t nb_rx = rte_eth_rx_burst(1, 0,
												bufs, BURST_SIZE);

		// Statistic for RX
		port_statistics[1].rx_count += nb_rx;
		port_statistics[1].tx_count = 0;

		// if there is no packet, continue
		if (unlikely(nb_rx == 0))
			continue;

		// process the packet
		for (int i = 0; i < nb_rx; i++)
		{
			// update the statistics
			port_statistics[1].rx_size += rte_pktmbuf_pkt_len(bufs[i]);

			// check the packet type
			packet_type = packet_checker(&bufs[i], 1);

			// function to check the packet type and send it to the right port
			if (packet_type == HTTP_GET)
			{
				// send the packet to port 0 if HTTP GET
				sent = rte_eth_tx_burst(0, 0, &bufs[i], 1);

				// update the statistics
				if (sent)
				{
					port_statistics[0].tx_count += sent;
					port_statistics[0].httpMatch += sent;
					port_statistics[0].tx_size += rte_pktmbuf_pkt_len(bufs[i]);
				}
			}
			else if (packet_type == TLS_CLIENT_HELLO)
			{
				// send the packet to port 0 if TLS CLIENT HELLO
				sent = rte_eth_tx_burst(0, 0, &bufs[i], 1);

				// update the statistics
				if (sent)
				{
					port_statistics[0].tx_count += sent;
					port_statistics[0].httpsMatch += sent;
					port_statistics[0].tx_size += rte_pktmbuf_pkt_len(bufs[i]);
				}
			}
			else
			{
				// update the statistics
				port_statistics[0].dropped += 1;

				// free up the buffer
				rte_pktmbuf_free(bufs[i]);
			}
		}

		// free up the buffer
		rte_pktmbuf_free(*bufs);

		// Print Statistcs to file
		time(&now);
		tm_info = localtime(&now);
		current_sec = tm_info->tm_sec;
		if (current_sec % TIMER_PERIOD_STATS == 0 && current_sec != last_run_stat)
		{
			char *filename = (char *)calloc(100, 100);

			// get the current minute
			int current_min = tm_info->tm_min;

			// check file
			if (!f_stat)
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
				f_stat = open_file(filename);

				// print the header of the statistics file
				print_stats_csv_header(f_stat);

				// free the string
				free(filename);
				last_run_file = tm_rounded->tm_min;
			}

			// convert the time to string
			strftime(time_str, sizeof(time_str), format, tm_info);

			// print out the stats to csv
			print_stats_csv(f_stat, time_str);
			fflush(f_stat);

			// clear the stats
			clear_stats();

			if (current_min % TIMER_PERIOD_SEND == 0 && current_min != last_run_file)
			{
				// create the filename
				strcat(filename, STAT_FILE);
				strcat(filename, time_str);
				strcat(filename, STAT_FILE_EXT);
				f_stat = open_file(filename);

				// print the header of the statistics file
				print_stats_csv_header(f_stat);

				// free the string
				free(filename);

				// set the last run file
				last_run_file = current_min;
			}

			// Set the last run time
			last_run_stat = current_sec;
		}

		/* if timer is enabled */
		if (TIMER_PERIOD > 0)
		{

			/* advance the timer */
			timer_tsc++;

			/* if timer has reached its timeout */
			if (timer_tsc >= TIMER_PERIOD)
			{
				/* do this only on main core */
				print_stats();
				/* reset the timer */
				timer_tsc = 0;
			}
		}
	}
}

// ======================================================= THE MAIN FUNCTION =======================================================
int main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;

	// Initializion the Environment Abstraction Layer (EAL)
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	// force quit handler
	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	// clean the data
	memset(port_statistics, 0, 32 * sizeof(struct port_statistics_data));

	// count the number of ports to send and receive
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < 2 || (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	// allocates the mempool to hold the mbufs
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
										MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	// check the mempool allocation
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	// initializing ports
	RTE_ETH_FOREACH_DEV(portid)
	if (port_init(portid, mbuf_pool) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n",
				 portid);

	// count the number of lcore
	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	// run the lcore main function
	lcore_main();

	// clean up the EAL
	rte_eal_cleanup();
}

// END OF MAIN FUNCTION