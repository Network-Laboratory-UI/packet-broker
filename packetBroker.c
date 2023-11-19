// ======================================================= THE LIBRARY =========================================================

#include "config.h"
#include "functions.c"

// ======================================================= THE VARIABLES =======================================================
FILE *f_dump;
FILE *f_stat;
// ======================================================= THE FUNCTIONS =======================================================

// DUMP PACKET
static void dump_packet(struct rte_mbuf *pkt, FILE *f_dump)
{
	rte_pktmbuf_dump(f_dump, pkt, rte_pktmbuf_pkt_len(pkt));
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
			// char tcp_payload_str[MAX_TCP_PAYLOAD_LEN + 1]; // +1 for null-terminator

			if (tcp_payload_len > 0)
			{
				// Copy the TCP payload into the string
				// Limit the copy to avoid buffer overflow
				// memcpy(tcp_payload_str, tcp_payload, tcp_payload_len);
				// tcp_payload_str[tcp_payload_len] = '\0';
				if (fastStrCmp(tcp_payload, HTTP_GET_MAGIC, HTTP_GET_MAGIC_LEN) == 0)
				{
					// TODO: Remove this
					printf("Payload: %s\n", tcp_payload);
					return HTTP_GET;
				}

				// Check if the payload contains a TLS handshake message
				if (fastStrCmp(tcp_payload, TLS_MAGIC, TLS_MAGIC_LEN) == 0)
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
		rte_eal_cleanup();
		exit(0);
	}
}
// END OF TERMINATION SIGNAL HANDLER

// PACKET PROCESSING THREAD FUNCTION
void *packetProcessingThread(void *arg)
{
	// initialization
	uint16_t port;
	uint64_t packet_type;
	uint16_t sent;

	// Main work of application loop
	while (!force_quit)
	{
		// memset(bufs, 0, BURST_SIZE);
		// TODO: get the portId from options
		struct rte_mbuf *bufs[BURST_SIZE];
		const uint16_t nb_rx = rte_eth_rx_burst(1, 0, bufs, BURST_SIZE);

		// if there is no packet, yield CPU to prevent overheating
		if (unlikely(nb_rx == 0))
		{
			sched_yield();
			continue;
		}

		// Statistic for RX
		// pthread_mutex_lock(&port_statistics[1].mutex);
		port_statistics[1].rx_count += nb_rx;
		port_statistics[1].tx_count = 0;
		// pthread_mutex_unlock(&port_statistics[1].mutex);

		// printf("No of packet: %d\n", nb_rx);

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
				// printf("Packet type HTTP_GET\n");
				//  send the packet to port 0 if HTTP GET
				// sent = rte_eth_tx_burst(0, 0, &bufs[i], 1);
				sent = 1;

				// dump packet
				dump_packet(bufs[i], f_dump);

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

				// dump packet
				dump_packet(bufs[i], f_dump);

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
		sched_yield();
		// free up the buffer
		rte_pktmbuf_free(*bufs);
	}
}

// Statistics Thread Function
void *statsPrintingThread(void *arg)
{
    // initialization
	uint16_t port;
	uint64_t timer_tsc = 0;
	uint64_t packet_type;
	uint16_t sent;
	int last_run_minute = 100;
    char time_str[80];
    const char *format = "%Y-%m-%dT%H:%M:%S";

    while (!force_quit)
    {
        // Your statistics printing logic here
        time_t now;
        time(&now);
        struct tm *tm_info = localtime(&now);

        // Print Statistcs to file
        int current_minute = tm_info->tm_min;
        
        if (current_minute % timer_period_stats == 0 && current_minute != last_run_minute)
        {
            strftime(time_str, sizeof(time_str), format, tm_info);
            print_stats_csv(f_stat, time_str);
            fflush(f_stat);
            // clear_stats();
            last_run_minute = current_minute;
        }

        /* if timer is enabled */
        if (timer_period > 0)
        {

            /* advance the timer */
            timer_tsc++;

            /* if timer has reached its timeout */
            if (timer_tsc >= timer_period)
            {
                /* do this only on main core */

                // Print overall statistics
                fprintf(stdout, "\n====================================================\n");
                fprintf(stdout, "Overall Statistics at %s:\n", asctime(tm_info));
                fprintf(stdout, "  Total packets sent: %" PRIu64 "\n", port_statistics[0].tx_count);
                fprintf(stdout, "  Total packets received: %" PRIu64 "\n", port_statistics[1].rx_count);
                fprintf(stdout, "  Total packets dropped: %" PRIu64 "\n", port_statistics[0].dropped);
                fprintf(stdout, "====================================================\n");

                // Print detailed statistics for each port
                print_stats_details(stdout, 0);
                print_stats_details(stdout, 1);

                fprintf(stdout, "====================================================\n");

                /* reset the timer */
                timer_tsc = 0;
            }
        }

        // Clear stats for the next period
        // clear_stats();

        // Sleep or yield to avoid excessive CPU usage
        sched_yield();
		sleep(1);

        // Set force_quit to true when needed
        // ...
    }

    return NULL;
}

// ======================================================= THE LCORE FUNCTION =======================================================
static inline void
lcore_main(void)
{
	// initialization
	uint16_t port;
	uint16_t core_count = rte_lcore_count(); // count the number of lcore
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

	// pthread_t threads[core_count];

	for (int i = 0; i < core_count; i++)
	{
		pthread_t thread_id;

		// Create a new thread that runs the packetProcessingThread function
		int result = pthread_create(&thread_id, NULL, packetProcessingThread, NULL);

		// Check if the thread was successfully created
		if (result != 0)
		{
			perror("Thread creation failed");
			exit(EXIT_FAILURE);
		}
		printf("Created thread %d\n", i);
	}
}

// ======================================================= THE MAIN FUNCTION =======================================================
int main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;
	f_dump = open_file(PCAP_FILE);
	f_stat = open_file(STAT_FILE);

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
	printf("Core count: %d\n", rte_lcore_count());

	// print the header of the statistics file
	print_stats_csv_header(f_stat);

	// run the lcore main function
	lcore_main();

	// Create the statistic threads
	pthread_t thread_id;
	// Create a new thread that runs the packetProcessingThread function
	int result = pthread_create(&thread_id, NULL, statsPrintingThread, NULL);
	// Check if the thread was successfully created
	if (result != 0)
	{
		perror("Thread creation failed");
		exit(EXIT_FAILURE);
	}
	pthread_join(thread_id, NULL);

	// clean up the EAL
	rte_eal_cleanup();
}

// END OF MAIN FUNCTION