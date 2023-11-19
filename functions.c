#include "config.h"

// ====================================================FUNCTIONS======================================================

// Faster string comparison using loop unrolling
int fastStrCmp(const char *s1, const char *s2, size_t len)
{
    size_t i;

    for (i = 0; i < len; i += 4)
    {
        uint32_t *s1_chunk = (uint32_t *)(s1 + i);
        uint32_t *s2_chunk = (uint32_t *)(s2 + i);

        if (*s1_chunk != *s2_chunk)
        {
            return 0; // Strings are not equal
        }
    }

    // Check the remaining bytes (if any)
    for (; i < len; ++i)
    {
        if (s1[i] != s2[i])
        {
            return 0; // Strings are not equal
        }
    }

    return 1; // Strings are equal
}

// OPEN FILE
FILE *open_file(const char *filename)
{
    FILE *f = fopen(filename, "w");
    if (f == NULL)
    {
        printf("Error opening file!\n");
        exit(1);
    }
    return f;
}

// PORT INITIALIZATION
static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool)
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

// Define the stats printing logic
static void print_stats_details(FILE *f_stat, int port)
{
    fprintf(stdout, "\nDetailed Statistics for Port %d:\n", port);
    fprintf(stdout, "  Packets sent count: %" PRIu64 "\n", port_statistics[port].tx_count);
    fprintf(stdout, "  Packets sent size: %" PRIu64 "\n", port_statistics[port].tx_size);
    fprintf(stdout, "  Packets received count: %" PRIu64 "\n", port_statistics[port].rx_count);
    fprintf(stdout, "  Packets received size: %" PRIu64 "\n", port_statistics[port].rx_size);
    fprintf(stdout, "  Packets dropped: %" PRIu64 "\n", port_statistics[port].dropped);
    fprintf(stdout, "  HTTP GET MATCH: %" PRIu64 "\n", port_statistics[port].httpMatch);
    fprintf(stdout, "  TLS CLIENT HELLO MATCH: %" PRIu64 "\n", port_statistics[port].httpsMatch);
}

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
static void clear_stats()
{
    memset(port_statistics, 0, RTE_MAX_ETHPORTS * sizeof(struct port_statistics_data));
}