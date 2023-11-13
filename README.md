# packet-broker

![](https://www.intel.co.id/content/dam/www/public/us/en/images/illustrations/dpdk-16x9.png.rendition.intel.web.864.486.png)

Packet Filtering DPDK is a high-performance software solution built on the Data Plane Development Kit (DPDK). It is designed to efficiently filter network packets, focusing exclusively on HTTP GET and TLS Client Hello packets. With Packet Filtering DPDK, network administrators can streamline packet processing and enhance network security by identifying and isolating these specific packet types with unparalleled speed and precision. This tool optimizes network performance and provides robust security for your infrastructure, ensuring efficient packet filtering without the need for any additional product branding.

## Getting Started

### Prerequisites
1. DPDK 20.11.2
2. Ubuntu 20.04
3. 3 NICs (1 for RX, 1 for TX, 1 for Management)

### Installation
1. Start Ubuntu 20.04
2. [Install DPDK 20.11.2](https://teenjb.notion.site/DPDK-Installation-d0366f258ee44bc192e378fb9a119615?pvs=4)
3. clone packet broker repository
    ```
    git clone https://github.com/Network-Laboratory-UI/packet-broker.git
    ```
4. build packet broker
    ```
    cd packet-broker
    make
    ```
5. make sure the NICs already binded to DPDK and setup the hugepages

### Run
run packet broker and the aggregator
```
sudo ./run.sh
```

### Clean
to clean the statistics and the build
```
make clean
```
