# ipfixprobe - IPFIX flow exporter - README

## Description
This NEMEA module creates biflows from input PCAP file / network interface and exports them to output interface.

## Requirements
- To compile this module you will need [libpcap](http://www.tcpdump.org/) development library installed,
  OR netcope-common to support high-speed transfers from [COMBO cards](https://www.liberouter.org/technologies/cards/) (NDP interface).

## Build & Installation

### Source codes

This project uses a standard process of:

```
autoreconf -i
./configure
make
sudo make install
```

Check `./configure --help` for more details and settings.

### RPM packages

RPM package can be created in the following versions using `--with` parameter of `rpmbuild`:
- `--with ndp` enables RPM with netcope-common, i.e., NDP communication interface; this disables libpcap input.
- `--with nemea` enables RPM with NEMEA interface (output)

These parameters affect required dependencies of the RPM and build process.

The default configuration of the RPM can be created using simply: `make rpm`

Alternative versions (described in the following section) can be created by:
- NEMEA version of RPM: `make rpm-nemea`
- NDP version of RPM: `make rpm-ndp`

We use [COPR infrastructure](https://copr.fedorainfracloud.org/coprs/g/CESNET/NEMEA/) to build and serve RPM packages for EPEL7 and EPEL8.
It is not possible to pass arguments to rpmbuild, so there is an option in configure to enforce NEMEA dependency:

`./configure --enable-nemearpm && make srpm`

The output source RPM can be uploaded to copr.

To install ipfixprobe with NEMEA dependency from binary RPM packages, it is possible to follow instructions on:
[https://copr.fedorainfracloud.org/coprs/g/CESNET/NEMEA/](https://copr.fedorainfracloud.org/coprs/g/CESNET/NEMEA/)

### Windows 10 CygWin

Install CygWin and the following packages:
- git
- pkg-config
- make
- automake
- autoconf
- libtool
- binutils
- gcc-core
- gcc-g++

Download npcap SDK [https://nmap.org/npcap/dist/npcap-sdk-1.07.zip](https://nmap.org/npcap/dist/npcap-sdk-1.07.zip) and copy content of the `Include` folder to `/usr/include` folder in your cygwin root installation folder (`C:\cygwin64\usr\include` for example). Then copy files of the `Lib` folder to `/lib` folder (or `Lib/x64/` based on your architecture).

Download npcap library [https://nmap.org/npcap/dist/npcap-1.31.exe](https://nmap.org/npcap/dist/npcap-1.31.exe) and install.

Add the following line to the `~/.bashrc` file
```
export PATH="/cygdrive/c/Windows/system32/Npcap:$PATH"
```

Build project using commands in previous sections. Tested on cygwin version 2.908


## Input / Output of the flow exporter

Input and output interfaces are dependent on the configuration (by `configure`).
The default setting uses libpcap and the output is in IPFIX format only.

When the project is configured with `./configure --with-nemea`, the flow
exporter supports NEMEA output via TRAP IFC besides the default IPFIX output.
For more information about NEMEA, visit
[https://nemea.liberouter.org](https://nemea.liberouter.org).

By default, the flow exporter uses libpcap, which allows for receiving packets
from PCAP file or network interface card.

When the project is configured with `./configure --with-ndp`, the flow exporter
does not link libpcap. Contrary, it is prepared for high-speed packet transfer
from special HW acceleration FPGA cards.  For more information about the cards,
visit [COMBO cards](https://www.liberouter.org/technologies/cards/) or contact
us.

### Output

- For NEMEA, the output is in UniRec format using [https://nemea.liberouter.org/trap-ifcspec/](https://nemea.liberouter.org/trap-ifcspec/)
- IPFIX [RFC 5101](https://tools.ietf.org/html/rfc5101)

## Parameters
### Module specific parameters
- `-p STRING`        Activate specified parsing plugins. Output interface (NEMEA only) for each plugin correspond the order which you specify items in -i and -p param. For example: '-i u:a,u:b,u:c -p http,basic,dns\' http traffic will be send to interface u:a, basic flow to u:b etc. If you don't specify -p parameter, flow meter will require one output interface for basic flow by default. Format: plugin_name[,...] Supported plugins: http,rtsp,tls,dns,sip,ntp,smtp,basic,passivedns,pstats,ssdp,dnssd,ovpn,idpcontent,netbios,basicplus
  - Some plugins have features activated with additional parameters. Format: plugin_name[:plugin_param=value[:...]][,...] If plugin does not support parameters, any parameters given will be ignored. Supported plugin parameters are listed bellow with output data.
- `-c NUMBER`        Quit after `NUMBER` of packets on each input are captured.
- `-I STRING`        Capture from given network interface. Parameter require interface name (eth0 for example). For nfb interface you can specify channel after interface delimited by : (/dev/nfb0:1) default channel is 0.
- `-r STRING`        Pcap file to read. `-` to read from stdin.
- `-n`               Don't send NULL record on exit (for NEMEA output).
- `-l NUMBER`        Snapshot length when reading packets. Set value between `120`-`65535`.
- `-t NUM:NUM`       Active and inactive timeout in seconds. Format: DOUBLE:DOUBLE. Value default means use default value 300.0:30.0.
- `-s STRING`        Size of flow cache. Parameter is used as an exponent to the power of two. Valid numbers are in range 4-30. default is 17 (131072 records).
- `-S NUMBER`        Print flow cache statistics. `NUMBER` specifies interval between prints.
- `-P`               Print pcap statistics every 5 seconds. The statistics do not behave the same way on all platforms.
- `-L NUMBER`        Link bit field value.
- `-D NUMBER`        Direction bit field value.
- `-F STRING`        String containing filter expression to filter traffic. See man pcap-filter.
- `-O`               Send ODID field instead of LINK_BIT_FIELD.
- `-q NUMBER`        Input queue size (default 64).
- `-Q NUMBER`        Output queue size (default 16536).
- `-e NUMBER`        Export max N flows per second.
- `-m NUMBER`        Max size of IPFIX data packet payload to send.
- `-x STRING`        Export to IPFIX collector. Format: HOST:PORT or [HOST]:PORT.
- `-u`               Use UDP when exporting to IPFIX collector.
- `-V`               Print version.
- `-v`               Increase verbosity of the output, it can be duplicated like -vv / -vvv.

### Common TRAP parameters
- `-h [trap,1]`      Print help message for this module / for libtrap specific parameters.
- `-i IFC_SPEC`      Specification of interface types and their parameters.
- `-v`               Be verbose.
- `-vv`              Be more verbose.
- `-vvv`             Be even more verbose.

## Algorithm
Stores packets from input PCAP file / network interface in flow cache to create flows. After whole PCAP file is processed, flows from flow cache are exported to output interface.
When capturing from network interface, flows are continuously send to output interfaces until N (or unlimited number of packets if the -c option is not specified) packets are captured and exported.

## Extension
`ipfixprobe` can be extended by new plugins for exporting various new information from flow.
There are already some existing plugins that export e.g. `DNS`, `HTTP`, `SIP`, `NTP`, `PassiveDNS`.

## Adding new plugin
To create new plugin use [create_plugin.sh](create_plugin.sh) script. This interactive script will generate .cpp and .h
file template and will also print `TODO` guide what needs to be done.

## Exporting packets
It is possible to export single packet with additional information using plugins (`ARP`).

## Possible issues
### Flows are not send to output interface when reading small pcap file (NEMEA output)

Turn off message buffering using `buffer=off` option on output interfaces.

```
./ipfixprobe -i u:abc:buffer=off -r traffic.pcap
```

## Output data
### Basic
Basic unirec fields exported on interface with basic (pseudo) plugin. These fields are also exported on interfaces where HTTP, DNS, SIP and NTP plugins are active.

| UniRec field           | Type             | Description                                         |
|:----------------------:|:----------------:|:---------------------------------------------------:|
| DST_MAC                | macaddr          | destination MAC address                             |
| SRC_MAC                | macaddr          | source MAC address                                  |
| DST_IP                 | ipaddr           | destination IP address                              |
| SRC_IP                 | ipaddr           | source IP address                                   |
| BYTES                  | uint64           | number of bytes in data flow (src to dst)           |
| BYTES_REV              | uint64           | number of bytes in data flow (dst to src)           |
| LINK_BIT_FIELD or ODID | uint64 or uint32 | exporter identification                             |
| TIME_FIRST             | time             | first time stamp                                    |
| TIME_LAST              | time             | last time stamp                                     |
| PACKETS                | uint32           | number of packets in data flow (src to dst)         |
| PACKETS_REV            | uint32           | number of packets in data flow (dst to src)         |
| DST_PORT               | uint16           | transport layer destination port                    |
| SRC_PORT               | uint16           | transport layer source port                         |
| DIR_BIT_FIELD          | uint8            | bit field for determining outgoing/incoming traffic |
| PROTOCOL               | uint8            | transport protocol                                  |
| TCP_FLAGS              | uint8            | TCP protocol flags (src to dst)                     |
| TCP_FLAGS_REV          | uint8            | TCP protocol flags (dst to src)                     |

### Basic plus
List of unirec fields exported together with basic flow fields on interface by basicplus plugin.
Fields without `_REV` suffix are fields from source flow. Fields with `_REV` are from the opposite direction.

| UniRec field | Type   | Description                 |
|:------------:|:------:|:---------------------------:|
| IP_TTL       | uint8  | IP TTL field                |
| IP_TTL_REV   | uint8  | IP TTL field                |
| IP_FLG       | uint8  | IP FLAGS                    |
| IP_FLG_REV   | uint8  | IP FLAGS                    |
| TCP_WIN      | uint16 | TCP window size             |
| TCP_WIN_REV  | uint16 | TCP window size             |
| TCP_OPT      | uint64 | TCP options bitfield        |
| TCP_OPT_REV  | uint64 | TCP options bitfield        |
| TCP_MSS      | uint32 | TCP maximum segment size    |
| TCP_MSS_REV  | uint32 | TCP maximum segment size    |
| TCP_SYN_SIZE | uint16 | TCP SYN packet size         |

### HTTP
List of unirec fields exported together with basic flow fields on interface by HTTP plugin.

| UniRec field                 | Type   | Description                 |
|:----------------------------:|:------:|:---------------------------:|
| HTTP_REQUEST_METHOD          | string | HTTP request method         |
| HTTP_REQUEST_HOST            | string | HTTP request host           |
| HTTP_REQUEST_URL             | string | HTTP request url            |
| HTTP_REQUEST_AGENT           | string | HTTP request user agent     |
| HTTP_REQUEST_REFERER         | string | HTTP request referer        |
| HTTP_RESPONSE_STATUS_CODE    | uint16 | HTTP response code          |
| HTTP_RESPONSE_CONTENT_TYPE   | string | HTTP response content type  |

### RTSP
List of unirec fields exported together with basic flow fields on interface by RTSP plugin.

| UniRec field                 | Type   | Description                 |
|:----------------------------:|:------:|:---------------------------:|
| RTSP_REQUEST_METHOD          | string | RTSP request method name    |
| RTSP_REQUEST_AGENT           | string | RTSP request user agent     |
| RTSP_REQUEST_URI             | string | RTSP request URI            |
| RTSP_RESPONSE_STATUS_CODE    | uint16 | RTSP response status code   |
| RTSP_RESPONSE_SERVER         | string | RTSP response server field  |
| RTSP_RESPONSE_CONTENT_TYPE   | string | RTSP response content type  |

### TLS
List of unirec fields exported together with basic flow fields on interface by TLS plugin.

| UniRec field        | Type   | Description                  |
|:-------------------:|:------:|:----------------------------:|
| TLS_SNI             | string | TLS server name indication   |
| TLS_JA3             | string | TLS client JA3 fingerprint   |

### DNS
List of unirec fields exported together with basic flow fields on interface by DNS plugin.

| UniRec field | Type   | Description                     |
|:------------:|:------:|:-------------------------------:|
| DNS_ID       | uint16 | transaction ID                  |
| DNS_ANSWERS  | uint16 | number of DNS answer records    |
| DNS_RCODE    | uint8  | response code field             |
| DNS_NAME     | string | question domain name            |
| DNS_QTYPE    | uint16 | question type field             |
| DNS_CLASS    | uint16 | class field of DNS question     |
| DNS_RR_TTL   | uint32 | resource record TTL field       |
| DNS_RLENGTH  | uint16 | length of DNS_RDATA             |
| DNS_RDATA    | bytes  | resource record specific data   |
| DNS_PSIZE    | uint16 | requestor's payload size        |
| DNS_DO       | uint8  | DNSSEC OK bit                   |

#### DNS_RDATA format

DNS_RDATA formatting is implemented for some base DNS RR Types in human-readable output.
Same as [here](https://www.liberouter.org/technologies/exporter/dns-plugin/):

| Record | Format |
|:------:|:------:|
| A      | <IPv4 in dotted decimal representation\> |
| AAAA   | <IPv6 represented as groups separated by semicolons\> |
| NS     | <parsed hostname\> |
| CNAME  | <parsed hostname\> |
| PTR    | <parsed hostname\> |
| DNAME  | <parsed hostname\> |
| SOA    | <mname\> <rname\> <serial\> <refresh\> <retry\> <expire\> <min ttl\> |
| SRV    | <service\> <protocol\> <name\> <target\> <priority\> <weight\> <port\> |
| MX     | <priority\> <mx hostname\> |
| TXT    | <txt string\> |
| MINFO  | <rmailbx\> <emailbx\> |
| HINFO  | <txt string\> |
| ISDN   | <txt string\> |
| DS     | <keytag\> <algorithm\> <digest\> <publickey\>\* |
| RRSIG  | <type_covered\> <algorithm\> <labels\> <original_ttl\> <signature_exp\> <signature_inc\> <keytag\> <signer_signature\>\* |
| DNSKEY | <flags\> <protocol\> <algorithm\> <publickey\>\* |
| other  | <not impl\>\* |

 \* binary data are skipped and not printed

### PassiveDNS
List of unirec fields exported together with basic flow fields on interface by PassiveDNS plugin.

| UniRec field | Type   | Description                             |
|:------------:|:------:|:---------------------------------------:|
| DNS_ID       | uint16 | transaction ID                          |
| DNS_ATYPE    | uint8  | response record type                    |
| DNS_NAME     | string | question domain name                    |
| DNS_RR_TTL   | uint32 | resource record TTL field               |
| DNS_IP       | ipaddr | IP address from PTR, A or AAAA record   |

### SIP
List of unirec fields exported together with basic flow fields on interface by SIP plugin.

| UniRec field      | Type   | Description                     |
|:-----------------:|:------:|:-------------------------------:|
| SIP_MSG_TYPE      | uint16 | SIP message code                |
| SIP_STATUS_CODE   | uint16 | status of the SIP request       |
| SIP_CSEQ          | string | CSeq field of SIP packet        |
| SIP_CALLING_PARTY | string | calling party (from) URI        |
| SIP_CALLED_PARTY  | string | called party (to) URI           |
| SIP_CALL_ID       | string | call ID                         |
| SIP_USER_AGENT    | string | user agent field of SIP packet  |
| SIP_REQUEST_URI   | string | SIP request URI                 |
| SIP_VIA           | string | via field of SIP packet         |

### NTP
List of unirec fields exported together with basic flow fields on interface by NTP plugin.

| UniRec field   | Type   | Description               |
|:--------------:|:------:|:-------------------------:|
| NTP_LEAP       | uint8  | NTP leap field            |
| NTP_VERSION    | uint8  | NTP message version       |
| NTP_MODE       | uint8  | NTP mode field            |
| NTP_STRATUM    | uint8  | NTP stratum field         |
| NTP_POLL       | uint8  | NTP poll interval         |
| NTP_PRECISION  | uint8  | NTP precision field       |
| NTP_DELAY      | uint32 | NTP root delay            |
| NTP_DISPERSION | uint32 | NTP root dispersion       |
| NTP_REF_ID     | string | NTP reference ID          |
| NTP_REF        | string | NTP reference timestamp   |
| NTP_ORIG       | string | NTP origin timestamp      |
| NTP_RECV       | string | NTP receive timestamp     |
| NTP_SENT       | string | NTP transmit timestamp    |

### SMTP
List of unirec fields exported on interface by SMTP plugin

| UniRec field              | Type   | Description                         |
|:-------------------------:|:------:|:-----------------------------------:|
| SMTP_2XX_STAT_CODE_COUNT  | uint32 | number of 2XX status codes          |
| SMTP_3XX_STAT_CODE_COUNT  | uint32 | number of 3XX status codes          |
| SMTP_4XX_STAT_CODE_COUNT  | uint32 | number of 4XX status codes          |
| SMTP_5XX_STAT_CODE_COUNT  | uint32 | number of 5XX status codes          |
| SMTP_COMMAND_FLAGS        | uint32 | bit array of commands present       |
| SMTP_MAIL_CMD_COUNT       | uint32 | number of MAIL commands             |
| SMTP_RCPT_CMD_COUNT       | uint32 | number of RCPT commands             |
| SMTP_STAT_CODE_FLAGS      | uint32 | bit array of status codes present   |
| SMTP_DOMAIN               | string | domain name of the SMTP client      |
| SMTP_FIRST_SENDER         | string | first sender in MAIL command        |
| SMTP_FIRST_RECIPIENT      | string | first recipient in RCPT command     |

#### SMTP\_COMMAND\_FLAGS
The following table shows bit values of `SMTP\_COMMAND\_FLAGS` for each SMTP command present in communication.

| Command  | Value  |
|:--------:|:------:|
| EHLO     | 0x0001 |
| HELO     | 0x0002 |
| MAIL     | 0x0004 |
| RCPT     | 0x0008 |
| DATA     | 0x0010 |
| RSET     | 0x0020 |
| VRFY     | 0x0040 |
| EXPN     | 0x0080 |
| HELP     | 0x0100 |
| NOOP     | 0x0200 |
| QUIT     | 0x0400 |
| UNKNOWN  | 0x8000 |

#### SMTP\_STAT\_CODE\_FLAGS
The following table shows bit values of `SMTP\_STAT_CODE\_FLAGS` for each present in communication.

| Status code | Value      |
|:-----------:|:----------:|
| 211         | 0x00000001 |
| 214         | 0x00000002 |
| 220         | 0x00000004 |
| 221         | 0x00000008 |
| 250         | 0x00000010 |
| 251         | 0x00000020 |
| 252         | 0x00000040 |
| 354         | 0x00000080 |
| 421         | 0x00000100 |
| 450         | 0x00000200 |
| 451         | 0x00000400 |
| 452         | 0x00000800 |
| 455         | 0x00001000 |
| 500         | 0x00002000 |
| 501         | 0x00004000 |
| 502         | 0x00008000 |
| 503         | 0x00010000 |
| 504         | 0x00020000 |
| 550         | 0x00040000 |
| 551         | 0x00080000 |
| 552         | 0x00100000 |
| 553         | 0x00200000 |
| 554         | 0x00400000 |
| 555         | 0x00800000 |
| *           | 0x40000000 |
| UNKNOWN     | 0x80000000 |

* Bit is set if answer contains SPAM keyword.

### PSTATS
List of unirec fields exported on interface by PSTATS plugin.  The plugin is compiled to gather statistics for the first `PSTATS_MAXELEMCOUNT` (30 by default) packets in the biflow record.
Note: the following fields are UniRec arrays.

| UniRec field               | Type     | Description                            |
|:--------------------------:|:--------:|:--------------------------------------:|
| PPI_PKT_LENGTHS            | uint16\* | sizes of the first packets             |
| PPI_PKT_TIMES              | time\*   | timestamps of the first packets        |
| PPI_PKT_DIRECTIONS         | int8\*   | directions of the first packets        |
| PPI_PKT_FLAGS              | uint8\*  | TCP flags for each packet              |

#### Plugin parameters:
- includezeros - Include zero-length packets in the lists.
- skipdup - Skip retransmitted (duplicated) TCP packets.

##### Example:
```
ipfixprobe -p pstats:includezeros -r sample.pcap -i "f:output.trapcap"
```

### SSDP
List of unirec fields exported together with basic flow fields on interface by SSDP plugin.

| UniRec field       | Type   | Description                     |
|:------------------:|:------:|:-------------------------------:|
| SSDP_LOCATION_PORT | uint16 | service port                    |
| SSDP_NT            | string | list of advertised service urns |
| SSDP_SERVER        | string | server info                     |
| SSDP_ST            | string | list of queried service urns    |
| SSDP_USER_AGENT    | string | list of user agents             |

All lists are semicolon separated.

### DNS-SD
List of unirec fields exported together with basic flow fields on interface by DNS-SD plugin.

| UniRec field    | Type   | Description                     |
|:---------------:|:------:|:-------------------------------:|
| DNSSD_QUERIES   | string | list of queries for services    |
| DNSSD_RESPONSES | string | list of advertised services     |

Format of DNSSD_QUERIES: [service_instance_name;][...]

Format of DNSSD_RESPONSES: [service_instance_name;service_port;service_target;hinfo;txt;][...]

#### Plugin parameters:
- txt - Activates processing of txt records.
    - Allows to pass a filepath to .csv file with whitelist filter of txt records.
   - File line format: service.domain,txt_key1,txt_key2,...
   - If no filepath is provided, all txt records will be aggregated.

### OVPN (OpenVPN)

List of UniRec fields exported together with basic flow fields on interface by OVPN plugin.

| UniRec field       | Type   | Description                     |
|:------------------:|:------:|:-------------------------------:|
| OVPN_CONF_LEVEL    | uint8  | level of confidence that the flow record is an OpenVPN tunnel |


### IDPContent (Initial Data Packets Content)

List of UniRec fields exported together with basic flow fields on the interface by IDPContent plugin.
The plugin is compiled to export `IDPCONTENT_SIZE` (100 by default) bytes from the first data packet in SRC -> DST direction,
and the first data packet in DST -> SRC direction.

| UniRec field       | Type   | Description                     |
|:------------------:|:------:|:-------------------------------:|
| IDP_CONTENT        | bytes  | Content of first data packet from SRC -> DST|
| IDP_CONTENT_REV    | bytes  | Content of first data packet from DST -> SRC|

### NetBIOS

List of UniRec fields exported together with basic flow fields on interface by NetBIOS plugin.

| UniRec field  | Type   | Description                 |
|:-------------:|:------:|:---------------------------:|
| NB_NAME       | string | NetBIOS Name Service name   |
| NB_SUFFIX     | uint8  | NetBIOS Name Service suffix |

### PHISTS

List of UniRec fields exported together with basic flow fields on the interface by PHISTS plugin.
The plugin exports the histograms of Payload sizes and Inter-Packet-Times for each direction. The
histograms bins are scaled logarithmicaly and are shown in following table:

| Bin Number | Size Len   | Inter Packet Time |
|:----------:|:----------:|:-----------------:|
| 1          | 0-15 B     |  0-15 ms          |
| 2          | 16-31 B    |  16-31 ms         |
| 3          | 32-63 B    |  32-63 ms         |
| 4          | 64-127 B   |  64-127 ms        |
| 5          | 128-255 B  |  128-255 ms       |
| 6          | 256-511 B  |  256-511 ms       |
| 7          | 512-1023 B |  512-1023 ms      |
| 8          | > 1024 B   |  > 1024 ms        |

The exported unirec fields and IPFIX basiclists is shown in following table:

| UniRec field        | Type    | Description                             |
|:-------------------:|:-------:|:---------------------------------------:|
| D_PHISTS_IPT        | uint32\*| DST->SRC: Histogram of interpacket times|
| D_PHISTS_SIZES      | uint32\*| DST->SRC: Histogram of packet sizes     |
| S_PHISTS_IPT        | uint32\*| SRC->DST: Histogram of interpacket times|
| S_PHISTS_SIZES      | uint32\*| SRC->DST: Histogram of packet sizes     |

#### Plugin parameters:
- includezeros - Include zero-length packets in the lists.

##### Example:
```
ipfixprobe -p phists:includezeros -r sample.pcap -i "f:output.trapcap"
```
### BSTATS

List of UniRec fields exported together with basic flow fields on the interface by BSTATS plugin.
The plugin is compiled to export the first `BSTATS_MAXELENCOUNT` (15 by default) burst in each direction.
The bursts are computed separately for each direction. Burst is defined by `MINIMAL_PACKETS_IN_BURST` (3 by default) and by `MAXIMAL_INTERPKT_TIME` (1000 ms by default) between packets to be included in a burst.

| UniRec field        | Type    | Description                                                     |
|:-------------------:|:-------:|:---------------------------------------------------------------:|
| SBI_BRST_PACKETS    | uint32\* | SRC->DST: Number of packets transmitted in i<sup>th</sup> burst|
| SBI_BRST_BYTES      | uint32\* | SRC->DST: Number of bytes transmitted in i<sup>th</sup> burst  |
| SBI_BRST_TIME_START | time\*   | SRC->DST: Start time of the i<sup>th</sup> burst               |
| SBI_BRST_TIME_STOP  | time\*   | SRC->DST: End time of the i<sup>th</sup> burst                 |
| DBI_BRST_PACKETS    | uint32\* | DST->SRC: Number of packets transmitted in i<sup>th</sup> burst|
| DBI_BRST_BYTES      | uint32\* | DST->SRC: Number of bytes transmitted in i<sup>th</sup> burst  |
| DBI_BRST_TIME_START | time\*   | DST->SRC: Start time of the i<sup>th</sup> burst               |
| DBI_BRST_TIME_STOP  | time\*   | DST->SRC: End time of the i<sup>th</sup> burst                 |

### WG (WireGuard)

List of UniRec fields exported together with basic flow fields on interface by WG plugin.

| UniRec field       | Type   | Description                     |
|:------------------:|:------:|:-------------------------------:|
| WG_CONF_LEVEL      | uint8  | level of confidence that the flow record is a WireGuard tunnel|
| WG_SRC_PEER        | uint32 | ephemeral SRC peer identifier                                 |
| WG_DST_PEER        | uint32 | ephemeral DST peer identifier                                 |

### Kubernetes

List of UniRec fields exported together with basic flow fields on the interface by Kuberentes plugin.

| UniRecField              | Type   | Description                                                                                                                                                                                         |
|:------------------------:|:------:|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
| K8S_APP_NAME             | string |  Name from label 'app' given to Pod                                                                                                                                                                 |
| K8S_NODE_NAME            | string |  Name and IP address of the node where Pod is currently running                                                                                                                                     |
| K8S_POD_NAME             | string |  Unique pod name. Can be used to execute some commands in its containers.                                                                                                                           |
| K8S_CONTAINER_IDS        | string |  Ids of all containers in pod deliminated by ','. Usefull in case you are logged on node where pod is running. Then you can login into container with this id                                       |
| K8S_CONTAINER_IMAGES     | string |  Images used in running containers within pod.                                                                                                                                                      |
| K8S_CONTAINER_IMAGE_IDS  | string |  Sha-256 hash of images of running containers. Can be useful when you need to determine particular container image.                                                                                 |
| K8S_PORTS_CONTAINER      | string |  List of open ports in containers. App is reachable within cluster in the same namespace at {container.ip}:port                                                                                     |
| K8S_PORTS_EXPOSED        | string |  List of exposed ports to node network. App is reachable within cluster in the same namespace at {node.ip}:port. These ports are used also when you create service to network outside the cluster.  |

#### Plugin parameters:
Each field can be set manually in the form key=value and the following table shows how parameters are mapped to fields.

| UniRecField              | Parameter           |
|:------------------------:|:-------------------:|
| K8S_APP_NAME             | app-name            |
| K8S_NODE_NAME            | node-name           |
| K8S_POD_NAME             | pod-name            |
| K8S_CONTAINER_IDS        | container-ids       |
| K8S_CONTAINER_IMAGES     | container-images    |
| K8S_CONTAINER_IMAGE_IDS  | container-image-ids |
| K8S_PORTS_CONTAINER      | ports-container     |
| K8S_PORTS_EXPOSED        | ports-exposed       |

There is also one extra parameter available - 'file-name'. This file can contain also key=value pairs for exporting fields. When field is defined in file-name and given also as a paramter, value for such key in file is overriden by parameter's value. File can also contain comments - lines starting with '#'.

##### Example:
```
ipfixprobe kubernetes:app-name=testapp:node-name=s2:pod-name=testpod:ports-exposed=80:ports-container=8080';'80:file-name=/path/to/testfile.txt -r sample.pcap -i "f:output.trapcap"
```

## Simplified function diagram
Diagram below shows how `ipfixprobe` works.

1. `Packet` is read from pcap file or network interface
2. `Packet` is processed by PcapReader and is about to put to flow cache
3. Flow cache create or update flow and call `pre_create`, `post_create`, `pre_update`, `post_update` and `pre_export` functions for each active plugin at appropriate time
4. `Flow` is put into exporter when considered as expired, flow cache is full or is forced to by a plugin
5. Exporter fills `unirec record`, which is then send it to output libtrap interface

```
       +--------------------------------+
       | pcap file or network interface |
       +-----+--------------------------+
             |
          1. |
             |                                  +-----+
    +--------v---------+                              |
    |                  |             +-----------+    |
    |    PcapReader    |      +------>  Plugin1  |    |
    |                  |      |      +-----------+    |
    +--------+---------+      |                       |
             |                |      +-----------+    |
          2. |                +------>  Plugin2  |    |
             |                |      +-----------+    |
    +--------v---------+      |                       |
    |                  |  3.  |      +-----------+    +----+ active plugins
    |   NHTFlowCache   +------------->  Plugin3  |    |
    |                  |      |      +-----------+    |
    +--------+---------+      |                       |
             |                |            .          |
          4. |                |            .          |
             |                |            .          |
    +--------v---------+      |                       |
    |                  |      |      +-----------+    |
    |  UnirecExporter  |      +------>  PluginN  |    |
    |                  |             +-----------+    |
    +--------+---------+                              |
             |                                  +-----+
          5. |
             |
       +-----v--------------------------+
       |    libtrap output interface    |
       +--------------------------------+
```
