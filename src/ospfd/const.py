"""RFC 2328 OSPF v2 protocol constants."""

from ipaddress import IPv4Address

# Protocol
OSPF_VERSION = 2
OSPF_IP_PROTOCOL = 89

# Multicast addresses
ALL_SPF_ROUTERS = "224.0.0.5"
ALL_D_ROUTERS = "224.0.0.6"

# Packet types
PACKET_TYPE_HELLO = 1
PACKET_TYPE_DD = 2
PACKET_TYPE_LSR = 3
PACKET_TYPE_LSU = 4
PACKET_TYPE_LSACK = 5

PACKET_TYPE_NAMES = {
    PACKET_TYPE_HELLO: "Hello",
    PACKET_TYPE_DD: "Database Description",
    PACKET_TYPE_LSR: "Link State Request",
    PACKET_TYPE_LSU: "Link State Update",
    PACKET_TYPE_LSACK: "Link State Acknowledgment",
}

# LSA types
LSA_TYPE_ROUTER = 1
LSA_TYPE_NETWORK = 2
LSA_TYPE_SUMMARY = 3
LSA_TYPE_ASBR_SUMMARY = 4
LSA_TYPE_EXTERNAL = 5

LSA_TYPE_NAMES = {
    LSA_TYPE_ROUTER: "Router",
    LSA_TYPE_NETWORK: "Network",
    LSA_TYPE_SUMMARY: "Summary (Network)",
    LSA_TYPE_ASBR_SUMMARY: "Summary (ASBR)",
    LSA_TYPE_EXTERNAL: "AS External",
}

# LSA sequence numbers (signed 32-bit)
INITIAL_SEQ_NUM = 0x80000001
MAX_SEQ_NUM = 0x7FFFFFFF

# LSA ages
MAX_AGE = 3600              # seconds
MAX_AGE_DIFF = 900          # 15 minutes
LS_REFRESH_TIME = 1800      # 30 minutes
MIN_LS_INTERVAL = 5         # seconds between originations of same LSA
MIN_LS_ARRIVAL = 1          # minimum seconds between accepting same LSA
CHECK_AGE = 300             # age increment for checksum verification

# Hello/Dead defaults
DEFAULT_HELLO_INTERVAL_BROADCAST = 10
DEFAULT_HELLO_INTERVAL_NBMA = 30
DEFAULT_DEAD_INTERVAL_MULTIPLIER = 4
DEFAULT_RXMT_INTERVAL = 5
DEFAULT_INF_TRANS_DELAY = 1

# DD flags
DD_FLAG_I = 0x04    # Init
DD_FLAG_M = 0x02    # More
DD_FLAG_MS = 0x01   # Master/Slave

# Router LSA flags
ROUTER_FLAG_V = 0x04  # Virtual link endpoint
ROUTER_FLAG_E = 0x02  # AS Boundary Router (ASBR)
ROUTER_FLAG_B = 0x01  # Area Border Router (ABR)

# Router LSA link types
LINK_TYPE_P2P = 1
LINK_TYPE_TRANSIT = 2
LINK_TYPE_STUB = 3
LINK_TYPE_VIRTUAL = 4

# Options field bits (Section A.2)
OPT_DN = 0x80      # DN bit (RFC 4576)
OPT_O = 0x40       # Opaque LSA (RFC 5250)
OPT_DC = 0x20      # Demand Circuits (RFC 1793)
OPT_EA = 0x10      # External Attributes (deprecated)
OPT_NP = 0x08      # NSSA (RFC 3101)
OPT_MC = 0x04      # Multicast (RFC 1584)
OPT_E = 0x02       # AS External LSAs (not in stub areas)
OPT_MT = 0x01      # Multi-Topology (RFC 4915)

# Authentication types
AUTH_NONE = 0
AUTH_SIMPLE = 1
AUTH_MD5 = 2

# Interface types
INTF_TYPE_P2P = 1
INTF_TYPE_BROADCAST = 2
INTF_TYPE_NBMA = 3
INTF_TYPE_P2MP = 4
INTF_TYPE_VIRTUAL = 5

# Interface states
INTF_STATE_DOWN = 0
INTF_STATE_LOOPBACK = 1
INTF_STATE_WAITING = 2
INTF_STATE_P2P = 3
INTF_STATE_DROTHER = 4
INTF_STATE_BACKUP = 5
INTF_STATE_DR = 6

# Interface events
INTF_EVT_IF_UP = 0
INTF_EVT_WAIT_TIMER = 1
INTF_EVT_BACKUP_SEEN = 2
INTF_EVT_NBR_CHANGE = 3
INTF_EVT_LOOP_IND = 4
INTF_EVT_UNLOOP_IND = 5
INTF_EVT_IF_DOWN = 6

# Neighbor states
NBR_STATE_DOWN = 0
NBR_STATE_ATTEMPT = 1
NBR_STATE_INIT = 2
NBR_STATE_2WAY = 3
NBR_STATE_EXSTART = 4
NBR_STATE_EXCHANGE = 5
NBR_STATE_LOADING = 6
NBR_STATE_FULL = 7

NBR_STATE_NAMES = {
    NBR_STATE_DOWN: "Down",
    NBR_STATE_ATTEMPT: "Attempt",
    NBR_STATE_INIT: "Init",
    NBR_STATE_2WAY: "2-Way",
    NBR_STATE_EXSTART: "ExStart",
    NBR_STATE_EXCHANGE: "Exchange",
    NBR_STATE_LOADING: "Loading",
    NBR_STATE_FULL: "Full",
}

# Neighbor events
NBR_EVT_HELLO_RECEIVED = 0
NBR_EVT_START = 1
NBR_EVT_2WAY_RECEIVED = 2
NBR_EVT_NEGOTIATION_DONE = 3
NBR_EVT_EXCHANGE_DONE = 4
NBR_EVT_BAD_LS_REQ = 5
NBR_EVT_LOADING_DONE = 6
NBR_EVT_ADJ_OK = 7
NBR_EVT_SEQ_NUM_MISMATCH = 8
NBR_EVT_1WAY = 9
NBR_EVT_KILL_NBR = 10
NBR_EVT_INACTIVITY_TIMER = 11
NBR_EVT_LL_DOWN = 12

# SPF
SPF_VERTEX_ROUTER = 1
SPF_VERTEX_NETWORK = 2

# Route path types
PATH_INTRA_AREA = 1
PATH_INTER_AREA = 2
PATH_TYPE1_EXTERNAL = 3
PATH_TYPE2_EXTERNAL = 4

# Netlink
RTPROT_OSPF = 89

# IP
IP_TOS_OSPF = 0xC0  # CS6 (DSCP 48) - Internetwork Control

# Backbone area
BACKBONE_AREA = IPv4Address("0.0.0.0")

# Default priority
DEFAULT_PRIORITY = 1
DEFAULT_COST = 10

# Opaque LSA types (RFC 5250)
LSA_TYPE_OPAQUE_LINK = 9    # link-scoped
LSA_TYPE_OPAQUE_AREA = 10   # area-scoped
LSA_TYPE_OPAQUE_AS = 11     # AS-scoped

# Opaque sub-types (upper byte of link_state_id)
OPAQUE_TYPE_RI = 4           # Router Information (RFC 7770)
OPAQUE_TYPE_EXTENDED_PREFIX = 7   # RFC 7684
OPAQUE_TYPE_EXTENDED_LINK = 8     # RFC 7684

# RI LSA TLV types (RFC 7770 / RFC 8665)
RI_TLV_SR_CAPABILITIES = 2
RI_TLV_SR_ALGORITHM = 19
RI_TLV_SID_LABEL_RANGE = 9

# Extended Prefix/Link TLV types (RFC 7684)
EP_TLV_EXTENDED_PREFIX = 1
EL_TLV_EXTENDED_LINK = 1

# SR sub-TLV types
SR_STLV_SID_LABEL = 1          # SID/Label value (within range TLVs)
SR_STLV_PREFIX_SID = 2         # Prefix-SID (within Extended Prefix)
SR_STLV_ADJ_SID = 2            # Adj-SID (within Extended Link)
SR_STLV_LAN_ADJ_SID = 3        # LAN Adj-SID (within Extended Link)

# SR algorithm values
SR_ALG_SPF = 0
SR_ALG_STRICT_SPF = 1

# Prefix-SID flags
PREFIX_SID_FLAG_NP = 0x40    # No-PHP
PREFIX_SID_FLAG_M = 0x20     # Mapping Server
PREFIX_SID_FLAG_E = 0x10     # Explicit-Null
PREFIX_SID_FLAG_V = 0x08     # Value (absolute label, not index)
PREFIX_SID_FLAG_L = 0x04     # Local

# Adj-SID flags
ADJ_SID_FLAG_B = 0x80        # Backup
ADJ_SID_FLAG_V = 0x40        # Value (label, not index)
ADJ_SID_FLAG_L = 0x20        # Local
ADJ_SID_FLAG_G = 0x10        # Group
ADJ_SID_FLAG_P = 0x08        # Persistent

# MPLS label constants
MPLS_LABEL_IMPLICIT_NULL = 3
MPLS_LABEL_EXPLICIT_NULL = 0
MPLS_LABEL_MIN_UNRESERVED = 16
MPLS_LABEL_MAX = 0xFFFFF  # 20-bit label

# Default SRGB
SR_DEFAULT_SRGB_START = 16000
SR_DEFAULT_SRGB_SIZE = 8000
