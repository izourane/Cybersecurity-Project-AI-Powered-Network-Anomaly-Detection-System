"""
ml_features.py

Behavioral feature extraction for AI-powered network anomaly detection.

Transforms packet-level traffic into ML-ready behavioral features.
Designed for real-time anomaly detection with Isolation Forest.

Author: Mohamed + ChatGPT
"""

from collections import defaultdict, deque
from dataclasses import dataclass
import time


@dataclass
class TrafficFeatures:

    # Basic traffic
    packet_size: int
    protocol: int

    # Behavioral features
    protocol_frequency: float
    is_arp: int
    is_dns: int
    is_tcp: int
    packets_per_source: int
    bytes_per_src: int
    unique_destinations: int

    # Traffic statistics
    packet_rate: float
    tcp_ratio: float
    udp_ratio: float
    dns_ratio: float
    arp_ratio: float

    # Statistical features
    avg_packet_size: float
    burst_score: float


class FeatureExtractor:

    def __init__(self, window_seconds: int = 30):

        self.window_seconds = window_seconds

        # ---------------------------------------------------
        # Counters
        # ---------------------------------------------------

        self.src_packet_counter = defaultdict(int)

        self.src_byte_counter = defaultdict(int)

        # ---------------------------------------------------
        # Destination tracking
        # ---------------------------------------------------

        self.src_destinations = defaultdict(set)

        # ---------------------------------------------------
        # Protocol counters
        # ---------------------------------------------------

        self.protocol_counter = defaultdict(int)

        # ---------------------------------------------------
        # Sliding window
        # ---------------------------------------------------

        self.packet_times = deque()

        self.packet_sizes = deque()

        # ---------------------------------------------------
        # Global counters
        # ---------------------------------------------------

        self.total_packets = 0

        # ---------------------------------------------------
        # Start time
        # ---------------------------------------------------

        self.start_time = time.time()

    def extract_features(self, packet_info):

        current_time = time.time()

        # ---------------------------------------------------
        # Packet attributes
        # ---------------------------------------------------

        src_ip = getattr(
            packet_info,
            "src_ip",
            "unknown"
        )

        dst_ip = getattr(
            packet_info,
            "dst_ip",
            "unknown"
        )

        protocol_name = getattr(
            packet_info,
            "protocol",
            "OTHER"
        )

        packet_size = getattr(
            packet_info,
            "size",
            0
        )
        normalized_protocol = protocol_name.upper()
        if protocol_name in ["HTTP", "HTTPS"]:
            normalized_protocol = "TCP"
        elif protocol_name == "DNS":
            normalized_protocol = "UDP"
        # ---------------------------------------------------
        # Update counters
        # ---------------------------------------------------

        self.total_packets += 1

        self.src_packet_counter[src_ip] += 1

        self.src_byte_counter[src_ip] += packet_size

        self.src_destinations[src_ip].add(
            dst_ip
        )

        self.protocol_counter[
            normalized_protocol
        ] += 1

        # ---------------------------------------------------
        # Protocol frequency
        # ---------------------------------------------------

        protocol_frequency = (
            self.protocol_counter[
                protocol_name
            ] / max(self.total_packets, 1)
        )

        # ---------------------------------------------------
        # Sliding window tracking
        # ---------------------------------------------------

        self.packet_times.append(
            current_time
        )

        self.packet_sizes.append(
            packet_size
        )

        # Remove old packets
        while (
            self.packet_times
            and current_time
            - self.packet_times[0]
            > self.window_seconds
        ):

            self.packet_times.popleft()

        # Limit stored packet sizes
        while len(self.packet_sizes) > 1000:

            self.packet_sizes.popleft()

        # ---------------------------------------------------
        # Traffic metrics
        # ---------------------------------------------------

        packet_rate = (
            len(self.packet_times)
            / self.window_seconds
        )

        avg_packet_size = (

            sum(self.packet_sizes)
            / len(self.packet_sizes)

            if self.packet_sizes
            else 0
        )

        unique_destinations = len(
            self.src_destinations[src_ip]
        )

        # ---------------------------------------------------
        # Protocol ratios
        # ---------------------------------------------------

        total_proto = max(
            self.total_packets,
            1
        )

        tcp_ratio = (
            self.protocol_counter["TCP"]
            / total_proto
        )

        udp_ratio = (
            self.protocol_counter["UDP"]
            / total_proto
        )

        dns_ratio = (
            self.protocol_counter["DNS"]
            / total_proto
        )

        arp_ratio = (
            self.protocol_counter["ARP"]
            / total_proto
        )

        # ---------------------------------------------------
        # Protocol encoding
        # ---------------------------------------------------

        protocol_map = {

            "TCP": 1,

            "UDP": 2,

            "ICMP": 3,

            "DNS": 4,

            "ARP": 5,

            "HTTPS": 6,

            "HTTP": 7,
        }

        protocol_encoded = protocol_map.get(
            protocol_name,
            0
        )
        is_arp = int(protocol_name == "ARP")

        is_dns = int(protocol_name == "DNS")

        is_tcp = int(
            protocol_name in ["TCP", "HTTP", "HTTPS"]
        )

        # ---------------------------------------------------
        # Burst detection
        # ---------------------------------------------------

        burst_score = (
            packet_rate
            * avg_packet_size
        )

        # ---------------------------------------------------
        # Return features
        # ---------------------------------------------------

        return TrafficFeatures(

            # Basic traffic
            packet_size=packet_size,

            protocol=protocol_encoded,

            # Behavioral
            protocol_frequency=round(
                protocol_frequency,
                4
            ),
            is_arp=is_arp,
            is_dns=is_dns,
            is_tcp=is_tcp,
            packets_per_source=
                self.src_packet_counter[src_ip],

            bytes_per_src=
                self.src_byte_counter[src_ip],

            unique_destinations=
                unique_destinations,

            # Traffic stats
            packet_rate=round(
                packet_rate,
                2
            ),

            tcp_ratio=round(
                tcp_ratio,
                3
            ),

            udp_ratio=round(
                udp_ratio,
                3
            ),

            dns_ratio=round(
                dns_ratio,
                3
            ),

            arp_ratio=round(
                arp_ratio,
                3
            ),

            # Statistical
            avg_packet_size=round(
                avg_packet_size,
                2
            ),

            burst_score=round(
                burst_score,
                2
            ),
        )

    def to_dict(
        self,
        features: TrafficFeatures
    ):

        return {

            # Basic traffic
            "packet_size":
                features.packet_size,

            "protocol":
                features.protocol,

            # Behavioral
            "protocol_frequency":
                features.protocol_frequency,

            "packets_per_source":
                features.packets_per_source,

            "bytes_per_src":
                features.bytes_per_src,

            "unique_destinations":
                features.unique_destinations,

            # Traffic stats
            "packet_rate":
                features.packet_rate,

            "tcp_ratio":
                features.tcp_ratio,

            "udp_ratio":
                features.udp_ratio,

            "dns_ratio":
                features.dns_ratio,

            "arp_ratio":
                features.arp_ratio,

            # Statistical
            "avg_packet_size":
                features.avg_packet_size,

            "burst_score":
                features.burst_score,
            
            "is_arp":
                features.is_arp,

            "is_dns":
                features.is_dns,

            "is_tcp":
                features.is_tcp,
        }