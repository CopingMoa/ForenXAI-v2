"""
Pure-Python flow extractor (PCAP / PCAPNG -> CICFlowMeter v4 CSV).

WHY THIS EXISTS
---------------
CICFlowMeter v4 is a Java tool that depends on jnetpcap native libraries.
On Windows those are frequently unavailable, and the whole PCAP intake path
is dead without them.  This module is a fallback that reads the capture with
scapy (pure Python, no native pcap driver needed for offline files) and
writes a CSV whose header uses the exact CICFlowMeter v4 column names the
frozen ForenXAI model schema expects.

It is a FALLBACK, not a replacement.  Findings produced through it are
tagged with engine="python" so the provenance is visible downstream.

FIDELITY
--------
Flow features come from the `cicflowmeter` package, an established Python
port of the CIC feature set.  Three corrections are applied here:

  1. CWR Flag Count.  The upstream port assigns it the forward URG count,
     which is simply the wrong field.  We count the TCP CWR bit directly.

  2. Flow timeout.  The port ships 240 s; CICFlowMeter v4 uses 120 s.  We
     use 120 s, so flows are segmented the way the reference tool does it.

  3. Column names.  The port emits snake_case; the model schema is the v4
     display names.  V4_NAMES below is the mapping.

The port is also driven directly rather than registered as a scapy session:
it targets scapy 2.5, whose session hook is `on_packet_received`, and scapy
2.7 renamed that to `process`.  Registered as a session under 2.7 it silently
receives no packets and reports zero flows as a success.

Six columns the port derives by identity (subflow totals, segment size
averages) were checked against real CICFlowMeter output rather than assumed:

    CICIDS2018 CSVs, 300,000 rows      identity holds on 100% of rows
    TRUSTLab training set, 1,120,000   identity holds on 100% of rows

so those are exact, not approximations.

KNOWN DIFFERENCES FROM THE JAVA TOOL
------------------------------------
  * The activity and bulk timeout constants differ from the v4 defaults, so
    the Active/Idle and Bulk columns are computed on slightly different
    boundaries.
  * Subflow splitting is not implemented the way v4 implements it; those
    four columns are emitted by the identity checked above, which is what
    v4 produces in practice but not how it produces it.

Feature values can therefore differ from what the Java tool would produce on
the same capture.  That matters for a forensic claim, which is why the
engine that produced a flow table is recorded with the case rather than
assumed.

MEMORY
------
The port holds every packet of a flow until that flow closes, because the
features are computed at close time.  Around 3.7 KB per retained packet, so
a dense capture is bounded by RAM, not by file size.  MAX_RETAINED_PACKETS
enforces this with an error naming a fix, rather than letting the process
grow until the machine stops.
"""

import csv
import os

try:
    from scapy.sessions import DefaultSession
    from scapy.utils import PcapReader

    from cicflowmeter import flow_session as flow_session_module
    from cicflowmeter.features.context import PacketDirection  # noqa: F401
    from cicflowmeter.features.flag_count import FlagCount
    from cicflowmeter.flow import Flow
    from cicflowmeter.flow_session import FlowSession
    from cicflowmeter.utils import get_logger

    AVAILABLE = True
    IMPORT_ERROR = None
except Exception as exc:  # pragma: no cover - depends on environment
    AVAILABLE = False
    IMPORT_ERROR = f"{type(exc).__name__}: {exc}"


# ============================================================
# COLUMN NAMES
# ============================================================

# cicflowmeter key -> CICFlowMeter v4 display name used by the model schema.
V4_NAMES = {
    # identity
    "src_ip": "Src IP",
    "dst_ip": "Dst IP",
    "src_port": "Src Port",
    "dst_port": "Dst Port",
    "protocol": "Protocol",
    "timestamp": "Timestamp",

    # flow level
    "flow_duration": "Flow Duration",
    "flow_byts_s": "Flow Bytes/s",
    "flow_pkts_s": "Flow Packets/s",

    # counts and volumes
    "tot_fwd_pkts": "Total Fwd Packet",
    "tot_bwd_pkts": "Total Bwd packets",
    "totlen_fwd_pkts": "Total Length of Fwd Packet",
    "totlen_bwd_pkts": "Total Length of Bwd Packet",

    # packet lengths
    "fwd_pkt_len_max": "Fwd Packet Length Max",
    "fwd_pkt_len_min": "Fwd Packet Length Min",
    "fwd_pkt_len_mean": "Fwd Packet Length Mean",
    "fwd_pkt_len_std": "Fwd Packet Length Std",
    "bwd_pkt_len_max": "Bwd Packet Length Max",
    "bwd_pkt_len_min": "Bwd Packet Length Min",
    "bwd_pkt_len_mean": "Bwd Packet Length Mean",
    "bwd_pkt_len_std": "Bwd Packet Length Std",
    "pkt_len_max": "Packet Length Max",
    "pkt_len_min": "Packet Length Min",
    "pkt_len_mean": "Packet Length Mean",
    "pkt_len_std": "Packet Length Std",
    "pkt_len_var": "Packet Length Variance",

    # headers
    "fwd_header_len": "Fwd Header Length",
    "bwd_header_len": "Bwd Header Length",

    # inter-arrival times
    "flow_iat_mean": "Flow IAT Mean",
    "flow_iat_max": "Flow IAT Max",
    "flow_iat_min": "Flow IAT Min",
    "flow_iat_std": "Flow IAT Std",
    "fwd_iat_tot": "Fwd IAT Total",
    "fwd_iat_max": "Fwd IAT Max",
    "fwd_iat_min": "Fwd IAT Min",
    "fwd_iat_mean": "Fwd IAT Mean",
    "fwd_iat_std": "Fwd IAT Std",
    "bwd_iat_tot": "Bwd IAT Total",
    "bwd_iat_max": "Bwd IAT Max",
    "bwd_iat_min": "Bwd IAT Min",
    "bwd_iat_mean": "Bwd IAT Mean",
    "bwd_iat_std": "Bwd IAT Std",

    # flags
    "fwd_psh_flags": "Fwd PSH Flags",
    "bwd_psh_flags": "Bwd PSH Flags",
    "fwd_urg_flags": "Fwd URG Flags",
    "bwd_urg_flags": "Bwd URG Flags",
    "fin_flag_cnt": "FIN Flag Count",
    "syn_flag_cnt": "SYN Flag Count",
    "rst_flag_cnt": "RST Flag Count",
    "psh_flag_cnt": "PSH Flag Count",
    "ack_flag_cnt": "ACK Flag Count",
    "urg_flag_cnt": "URG Flag Count",
    "ece_flag_cnt": "ECE Flag Count",
    "cwr_flag_count": "CWR Flag Count",

    # ratios and window sizes
    "down_up_ratio": "Down/Up Ratio",
    "pkt_size_avg": "Average Packet Size",
    "init_fwd_win_byts": "FWD Init Win Bytes",
    "init_bwd_win_byts": "Bwd Init Win Bytes",

    # activity
    "active_max": "Active Max",
    "active_min": "Active Min",
    "active_mean": "Active Mean",
    "active_std": "Active Std",
    "idle_max": "Idle Max",
    "idle_min": "Idle Min",
    "idle_mean": "Idle Mean",
    "idle_std": "Idle Std",

    # bulk
    "fwd_byts_b_avg": "Fwd Bytes/Bulk Avg",
    "fwd_pkts_b_avg": "Fwd Packet/Bulk Avg",
    "bwd_byts_b_avg": "Bwd Bytes/Bulk Avg",
    "bwd_pkts_b_avg": "Bwd Packet/Bulk Avg",
    "fwd_blk_rate_avg": "Fwd Bulk Rate Avg",
    "bwd_blk_rate_avg": "Bwd Bulk Rate Avg",

    # derived identities (verified against real CICFlowMeter output)
    "fwd_seg_size_avg": "Fwd Segment Size Avg",
    "bwd_seg_size_avg": "Bwd Segment Size Avg",
    "subflow_fwd_pkts": "Subflow Fwd Packets",
    "subflow_bwd_pkts": "Subflow Bwd Packets",
    "subflow_fwd_byts": "Subflow Fwd Bytes",
    "subflow_bwd_byts": "Subflow Bwd Bytes",
}


# ============================================================
# SAFETY LIMITS
# ============================================================
#
# These exist because of how the feature computation works, not out of
# caution. Every feature -- packet lengths, IATs, flag counts, bulk rates --
# is computed at flow close by iterating that flow's packets, so a Flow must
# retain every scapy Packet object it has seen until it is written out.
#
# Measured on this machine: about 3.7 KB of resident memory per retained
# packet. A 183 MB capture with 2.4 million packets reached 9 GB and was
# still climbing. Left unbounded, a large capture takes the machine down
# rather than returning an error, and an investigator loses the session.
#
# So the budget below is enforced on retained packets -- the thing that
# actually consumes memory -- rather than on file size, which does not
# predict packet count. File size is a cheap pre-check on top of it.

# Packets held across all open flows before the capture is refused.
# 600,000 x ~3.7 KB is roughly 2.2 GB resident.
MAX_RETAINED_PACKETS = 600_000

# Concurrent open flows held in memory before we stop accepting the capture.
MAX_OPEN_FLOWS = 200_000

# Cheap pre-check. Captures vary from roughly 600 to 5,000 bytes per packet,
# so this cannot be exact; the packet budget above is the real limit.
MAX_PCAP_BYTES = 2 * 1024 * 1024 * 1024      # 2 GiB

# Flow timeout, in seconds. CICFlowMeter v4 uses 120 s and the cicflowmeter
# port ships 240 s. We use 120 s: it matches the reference implementation
# the model was trained against, and it also lets flows close -- and free
# their packets -- twice as early.
FLOW_TIMEOUT_SECONDS = 120


class CaptureTooLarge(RuntimeError):
    """The capture exceeds a limit this extractor will attempt."""


# ============================================================
# CSV WRITER
# ============================================================

class _V4Writer:
    """
    Writes flow dictionaries out under CICFlowMeter v4 column names.

    The header is fixed at construction from V4_NAMES so every row has the
    same columns in the same order, whatever the first flow happened to
    contain.
    """

    def __init__(self, path):
        self._keys = list(V4_NAMES.keys())
        self._fh = open(path, "w", newline="", encoding="utf-8")
        self._writer = csv.writer(self._fh)
        self._writer.writerow([V4_NAMES[k] for k in self._keys])
        self.rows = 0

    def write(self, data):
        self._writer.writerow([data.get(k, 0) for k in self._keys])
        self.rows += 1

    def close(self):
        if self._fh is not None and not self._fh.closed:
            self._fh.flush()
            self._fh.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


# ============================================================
# FLOW CORRECTIONS
# ============================================================

_PATCHED = False


def _apply_corrections():
    """
    Two corrections to the cicflowmeter port, applied once.

    1. CWR Flag Count. Upstream sets it to the forward URG count:

           data["cwr_flag_count"] = data["fwd_urg_flags"]

       which is a different field entirely. CWR is the congestion-window-
       reduced bit, rendered as "C" by scapy's TCP flags. It is nonzero in
       0.0034% of the TRUSTLab training rows, so hardcoding a zero would
       also be wrong.

    2. Flow timeout. The port ships EXPIRED_UPDATE = 240 s; CICFlowMeter v4
       uses 120 s. flow_session imported the constant by name, so the
       binding inside that module is what has to change -- editing
       cicflowmeter.constants after import would have no effect.
    """
    global _PATCHED
    if _PATCHED:
        return

    original = Flow.get_data

    def get_data(self, include_fields=None):
        data = original(self, include_fields=None)
        data["cwr_flag_count"] = FlagCount(self).count("CWR")
        if include_fields is not None:
            data = {k: v for k, v in data.items() if k in include_fields}
        return data

    Flow.get_data = get_data

    flow_session_module.EXPIRED_UPDATE = FLOW_TIMEOUT_SECONDS

    _PATCHED = True


# ============================================================
# SESSION
# ============================================================

class _ForenXAISession(FlowSession):
    """
    Flow accumulator, driven directly rather than through scapy.

    Two deviations from how the `cicflowmeter` package uses this class, both
    deliberate:

    1. It is never handed to scapy as a `session=`.  The package was written
       against scapy 2.5, whose session hook is `on_packet_received`; scapy
       2.7 renamed it to `process`.  Registered as a session under 2.7 the
       hook is never called, no packets arrive, and the run completes
       "successfully" with zero flows -- a silent wrong answer.  Feeding
       packets in ourselves removes the dependency on that hook name.

    2. FlowSession.__init__ is bypassed.  It builds its writer through a
       factory that opens the output path immediately, so calling it and
       then replacing the writer would leave two handles on one file.
    """

    def __init__(self, csv_path):
        self.flows = {}
        self.logger = get_logger(False)
        self.packets_count = 0
        self.fields = None
        self.output_writer = _V4Writer(csv_path)
        DefaultSession.__init__(self)

    def retained_packets(self):
        """Packets currently held across all open flows."""
        return sum(len(flow.packets) for flow in self.flows.values())

    def feed(self, pkt):
        self.on_packet_received(pkt)

        # Checked periodically rather than per packet: retained_packets()
        # walks every open flow, so calling it on each packet would itself
        # be the bottleneck.
        if self.packets_count % 50_000 != 0:
            return

        if len(self.flows) > MAX_OPEN_FLOWS:
            raise CaptureTooLarge(
                f"More than {MAX_OPEN_FLOWS:,} flows are open at once.\n\n"
                + _split_advice()
            )

        held = self.retained_packets()
        if held > MAX_RETAINED_PACKETS:
            raise CaptureTooLarge(
                f"{held:,} packets are being held in memory, over the "
                f"{MAX_RETAINED_PACKETS:,} limit.\n\n"
                "Every flow feature is computed from that flow's packets "
                "when the flow closes, so the packets cannot be released "
                "earlier. This capture is denser than this extractor can "
                "hold.\n\n"
                + _split_advice()
            )

    def finish(self):
        """Flush every flow still open at end of capture."""
        self.garbage_collect(None)
        self.output_writer.close()


def _split_advice():
    return (
        "Split the capture and analyse the parts separately. With "
        "Wireshark installed:\n\n"
        "    editcap -c 500000 capture.pcap part.pcap\n\n"
        "Installing CICFlowMeter v4 also removes this limit; it streams "
        "flows instead of holding them."
    )


# ============================================================
# ENTRY POINT
# ============================================================

def extract(pcap_path, output_csv, log_fn=None, progress_every=200_000):
    """
    Read a PCAP / PCAPNG and write a CICFlowMeter v4 shaped CSV.

    Returns the path written.

    Raises RuntimeError if the dependencies are missing, CaptureTooLarge if
    the capture exceeds a limit, ValueError if no flows came out.
    """

    if not AVAILABLE:
        raise RuntimeError(
            "The Python flow extractor is unavailable.\n\n"
            f"Import failed with: {IMPORT_ERROR}\n\n"
            "Install it with:\n"
            "    pip install cicflowmeter scapy"
        )

    if not os.path.isfile(pcap_path):
        raise FileNotFoundError(f"Capture does not exist:\n{pcap_path}")

    size = os.path.getsize(pcap_path)
    if size == 0:
        raise ValueError("The supplied capture is empty.")
    if size > MAX_PCAP_BYTES:
        raise CaptureTooLarge(
            f"Capture is {size / 1024**3:.1f} GiB, over the "
            f"{MAX_PCAP_BYTES / 1024**3:.0f} GiB limit. Split it first."
        )

    _apply_corrections()

    parent = os.path.dirname(os.path.abspath(output_csv))
    os.makedirs(parent, exist_ok=True)

    if log_fn:
        log_fn("[i] Flow engine: Python (scapy + cicflowmeter).", "info")
        log_fn(f"[i] Reading capture ({size / 1024**2:.1f} MB) ...", "info")

    session = _ForenXAISession(output_csv)
    read = 0
    skipped = 0

    try:
        # PcapReader streams one packet at a time, so a large capture does
        # not have to fit in memory. No BPF filter: compiling one needs a
        # native pcap driver, which is the dependency this fallback exists
        # to avoid. Non-IP traffic is dropped by the session itself.
        with PcapReader(pcap_path) as reader:
            for pkt in reader:
                read += 1
                try:
                    session.feed(pkt)
                except CaptureTooLarge:
                    raise
                except Exception:
                    # One malformed frame must not abandon the capture.
                    skipped += 1
                if log_fn and progress_every and read % progress_every == 0:
                    log_fn(f"[i] {read:,} packets read ...", "info")

        session.finish()
    finally:
        session.output_writer.close()

    if read == 0:
        raise ValueError(
            "The capture contained no packets, or could not be parsed as "
            "PCAP / PCAPNG."
        )

    rows = _count_rows(output_csv)
    if rows == 0:
        raise ValueError(
            f"Read {read:,} packets but extracted no flows.\n\n"
            "The file parsed, but it contained no TCP or UDP traffic over "
            "IP -- which is all this feature set describes."
        )

    if log_fn:
        log_fn(
            f"[+] Extracted {rows:,} flows from {read:,} packets.",
            "success",
        )
        if skipped:
            log_fn(
                f"[!] {skipped:,} packets could not be parsed and were "
                "skipped.",
                "warning",
            )

    return output_csv


def _count_rows(csv_path):
    with open(csv_path, "r", encoding="utf-8", newline="") as fh:
        return max(0, sum(1 for line in fh if line.strip()) - 1)


# ============================================================
# SELF CHECK
# ============================================================

def check_schema(required_features):
    """
    Compare what this extractor emits against the model's feature list.

    Returns (missing, extra) as sorted lists.  `missing` must be empty or
    the CSV cannot be scored.
    """
    produced = set(V4_NAMES.values())
    required = set(required_features)
    return sorted(required - produced), sorted(produced - required)
