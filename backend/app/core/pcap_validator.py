import os
from dataclasses import dataclass
from typing import Optional

# PCAP Magic Byte Sequences
LIBPCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"   # Standard Libpcap (Little-Endian)
LIBPCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"   # Standard Libpcap (Big-Endian)
LIBPCAP_NSEC_LE = b"\x4d\x3c\xb2\xa1"    # Nanosecond Libpcap (Little-Endian)
LIBPCAP_NSEC_BE = b"\xa1\xb2\x3c\x4d"    # Nanosecond Libpcap (Big-Endian)

# PCAPNG Block Type & Byte-Order Magic
PCAPNG_SHB_MAGIC = b"\x0a\x0d\x0d\x0a"   # Section Header Block (4 bytes)
PCAPNG_BOM_LE = b"\x4d\x3c\x2b\x1a"      # Little-endian BOM
PCAPNG_BOM_BE = b"\x1a\x2b\x3c\x4d"      # Big-endian BOM

@dataclass
class PcapValidationResult:
    is_valid: bool
    format: str                     # "pcap", "pcapng", "unknown"
    file_size: int
    error_message: Optional[str] = None
    endianness: Optional[str] = None # "little", "big"
    nanosecond: bool = False

class PcapValidator:
    """Multi-layer forensic validator for .pcap and .pcapng files."""

    @staticmethod
    def validate_file(filepath: str) -> PcapValidationResult:
        # 1. Check file existence
        if not os.path.exists(filepath):
            return PcapValidationResult(
                is_valid=False,
                format="unknown",
                file_size=0,
                error_message="Specified capture file does not exist on disk.",
            )

        # 2. Check file size
        file_size = os.path.getsize(filepath)
        if file_size == 0:
            return PcapValidationResult(
                is_valid=False,
                format="unknown",
                file_size=0,
                error_message="The uploaded file is empty (0 bytes). Please upload a valid packet capture.",
            )

        from backend.app.config import settings
        if file_size > settings.MAX_UPLOAD_SIZE_BYTES:
            max_mb = settings.MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)
            curr_mb = file_size / (1024 * 1024)
            return PcapValidationResult(
                is_valid=False,
                format="unknown",
                file_size=file_size,
                error_message=f"File exceeds maximum allowed size ({curr_mb:.1f}MB > {max_mb}MB limit).",
            )

        if file_size < 24:
            return PcapValidationResult(
                is_valid=False,
                format="unknown",
                file_size=file_size,
                error_message=f"Corrupted capture: File size ({file_size} bytes) is smaller than the minimum 24-byte PCAP header.",
            )

        # 3. Inspect binary magic numbers
        try:
            with open(filepath, "rb") as f:
                header_bytes = f.read(32)
        except Exception as e:
            return PcapValidationResult(
                is_valid=False,
                format="unknown",
                file_size=file_size,
                error_message=f"File read error: Unable to open file ({str(e)}).",
            )

        if len(header_bytes) < 4:
            return PcapValidationResult(
                is_valid=False,
                format="unknown",
                file_size=file_size,
                error_message="File header is truncated.",
            )

        first_4 = header_bytes[:4]

        # Check Libpcap (classic or nanosecond)
        if first_4 == LIBPCAP_MAGIC_LE:
            return PcapValidator._verify_scapy_readable(filepath, "pcap", file_size, endianness="little", nanosecond=False)
        elif first_4 == LIBPCAP_MAGIC_BE:
            return PcapValidator._verify_scapy_readable(filepath, "pcap", file_size, endianness="big", nanosecond=False)
        elif first_4 == LIBPCAP_NSEC_LE:
            return PcapValidator._verify_scapy_readable(filepath, "pcap", file_size, endianness="little", nanosecond=True)
        elif first_4 == LIBPCAP_NSEC_BE:
            return PcapValidator._verify_scapy_readable(filepath, "pcap", file_size, endianness="big", nanosecond=True)

        # Check PCAPNG
        if first_4 == PCAPNG_SHB_MAGIC:
            if len(header_bytes) >= 12:
                bom = header_bytes[8:12]
                if bom in (PCAPNG_BOM_LE, PCAPNG_BOM_BE):
                    endianness = "little" if bom == PCAPNG_BOM_LE else "big"
                    return PcapValidator._verify_scapy_readable(filepath, "pcapng", file_size, endianness=endianness)
            return PcapValidationResult(
                is_valid=False,
                format="pcapng",
                file_size=file_size,
                error_message="Corrupted PCAPNG header: Section Header Block has invalid Byte-Order Magic.",
            )

        # Neither matched
        return PcapValidationResult(
            is_valid=False,
            format="unknown",
            file_size=file_size,
            error_message="Unsupported or corrupted format: Missing valid Libpcap (.pcap) or PCAPNG (.pcapng) magic signature.",
        )

    @staticmethod
    def _verify_scapy_readable(
        filepath: str,
        fmt: str,
        file_size: int,
        endianness: Optional[str] = None,
        nanosecond: bool = False,
    ) -> PcapValidationResult:
        """Attempt reading the capture using Scapy PcapReader to verify frames can be decoded safely."""
        from scapy.utils import PcapReader
        try:
            with PcapReader(filepath) as reader:
                try:
                    reader.read_packet()
                except EOFError:
                    pass  # Capture with valid header but 0 packets is allowed
                except Exception as e:
                    return PcapValidationResult(
                        is_valid=False,
                        format=fmt,
                        file_size=file_size,
                        error_message=f"Corrupted packet frames: {str(e)}",
                        endianness=endianness,
                        nanosecond=nanosecond,
                    )

            return PcapValidationResult(
                is_valid=True,
                format=fmt,
                file_size=file_size,
                error_message=None,
                endianness=endianness,
                nanosecond=nanosecond,
            )
        except Exception as e:
            return PcapValidationResult(
                is_valid=False,
                format=fmt,
                file_size=file_size,
                error_message=f"Corrupted PCAP capture: Unable to initialize packet reader ({str(e)}).",
                endianness=endianness,
                nanosecond=nanosecond,
            )
