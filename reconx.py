import os
import shutil
import hashlib
import logging
from datetime import datetime
from scapy.all import sniff, wrpcap, rdpcap, IP
import argparse
from typing import Optional, Dict

class ReconX:
    """
    ReconX: Simple digital forensics tool for evidence management, network capture, and reporting.
    """

    def __init__(self, case_directory: str, log_level: str = "INFO"):
        self.case_directory = os.path.abspath(case_directory)
        self.report_file = os.path.join(self.case_directory, "ReconX_Report.txt")
        self.evidence_data: Dict[str, Dict[str, str]] = {}
        self.setup_logging(log_level)

    def setup_logging(self, log_level: str):
        os.makedirs(self.case_directory, exist_ok=True)
        log_file = os.path.join(self.case_directory, "ReconX_Log.txt")
        logging.basicConfig(
            level=getattr(logging, log_level.upper(), logging.INFO),
            format="%(asctime)s [%(levelname)s]: %(message)s",
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(),
            ],
            force=True
        )

    def validate_directory(self, directory: str) -> str:
        if not os.path.exists(directory):
            os.makedirs(directory)
        return os.path.abspath(directory)

    def validate_file(self, file_path: str) -> str:
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File '{file_path}' does not exist.")
        return os.path.abspath(file_path)

    def capture_network_traffic(self, duration: int = 30, iface: Optional[str] = None):
        try:
            network_folder = self.validate_directory(os.path.join(self.case_directory, "Network_Traffic"))
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            capture_file_path = os.path.join(network_folder, f"Capture_{timestamp}.pcap")
            logging.info(f"Capturing network traffic for {duration} seconds...")
            packets = sniff(timeout=duration, store=True, iface=iface)
            wrpcap(capture_file_path, packets)
            logging.info(f"Network traffic captured and saved to: {capture_file_path}")
            self.analyze_network_traffic(capture_file_path)
        except Exception as e:
            logging.error(f"Error during network traffic capture: {e}")

    def analyze_network_traffic(self, capture_file: str):
        try:
            validated_capture_file = self.validate_file(capture_file)
            packets = rdpcap(validated_capture_file)
            ip_summary = []
            for packet in packets:
                if IP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    ip_summary.append((src_ip, dst_ip))
                    logging.debug(f"Packet: Source IP - {src_ip}, Destination IP - {dst_ip}")
            logging.info(f"Network traffic analysis completed. Analyzed {len(packets)} packets.")
            return ip_summary
        except Exception as e:
            logging.error(f"Error during network traffic analysis: {e}")

    def incident_response(self):
        try:
            incident_folder = self.validate_directory(os.path.join(self.case_directory, "Incident_Response"))
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            incident_report_path = os.path.join(incident_folder, f"Incident_Report_{timestamp}.txt")
            with open(incident_report_path, "w") as incident_report:
                incident_report.write(
                    "Incident Response Report\n========================\n\n"
                    f"Generated: {timestamp}\n"
                    "Actions taken:\n"
                    "- Isolated affected systems\n"
                    "- Blocked malicious IP addresses\n"
                )
            logging.info(f"Incident response report generated: {incident_report_path}")
        except Exception as e:
            logging.error(f"Error during incident response: {e}")

    def acquire_evidence(self, source_path: str):
        try:
            evidence_folder = self.validate_directory(os.path.join(self.case_directory, "Evidence"))
            destination_file_path = os.path.join(evidence_folder, os.path.basename(source_path))
            if not os.path.exists(destination_file_path):
                shutil.copy2(source_path, destination_file_path)
                logging.info(f"Evidence acquired from {source_path} to {destination_file_path}")
            else:
                logging.warning(f"Evidence file already exists at {destination_file_path}, skipping copy.")
            file_hash = self.hash_file(destination_file_path)
            if file_hash:
                logging.info(f"SHA256 hash: {file_hash}")
            return destination_file_path
        except Exception as e:
            logging.error(f"Error acquiring evidence: {e}")

    def hash_file(self, file_path: str) -> Optional[str]:
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logging.error(f"Error hashing file {file_path}: {e}")
            return None

    def analyze_evidence(self, keyword: str):
        try:
            evidence_path = os.path.join(self.case_directory, "Evidence")
            found = False
            for root, dirs, files in os.walk(evidence_path):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    file_hash = self.hash_file(file_path)
                    try:
                        with open(file_path, "r", errors="ignore") as file:
                            content = file.read()
                            if keyword.lower() in content.lower():
                                self.evidence_data[file_name] = {
                                    "Path": file_path,
                                    "Hash": file_hash,
                                }
                                found = True
                    except Exception:
                        continue  # Not all evidence will be textual
            if found:
                logging.info(f"Keyword '{keyword}' found in evidence.")
            else:
                logging.info(f"Keyword '{keyword}' not found in any evidence file.")
        except Exception as e:
            logging.error(f"Error analyzing evidence: {e}")

    def generate_report(self):
        try:
            with open(self.report_file, "w") as report:
                report.write("ReconX Report\n==============\n\n")
                if self.evidence_data:
                    report.write("Evidence Details:\n\n")
                    for file_name, details in self.evidence_data.items():
                        report.write(f"File: {file_name}\n")
                        report.write(f"Path: {details['Path']}\n")
                        report.write(f"SHA256 Hash: {details['Hash']}\n\n")
                else:
                    report.write("No evidence files found or keyword not present.\n")
            logging.info(f"Report generated: {self.report_file}")
        except Exception as e:
            logging.error(f"Error generating report: {e}")

def main():
    parser = argparse.ArgumentParser(description="ReconX CLI - Digital Forensics Tool")
    parser.add_argument("case_directory", help="Path to the case directory (will be created if missing)")
    parser.add_argument("--log-level", default="INFO", help="Logging level (DEBUG, INFO, WARNING, ERROR)")
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available subcommands")

    # Capture network
    parser_capture = subparsers.add_parser("capture", help="Capture network traffic")
    parser_capture.add_argument("--duration", type=int, default=60, help="Duration in seconds")
    parser_capture.add_argument("--iface", default=None, help="Network interface (default: all)")

    # Acquire evidence
    parser_acquire = subparsers.add_parser("acquire", help="Acquire evidence file")
    parser_acquire.add_argument("source_path", help="Path to the evidence file to acquire")

    # Analyze evidence
    parser_analyze = subparsers.add_parser("analyze", help="Analyze evidence for a keyword")
    parser_analyze.add_argument("keyword", help="Keyword to search in evidence files")

    # Incident response
    subparsers.add_parser("incident", help="Generate incident response report")

    # Generate report
    subparsers.add_parser("report", help="Generate summary report")

    args = parser.parse_args()
    reconx = ReconX(args.case_directory, log_level=args.log_level)

    try:
        if args.command == "capture":
            reconx.capture_network_traffic(duration=args.duration, iface=args.iface)
        elif args.command == "acquire":
            reconx.acquire_evidence(args.source_path)
        elif args.command == "analyze":
            reconx.analyze_evidence(args.keyword)
        elif args.command == "incident":
            reconx.incident_response()
        elif args.command == "report":
            reconx.generate_report()
        else:
            parser.print_help()
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
