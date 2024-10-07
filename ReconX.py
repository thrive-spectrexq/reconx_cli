import os
import shutil
import hashlib
import logging
from datetime import datetime
from scapy.all import *


class ReconX:
    def __init__(self, case_directory):
        self.case_directory = case_directory
        self.report_file = "ReconX_Report.txt"
        self.evidence_data = {}

        # Configure the logging system here
        self.setup_logging()

    def setup_logging(self):
        log_file = os.path.join(self.case_directory, "ReconX_Log.txt")

        # Configure the root logger here
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s]: %(message)s",
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(),
            ],
        )

    def validate_directory(self, directory):
        if not os.path.exists(directory):
            raise ValueError(f"Directory '{directory}' does not exist.")
        return os.path.abspath(directory)

    def validate_file(self, file_path):
        if not os.path.isfile(file_path):
            raise ValueError(f"File '{file_path}' does not exist.")
        return os.path.abspath(file_path)

    def capture_network_traffic(self, duration=30):
        try:
            logging.info("Capturing network traffic...")

            network_folder = os.path.join(self.case_directory, "Network_Traffic")
            validated_network_folder = self.validate_directory(network_folder)

            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            capture_file_path = os.path.join(
                validated_network_folder, f"Capture_{timestamp}.pcap"
            )

            # Use Scapy's sniff function to capture network traffic for a specified duration
            packets = sniff(timeout=duration, store=True)

            # Save captured packets to a pcap file
            wrpcap(capture_file_path, packets)

            logging.info(f"Network traffic captured and saved to: {capture_file_path}")

            # Analyze captured packets
            self.analyze_network_traffic(capture_file_path)

        except Exception as e:
            logging.error(f"Error during network traffic capture: {e}")

    def analyze_network_traffic(self, capture_file):
        try:
            logging.info("Analyzing network traffic...")

            validated_capture_file = self.validate_file(capture_file)

            packets = rdpcap(validated_capture_file)

            # Perform packet analysis based on your requirements
            for packet in packets:
                # Example: Print source and destination IP addresses for each packet
                if IP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    logging.debug(
                        f"Packet: Source IP - {src_ip}, Destination IP - {dst_ip}"
                    )

            logging.info("Network traffic analysis completed.")

        except Exception as e:
            logging.error(f"Error during network traffic analysis: {e}")

    def incident_response(self):
        try:
            incident_folder = os.path.join(self.case_directory, "Incident_Response")
            if not os.path.exists(incident_folder):
                os.makedirs(incident_folder)

            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            incident_report_path = os.path.join(
                incident_folder, f"Incident_Report_{timestamp}.txt"
            )

            with open(incident_report_path, "w") as incident_report:
                incident_report.write(
                    "Incident Response Report\n========================\n\n"
                )

                # Add incident response actions here, e.g., isolate affected systems, block malicious IPs, etc.
                incident_report.write("Actions taken:\n")
                incident_report.write("- Isolated affected systems\n")
                incident_report.write("- Blocked malicious IP addresses\n")

            print(f"Incident response report generated: {incident_report_path}")

        except Exception as e:
            print(f"Error during incident response: {e}")

    def acquire_evidence(self, source_path):
        try:
            destination_path = os.path.join(self.case_directory, "Evidence")
            if not os.path.exists(destination_path):
                os.makedirs(destination_path)

            destination_file_path = os.path.join(
                destination_path, os.path.basename(source_path)
            )

            if not os.path.exists(destination_file_path):
                shutil.copy(source_path, destination_path)
                print(f"Evidence acquired from {source_path} to {destination_path}")
            else:
                print(
                    f"Evidence file already exists in {destination_path}. Skipping copying."
                )
        except Exception as e:
            print(f"Error acquiring evidence: {e}")

    def hash_file(self, file_path):
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            print(f"Error hashing file {file_path}: {e}")
            return None

    def analyze_evidence(self, keyword):
        try:
            evidence_path = os.path.join(self.case_directory, "Evidence")
            for root, dirs, files in os.walk(evidence_path):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    file_hash = self.hash_file(file_path)

                    with open(file_path, "r", errors="ignore") as file:
                        content = file.read()
                        if keyword.lower() in content.lower():
                            self.evidence_data[file_name] = {
                                "Path": file_path,
                                "Hash": file_hash,
                            }
        except Exception as e:
            print(f"Error analyzing evidence: {e}")

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
                    report.write("No evidence files found.\n")

            print(f"Report generated: {self.report_file}")
        except Exception as e:
            print(f"Error generating report: {e}")


if __name__ == "__main__":
    try:
        case_directory = input("Enter the case directory: ")
        source_evidence = input("Enter the source evidence path: ")
        keyword_to_search = input("Enter the keyword to search: ")

        reconx_tool = ReconX(case_directory)
        reconx_tool.capture_network_traffic(
            duration=60
        )  # Capture network traffic for 60 seconds
        reconx_tool.acquire_evidence(source_evidence)
        reconx_tool.analyze_evidence(keyword_to_search)
        reconx_tool.incident_response()
        reconx_tool.generate_report()

    except Exception as main_error:
        logging.error(f"An unexpected error occurred: {main_error}")  # Error logging..
