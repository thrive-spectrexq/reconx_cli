# ReconX-Simple_Digital_Forensics_CLI_Tool
# ReconX

ReconX is a simple python digital forensics tool designed for capturing and analyzing network traffic, acquiring and analyzing evidence, performing incident response, and generating comprehensive reports.

## Features

- **Network Traffic Capture:** Capture network traffic using Scapy, allowing for flexible and customizable packet analysis.

- **Evidence Acquisition:** Easily acquire evidence from specified sources and organize it within the case directory.

- **Evidence Analysis:** Conduct keyword-based analysis on acquired evidence to identify relevant information.

- **Incident Response:** Perform incident response actions and generate incident response reports.

- **Reporting:** Generate detailed reports summarizing captured network traffic, evidence details, and incident response actions.

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/thrive-spectrexq/ReconX.git
    cd ReconX
    ```

2. Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

3. Run the script:

    ```bash
    python ReconX.py
    ```

## Usage

1. **Capture Network Traffic:**
    ```bash
    Enter the case directory: Case123
    Enter the source evidence path: C:\path\to\evidence.txt
    Enter the keyword to search: suspicious_keyword
    ```

2. **Acquire Evidence:**
    - Source evidence is copied to the `Case123/Evidence` directory.

3. **Analyze Evidence:**
    - Keyword-based analysis is performed on the acquired evidence.

4. **Incident Response:**
    - Incident response actions are taken, and a report is generated.

5. **Generate Report:**
    - A detailed report is generated in `ReconX_Report.txt`.

## Contributing

Contributions are welcome! If you have suggestions, feature requests, or bug reports, please [open an issue](https://github.com/thrive-spectre/ReconX-Simple_Digital_Forensics_CLI_Tool/issues) or [submit a pull request](https://github.com/thrive-spectre/ReconX-Simple_Digital_Forensics_CLI_Tool/pulls).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
