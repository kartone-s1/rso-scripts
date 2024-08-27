# KAPE Forensic Collector Script

## Overview

This repository contains a PowerShell script designed to automate the download, extraction, and usage of the KAPE (Kroll Artifact Parser and Extractor) forensic tool. The script facilitates the collection and parsing of forensic artifacts from target systems and supports uploading the results to an S3 bucket or an SMB share.

## Features

- **Download KAPE Collector**: The script can automatically download the latest KAPE collector from a specified URL.
- **Write KAPE Collector**: Option to write the KAPE collector directly from a base64 encoded string to the specified path.
- **Run KAPE**: Executes KAPE to collect and parse artifacts based on provided targets and modules.
- **Upload to S3**: Automates the uploading of collected artifacts to an AWS S3 bucket.
- **Upload to SMB**: Supports uploading collected artifacts to a specified SMB share.
- **Dynamic Parameter Support**: Automatically recognizes available KAPE modules and targets for streamlined usage.

## Setup and Installation

### Prerequisites

- **PowerShell 5.1 or later**: Required to run the script.
- **AWS Tools for PowerShell**: Needed if uploading to an S3 bucket. The script will install it if not already present.
- **KAPE**: Ensure KAPE is accessible via the specified paths or provide a valid URL for download.

### Required Files

1. **aws_config.txt**: Contains the AWS credentials and S3 bucket details.
2. **smb_config.txt**: Contains the SMB share credentials and paths.

### File Structure

- **Modules/**: Directory containing KAPE modules (`*.mkape`).
- **Targets/**: Directory containing KAPE targets (`*.tkape`).
- **7z.exe**: The 7-Zip executable required for compressing large files.
- **kape.exe**: The KAPE executable.

### aws_config.txt Example

```txt
awsAccessKey=YOUR_AWS_ACCESS_KEY
awsSecretKey=YOUR_AWS_SECRET_KEY
bucketName=YOUR_S3_BUCKET_NAME
s3Key=YOUR_S3_OBJECT_KEY
region=YOUR_AWS_REGION
```

### smb_config.txt Example

```txt
username=YOUR_SMB_USERNAME
password=YOUR_SMB_PASSWORD
share=YOUR_SMB_SHARE_PATH
```

## Usage

### Basic Commands

- **Download KAPE Collector**:
    ```powershell
    Download-KAPECollector -URL "https://example.com/kape.zip" -OutputPath "C:\Path\To\KAPE"
    ```

- **Run KAPE Collector**:
    ```powershell
    Invoke-Kape -tsource C:\ -tdest C:\KAPE\Output -Target 'Triage-Windows' -Module 'SystemInfo'
    ```

- **Upload to S3**:
    ```powershell
    Upload-To-S3 -filename "C:\KAPE\Output\collector.zip"
    ```

- **Copy to SMB Share**:
    ```powershell
    Copy-ToSMBShare -SourceFilePath "C:\KAPE\Output\collector.zip" -DestinationSMBPath "\\server\share" -Username "user" -Password "pass"
    ```

### Script Parameters

- **`$tsource`**: The source directory for the target collection.
- **`$tdest`**: The destination directory for the collected artifacts.
- **`$UploadToS3`**: Uploads the collected artifacts to an S3 bucket.
- **`$UploadToSMB`**: Uploads the collected artifacts to an SMB share.
- **`$sleep`**: Introduces a delay with optional jitter before executing KAPE.

### Example Usage

```powershell
Invoke-Kape -tsource "C:\" -tdest "C:\KAPE\Output" -Target "Triage-Windows" -UploadToS3 -OutputPath "C:\KAPE\COLLECTOR\"
```

## Contributing

Feel free to submit issues or pull requests. Please ensure that all code is properly documented and tested before submission.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.
