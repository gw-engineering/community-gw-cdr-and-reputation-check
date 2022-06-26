# Glasswall CDR & File Reputation Check - Community Script

## Purpose

The script expects potentially malicious files to exist in a folder named, "input".

- Files are presented to the Glasswall CDR Platform REST API for processing. The output of the CDR step is sent to a folder named, "output/clean_cdr_files".

- If that files cannot be processed or is unsupported, the file is checked by the reputation service to determine if the file hash is known in any malware databases.

- Only if reputation is not malicious, will a copy of the file be placed into a folder named, "output/good_reputation_no_cdr".

- The reputation reports of files which could not be processed by the CDR step, will be recorded in a folder named, "output/reputation_reports_no_cdr". Within this folder, "good_reputation_files_no_cdr" and "bad_reputation_files_no_cdr" subfolders contain the applicable reports. No potentially malicious files are contained in the reporting folders. The output of the reports can be switched-off by changing the value of 'CREATE_REPUTATION_REPORTS' to 'False'. The format of these reports can be XML or JSON and this can be controlled by editing the value of 'CDR_REPORT_FORMAT'.

### Unsupported Files - Workaround

- The script will detect the true file type using the Glasswall CDR engine. Sometimes an attacker will use a different file extension to evade a filter. Glasswall will determine the true file type, looking at the structure of the data inside the file. Files with unstructured data, such as '.txt' or '.csv' files are not supported by Glasswall as they can be used by an attacker insert malicious software.

### TXT

- Converting the contents of a text file to a file format such as PDF is a usability option, as that file has an associated specification which facilitates the CDR process. However, if the original '.txt' file contained malicious code, that would still be visible in the PDF visual layer, (although not active). So the conversion would not eliminate all possible risk, but would mitigate the likelihood that a malicious file with a '.txt' extension could have it's file extension changed to a executable type. This script supports this approach and will convert the '.txt' file to a '.pdf' format, and will then *CDR* that converted '.pdf' file. The sanitised file is placed in the clean_cdr_files tree structure, if 'CONVERT_TXT2PDF_AND_CDR = True'. If this value is set to 'False', no Text file conversion will take place.

### CSV

- Converting the contents of a CSV file to a file format such as Excel is a usability option, as that file has an associated specification which facilitates the CDR process. However, if the original '.csv' file contained malicious code, that would still be visible in the Excel file visual layer, (although not active). So the conversion would not eliminate all possible risk, but would mitigate the likelihood that a malicious file with a '.csv' extension could have it's file extension changed to a executable type. This script supports this approach and will convert the '.csv' file to a '.elsx' format, and will then *CDR* that converted '.xlsx' file. The sanitised file is placed in the clean_cdr_files tree structure, if 'CONVERT_CSV2EXCEL_AND_CDR = True'. If this value is set to 'False', no CSV file conversion will take place.

- The script enables the (1) creation of files which have been CDR'd and (2) to produce accompanying analysis reports. Either step can be switched-off by setting 'CREATE_CDR_ANALYSIS_REPORTS' and  'CREATE_CDR_FILES' values to 'False'.

- Rate limiting is in place at the demonstration API url. The 'API_WAIT_PERIOD' value can be set to avoid hitting a rate limiting penalty

## Process Flow

![alt Process](images/Flowchart.drawio.png "Process")

## Setup

requirements.txt provides a list of python libraries that are needed

.env file should exist and contain the following key value pairs:

```text
#env variables
TICLOUD_USERNAME = "<insert>"
TICLOUD_PASSWORD = "<insert>"
```

## FAQs

- Q: What is the Reputation service?
- A: The service discloses if a scanner has deemed the file to be malicious previously. The look-up uses a SHA256 hash to match adverse findings about the file in question. The file is not actively scanned for malware. The information that is returned relates only to its reputation, which is informed by previous assessments by third parties.

- Q: If I rely on a Reputation Service is there is risk?
- A: A malicious file may enjoy a reputation that is not adverse for a period of time, which is usually because the security community has not yet determined the threat. There is a risk in relying solely on the reputation of a file. Ideally other countermeasures such as CDR or Sandboxing would be employed.

- Q: Who provides the Reputation Service
- A: ReversingLabs - `https://www.reversinglabs.com`

- Q: Is the Reputation Service free for commercial use?
- A: No. A Licence must be purchased

- Q: Why does the CDR step sometimes fail?
- A: Occasionally, if the file is badly broken and does not sufficiently conform to a file specification, safe file reconstruction may be prevented. Whilst a document parser *may* be able to open a non-conforming file and represent its contents, a bad actor may be relying on a vulnerability in the parser or local environment to mount an attack.

- Q: Why does this script convert a TXT file into a PDF, and only place the final PDF that has been CDR'd into the destination path?
- A: A text file can effectively represent any type of data, including software. The conversion to a PDF format, effectively enforces rules on how that data is structured and accessed by the parser. The step does not remove content from the visual layer, which might represent malicious code. The final step of performing CDR on the PDF file, ensures that any active content that might have made it through the conversion process is removed, with hyperlinks also being deactivated. Again the malicious code that by be printed to the visual layer, from the original TXT file may still be visible to read but it's no longer active, or accessible for execution, simply by changing the file extension.

- Q: Why does this script convert a CSV file into an EXCEL file, and only place the final .xlsx that has been CDR'd into the destination path?
- A: In a similar way to TXT files, malicious data can exist in the file. Whilst the data is structured in terms of comma-separated values, the values can be problematic. The RFC (`https://www.ietf.org/rfc/rfc4180.txt`) states,

Security considerations:

```text
CSV files contain passive text data that should not pose any risks. However, it is possible in theory that malicious binary data may be included in order to exploit potential buffer overruns in the program processing CSV data. Additionally, private data may be shared via this format (which of course applies to any text data)."
```

CSV-injection attacks have been demonstrated in the past, and therefore the CSV can pose a risk. This script converts the CSV to an EXCEL format, and the completes the CDR process to apply the industry specification for EXCEL.
