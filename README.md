# Glasswall CDR & File Reputation Check

## Purpose

The script expects potentially malicious files to exist in a folder named, "input".

- Files are presented to the Glasswall CDR Platform REST API for processing. The output of the CDR step is sent to a folder named, "clean_cdr".

- In the event that files cannot be processed or is unsupported, the file is checked by the reputation service to determine if the file hash is known in any malware databases.

- Only if reputation is not malicious, will a copy of the file be placed into a folder named, "good_reputation_no_cdr".

- The reputation reports of files which could not be processed by the CDR step, will be recorded in a folder named, "reputation_report".

## Process Flow

![alt Process](Flowchart.png "Process")


## Setup

requirements.txt provides a list of python libraries that are needed

.env file should exist and contain the following key value pairs:

```
#env variables
TICLOUD_USERNAME = "<insert>"
TICLOUD_PASSWORD= "<insert>"
```

## FAQs

- Q: What is the Reputation service?
- A: The service discloses if a scanner has deemed the file to be malicious previously. The look-up uses a SHA256 hash to match adverse findings about the file in question. The file is not actively scanned for malware. The information that is returned relates only to its reputation, which is informed by previous assessments by third parties. 

- Q: If I rely on a Reputation Service is there is risk?
- A: A malicious file may enjoy a reputation that is not adverse for a period of time, which is usually because the security community has not yet determined the threat. There is a risk in relying solely on the reputation of a file. Ideally other countermeasures such as CDR or Sandboxing would be employed.

- Q: Who provides the Reputation Service
- A: ReversingLabs

- Q: Is the Reputation Service free for commercial use?
- A: No. A Licence must be purchased

- Q: Why does the CDR step sometimes fail?
- A: Occassionally, if the file is badly broken and does not sufficiently conform to a file specification, safe file reconstruction may be prevented. Whilst a document parser *may* be able to open a non-conforming file and represent its contents, a bad actor may be relying on a vulnerability in the parser or local environment to mount an attack. 