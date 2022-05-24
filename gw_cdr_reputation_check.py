import os
import requests
import json
import hashlib
import shutil
from ReversingLabs.SDK.ticloud import FileReputation
from dotenv import load_dotenv
load_dotenv()

#.env file should contain the following pairs
#TICLOUD_USERNAME =  
#TICLOUD_PASSWORD = 

GW_CDR_PLATFORM_URL = "https://api.glasswall.com"
#Note the the 'GW_CDR_PLATFORM_URL' address is for demonstration purposes only

TICLOUD_HOST_URL = "https://ticloud01.reversinglabs.com"
INPUT_FILE_PATH = r"input"
OUTPUT_FILE_PATH = r"output"
CLEAN_CDR_OUTPUT_FILE_PATH = r"clean_cdr"
REPUTATION_REPORT_PATH = r"reputation_reports"
BAD_REPUTATION_FOLDER = r"bad_reputation_files"
GOOD_REPUTATION_FOLDER = r"good_reputation_files"
COPIED_GOOD_REPUTATION_FILE_PATH = r"good_reputation_no_cdr"

def cdr_platform_request(url, file):
    try:
        response = requests.post(
            url=url,
            files=[("file", file)],
            headers=
            {
                "accept": "application/octet-stream"
            }
        )
        if (response.status_code == 200):
            print(response)
            print("Connected to CDR Platform")
            response.raise_for_status()
        else:
            print(response)
            print("CDR Platform not able to process request")
            #Code here will only run if the request is successful
    except requests.ConnectionError as error:
        print(error)
    except requests.exceptions.ConnectionError as errc:
        print(errc)
    except requests.exceptions.Timeout as errt:
        print(errt)
    except requests.exceptions.RequestException as err:
        print(err)
    return response

def write_ticloud_reputation_report_to_file(f, report):
    global reputation_outcome
    report_json = json.loads(report.text,)
    #f.write('Status: '+report_json['rl']['malware_presence']['status'])
    if report_json['rl']['malware_presence']['status'] == 'MALICIOUS':
        #f.write('\r'+'Threat Name: '+report_json['rl']['malware_presence']['threat_name'])
        
        reputation_outcome="BAD"
        print(reputation_outcome+" - Reputation service reports that the file is Malicious\n")
    else:
        #f.write('\r'+'Threat Name: No detected threat')
        reputation_outcome="GOOD"
        print(reputation_outcome+" - Reputation service reports no threats")
    f.write('\r'+'\r'+report.text)

ticloud_file_reputation = FileReputation(
    host = TICLOUD_HOST_URL,
    username = os.environ.get('TICLOUD_USERNAME'),
    password = os.environ.get('TICLOUD_PASSWORD')
)
def main():
    print("\nStarting to process files \n")
    # Create the reputation directories if they don't already exist
    os.makedirs(os.path.dirname(OUTPUT_FILE_PATH+os.sep+REPUTATION_REPORT_PATH+os.sep), exist_ok=True)
    os.makedirs(os.path.dirname(OUTPUT_FILE_PATH+os.sep+REPUTATION_REPORT_PATH+os.sep+BAD_REPUTATION_FOLDER+os.sep), exist_ok=True)
    os.makedirs(os.path.dirname(OUTPUT_FILE_PATH+os.sep+REPUTATION_REPORT_PATH+os.sep+GOOD_REPUTATION_FOLDER+os.sep), exist_ok=True)

    # Iterate through the input file path locating all files
    for root, dirs, files in os.walk(INPUT_FILE_PATH, topdown=True, followlinks=False):
        for filename in files:
      
            filepath = root + os.sep + filename
            
            #path which pristine CDR files will go to
            new_cdr_filepath = root.replace(INPUT_FILE_PATH, (OUTPUT_FILE_PATH+os.sep+CLEAN_CDR_OUTPUT_FILE_PATH), 1) +os.sep + filename
 
            #path which files with a good reputation, but no CDR go to - caution these files may later be identified as malicious
            copy_filepath = root.replace(INPUT_FILE_PATH, (OUTPUT_FILE_PATH+os.sep+COPIED_GOOD_REPUTATION_FILE_PATH), 1) +os.sep + filename
            print("Checking file type with Glassall")
            with open(filepath, "rb") as file_binary:
                filetype_detection_responce = cdr_platform_request(GW_CDR_PLATFORM_URL+"/api/filetypedetection/file", file_binary)
                
            filetype_detection_responce_json = json.loads(filetype_detection_responce.content)
            print(filetype_detection_responce_json)

            if filetype_detection_responce_json.get("rebuildProcessingStatus") != "FILE_TYPE_UNSUPPORTED":
                with open(filepath, "rb") as file_binary:
                    cdr_platform_response = cdr_platform_request(GW_CDR_PLATFORM_URL+"/api/rebuild/file", file_binary)
                    print("Requesting rebuild from Glassall CDR Platform")
                    if cdr_platform_response.status_code == 200 and cdr_platform_response.content:
                        # The CDR platform has rebuilt and returned the file
                        # Create the output directory if it does not already exist
                        os.makedirs(os.path.dirname(new_cdr_filepath), exist_ok=True)
                        # Write the rebuilt file to the clean output file path
                        with open(new_cdr_filepath, "wb") as file_binary:
                            file_binary.write(cdr_platform_response.content)
                        print("GOOD - CDR Successful - wrote clean file to:", os.path.abspath(new_cdr_filepath+os.sep+filename)+"\n")

                    else:
                        # An error occurred, print the rebuild processing status
                        cdr_platform_response_json = json.loads(cdr_platform_response.content)
                        print((cdr_platform_response_json.get("rebuildProcessingStatus")))
            else:
                               
                print("CDR not possible for "+filename+" - Checking the file's malware reputation")
                with open(filepath,"rb") as file_binary:
                    file_bytes = file_binary.read()

                file_sha256_hash = hashlib.sha256(file_bytes).hexdigest();
                ticloud_reputation_report = ticloud_file_reputation.get_file_reputation(hash_input=file_sha256_hash, extended_results=True)

                               
                with open(OUTPUT_FILE_PATH+os.sep+REPUTATION_REPORT_PATH+os.sep+file_sha256_hash, "a") as file:
                    write_ticloud_reputation_report_to_file(file, ticloud_reputation_report)

                if reputation_outcome=="GOOD":
                        
                    shutil.move(os.path.abspath(OUTPUT_FILE_PATH+os.sep+REPUTATION_REPORT_PATH+os.sep+file_sha256_hash), os.path.abspath(OUTPUT_FILE_PATH+os.sep+REPUTATION_REPORT_PATH+os.sep+"good_reputation_files"+os.sep+file_sha256_hash+" "+"~"+filename+"~"+".json"))
                                      
                    print("Copying original "+filepath+" with good reputation to "+copy_filepath+"\n")
                    os.makedirs(os.path.dirname(copy_filepath), exist_ok=True)
                    shutil.copyfile(os.path.abspath(filepath),os.path.abspath(copy_filepath))
                else:
                    shutil.move(os.path.abspath(OUTPUT_FILE_PATH+os.sep+REPUTATION_REPORT_PATH+os.sep+file_sha256_hash), os.path.abspath(OUTPUT_FILE_PATH+os.sep+REPUTATION_REPORT_PATH+os.sep+"bad_reputation_files"+os.sep+file_sha256_hash+" "+"~"+filename+"~"+".json"))

    print("Ending\n") 
if __name__ == "__main__":
    main()