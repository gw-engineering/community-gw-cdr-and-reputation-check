'''Community script to support reputation lookup of files, and to convert TEXT and CSV files to
a supported file format.
'''
import json
import hashlib
import shutil
import os
import time
import pathlib
import logging
from fpdf import FPDF
from dotenv import load_dotenv
from ReversingLabs.SDK.ticloud import FileReputation
import requests
import pandas as pd
load_dotenv()

# .env file should contain the following pairs
# TICLOUD_USERNAME =
# TICLOUD_PASSWORD =

GW_CDR_PLATFORM_URL = "https://api.glasswall.com"
# Note the the 'GW_CDR_PLATFORM_URL' address is for demonstration purposes only
TICLOUD_HOST_URL = "https://ticloud01.reversinglabs.com"
INPUT_FILE_PATH = r"input"
OUTPUT_FILE_PATH = r"output"
CLEAN_CDR_OUTPUT_FILE_PATH = r"clean_cdr_files"
CLEAN_CDR_ANALYSIS_FILE_PATH = r"cdr_analysis_files"
REPUTATION_REPORT_PATH = r"reputation_reports_no_cdr"
BAD_REPUTATION_FOLDER = r"bad_reputation_files_no_cdr"
GOOD_REPUTATION_FOLDER = r"good_reputation_files_no_cdr"
COPIED_GOOD_REPUTATION_FILE_PATH = r"good_reputation_no_cdr"
TXT2PDF_OUTPUT_FILE_PATH = r"temp_txt2pdf_files_no_cdr"  # temp_txt_pdf_files
CSV2EXCEL_OUTPUT_FILE_PATH = r"temp_csv2excel_files_no_cdr"  # temp_csv_pdf_files
WAIT_429_ERROR = 0  # wait period (s)if 429 error received #Ensure rate limiting is observed
API_WAIT_PERIOD = 1  # Set API wait period(s) to avoid hitting rate throttling
CREATE_CDR_ANALYSIS_REPORTS = True
CREATE_CDR_FILES = True
CREATE_REPUTATION_REPORTS = True
CONVERT_TXT2PDF_AND_CDR = True
CONVERT_CSV2EXCEL_AND_CDR = True
REMOVE_TEMP_PDF_FOLDER = True
REMOVE_TEMP_EXCEL_FOLDER = True
CDR_REPORT_FORMAT = 'JSON'  # JSON or XML
LOGGING_LEVEL = logging.INFO

def cdr_platform_request(url, file):
    '''Send files to local or remote Glasswall CDR Platform'''
    logging.info('Managing connection to CDR Platform')
    try:
        response = requests.post(
            url=url,
            files={
                'file': (file),
                'format': (None, CDR_REPORT_FORMAT),
            },
            headers=
            {
                'accept': 'application/octet-stream',
                'User-agent': 'Glasswall_API_open_source_client'
            }
        )
        if response.status_code == 200:
            # logging.info(response)
            logging.info("Connected to CDR Platform")
            response.raise_for_status()
            time.sleep(API_WAIT_PERIOD)
            logging.info(print("API throttle - waiting", API_WAIT_PERIOD, "second(s)"))
        elif response.status_code == 429:
            logging.error("Need to throttle back - hitting 429 errors from CDR Platform")
            time.sleep(WAIT_429_ERROR)
        else:
            logging.error(response)
            logging.error("CDR Platform not able to process request")
    except requests.ConnectionError as error:
        logging.error(error)
    except requests.exceptions.Timeout as errt:
        logging.error(errt)
    except requests.exceptions.RequestException as err:
        logging.error(err)
    return response

def write_ticloud_reputation_report_to_file(f, report):
    '''Write the reputation of files which can't be CDR'd'''
    global REPUTATION_OUTCOME
    report_json = json.loads(report.text,)
    # f.write('Status: '+report_json['rl']['malware_presence']['status'])
    if report_json['rl']['malware_presence']['status'] == 'MALICIOUS':
        # f.write('\r'+'Threat Name: '+report_json['rl']['malware_presence']['threat_name'])

        REPUTATION_OUTCOME="BAD"
        logging.debug(print(REPUTATION_OUTCOME+ \
            " - Reputation service reports that the file is Malicious"))
    else:
        # f.write('\r'+'Threat Name: No detected threat')
        REPUTATION_OUTCOME="GOOD"
        logging.debug(print('Managing reputation lookup', REPUTATION_OUTCOME+ \
            " - Reputation service reports no threats"))
    f.write('\r'+'\r'+report.text)

# Check the reputation of files which can't be CDR'd
ticloud_file_reputation = FileReputation(
    host = TICLOUD_HOST_URL,
    # These values should be in a .env file
    username = os.environ.get('TICLOUD_USERNAME'),
    password = os.environ.get('TICLOUD_PASSWORD')
)

def remove_temp_txt_to_pdf_folder():
    '''Will remove the temporary pdf folder which has not been CDR'd'''
    if REMOVE_TEMP_PDF_FOLDER is True:
        removepath=TXT2PDF_OUTPUT_FILE_PATH
        if os.path.exists(removepath) and os.path.isdir(removepath):
            shutil.rmtree(removepath)

# Will remove the temporary excel folder which has not been CDR'd
def remove_temp_csv_to_excel_folder():
    '''Will remove the temporary excel folder which has not been CDR'd'''
    if REMOVE_TEMP_EXCEL_FOLDER is True:
        removepath=CSV2EXCEL_OUTPUT_FILE_PATH
        if os.path.exists(removepath) and os.path.isdir(removepath):
            shutil.rmtree(removepath)

def create_pdf(filepath, pdf_output_file_name, txt2pdf_copy_filepath):
    '''Create PDF from unsupported TXT file'''
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size = 12)
    with open(filepath, "r", encoding="utf8") as f:
        for x in f:
            pdf.cell(200, 10, txt = x, ln = 1, align = 'L')
    pdf.output(txt2pdf_copy_filepath+os.sep+pdf_output_file_name)


def txt_to_pdf():
    '''Write txt files which can't be CDR'd to a PDF in temporary location'''
    if CONVERT_TXT2PDF_AND_CDR is True:
        for root, _ , files in os.walk(INPUT_FILE_PATH, topdown=True, followlinks=False):
            for filename in files:
                filepath = root + os.sep + filename
                # Path which files with a good reputation and the .TXT \
                # file has been converted to PDF
                txt2pdf_copy_filepath = root.replace(INPUT_FILE_PATH, TXT2PDF_OUTPUT_FILE_PATH, 1)
                # Create the pdf output directory if it does not already exist
                os.makedirs(os.path.dirname(txt2pdf_copy_filepath+os.sep), exist_ok=True)
                file_extension = pathlib.Path(filename).suffix
                if file_extension == '.txt':
                    logging.info("Creating PDFs instead of TXT files\n")
                    logging.debug(filename)
                    filepath = root + os.sep + filename
                    pdf_output_file_name = filename + "~.pdf"
                    create_pdf(filepath, pdf_output_file_name, txt2pdf_copy_filepath)
                    logging.debug("+----------+")

def txt_to_pdf_with_cdr():
    '''Write PDF files which were converted from TXT and CDR them. \
        Place in desired clean destination tree'''
    for root, _ , files in os.walk(TXT2PDF_OUTPUT_FILE_PATH, topdown=True, followlinks=False):
        for filename in files:
            filepath = root + os.sep + filename
            logging.debug(filename)
            if CONVERT_TXT2PDF_AND_CDR is True:
                dynamic_source_file = TXT2PDF_OUTPUT_FILE_PATH
                dynamic_target_file = CLEAN_CDR_OUTPUT_FILE_PATH
                cdr_rebuild_files(filename, root, filepath, dynamic_source_file, \
                    dynamic_target_file)
    # Clean-up temp folder
    remove_temp_txt_to_pdf_folder()

def create_excel(filepath, csv2excel_copy_filepath, csv_excel_output_file_name):
    '''Create PDF from unsupported TXT file'''
    logging.debug(filepath)
    logging.debug(csv2excel_copy_filepath+os.sep+csv_excel_output_file_name)
    read_file = pd.read_csv (filepath)
    read_file.to_excel (csv2excel_copy_filepath+os.sep+csv_excel_output_file_name, \
        index = None, header=True)

def csv_to_excel():
    '''Convert CSV file to Excel format'''
    if CONVERT_CSV2EXCEL_AND_CDR is True:
        logging.info("csv2excel")
        for root, _ , files in os.walk(INPUT_FILE_PATH, topdown=True, followlinks=False):
            for filename in files:
                filepath = root + os.sep + filename
                # Path which files with a good reputation and the \
                # .CSV file has been converted to EXCEL
                csv2excel_copy_filepath = root.replace(INPUT_FILE_PATH, \
                    CSV2EXCEL_OUTPUT_FILE_PATH, 1)
                # Create the CSV output directory if it does not already exist
                os.makedirs(os.path.dirname(csv2excel_copy_filepath+os.sep), exist_ok=True)
                file_extension = pathlib.Path(filename).suffix
                if file_extension == '.csv':
                    logging.info("Creating Excel files instead of CSV files\n")
                    logging.debug(filename)
                    filepath = root + os.sep + filename
                    csv_excel_output_file_name = filename + "~.xlsx"
                    create_excel(filepath, csv2excel_copy_filepath, csv_excel_output_file_name)
                    logging.debug("+----------+")

def csv_to_excel_with_cdr():
    '''Write PDF files which were converted from TXT and CDR them. \
        Place in desired clean destination tree'''
    for root, _ , files in os.walk(CSV2EXCEL_OUTPUT_FILE_PATH, topdown=True, followlinks=False):
        for filename in files:
            filepath = root + os.sep + filename
            logging.debug(filename)
            if CONVERT_CSV2EXCEL_AND_CDR is True:
                dynamic_source_file = CSV2EXCEL_OUTPUT_FILE_PATH
                dynamic_target_file = CLEAN_CDR_OUTPUT_FILE_PATH
                cdr_rebuild_files(filename, root, filepath, dynamic_source_file, \
                    dynamic_target_file)
    remove_temp_csv_to_excel_folder()

def cdr_file_check_analyse():
    '''Perform CDR File Check and Analysis If Possible'''
    for root, _ , files in os.walk(INPUT_FILE_PATH, topdown=True, followlinks=False):
        logging.debug(INPUT_FILE_PATH)
        for filename in files:
            filepath = root + os.sep + filename
            # create filepath for files which are determined to have a \
            # good reputation, but can't be CDR'd
            copy_filepath = root.replace(INPUT_FILE_PATH, \
                (OUTPUT_FILE_PATH+os.sep+COPIED_GOOD_REPUTATION_FILE_PATH), 1) +os.sep + filename
            with open(filepath, "rb") as file_binary:
                logging.info("Checking file type with Glassall")
                filetype_detection_responce = cdr_platform_request\
                    (GW_CDR_PLATFORM_URL+"/api/filetypedetection/file", file_binary)
                file_bytes = file_binary.read()
                file_sha256_hash = hashlib.sha256(file_bytes).hexdigest()
                # print(file_sha256_hash)
                logging.debug(filename)
            filetype_detection_responce_json = json.loads(filetype_detection_responce.content)
            file_supported_outcome=(filetype_detection_responce_json.get("rebuildProcessingStatus"))

            if file_supported_outcome=="FILE_WAS_UN_PROCESSABLE" \
                or file_supported_outcome=="FILE_TYPE_UNSUPPORTED":
                filecheck=False
                logging.debug(print("Value:", file_supported_outcome))
                logging.debug(print("Could proceed with CDR Analysis?:", filecheck))
                logging.debug("+----------+")
            else:
                filecheck=True
                logging.debug(print("Value:", file_supported_outcome))
                logging.debug(print("Could proceed with CDR Analysis?:", filecheck))
                if CREATE_CDR_ANALYSIS_REPORTS is True:
                    logging.info("Performing CDR Analysis")
                else:
                    logging.info("CDR Analysis not enabled")

                # Perform CDR Analysis If Possible
                if CREATE_CDR_ANALYSIS_REPORTS is True and filecheck is True: \
                    # Won't perform CDR Analysis if check failed. Note sometimes this is possible.
                    with open(filepath, "rb") as file_binary:
                        logging.info("Creating CDR Analysis Report")

                        if CDR_REPORT_FORMAT == 'JSON':
                            cdr_report_ext='.json'
                        else:
                            cdr_report_ext='.xml'
                        new_cdr_analysis_filepath = root.replace(INPUT_FILE_PATH, \
                            (OUTPUT_FILE_PATH+os.sep+CLEAN_CDR_ANALYSIS_FILE_PATH), 1) \
                            +os.sep + filename +"~"+(file_sha256_hash)+cdr_report_ext
                        cdr_platform_analyse_response = cdr_platform_request\
                            (GW_CDR_PLATFORM_URL+"/api/analyse/file", file_binary)
                        logging.info("Requesting analysis report from Glassall CDR Platform")

                        if cdr_platform_analyse_response.status_code == 200 \
                            and cdr_platform_analyse_response.content:
                            # The CDR platform has analysed the file
                            # Create the output directory if it does not already exist
                            os.makedirs(os.path.dirname(new_cdr_analysis_filepath), exist_ok=True)
                            # Write the analysis file to the clean output file path
                            with open(new_cdr_analysis_filepath, "wb") as file_binary:
                                file_binary.write(cdr_platform_analyse_response.content)
                            logging.debug(print("GOOD - CDR Analysis Successful - wrote clean \
                            file to:", os.path.abspath(new_cdr_analysis_filepath)))
                        logging.debug(print(filename, INPUT_FILE_PATH, \
                            CLEAN_CDR_ANALYSIS_FILE_PATH))

                        if CREATE_CDR_FILES is True:
                            # Moving to CDR Rebuild step
                            dynamic_source_file = INPUT_FILE_PATH
                            dynamic_target_file = CLEAN_CDR_OUTPUT_FILE_PATH
                            cdr_rebuild_files(filename, root, filepath, \
                                dynamic_source_file, dynamic_target_file)
                    # Path which files with a good reputation, but no CDR go to - \
                    # caution these files may later be identified as malicious


            get_reputation_of_files (filecheck, filename, filepath, copy_filepath)

def cdr_rebuild_files(filename, root, filepath, dynamic_source_file, dynamic_target_file):
    '''Generic call to CDR Files'''
    # Path which pristine CDR files will go to
    # This calculation is off
    new_cdr_filepath = root.replace(dynamic_source_file, \
        (OUTPUT_FILE_PATH+os.sep+dynamic_target_file), 1) +os.sep + filename
    logging.info(new_cdr_filepath)
    with open(filepath, "rb") as file_binary:
        logging.info("Creating Rebuilt File")
        cdr_platform_rebuild_response = cdr_platform_request\
            (GW_CDR_PLATFORM_URL+"/api/rebuild/file", file_binary)
        logging.info("Requesting rebuild from Glassall CDR Platform")

        if cdr_platform_rebuild_response.status_code == 200 \
            and cdr_platform_rebuild_response.content:
            # The CDR platform has rebuilt and returned the file
            # Create the output directory if it does not already existtest
            os.makedirs(os.path.dirname(new_cdr_filepath), exist_ok=True)
            # Write the rebuilt file to the clean output file path
            with open(new_cdr_filepath, "wb") as file_binary:
                file_binary.write(cdr_platform_rebuild_response.content)
            logging.debug(print("GOOD - CDR Successful - wrote clean file to:", \
                os.path.abspath(new_cdr_filepath)))
            logging.debug("+--------------------+")

        else:
            # An error occurred, print the rebuild processing status
            cdr_platform_response_json = json.loads(cdr_platform_rebuild_response.content)
            logging.debug(print((cdr_platform_response_json.get("rebuildProcessingStatus"))))

def get_reputation_of_files (filecheck, filename, filepath, copy_filepath):
    '''Iterate through files which cannot be CDR'd and obtain reputation result'''
    if CREATE_REPUTATION_REPORTS is True and filecheck is False:
        logging.debug(print("CDR not possible for "+filename+\
            " - Checking the file's malware reputation"))
        with open(filepath,"rb") as file_binary:
            file_bytes = file_binary.read()
        file_sha256_hash = hashlib.sha256(file_bytes).hexdigest()
        ticloud_reputation_report = ticloud_file_reputation.get_file_reputation\
            (hash_input=file_sha256_hash, extended_results=True)

        # Create the reputation directory if it does not already exist
        os.makedirs(os.path.dirname(OUTPUT_FILE_PATH+os.sep+REPUTATION_REPORT_PATH+os.sep), \
            exist_ok=True)

        with open(OUTPUT_FILE_PATH+os.sep+REPUTATION_REPORT_PATH+os.sep+file_sha256_hash, "a", \
            encoding="utf8") as file:
            write_ticloud_reputation_report_to_file(file, ticloud_reputation_report)

        if REPUTATION_OUTCOME=="GOOD":
            # Create the good reputation directories if it does not already exist
            os.makedirs(os.path.dirname\
                (OUTPUT_FILE_PATH+os.sep+REPUTATION_REPORT_PATH+os.sep\
                    +GOOD_REPUTATION_FOLDER+os.sep), exist_ok=True)
            shutil.move(os.path.abspath(OUTPUT_FILE_PATH+os.sep\
                +REPUTATION_REPORT_PATH+os.sep+file_sha256_hash), \
                os.path.abspath(OUTPUT_FILE_PATH+os.sep+REPUTATION_REPORT_PATH+os.sep\
                    +GOOD_REPUTATION_FOLDER+os.sep+file_sha256_hash+" "+"~"+filename+"~"+".json"))
            logging.debug(print("Copying original "+filepath+" with good reputation to "\
                +copy_filepath))
            os.makedirs(os.path.dirname(copy_filepath), exist_ok=True)
            shutil.copyfile(os.path.abspath(filepath),os.path.abspath(copy_filepath))
            logging.debug("+--------------------+")

        else:
            # Create the bad reputation directories if it does not already exist
            os.makedirs(os.path.dirname(OUTPUT_FILE_PATH+os.sep+REPUTATION_REPORT_PATH+os.sep\
                +BAD_REPUTATION_FOLDER+os.sep), exist_ok=True)
            shutil.move(os.path.abspath(OUTPUT_FILE_PATH+os.sep+REPUTATION_REPORT_PATH\
                +os.sep+file_sha256_hash), \
                os.path.abspath(OUTPUT_FILE_PATH+os.sep+REPUTATION_REPORT_PATH+os.sep\
                    +BAD_REPUTATION_FOLDER+os.sep+file_sha256_hash+" "+"~"+filename+"~"+".json"))
            logging.debug(print("Keeping original "+filepath+" with bad reputation - no copy"))
            logging.debug("+--------------------+")

def main():
    '''Execute program'''
    logging.basicConfig(filename='gw_cdr_logging.log', filemode='w', level=LOGGING_LEVEL, \
        format='%(asctime)s %(message)s')
    logging.info(print('Starting Program'))
    # Iterate through the input file path locating all files

    if CONVERT_TXT2PDF_AND_CDR is True:
        logging.info("Converting TXT files to PDF")
        txt_to_pdf()
        txt_to_pdf_with_cdr()
    else:
        logging.info("No TXT to PDF step\n")
    if CONVERT_CSV2EXCEL_AND_CDR is True:
        logging.info("Converting CSV files to EXCEL")
        csv_to_excel()
        csv_to_excel_with_cdr()
    else:
        logging.info("No CSV to EXCEL step\n")

    cdr_file_check_analyse()
    logging.info(print('Finished Program'))

if __name__ == "__main__":
    main()
