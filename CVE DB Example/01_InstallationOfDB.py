# -*- coding: utf-8 -*-
"""
Created on Wed Apr 27 2020
Python 3.7.6
@author: WatchfulSleeper
"""
import mysql.connector
import os
from pathlib import Path
import datetime
import zipfile
import requests
import urllib.request
import json
from tqdm import tqdm

#default parameters
workdir = Path.cwd() #change to folder where you want have database.
startYear = 2002 #change start year if you don't want old vulnerabilities. Don't change to less than 2002.

#Fix global parameters. Don't change!!!
targetYear = int(datetime.datetime.today().strftime('%Y'))
jsonFileNameList = []

#create folders
if not Path.exists(workdir):
    Path.mkdir(workdir)
os.chdir(workdir)
if not Path.exists(workdir / 'Logs'):
    Path.mkdir(workdir / 'Logs')
if not Path.exists(workdir / 'Download'):
    Path.mkdir(workdir / 'Download')

# START logging logic
def logging(severity, Messange):
    directoryExist = Path.exists(workdir / 'Logs')
    severityString = 'UNKNOWN'
    currentDate = datetime.datetime.today().strftime ('%Y-%m-%d')
    currentTime = datetime.datetime.today().strftime('%Y-%m-%d %H:%M:%S,%f')
    if not directoryExist:
        Path.mkdir('Logs')
    logFileName = currentDate + '-daily-log.log'
    fileExist = Path.exists(workdir / 'Logs' / logFileName)
    if severity == 1:
        severityString = 'DEBUG'
    elif severity == 2:
        severityString = 'INFORMATION'
    elif severity == 3:
        severityString = 'ERROR'
    else:
        severityString = 'UNKNOWN'
    if fileExist:
        with open(workdir / 'Logs' / logFileName, 'a+', encoding="utf8") as log_file:
            log_file.write(currentTime + ':' + severityString + ': ' + Messange + '\n')
    else:
        with open(workdir / 'Logs' / logFileName, 'w', encoding="utf8") as log_file:
            log_file.write(currentTime + ':' + severityString + ': ' + Messange + '\n')
logging(2, 'Script has been start')
# END logging logic

# START create name of file from year and return names
def source_file_name_creator(year):
    yearStr = str(year)
    zipName = 'nvdcve-1.1-' + yearStr + '.json.zip'
    jsonFileName = 'nvdcve-1.1-' + yearStr + '.json'
    return zipName, jsonFileName
# END

# START unzip file
def unzip_file(zipFileToExtract):
    with zipfile.ZipFile(zipFileToExtract, 'r') as zipRef:
        zipRef.extractall()
    logging(2, 'Extracting ZIP: ' + zipFileToExtract)
# END

# START download file from nvd.nist.gov
def download_source_file_json(zipNameToDownload):
    baseDownloadURL = "https://nvd.nist.gov/feeds/json/cve/1.1/"
    try:
        targetDownloadURL = baseDownloadURL + zipNameToDownload
        webStatusCode = urllib.request.urlopen(targetDownloadURL).getcode()
        zipUrl = targetDownloadURL
        if webStatusCode == 200:     
            response = requests.get(zipUrl)
            with open(zipNameToDownload, 'wb') as zFile:
                zFile.write(response.content)
            logging(2, 'Downloading ZIP from URL ' + zipUrl + ' and saving it to file: ' + zipNameToDownload)
        else:
            logging(3, 'URL ' + zipUrl + ' is not available.')
    except:
        logging(3, 'Something is wrong with URL: ' + zipUrl)        
# END

# START create mysql queries and return
def mysql_queries(tableName, CVE_Name, Description, Affected_versions, CVSSv2_Score, CVSSv2_Severity, CVSSv2_Vector, CVSSv3_Score, CVSSv3_Severity, CVSSv3_Vector, Create_date, Modify_date, Product_name, Part_name, Vendor_name):
    if tableName == 'CVE':
        mySql_insert_query = """INSERT INTO CVE (CVE_Name, Description, Affected_versions, CVSSv2_Score, CVSSv2_Severity, CVSSv2_Vector, CVSSv3_Score, CVSSv3_Severity, CVSSv3_Vector, Create_date, Modify_date)
                               VALUES ('""" + CVE_Name + """', '""" + Description + """', '""" + Affected_versions + """', '""" + CVSSv2_Score + """', '""" + CVSSv2_Severity + """', '""" + CVSSv2_Vector + """', '""" + CVSSv3_Score + """', '""" + CVSSv3_Severity + """', '""" + CVSSv3_Vector + """', '""" + Create_date + """', '""" + Modify_date + """')
                               ON DUPLICATE KEY UPDATE Description = '""" + Description + """', Affected_versions = '""" + Affected_versions + """', CVSSv2_Score = '""" + CVSSv2_Score + """', CVSSv2_Severity = '""" + CVSSv2_Severity + """', CVSSv2_Vector = '""" + CVSSv2_Vector + """', CVSSv3_Score = '""" + CVSSv3_Score + """', CVSSv3_Severity = '""" + CVSSv3_Severity + """', CVSSv3_Vector = '""" + CVSSv3_Vector + """', Create_date = '""" + Create_date + """', Modify_date = '""" + Modify_date + """';"""
    elif tableName == 'CPE_LIST':
        mySql_insert_query = """INSERT INTO CPE_LIST (CVE_ID, PRODUCT_ID) SELECT (SELECT CVE_ID FROM CVE WHERE CVE_Name = '""" + CVE_Name + """'), (SELECT PRODUCT_ID FROM PRODUCT WHERE Product_name = '""" + Product_name + """') WHERE NOT EXISTS (SELECT * FROM CPE_LIST WHERE CVE_ID = (SELECT CVE_ID FROM CVE WHERE CVE_Name = '""" + CVE_Name + """') AND PRODUCT_ID = (SELECT PRODUCT_ID FROM PRODUCT WHERE Product_name = '""" + Product_name + """'));"""
    elif tableName == 'PRODUCT':
        mySql_insert_query = """INSERT IGNORE INTO PRODUCT (Product_name, PART_ID, VENDOR_ID) VALUES ('""" + Product_name + """', (SELECT PART_ID FROM PART WHERE Part_name='""" + Part_name + """'), (SELECT VENDOR_ID FROM VENDOR WHERE Vendor_name='""" + Vendor_name + """'));"""
    elif tableName == 'VENDOR':
        mySql_insert_query = """INSERT IGNORE INTO VENDOR (Vendor_name) VALUES ('""" + Vendor_name + """');"""
    else:
        print('error')
    return mySql_insert_query
# END

# START from downloaded json make data for mysql
def json_to_mysql(fileName):
    logging(2, 'Processing file: ' + str(fileName))
    print('Processing file: ' + str(fileName))
    count = 0
    curCount = 0
    mySql_insert_queryList = []
    mySql_insert_query = ''
    if fileName.is_file():
        with open(fileName, encoding="utf8") as json_file:
            data = json.load(json_file)
            for i in data['CVE_Items']:
                count += 1
            for i in data['CVE_Items']:
                CVE_Name = ''
                Description = ''
                Affected_versions = ''
                CVSSv2_Score = ''
                CVSSv2_Severity = ''
                CVSSv2_Vector = ''
                CVSSv3_Score = ''
                CVSSv3_Severity = ''
                CVSSv3_Vector = ''
                Create_date = ''
                Modify_date = ''
                Part_name = ''
                Vendor_name = ''
                Product_name = ''

                #CVE ID
                for j, value in i['cve']['CVE_data_meta'].items():
                    if j == 'ID':
                        CVE_Name = value
                        
                #description
                Description = i['cve']['description']['description_data'][0]['value']
                Description = Description.replace(';', 'semicolon').replace('à', 'a').replace('Ã', 'A').replace('Â', 'A').replace('≤', 'less or equal than').replace('ï¿½', '`').replace('\\', '(backslash)').replace('\'', '\\\'')
                
                #CPE
                Affected_versionsList = []
                for j in i['configurations']['nodes']:
                    if 'cpe_match' in j:
                        for k in j['cpe_match']:
                            if k['vulnerable'] == True:
                                cpe = k['cpe23Uri']
                                cpe = cpe.split(':')
                                part = cpe[2]
                                Part_name = ''
                                if part == 'a':
                                    Part_name = 'application'
                                elif part == 'o':
                                    Part_name = 'operating system'
                                elif part == 'h':
                                    Part_name = 'hardware'
                                Vendor_name = ''
                                Vendor_name = cpe[3]
                                Vendor_name = Vendor_name.replace('\\', '').replace("'", "`")
                                mySql_insert_query = mysql_queries('VENDOR', CVE_Name, Description, Affected_versions, CVSSv2_Score, CVSSv2_Severity, CVSSv2_Vector, CVSSv3_Score, CVSSv3_Severity, CVSSv3_Vector, Create_date, Modify_date, Product_name, Part_name, Vendor_name)
                                mySql_insert_queryList.append(mySql_insert_query)
                                Product_name = ''
                                Product_name = cpe[4]
                                Product_name = Product_name.replace('\\', '').replace("'", "`")
                                mySql_insert_query = mysql_queries('PRODUCT', CVE_Name, Description, Affected_versions, CVSSv2_Score, CVSSv2_Severity, CVSSv2_Vector, CVSSv3_Score, CVSSv3_Severity, CVSSv3_Vector, Create_date, Modify_date, Product_name, Part_name, Vendor_name)
                                mySql_insert_queryList.append(mySql_insert_query)
                                version,update,edition,language,swEdition,targetSw,targetHw,other = '*','*','*','*','*','*','*','*'
                                version = cpe[5]
                                update = cpe[6]
                                edition = cpe[7]
                                language = cpe[8]
                                swEdition = cpe[9]
                                targetSw = cpe[10]
                                targetHw = cpe[11]
                                other = cpe[12]
                                Affected_versionsList.append(Product_name.replace('_', ' ').capitalize())
                                Affected_versionsList.append(':')
                                versionWrite = False
                                if version != '*' and version != '-':
                                    Affected_versionsList.append(version)
                                    Affected_versionsList.append(',')
                                    versionWrite = True
                                if update != '*' and update != '-':
                                    Affected_versionsList.append(' ' + update)
                                    Affected_versionsList.append(',')
                                    versionWrite = True
                                if edition != '*' and edition != '-':
                                    Affected_versionsList.append(' ' + edition)
                                    Affected_versionsList.append(',')
                                    versionWrite = True
                                if language != '*' and language != '-':
                                    Affected_versionsList.append(' ' + language)
                                    Affected_versionsList.append(',')
                                    versionWrite = True
                                if swEdition != '*' and swEdition != '-':
                                    Affected_versionsList.append(' ' + swEdition)
                                    Affected_versionsList.append(',')
                                    versionWrite = True
                                if targetSw != '*' and targetSw != '-':
                                    Affected_versionsList.append(' ' + targetSw)
                                    Affected_versionsList.append(',')
                                    versionWrite = True
                                if targetHw != '*' and targetHw != '-':
                                    Affected_versionsList.append(' ' + targetHw)
                                    Affected_versionsList.append(',')
                                    versionWrite = True
                                if other != '*' and other != '-':
                                    Affected_versionsList.append(' ' + other)
                                    Affected_versionsList.append(',')
                                    versionWrite = True
                                if versionWrite:
                                    del Affected_versionsList[-1]
                                versionRange = False
                                if 'versionStartIncluding' in k:
                                    Affected_versionsList.append(' after ' + k['versionStartIncluding'] + ' including')
                                    Affected_versionsList.append(',')
                                    versionRange = True
                                if 'versionStartExcluding' in k:
                                    Affected_versionsList.append(' after ' + k['versionStartExcluding'])
                                    Affected_versionsList.append(',')
                                    versionRange = True
                                if 'versionEndExcluding' in k:
                                    Affected_versionsList.append(' before ' + k['versionEndExcluding'])
                                    Affected_versionsList.append(',')
                                    versionRange = True
                                if 'versionEndIncluding' in k:
                                    Affected_versionsList.append(' before ' + k['versionEndIncluding'] + ' including')
                                    Affected_versionsList.append(',')
                                    versionRange = True
                                if versionRange:
                                    del Affected_versionsList[-1]
                                if versionWrite == False and versionRange == False:
                                    del Affected_versionsList[-1]
                                Affected_versionsList.append(' / ')
                    if 'children' in j:
                        for o in j['children']:
                            for k in o['cpe_match']:
                                if k['vulnerable'] == True:
                                    cpe = k['cpe23Uri']
                                    cpe = cpe.split(':')
                                    part = cpe[2]
                                    Part_name = ''
                                    if part == 'a':
                                        Part_name = 'application'
                                    elif part == 'o':
                                        Part_name = 'operating system'
                                    elif part == 'h':
                                        Part_name = 'hardware'
                                    Vendor_name = ''
                                    Vendor_name = cpe[3]
                                    Vendor_name = Vendor_name.replace('\\', '').replace("'", "`")
                                    mySql_insert_query = mysql_queries('VENDOR', CVE_Name, Description, Affected_versions, CVSSv2_Score, CVSSv2_Severity, CVSSv2_Vector, CVSSv3_Score, CVSSv3_Severity, CVSSv3_Vector, Create_date, Modify_date, Product_name, Part_name, Vendor_name)
                                    mySql_insert_queryList.append(mySql_insert_query)
                                    Product_name = ''
                                    Product_name = cpe[4]
                                    Product_name = Product_name.replace('\\', '').replace("'", "`")
                                    mySql_insert_query = mysql_queries('PRODUCT', CVE_Name, Description, Affected_versions, CVSSv2_Score, CVSSv2_Severity, CVSSv2_Vector, CVSSv3_Score, CVSSv3_Severity, CVSSv3_Vector, Create_date, Modify_date, Product_name, Part_name, Vendor_name)
                                    mySql_insert_queryList.append(mySql_insert_query)
                                    version,update,edition,language,swEdition,targetSw,targetHw,other = '*','*','*','*','*','*','*','*'
                                    version = cpe[5]
                                    update = cpe[6]
                                    edition = cpe[7]
                                    language = cpe[8]
                                    swEdition = cpe[9]
                                    targetSw = cpe[10]
                                    targetHw = cpe[11]
                                    other = cpe[12]
                                    Affected_versionsList.append(Product_name.replace('_', ' ').capitalize())
                                    Affected_versionsList.append(': ')
                                    versionWrite = False
                                    if version != '*' and version != '-':
                                        Affected_versionsList.append(version)
                                        Affected_versionsList.append(',')
                                        versionWrite = True
                                    if update != '*' and update != '-':
                                        Affected_versionsList.append(' ' + update)
                                        Affected_versionsList.append(',')
                                        versionWrite = True
                                    if edition != '*' and edition != '-':
                                        Affected_versionsList.append(' ' + edition)
                                        Affected_versionsList.append(',')
                                        versionWrite = True
                                    if language != '*' and language != '-':
                                        Affected_versionsList.append(' ' + language)
                                        Affected_versionsList.append(',')
                                        versionWrite = True
                                    if swEdition != '*' and swEdition != '-':
                                        Affected_versionsList.append(' ' + swEdition)
                                        Affected_versionsList.append(',')
                                        versionWrite = True
                                    if targetSw != '*' and targetSw != '-':
                                        Affected_versionsList.append(' ' + targetSw)
                                        Affected_versionsList.append(',')
                                        versionWrite = True
                                    if targetHw != '*' and targetHw != '-':
                                        Affected_versionsList.append(' ' + targetHw)
                                        Affected_versionsList.append(',')
                                        versionWrite = True
                                    if other != '*' and other != '-':
                                        Affected_versionsList.append(' ' + other)
                                        Affected_versionsList.append(',')
                                        versionWrite = True
                                    if versionWrite:
                                        del Affected_versionsList[-1]
                                    versionRange = False
                                    if 'versionStartIncluding' in k:
                                        Affected_versionsList.append(' after ' + k['versionStartIncluding'] + ' including')
                                        Affected_versionsList.append(',')
                                        versionRange = True
                                    if 'versionStartExcluding' in k:
                                        Affected_versionsList.append(' after ' + k['versionStartExcluding'])
                                        Affected_versionsList.append(',')
                                        versionRange = True
                                    if 'versionEndExcluding' in k:
                                        Affected_versionsList.append(' before ' + k['versionEndExcluding'])
                                        Affected_versionsList.append(',')
                                        versionRange = True
                                    if 'versionEndIncluding' in k:
                                        Affected_versionsList.append(' before ' + k['versionEndIncluding'] + ' including')
                                        Affected_versionsList.append(',')
                                        versionRange = True
                                    if versionRange:
                                        del Affected_versionsList[-1]
                                    if versionWrite == False and versionRange == False:
                                        del Affected_versionsList[-1]
                                    Affected_versionsList.append(' / ')
                Affected_versions_prep = ''
                if Affected_versionsList:
                    del Affected_versionsList[-1]
                for l in Affected_versionsList:
                    Affected_versions_prep = Affected_versions_prep + '' + l
                Affected_versions = Affected_versions_prep
                
                #CVSS3
                CVSSv3_Score = '0'
                CVSSv3_Severity = 'NULL'
                CVSSv3_Vector = 'NULL'
                for j in i['impact']:
                    if 'baseMetricV3' in j:
                        CVSSv3_Score = i['impact']['baseMetricV3']['cvssV3']['baseScore']
                        CVSSv3_Score = str(CVSSv3_Score)
                        CVSSv3_Severity = i['impact']['baseMetricV3']['cvssV3']['baseSeverity']
                        CVSSv3_Vector = i['impact']['baseMetricV3']['cvssV3']['vectorString']
                
                #CVSS2
                CVSSv2_Score = '0'
                CVSSv2_Severity = 'NULL'
                CVSSv2_Vector = 'NULL'
                for j in i['impact']:
                    if 'baseMetricV2' in j:
                        CVSSv2_Score = i['impact']['baseMetricV2']['cvssV2']['baseScore']
                        CVSSv2_Score = str(CVSSv2_Score)
                        CVSSv2_Severity = i['impact']['baseMetricV2']['severity']
                        CVSSv2_Vector = i['impact']['baseMetricV2']['cvssV2']['vectorString']

                #CREATE DATE
                Create_date = ''
                Create_date = i['publishedDate']
                Create_date = Create_date.replace('T', ' ').replace('Z', '')

                #MODIFY DATE
                Modify_date = ''
                Modify_date = i['lastModifiedDate']
                Modify_date = Modify_date.replace('T', ' ').replace('Z', '')

                #Queries creation
                mySql_insert_query = mysql_queries('CVE', CVE_Name, Description, Affected_versions, CVSSv2_Score, CVSSv2_Severity, CVSSv2_Vector, CVSSv3_Score, CVSSv3_Severity, CVSSv3_Vector, Create_date, Modify_date, Product_name, Part_name, Vendor_name)
                mySql_insert_queryList.append(mySql_insert_query)
                mySql_insert_query = mysql_queries('CPE_LIST', CVE_Name, Description, Affected_versions, CVSSv2_Score, CVSSv2_Severity, CVSSv2_Vector, CVSSv3_Score, CVSSv3_Severity, CVSSv3_Vector, Create_date, Modify_date, Product_name, Part_name, Vendor_name)
                mySql_insert_queryList.append(mySql_insert_query)

        #Open connection to database
        try:
            connection = mysql.connector.connect(host='<IP address>',
                                                 database='<Name of database>',
                                                 user='<Username>',
                                                 password='<Password>')
            logging(2, 'Opening MySQL connection')
        except mysql.connector.Error as error:
            logging(3, 'Connection error: ' + str(error))
        
        #Proceed queries
        count = len(mySql_insert_queryList)                
        with tqdm(total=len(mySql_insert_queryList)) as progressBar:
            for mySql_insert_query in mySql_insert_queryList:
                curCount += 1
                if (curCount % 1000) == 0:
                    progressBar.update(1000)
                try:
                    cursor = connection.cursor()
                    cursor.execute(mySql_insert_query)
                    connection.commit()
                    cursor.close()        
                except mysql.connector.Error as error:
                    logging(3, 'Running query error is: ' + str(error) + ' query: ' + str(mySql_insert_query))

        #Close connection to database
        if (connection.is_connected()):
            connection.close()
            logging(2, 'Closing MySQL connection')
    else:
        logging(3, 'File to convert not exist')    
# END

# Download and unzip files to Download folder
while (targetYear >= startYear):
    zipName, jsonFileName = source_file_name_creator(startYear)
    os.chdir('Download')
    download_source_file_json(zipName)
    unzip_file(zipName)
    os.chdir(workdir)
    jsonFileNameList.append(jsonFileName)
    startYear += 1

# for each file in download folder extract data to mysql
for i in jsonFileNameList:
    jsonPathName = Path('Download/' + i)  
    json_to_mysql(jsonPathName)