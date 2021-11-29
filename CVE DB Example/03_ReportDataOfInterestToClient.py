# -*- coding: utf-8 -*-
"""
Created on Fri Mar  6 10:25:48 2020
Python 3.7.6
@author: WatchfulSleeper
"""
import mysql.connector
import sys
from datetime import datetime, date, timedelta
from pathlib import Path
import smtplib
from os.path import basename
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

#default parameters
workdir = Path.cwd() #change to folder where you want have database.
emails = []
HTMLhead = """<!DOCTYPE html>

<html lang="en" xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css">
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/js/bootstrap.min.js"></script>
    <style>
        
        th, td {padding: 10px;
                vertical-align: top;
        }
        .summ {
            background-color: #f2f2f2;
            border-top: solid 1px;
        }
        .summ:hover {
            background-color: #e6e6e6;
        }
        .summ:hover a {
            color: #0066ff;
        }
        .collapse {margin-bottom: 30px;}
        .status {
            padding: 1px;
            border-radius: 2px;
        }
        .status[data-status="HIGH"] {
            background-color: red;
            color: white;
        }
        .status[data-status="MEDIUM"] {
            background-color: orange;
        }
        .status[data-status="CRITICAL"] {
            background-color: darkred;
            color: white;
        }
        .status[data-status="LOW"] {
            background-color: yellow;
        }
        .status[data-status="New!"] {
            background-color: white;
            color: red;
        }
        .status[data-status="Update"] {
            background-color: white;
            color: black;
        }
        .status[data-status="NULL"] {
            display: none;
        }
    </style>
    <title></title>
</head>
<body>
    <div class="container">
        <h2>New or updated vulnerabilities</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 220px"><h3>CVE Name</h3></th>
                    <th style="width: 400px"><h3>Basic information</h3></th>
                    <th style="width: 200px"><h3>CVSS Severity</h3></th>
                </tr>
            </thead>
        </table>"""
HTMLfoot = """</div>
</body>
</html>"""

# START of logging logic
def logging(severity, Messange):
    directoryExist = Path.exists(workdir / 'Logs')
    severityString = 'UNKNOWN'
    currentDate = datetime.today().strftime ('%Y-%m-%d')
    currentTime = datetime.today().strftime('%Y-%m-%d %H:%M:%S,%f')
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
# END
logging(2, 'Script has been start')

# START open connection to database
def openDatabase(databaseName):
    try:
        connection = mysql.connector.connect(host='<IP address>',
                                                 database=databaseName,
                                                 user='<Username>',
                                                 password='<Password>')
        logging(2, 'Opening MySQL connection to ' + databaseName + ' database')
    except mysql.connector.Error as error:
        logging(3, 'Connection error: ' + str(error))
        sys.exit(2) 
    return(connection)
# END

# START close connection to database
def closeDatabase(connection):
    if (connection.is_connected()):
        connection.close()
        logging(2, 'Closing MySQL connection')
# END

# START extract data from order DB and return
def extractDataFromOrderDB():
    connection = openDatabase('<Name of Orders DB>')
    result = []
    results = []
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM `order`")
        result = cursor.fetchall()
        results.append(result)
        cursor.close()  
        logging(2, 'Fetching data from cve-order-db database.')
    except mysql.connector.Error as error:
        print('query error' + str(error))
        logging(3, 'Running query error is: ' + str(error) + ' query: SELECT * FROM `order`')
    closeDatabase(connection)
    return(result)
# END

# START send email   
def sendEmail(email, currentToSendFile):
    succeedSend = False
    try:
        user = '<Domain Username>'
        password = '<Password>'

        address_book = email
        msg = MIMEMultipart()    
        sender = '<Sender email address>'
        subject = "<Subject>"
        body = "<Email body>"

        msg['From'] = sender
        msg['To'] = address_book
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        f = currentToSendFile
        with open(workdir / 'Orders' / address_book / currentToSendFile, 'rb') as file:
            part = MIMEApplication(file.read(), Name=basename(f))
        # After the file is closed
        part['Content-Disposition'] = 'attachment; filename="%s"' % basename(f)
        msg.attach(part)

        text=msg.as_string()
        # Send the message via our SMTP server
        s = smtplib.SMTP('<Email server IP address>', '<PORT>')
        s.login(user, password)
        s.sendmail(sender,address_book, text)
        s.quit()
        logging(2, 'Email send to address ' + address_book + '!')
        succeedSend = True
    except:
        logging(3, 'Email not send to address ' + address_book + '!')
        succeedSend = False
    return(succeedSend)
# END

# START create files with first line
def fileCreator(fileName,email):
    if '.HTML' in fileName:
        fileType = 'HTML'
    elif '.csv' in fileName:
        fileType = 'CSV'
    else:
        fileType = 'Other'
    directoryExist = Path.exists(workdir / 'Orders' / email)
    if not directoryExist:
        logging(2, 'Creating folder ' + email + '!')
        Path.mkdir(workdir / 'Orders' / email)
    fileExist = Path.exists(workdir / 'Orders' / email / fileName)
    if not fileExist:
        logging(2, 'Creating file ' + fileName + '!')
        if fileType == 'CSV':
            with open(workdir / 'Orders' / email / fileName, 'a+', encoding="utf8") as file:
                firstLineList = ['CVE Name', 'Description', 'Affected_versions', 'Part', 'Vendor', 'Product', 'CVSSv3 Score', 'CVSSv3 Severity', 'CVSSv3 vector', 'CVSSv2 Score', 'CVSSv2 Severity', 'CVSSv2 vector', 'Published date', 'Last modify date']
                for l in firstLineList:
                    file.write(l + ';')
                file.write('\n')
        if fileType == 'HTML':
            with open(workdir / 'Orders' / email / currentToSendFileHTML, 'a+', encoding="utf8") as file:
                file.write(HTMLhead)
# END

#create Orders folder
directoryExist = Path.exists(workdir / 'Orders')
if not directoryExist:
    logging(2, 'Creating folder Orders!')
    Path.mkdir(workdir / 'Orders')

#load orders data
orders = extractDataFromOrderDB()

#open CVE DB and extract data of interest
connection = openDatabase('<DB name>')
for order in orders:
    product_id = order[2]
    email = order[4]
    logging(2, 'Processing data with product_id:' + str(product_id) + ' and email address ' + email +'.')
    allSendDataFile = email + '.csv'
    fileCreator(allSendDataFile,email)
    currentToSendFile = str(date.today().strftime('%Y-%m-%d')) + '-zranitelnosti.csv'
    fileCreator(currentToSendFile,email)
    # create HTML file
    currentToSendFileHTML = str(date.today().strftime('%Y-%m-%d')) + '-zranitelnosti.HTML'
    fileCreator(currentToSendFileHTML,email)
    semFile = email + '.sem'
    fileExist = Path.exists(workdir / 'Orders' / email / semFile)
    if fileExist:
        startDate = date.today() - timedelta(days=1)
    else:
        startDate = date.today() - timedelta(days=20000)
        logging(2, 'File ' + semFile + ' not found. Will be send all vulnerabilities ever.')
    startDate = startDate.strftime('%Y-%m-%d')
    mySql_insert_query = """SELECT CVE.CVE_Name,CVE.Description,CVE.Affected_versions,PART.Part_name,VENDOR.Vendor_name,PRODUCT.Product_name,CVE.CVSSv3_Score,CVE.CVSSv3_Severity,CVE.CVSSv3_Vector,CVE.CVSSv2_Score,CVE.CVSSv2_Severity,CVE.CVSSv2_Vector,CVE.Create_date,CVE.Modify_date FROM CVE INNER JOIN CPE_LIST ON CVE.CVE_ID = CPE_LIST.CVE_ID INNER JOIN PRODUCT ON PRODUCT.PRODUCT_ID = CPE_LIST.PRODUCT_ID INNER JOIN PART ON PART.PART_ID = PRODUCT.PART_ID INNER JOIN VENDOR ON VENDOR.VENDOR_ID = PRODUCT.VENDOR_ID WHERE PRODUCT.product_id = '""" + str(product_id) + """' AND CVE.Modify_date >= '""" + startDate + """';"""
    result = []
    try:
        cursor = connection.cursor()
        cursor.execute(mySql_insert_query)
        result = cursor.fetchall()
        cursor.close()
        logging(2, 'Fetching data for product_id: ' + str(product_id))
    except mysql.connector.Error as error:
        print('query error' + str(error))
        logging(3, 'Running query error is: ' + str(error) + ' query: ' + mySql_insert_query)
    if result:
        emails.append(email)
        with open(workdir / 'Orders' / email / allSendDataFile, 'a+', encoding="utf8") as file:
            for lineOfResult in result:
                loopCount = 0
                for data in lineOfResult:
                    loopCount += 1
                    if loopCount == 7 or loopCount == 10:
                        data = str(data).replace('.', ',')
                    if len(str(data)) > 30000:
                        data = 'Too long.'
                    file.write(str(data) + ';')
                file.write("\n")
        with open(workdir / 'Orders' / email / currentToSendFile, 'a+', encoding="utf8") as file:
            for lineOfResult in result:
                loopCount = 0
                for data in lineOfResult:
                    loopCount += 1
                    if loopCount == 7 or loopCount == 10:
                        data = str(data).replace('.', ',')
                    if len(str(data)) > 30000:
                        data = 'Too long.'
                    file.write(str(data) + ';')
                file.write("\n")
        # ADD HTML CREATION
        with open(workdir / 'Orders' / email / currentToSendFileHTML, 'a+', encoding="utf8") as file:
            for lineOfResult in result:
                loopCount = 0
                for data in lineOfResult:
                    loopCount += 1
                    if loopCount == 7 or loopCount == 10:
                        data = str(data).replace('.', ',')
                    if loopCount == 1:
                        CVE_Name = str(data)
                    if loopCount == 2:
                        Description = str(data)
                    if loopCount == 3:
                        Affected_versions = str(data)
                        Affected_versions = Affected_versions.replace(' / ', '<br>')
                    if loopCount == 4:
                        Part_name = str(data).capitalize()
                    if loopCount == 5:
                        Vendor_name = str(data).capitalize()
                    if loopCount == 6:
                        Product_name = str(data).capitalize()
                        Product_name = Product_name.replace('_', ' ')
                    if loopCount == 7:
                        CVSSv3_Score = str(data)
                    if loopCount == 8:
                        CVSSv3_Severity = str(data)
                    if loopCount == 9:
                        CVSSv3_Vector = str(data)
                    if loopCount == 10:
                        CVSSv2_Score = str(data)
                    if loopCount == 11:
                        CVSSv2_Severity = str(data)
                    if loopCount == 12:
                        CVSSv2_Vector = str(data)
                    if loopCount == 13:
                        Create_date = str(data)
                        x = Create_date.split(' ', 1)
                        today = date.today().strftime('%Y-%m-%d')
                        yesterday = date.today() - timedelta(days=1)
                        yesterday = yesterday.strftime('%Y-%m-%d')
                        if x[0] == str(today):
                            vulStatus = 'New!'
                        elif x[0] == str(yesterday):
                            vulStatus = 'New!'
                        else:
                            vulStatus = 'Update'
                    if loopCount == 14:
                        Modify_date = str(data)
                file.write("""
        <table class="summ" data-target='#""" + CVE_Name +"""' data-toggle="collapse">
            <tbody>
                <tr>
                    <td style="width: 220px"><a href="https://nvd.nist.gov/vuln/detail/""" + CVE_Name +"""" title="nvd.nist.gov" target="_blank"><strong>""" + CVE_Name +"""</strong></a></td>
                    <td style="width: 400px">
                        <div><strong>Product:</strong> """ + Product_name + """</div>
                        <div><strong>Published date:</strong> """ + Create_date + """</div>
                        <div><strong>Last modify date:</strong> """ + Modify_date + """</div>
                    </td>
                    <td style="width: 200px">
                        <div><strong>V3.1:</strong> <span class="status" data-status='""" + CVSSv3_Severity + """'>""" + CVSSv3_Score + """ """ + CVSSv3_Severity + """</span></div>
                        <div><strong>V2.0:</strong> <span class="status" data-status='""" + CVSSv2_Severity + """'>""" + CVSSv2_Score + """ """ + CVSSv2_Severity + """</span></div>
                    </td>
                    <td style="width: 100px; height: 100px; display: grid; justify-content: center; align-content: center;" class="status" data-status='""" + vulStatus + """'>
                        <div><strong>""" + vulStatus + """</strong></div>
                    </td>
                </tr>
            </tbody>
        </table>
        <div id='""" + CVE_Name +"""' class="collapse">
            <h3>Detail information</h3>
            <table>
                <tbody>
                    <tr>
                        <th>Description</th>
                        <td style="width: 600px">""" + Description + """</td>
                    </tr>
                    <tr>
                        <th>Product</th>
                        <td>""" + Product_name + """</td>
                    </tr>
                    <tr>
                        <th>Part</th>
                        <td>""" + Part_name + """</td>
                    </tr>
                    <tr>
                        <th>Vendor</th>
                        <td>""" + Vendor_name + """</td>
                    </tr>
                    <tr>
                        <th>Affected versions</th>
                        <td style="width: 150px">""" + Affected_versions + """</td>
                    </tr>
                </tbody>
            </table>
            <h3>CVSS information</h3>
            <table>
                <thead>
                    <tr>
                        <th>CVSSv3 Score</th>
                        <th>CVSSv3 Severity</th>
                        <th>CVSSv3 Vector</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>""" + CVSSv3_Score + """</td>
                        <td>""" + CVSSv3_Severity + """</td>
                        <td>""" + CVSSv3_Vector + """</td>
                    </tr>
                </tbody>
        
                <thead>
                    <tr>
                        <th>CVSSv2 Score</th>
                        <th>CVSSv2 Severity</th>
                        <th>CVSSv2 Vector</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>""" + CVSSv2_Score + """</td>
                        <td>""" + CVSSv2_Severity + """</td>
                        <td>""" + CVSSv2_Vector + """</td>
                    </tr>
                </tbody>
            </table>
        </div>
        """)
        # END OF HTML CREATION
    else:
        logging(2, 'No data for product_id ' + str(product_id) + '. Skipping.')
with open(workdir / 'Orders' / email / currentToSendFileHTML, 'a+', encoding="utf8") as file:
       file.write(HTMLfoot)
closeDatabase(connection)
# End of extration

# Send email to klients
emails = list(set(emails))
for emailAddress in emails:
    semFile = emailAddress + '.sem' # Semafor file (remove if klient want send all vulnerabilities
    if sendEmail(emailAddress, currentToSendFileHTML):
        with open(workdir / 'Orders' / emailAddress / semFile, 'w', encoding="utf8") as sem_File:
            sem_File.write('Email send! \n')