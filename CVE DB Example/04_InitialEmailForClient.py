# -*- coding: utf-8 -*-
"""
Created on Fri Mar  6 10:25:48 2020
Python 3.7.6
@author: WatchfulSleeper
"""
import mysql.connector
import sys
from datetime import datetime
from pathlib import Path
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
#default parameters
workdir = Path.cwd() #change to folder where you want have database.

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
def sendEmail(email):
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

# If orders DB changed, send initial email to new klients with info
orders = extractDataFromOrderDB()
directoryExist = Path.exists(workdir / 'Orders')
if not directoryExist:
    logging(2, 'Creating folder Orders!')
    Path.mkdir(workdir / 'Orders')
for order in orders:
    email = order[4]
    emails = []
    fileExist = Path.exists(workdir / 'Orders' / 'FirstEmails.csv')
    if not fileExist:
        logging(2, 'Creating file FirstEmails.csv!')
        with open(workdir / 'Orders' / 'FirstEmails.csv', 'a+', encoding="utf8") as file:
            file.write('')
    with open(workdir / 'Orders' / 'FirstEmails.csv', 'r', encoding="utf8") as file:
        for line in file:
            currentLine = line[:-1]
            emails.append(currentLine)
    if not email in emails:
        if sendEmail(email):
            with open(workdir / 'Orders' / 'FirstEmails.csv', 'a+', encoding="utf8") as file:
                file.write(email + '\n')