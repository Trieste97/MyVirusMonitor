#Import modules
import json, time, requests, os
import mysql.connector, hashlib

from datetime import datetime, timedelta
from queue import Queue
#End imports

#################################################################################
#                                                                               #
#                            BEGIN UTILITY FUNCTIONS                            #
#                                                                               #
#################################################################################


#Error handling and reporting funcion
def report_error(error):
    log_file = open("error_log", "a")
    current_time = datetime.now()
    log_file.write(current_time.strftime("%d/%m/%Y %H:%M:%S") + "\n")
    log_file.write("Some problem happened scanning file\n" + error +"\n")
    log_file.close()


#Initial scan of file found in directory (uploaded by user)
def scan(filename):
    print("Scanning file " + filename)
    file_id = ""
    response = None

    with open("../FlaskApp/tmp_files/" + filename, "rb") as file:
        headers = {'x-apikey': api_key}
        files = {'file': (filename, file)}
        response = requests.post(post_scan_url, files=files, headers=headers)
        file_id = hashlib.sha256(file).hexdigest()

    if response != None and response.status_code == 200:
        insert(resource_id, filename)
        print("Scan succesfull")
    elif response != None:
        print("Some problem happened\n" + "Status code: " + response.status_code)
    else:
        print("Some problem happened\n")


    print("Going to sleep for 15 seconds")
    time.sleep(16)


#Inserting new file in DB and put in queue for update the report
def insert(resource_id_, file_name_):
    print("Inserting file")
    query = ("INSERT INTO File(name,resource_id,next_scan) VALUES(%s,%s,%s)")
    nextscan_ = datetime.now() + timedelta(hours=20)

    try:
        cursor.execute(query, (file_name_,resource_id_,nextscan_,))
        db_connection.commit()
        print("File successfully inserted")
        newfile_id = cursor.lastrowid
        queue_toscan.put((1, str(newfile_id)))
        print("File successfully queued for update")

    except mysql.connector.IntegrityError:
        print("File already registered")


#Submitting request for the re-analysys of the file
def rescan(id_):
    print("Re-scanning file")
    query = ("SELECT resource_id FROM File WHERE id = %s")
    cursor.execute(query, (id_,))
    resource_ = cursor.fetchone()[0]

    print("Submitting resource to VirusTotal")
    headers = {'x-apikey': api_key}
    url = post_rescan_url.replace("{id}", resource_)
    response = requests.post(url, headers=headers)
    print("Received response")		

    if response.status_code == 200:
        print("Resource submitted successfully")
        nextscan_ = datetime.now() + timedelta(hours=20)
        query = ("UPDATE File SET next_scan = %s WHERE id = %s")
        cursor.execute(query, (nextscan_,id_,))
        db_connection.commit()
        queue_toscan.put((1,id_))
    else:
        print("Couldn't submit resource")
        nextscan_ = datetime.now() + timedelta(hours=1)
        query = ("UPDATE File SET next_scan = %s WHERE id = %s")
        cursor.execute(query, (nextscan_,id_,))
        db_connection.commit()


#Updating info in DB with the response from VirusTotal
def update(id_):
    print("Updating file")
    query = ("SELECT resource_id FROM File WHERE id = %s")
    cursor.execute(query, (id_,))
    resource_ = cursor.fetchone()[0]

    print("Requesting data from VirusTotal")
    headers = {'x-apikey': api_key}
    url = get_report_url.replace("{id}", resource_)
    response = requests.post(url, headers=headers)
    print("Data received")

    if response.status_code != 200:
        print("Some problem happened\n" + "Status code: {}".format(response.status_code))
        queue_toscan.put((1, id_))
        return
    
    report = response.json()
    detected_av_query = ("SELECT av_name FROM VirusDetected WHERE file_id = %s")
    cursor.execute(detected_av_query, (id_,))
    detected_av_list = []
    for x in range(cursor.rowcount):
        detected_av_list.append(cursor.fetchone()[0])

    processed_av_query = ("SELECT av_name FROM AvProcessedFile WHERE file_id = %s")
    cursor.execute(processed_av_query, (id_,))
    processed_av_list = []
    for x in range(cursor.rowcount):
        processed_av_list.append(cursor.fetchone()[0])
    

    #Obtaining last scan date and formatting it in YYYY-MM-DD HH-mm-ss
    scan_date = report['data']['attributes']['last_analysis_date']
    scan_date = datetime.fromtimestamp(scan_date).strftime("%Y-%m-%d %I:%M:%S")

    #Obtaining all the info about the analysis
    analysis_data = report['data']['attributes']['last_analysis_results']

    if len(analysis_data) <= 0:
        print("Report is not ready")
        queue_toscan.put((1, id_))
        return

    print("Report is ready")
    for av, info_scan in analysis_data.items():
        check_av(av)

        if av in detected_av_list:
            #1 caso: file individuato da av che lo aveva già individuato
            if info_scan['category'] == "undetected":
                #per ora non fare niente
                pass

            #2 caso: file non individuato da av che prima lo aveva individuato => FALSO POSITIVO
            elif info_scan['category'] == "malicious":
                rmv_query = ("DELETE FROM VirusDetected WHERE file_id = %s and av_name = %s")
                cursor.execute(rmv_query, (id_,av,))
                db_connection.commit()

                try:
                    ins_query = ("INSERT INTO FalsePositive(file_id,av_name) VALUES(%s,%s)")
                    cursor.execute(ins_query, (id_,av,))
                    db_connection.commit()

                except mysql.connector.IntegrityError:
                    print("False positive already registered")

        #3 caso: file individuato da av che non lo aveva individuato
        elif info_scan['category'] == "malicious":
            ins_query = ("INSERT INTO VirusDetected(file_id,av_name,detect_date) VALUES(%s,%s,%s)")
            cursor.execute(ins_query, (id_,av,scan_date,))
            db_connection.commit()

        #checks for antivirus che hanno processato il file
        if av not in processed_av_list:
            try:
                ins_query = ("INSERT INTO AvProcessedFile(file_id,av_name) VALUES(%s,%s)")
                cursor.execute(ins_query, (id_,av,))
                db_connection.commit()

            except mysql.connector.IntegrityError:
                print("AntiVirus-File already registered as processed")


#################################################################################
#                                                                               #
#                            END UTILITY FUNCTIONS                              #
#                                                                               #
#################################################################################

#Database connection using external credential file
conf_file = open("VMConfig.json")
conf = json.loads(conf_file.read())
db_connection = mysql.connector.connect(
        user=conf['db_user'],
        password=conf['db_psw'],
        host=conf['db_host'],
        database=conf['db_name'])
cursor = db_connection.cursor(buffered=True)

#queue for processing files
queue_toscan = Queue(1000)

#VirusTotal requirements
api_key = conf['vm_api']
conf_file.close()
post_scan_url = "https://www.virustotal.com/api/v3/files"
post_rescan_url = "https://www.virustotal.com/api/v3/files/{id}/analyse"
get_report_url = "https://www.virustotal.com/api/v3/files/{id}"

#Start Virus Monitor
print("VirusMonitor started")
was_empty = True

while True:
    print("Checking if there are files in directory to scan")
    path, dirs, files = next(os.walk("../FlaskApp/tmp_files"))
    for file_ in files:
        try:
            scan(file_)
            os.remove("../FlaskApp/tmp_files/" + file_)
            print("File " + file_ + " successfully scanned and deleted")
        except Exception as e:
            report_error(str(e))


    print("Querying files to control")
    query = ("SELECT id FROM File WHERE next_scan < NOW() ORDER BY next_scan LIMIT 30")
    cursor.execute(query)

    print("Got {}/30 files to scan".format(cursor.rowcount))
    for x in range(cursor.rowcount):
        queue_toscan.put((0, str(cursor.fetchone()[0])))

    while not queue_toscan.empty():

        was_empty = False
        tmp = queue_toscan.get()

        #action = 0 OR 1 OR 2
        #action = 0 => id_ = file id to rescan
        #action = 1 => id_ = file id to get report and update
        action_ = tmp[0]
        id_ = tmp[1]

        print("Checking file with id = {}, action = {}".format(id_, action_))

        try:
            if action_ == 0:
                rescan(id_)

            elif action_ == 1:
                update(id_)

        except Exception as e:
            report_error(str(e))

        print("Going to sleep for 15 seconds")
        time.sleep(16)

    if was_empty:
        print("Going to sleep for 5 minutes")
        db_connection.commit()
        time.sleep(300)
    
    was_empty = True