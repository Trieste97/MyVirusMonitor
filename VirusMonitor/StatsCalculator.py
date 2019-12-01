import json, mysql.connector, time

#Function for calculate antivirus general stats (detects,false positives and processed files)
def get_av_general_stats(db_connection, cursor):
    data = {}

    #Obtaining total number of files
    cursor.execute("SELECT count(*) FROM File;")
    data['num_files'] = cursor.fetchone()[0]

    #Obtaining list of all AVs
    av_list = []
    cursor.execute("SELECT name FROM AntiVirus;")
    for av in cursor.fetchall():
        av_list.append(av[0])

    print("Starting to retrieve data")
    data['num_antiviruses'] = len(av_list)
    data['av_stats'] = {}
    for av_name in av_list:
        cursor.execute("SELECT num_files_detected FROM AV_num_files_detected WHERE av_name = %s", (av_name,))
        num_files_detected_t = cursor.fetchone()
        cursor.execute("SELECT num_files_processed FROM AV_num_files_processed WHERE av_name = %s", (av_name,))
        num_files_processed_t = cursor.fetchone()
        cursor.execute("SELECT num_false_positives FROM AV_num_false_positives WHERE av_name = %s", (av_name,))
        num_false_positives_t = cursor.fetchone()

        num_files_detected = 0
        if num_files_detected_t is not None:
            num_files_detected = num_files_detected_t[0]

        num_files_processed = 0
        if num_files_processed_t is not None:
            num_files_processed = num_files_processed_t[0]

        num_false_positives = 0
        if num_false_positives_t is not None:
            num_false_positives = num_false_positives_t[0]

        perc_detected = 0
        if num_files_processed > 0:
            perc_detected = (num_files_detected / num_files_processed) * 100
            perc_detected = float('%.2f' % (perc_detected))

        perc_false = 0
        if num_files_processed > 0:
            perc_false = (num_false_positives / num_files_processed) * 100
            perc_false = float('%.2f' % (perc_false))
        
        perc_processed = 0
        if data['num_files'] > 0:
            perc_processed = (num_files_processed / data['num_files']) * 100
            perc_processed = float('%.2f' % (perc_processed))

        data['av_stats'][av_name] = {
            "files_detected": num_files_detected,
            "false_positives": num_false_positives,
            "files_processed": num_files_processed,
            "perc_detected": perc_detected,
            "perc_false": perc_false,
            "perc_processed": perc_processed
        }

    return data

def get_av_time_stats(db_connection,cursor):
    data = {}
    cursor.execute("SELECT id From File")
    file_id_rows = cursor.fetchall()
    file_id_list = []
    for row in file_id_rows:
        file_id_list.append(row[0])

    # AV LIST AND THEIR DAYS PASSED + NUMBER OF FILES (FILES DETECTED AFTER THE FIRST TIME OF ANOTHER AV)
    #avg_days IS THE AVERAGE OF DAYS PASSED FROM FIRST DETECT TO THE CURRENT
    cursor.execute("SELECT name FROM AntiVirus")
    data['num_antiviruses'] = cursor.rowcount
    data['av_data'] = {}
    av_name_rows = cursor.fetchall()
    for row in av_name_rows:
        data['av_data'][row[0]] = {
            "files": 0,
            "avg_days": 0
        }

    # CALCULATING TIME PASSED SINCE FIRST DETECT FOR EACH FILE_ID
    for file_id in file_id_list:
        cursor.execute("SELECT detect_date FROM VirusDetected WHERE file_id = %s ORDER BY detect_date LIMIT 1",
                        (file_id,))
        # first_detect_date_t is a tuple, if there is at least one detect
        first_detect_date_t = cursor.fetchone()
        if first_detect_date_t is None:
            continue

        first_detect_date = first_detect_date_t[0]
        cursor.execute("SELECT av_name,detect_date FROM VirusDetected WHERE file_id = %s AND NOT detect_date = %s "
                        "ORDER BY detect_date", (file_id, first_detect_date,))
        data_rows = cursor.fetchall()
        for row in data_rows:
            av_name, detect_date = row
            days_passed = (detect_date - first_detect_date).days

            current_avg = data['av_data'][av_name]["avg_days"]
            current_files = data['av_data'][av_name]["files"]
            new_avg = ((current_avg * current_files) + days_passed) / (current_files+1)
            data['av_data'][av_name]["avg_days"] = new_avg
            data['av_data'][av_name]["files"] = current_files + 1

    #AVS to delete because they have no files processed
    avs_to_delete = []
    for av_name in data['av_data'].keys():
        if data['av_data'][av_name]['files'] < 10:
            avs_to_delete.append(av_name)
        else:
            avg_days = data['av_data'][av_name]['avg_days']
            data['av_data'][av_name]['avg_days'] = float('%.2f' % (avg_days))

    for av_name in avs_to_delete:
	    data['av_data'].pop(av_name)

    return data

def get_av_copies_stats(db_connection,cursor):
    data = {}
    cursor.execute("SELECT name FROM AntiVirus")
    av_names_t = cursor.fetchall()
    for av1_t in av_names_t:
        for av2_t in av_names_t:
            av1 = av1_t[0]
            av2 = av2_t[0]

            #data[AV1 seems to copy(->) AV2]
            if av1 != av2:
                data[av1 + "->" + av2] = {
                    "files": 0,
                    "avg_days": 0
                }

    files_ids_list = []
    cursor.execute("SELECT id from File")
    file_ids_t = cursor.fetchall()
    for file_t in file_ids_t:
        files_ids_list.append(file_t[0])

    for file_id in files_ids_list:
        cursor.execute("SELECT av_name,detect_date from VirusDetected WHERE file_id = %s ORDER BY detect_date", (file_id,))
        if cursor.rowcount == 0:
            continue

        #Excluding the AVS that detect it first
        file_detects = cursor.fetchall()
        first_avs = []
        first_date = file_detects[0][1]
        for info in file_detects:
            av_name,detect_date = info
            if detect_date == first_date:
                first_avs.append([av_name, first_date])
            else:
                for av_before in first_avs:
                    av_before_name = av_before[0]
                    av_before_date = av_before[1]

                    if ((detect_date - av_before_date).days) == 0:
                        continue

                    occurrences = data[av_name + "->" + av_before_name]["files"]
                    days = data[av_name + "->" + av_before_name]["avg_days"] * occurrences
                    data[av_name + "->" + av_before_name]["files"] = occurrences+1
                    data[av_name + "->" + av_before_name]["avg_days"] = (days + (detect_date - av_before_date).days)/(occurrences+1)

                first_avs.append([av_name, detect_date])

    avs_to_delete = []
    for av_name in data.keys():
        if data[av_name]['files'] > 0:
            avg_days = data[av_name]['avg_days']
            data[av_name]['avg_days'] = float('%.2f' % (avg_days))

            if data[av_name]['avg_days'] > 10 or data[av_name]['files'] < 10:
                avs_to_delete.append(av_name)
        else:
            avs_to_delete.append(av_name)
            

    for av_name in avs_to_delete:
        del data[av_name]

    return data



#Initialization
conf_file = open("VMConfig.json")
conf = json.loads(conf_file.read())
db_user = conf['db_user']
db_psw = conf['db_psw']
db_host = conf['db_host']
db_name = conf['db_name']
conf_file.close()

data = {}
while True:
    print("Connecting to DB")
    db_connection = mysql.connector.connect(
        user=conf['db_user'],
        password=conf['db_psw'],
        host=conf['db_host'],
        database=conf['db_name']
    )
    cursor = db_connection.cursor(buffered=True)

    av_general_stats = get_av_general_stats(db_connection,cursor)
    print("Writing general stats on JSON file")
    with open('../StatsFiles/general_stats.json', 'w+') as f:
        f.write(json.dumps(av_general_stats))
        
    av_time_stats = get_av_time_stats(db_connection,cursor)
    print("Writing time stats on JSON file")
    with open('../StatsFiles/time_stats.json', 'w+') as f:
        f.write(json.dumps(av_time_stats))

    av_copies_stats = get_av_copies_stats(db_connection,cursor)
    print("Writing time stats on JSON file")
    with open('../StatsFiles/copies_stats.json', 'w+') as f:
        f.write(json.dumps(av_copies_stats))
    
    print("Closing connection to DB")
    db_connection.close()

    #Freeing memory
    av_general_stats = None
    av_time_stats = None
    av_copies_stats = None

    print("Going to sleep for 1 hour")
    time.sleep(3600)
