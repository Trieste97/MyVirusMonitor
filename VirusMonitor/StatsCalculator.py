import json, mysql.connector, time

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
        print("Calculating stats of " + av_name)
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
        
    print("Closing connection to DB")
    db_connection.close()

    print("Writing stats on JSON file")
    f = open('../StatsFiles/general_stats.json', 'w+')
    f.write(json.dumps(data))
    f.close()

    data = {}

    print("Going to sleep for 1 hour")
    time.sleep(3600)