import json, mysql.connector, time, math, heapq
from datetime import datetime,timedelta
from xlsxwriter import Workbook

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
            seconds_passed = (detect_date - first_detect_date).seconds
            seconds_passed += (detect_date - first_detect_date).days * 86400

            current_avg = data['av_data'][av_name]["avg_days"]
            current_files = data['av_data'][av_name]["files"]
            new_avg = ((current_avg * current_files) + seconds_passed) / (current_files+1)
            data['av_data'][av_name]["avg_days"] = new_avg
            data['av_data'][av_name]["files"] = current_files + 1

    #AVS to delete because they have no files processed
    avs_to_delete = []
    for av_name in data['av_data'].keys():
        if data['av_data'][av_name]['files'] < 10:
            avs_to_delete.append(av_name)
        else:
            #Converting seconds to days
            current_seconds = data['av_data'][av_name]['avg_days']
            data['av_data'][av_name]['avg_days'] = float('%.2f' % (current_seconds / 86400))

    for av_name in avs_to_delete:
	    data['av_data'].pop(av_name)

    return data

def get_av_copies_stats(db_connection,cursor):
    data = {}
    cursor.execute("SELECT name FROM AntiVirus")
    av_names_t = cursor.fetchall()
    av_names = []
    for av1_t in av_names_t:
        av_names.append(av1_t[0])
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

                    total_seconds_passed = (detect_date - av_before_date).seconds
                    total_seconds_passed += (detect_date - av_before_date).days*86400
                    if (total_seconds_passed) == 0:
                        continue

                    occurrences = data[av_name + "->" + av_before_name]["files"]
                    seconds = data[av_name + "->" + av_before_name]["avg_days"] * occurrences
                    data[av_name + "->" + av_before_name]["files"] = occurrences+1
                    data[av_name + "->" + av_before_name]["avg_days"] = (seconds + total_seconds_passed)/(occurrences+1)

                first_avs.append([av_name, detect_date])

    avs_to_delete = []
    for av_couple in data.keys():
        if data[av_couple]['files'] > 0:
            #Converting seconds to days
            avg_seconds = data[av_couple]['avg_days']
            data[av_couple]['avg_days'] = float('%.2f' % (avg_seconds/86400))

            if data[av_couple]['avg_days'] > 10 or data[av_couple]['files'] < 10:
                avs_to_delete.append(av_couple)
        else:
            avs_to_delete.append(av_couple)
            

    for av_couple in avs_to_delete:
        del data[av_couple]

    avs_to_delete = []
    #For every couple Av1->Av2, takes max one Av1, the highest probable (highest number of occorrences)
    for av1 in av_names:
        numOccurMax = 0
        avMax = ""

        for av_couple in data.keys():
            av1_2 = av_couple.split("->")[0]
            av2_2 = av_couple.split("->")[1]

            if av1 == av1_2:
                occur = data[av_couple]['files']
                if occur > numOccurMax:
                    numOccurMax = occur
                    if avMax != "":
                        avs_to_delete.append(av1+"->"+avMax)
                    avMax = av2_2
                else:
                    avs_to_delete.append(av_couple)

    for av_couple in avs_to_delete:
        del data[av_couple]
    
    return data

def get_av_copies_stats_cc(db_connection,cursor):
    def max_of_timeslots(list):
        int_list = []
        for item in list:
            int_list.append(int(item))

        try:
            return max(int_list)
        except ValueError:
            return 0

    def write_on_excel():
        wb = Workbook('../Stats/Matrix_CC.xlsx')
        sheet1 = wb.add_worksheet('Matrix(sum)')
        sheet2 = wb.add_worksheet('Matrix(time)')

        count = 0
        for av_name in timeslots.keys():
            count += 1
            sheet1.write(count, 0, av_name)
            sheet1.write(0, count, av_name)
            sheet2.write(count, 0, av_name)
            sheet2.write(0, count, av_name)


        for i in range(len(av_list)):
            for j in range(len(av_list)):
                sheet1.write(i+1, j+1, matrix_sum[av_list[i]][av_list[j]])
                sheet2.write(i+1, j+1, matrix_time[av_list[i]][av_list[j]])

        sheet1.conditional_format(1,1,len(av_list),len(av_list), {
            'type': '2_color_scale',
            'min_color': 'white',
            'max_color': 'red'
        })

        red_format = wb.add_format({'bg_color':   '#E74C4C'})
        sheet2.conditional_format(1,1,len(av_list),len(av_list), {
            'type':     'cell',
            'criteria': 'equal to',
            'value':     0,
            'format':    red_format
        })
        wb.close()

    #USING CROSS-CORRELATION
    #The starting point
    cursor.execute('SELECT min(detect_date) FROM VirusDetected')
    starting_date = cursor.fetchone()[0]
    starting_date = (starting_date - timedelta(seconds=1))

    #Obtaining list of all AVs
    av_list = []
    timeslots = {}
    data = {}
    matrix_sum = {}
    matrix_time = {}
    cursor.execute("SELECT name FROM AntiVirus ORDER BY name")
    for av in cursor.fetchall():
        av_list.append(av[0])
        timeslots[av[0]] = {}
        data[av[0]] = {}
        matrix_sum[av[0]] = {}
        matrix_time[av[0]] = {}

    for av_name in timeslots.keys():
        cursor.execute("SELECT detect_date FROM VirusDetected WHERE av_name = %s;", (av_name,))
        for date in cursor.fetchall():
            #date is a tuple containing 1 element => date[0] is the element
            tot_seconds = (date[0] - starting_date).total_seconds()

            #dividing the seconds for the time-slot I configured, in this case: 8 hours is a time-slot (28800 seconds)
            time_slot = math.ceil(tot_seconds / 28800)
            if str(time_slot) in timeslots[av_name]:
                curr = timeslots[av_name][str(time_slot)]
                timeslots[av_name][str(time_slot)] = curr+1
            else:
                data[av_name][str(time_slot)] = 1

    #APPLYING CROSS-CORRELATION
    for av_name1 in timeslots.keys():
        max_av1 = max_of_timeslots(timeslots[av_name1].keys())
        for av_name2 in timeslots.keys():
            #calculating the max time_slot for stimate the range of n to use
            max_av2 = max_of_timeslots(timeslots[av_name2].keys())
            max_of = max(max_av1,max_av2)

            #calling the variables of the result (time and the sum) respectively
            #best_time, best_sum
            #best_time can go from -max_of to max_of+1 (-n to +n)
            best_time = 0
            #best_sum can go from 0 to ...
            best_sum = 0
            for n in range(-max_of, max_of+1):
                #Formula : (f.g)[n] = sum(f(m-n)*g(m)), with m from -inf to +inf
                sum = 0
                for m in timeslots[av_name2].keys():
                    if str(int(m)-n) in timeslots[av_name1]:
                        sum += timeslots[av_name1][str(int(m)-n)] * timeslots[av_name2][m]

                if sum > best_sum:
                    best_sum = sum
                    best_time = n

            matrix_sum[av_name1][av_name2] = best_sum
            matrix_time[av_name1][av_name2] = best_time

    with open('../Stats/CC_timeslots.json','w+') as f:
        f.write(json.dumps(timeslots))

    write_on_excel()

    #ELIMINATING ALL except the 10 highest sums
    #such that their time is < 0
    elem_to_delete = []
    elem_to_max = []
    for i in range(len(av_list)):
        current_max_sum = 0
        for j in range(len(av_list)):
            sum = matrix_sum[av_list[i]][av_list[j]]
            time = matrix_time[av_list[i]][av_list[j]]

            if time < 0:
                #se è vuoto:
                if not data[av_list[i]]:
                    data[av_list[i]][av_list[j]] = sum
                    current_max_sum = sum
                else:
                    av_before = list(data[av_list[i]])[0]
                    sum_before = data[av_list[i]][av_before]
                    if sum > sum_before:
                        del data[av_list[i]][av_before]
                        data[av_list[i]][av_list[j]] = sum
                        current_max_sum = sum

        if not data[av_list[i]]:
            elem_to_delete.append(av_list[i])
        else:
            elem_to_max.append(current_max_sum)

    for elem in elem_to_delete:
        del data[elem]

    elem_to_delete = []
    highest_sums = heapq.nlargest(10, elem_to_max)
    for av1 in data.keys():
        av2 = list(data[av1].keys())[0]
        if not data[av1][av2] in highest_sums:
            elem_to_delete.append(av1)

    for elem in elem_to_delete:
        del data[elem]

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
    with open('../Stats/general_stats.json', 'w+') as f:
        f.write(json.dumps(av_general_stats))
        
    av_time_stats = get_av_time_stats(db_connection,cursor)
    print("Writing time stats on JSON file")
    with open('../Stats/time_stats.json', 'w+') as f:
        f.write(json.dumps(av_time_stats))
    
    av_copies_stats = get_av_copies_stats(db_connection,cursor)
    print("Writing copies stats on JSON file")
    with open('../Stats/copies_stats.json', 'w+') as f:
        f.write(json.dumps(av_copies_stats))

    #with cross-correlation method
    av_copies_stats_cc = get_av_copies_stats_cc(db_connection,cursor)
    print("Writing copies (cross-correlation) stats on JSON file")
    with open('../Stats/copies_stats_cc.json', 'w+') as f:
        f.write(json.dumps(av_copies_stats_cc))
    
    print("Closing connection to DB")
    db_connection.close()

    print("Going to sleep for 1 hour")
    time.sleep(3600)