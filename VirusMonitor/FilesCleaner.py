import json, mysql.connector, sys

#Runned with ./FilesCleaner minDetects maxDetects
#It eliminates all files such that its detects are < minDetects or > maxDetects
min_detects = 0
max_detects = 0
try:
    min_detects = int(sys.argv[1])
    max_detects = int(sys.argv[2])
except IndexError as e:
    print("To run with minimum detects and maximum detects as first and second arguments")
    sys.exit()
except ValueError as e:
    print("Arguments must be integers")
    sys.exit()

#Initialization
conf_file = open("VMConfig.json")
conf = json.loads(conf_file.read())
db_connection = mysql.connector.connect(
        user=conf['db_user'],
        password=conf['db_psw'],
        host=conf['db_host'],
        database=conf['db_name'])
cursor = db_connection.cursor(buffered=True)
conf_file.close()

query = ("SELECT id from File")
cursor.execute(query)

file_ids_toremove = []
file_ids = cursor.fetchall()
for file_id_ in file_ids:
    file_id = file_id_[0]
    query = ("SELECT count(*) FROM VirusDetected WHERE file_id = %s")
    cursor.execute(query, (file_id,))
    num_detects = cursor.fetchone()[0]

    if num_detects < min_detects or num_detects > max_detects:
        file_ids_toremove.append(file_id)

num_files_deleted = len(file_ids_toremove)
for file_id in file_ids_toremove:
    query = ("DELETE FROM File WHERE id = %s")
    cursor.execute(query, (file_id,))
    db_connection.commit()

db_connection.close()

print("Files deleted: {}".format(num_files_deleted))