import json, mysql.connector

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

    if num_detects == 0:
        file_ids_toremove.append(file_id)

for file_id in file_ids_toremove:
    query = ("DELETE FROM File WHERE id = %s")
    cursor.execute(query, (file_id,))
    db_connection.commit()

db_connection.close()