import requests, sys, json, mysql.connector, time
from datetime import datetime

#Initialization
conf_file = open("VMConfig.json")
conf = json.loads(conf_file.read())
db_connection = mysql.connector.connect(
    user=conf['db_user'],
    password=conf['db_psw'],
    host=conf['db_host'],
    database=conf['db_name'])
cursor = db_connection.cursor(buffered=True)
comments_url = conf['comments_url']
conf_file.close()

files_to_add = 0
files_added = 0
#Taking number of files to add to the monitor from args
try:
    files_to_add = int(sys.argv[1])

except IndexError as e:
    print("ERROR: need first argument as the number of files to add")
    sys.exit()

except ValueError as e:
    print("ERROR: invalid number given as argument")
    sys.exit()
    

while files_added < files_to_add:
    resp = requests.get(comments_url)
    
    if resp.status_code == 200:
        data = resp.json()

        for comment in data['data']:
            resource_id = comment['relationships']['item']['data']['id']
            resource_type = comment['relationships']['item']['data']['type']

            #Add into DB with 'auto-added' filename
            if resource_type == 'file':
                query = ("INSERT INTO File(name,resource_id,next_scan) VALUES(%s,%s,%s)")
                nextscan = datetime.now()

                try:
                    cursor.execute(query, ('auto-added',resource_id,nextscan,))
                    db_connection.commit()
                    print("File n. {} successfully inserted".format(files_added+1))
                    files_added += 1

                except mysql.connector.IntegrityError:
                    #file already registered
                    pass

            if files_added >= files_to_add:
                break

        #Finding next_url for next request and repeating it
        comments_url = data['links']['next']

    else if resp.status_code == 429:
        print("Going to sleep for 10 minutes because requests limit excedeed")
        time.sleep(600)
    else:
        print("Some problem happened, status code: {}".format(resp.status_code))