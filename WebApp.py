from flask import Flask, render_template, request, url_for, redirect, session, flash
from werkzeug import secure_filename
import mysql.connector, json

from BackEnd import VirusMonitor
from BackEnd import BlockingQueue
from BackEnd import SyncPrint

#FLASK HANDLERS
app = Flask(__name__)
app.secret_key = "3CDDB48BDD8D59EEB44FDFAA99B5"

#WEB LOGIN INFO
true_user = 'admin_tesi_vm'
true_pass = 'admin_pass'

#DATABASE HANDLERS
conf_file = open('BackEnd/ServerConfig.json')
conf_info = json.loads(conf_file.read())
db_connection = mysql.connector.connect(
	user=conf_info['db_user'], password=conf_info['db_password'],
	host=conf_info['db_host'], database=conf_info['db_name'])
conf_file.close()

cursor = db_connection.cursor(buffered=True)

#CODA BLOCCANTE PER TASKS
tasks_queue = BlockingQueue.BlockingQueue()

#WEB FUNCTIONS
@app.route('/')
def index():
	if session['logged_in']:
		return home()

	return render_template('index.html')

@app.route('/login', methods = ['POST'])
def login():
	tried_user = request.form['user']
	tried_pass = request.form['pass']

	if tried_user == true_user and tried_pass == true_pass:
		session['logged_in'] = True
		return redirect(url_for('home'))
	
	return redirect(url_for('index'))

@app.route('/home', methods = ['GET'])
def home():
	if not session['logged_in']:
		return index()

	cursor.execute("SELECT * FROM File")
	rows = cursor.fetchall()			
	return render_template("home.html", files = rows)

@app.route('/antivirus', methods = ['GET'])
def antivirus():
	if not session['logged_in']:
		return index()

	cursor.execute("SELECT * FROM AntiVirus WHERE num_files_processed > 0 ORDER BY num_files_detected / num_files_processed")
	rows = cursor.fetchall()

	percs = []
	for row in rows:
		num_files_detected = row[1]
		num_files_processed = row[3]
		perc = 0
		if num_files_processed > 0:
			perc = (num_files_detected / num_files_processed) * 100
			perc = float('%.2f'%(perc))
		percs.append(perc)
		
	#idx 0: nome antivirus
	#idx 1: num file rilevati
	#idx 2: num falsi pos
	#idx 3: num file processati
	return render_template("antivirus.html", av_list = rows, perc_list = percs, length = len(rows))

@app.route('/file', methods = ['GET'])
def file_info():
	if not session['logged_in']:
		return index()

	id = request.args['id']
	detailed_info = []

	cursor.execute("SELECT distinct(detect_date) FROM VirusDetected WHERE file_id = " + id + " ORDER BY detect_date")
	dates = cursor.fetchall()

	count = 0
	for date_ in dates:
		cursor.execute("SELECT av_name FROM VirusDetected WHERE file_id = %s AND detect_date = %s", (id, date_[0]))
		count += cursor.rowcount

		detailed_info.append((date_[0], cursor.rowcount, cursor.fetchall(), count))

	cursor.execute("SELECT name FROM File WHERE id = " + id)
	file_name = cursor.fetchone()

	#formato di info: (detect_date, num_av_per_date, av_list, num_av_detect_total)
	return render_template("file_info.html", info = detailed_info, name = file_name, length = len(dates))

@app.route('/add', methods = ['POST'])
def add_file():
	if not session['logged_in']:
		return index()

	#TODO
	#contare num files, in caso > 10 non caricare
	#VM prenderà da qui i files
	f = request.files['file']
	f.save('tmp_files/' + secure_filename(f.filename))
	return 'file uploaded successfully'

@app.route('/rmv', methods = ['POST'])
def rmv_file():
	if not session['logged_in']:
		return index()

	id = request.data
	#commented for now for avoiding damage
	#cursor.execute("DELETE FROM File WHERE id = " + id)
	#db_connection.commit()
	return render_template("home.html")


#MAIN
if __name__ == '__main__':
	#classe per eseguire print sincronizzati
	sync_print = SyncPrint.SyncPrint()
		
	#creo e avvio il virus monitor
	virusmonitor = VirusMonitor.VirusMonitor(db_connection, tasks_queue, sync_print)
	#virusmonitor.start()

	#avvio il sito web
	app.run(port=12345, debug=True)

	#db_connection.close()
