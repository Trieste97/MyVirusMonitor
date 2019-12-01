from flask import Flask, render_template, request, url_for, redirect, session
from werkzeug import secure_filename
from datetime import datetime
import mysql.connector, json, os

#Update error_log permission with:
#chown -R www-data:www-data path_to_file

#FLASK HANDLERS
app = Flask(__name__)
app.secret_key = "3CDDB48BDD8D59EEB44FDFAA99B5"

#WEB LOGIN INFO
conf_file = open("/var/www/FlaskApp/Config.json")
conf = json.loads(conf_file.read())

true_user = conf['site_user']
true_pass = conf['site_psw']

#DATABASE HANDLERS
db_connection = mysql.connector.connect(
	user=conf['db_user'],
	password=conf['db_psw'],
	host=conf['db_host'],
	database=conf['db_name'])

cursor = db_connection.cursor(buffered=True)

conf_file.close()

supported_filetypes = [
	"exe", "eml", "xls", "img", "virus", "zip", "rar", "ace", "doc", "msi", ""
]

#CHECK IF DB CNX IS STILL OPEN
def check_db_connection():
	try:
		db_connection.ping()
	except:
		db_connection.reconnect()

#ERROR LOG FUNCTION
def write_error_log(error):
	current_time = datetime.now()
	error_file = open("/var/www/FlaskApp/FlaskApp/error_log", "a")
	error_file.write(current_time.strftime("%d/%m/%Y %H:%M:%S") + "\n")
	error_file.write(error + "\n\n")
	error_file.close()

#ADD NEW FILE MANAGEMENT
def manage_new_file(file):
	if file.filename == '':
		return "nofile"

	filetype_idx = file.filename.rfind('.') + 1
	filetype = file.filename[filetype_idx :]
	if filetype not in supported_filetypes:
		return "not_supported_format"

	path, dirs, files = next(os.walk("/var/www/FlaskApp/FlaskApp/tmp_files"))
	file_count = len(files)
	if file_count > 20:
		return "too_many_files"

	#TODO: gestire file size, max 100MB
	#if file_size > 100000000:
	#	return "too_big"

	cursor.execute("SELECT * FROM File")
	num_files_in_db = cursor.rowcount
	if num_files_in_db > 2000:
		return  "too_many_files_db"

	fname = file.filename
	count = 0
	while fname in files:
		fname = str(count) + fname
		count += 1

	filename = secure_filename(fname)
	file.save(os.path.join("/var/www/FlaskApp/FlaskApp/tmp_files", filename))
	return "success"


#WEB FUNCTIONS
@app.route('/')
def index():
	if session.get('logged_in'):
		return home()

	return render_template('index.html')

@app.route('/login', methods = ['POST'])
def login():
	if session.get('logged_in'):
		return home()

	tried_user = request.form['user']
	tried_pass = request.form['pass']

	if tried_user == true_user and tried_pass == true_pass:
		session['logged_in'] = True
		return redirect(url_for('home'))

	return redirect(url_for('index'))

@app.route('/home', methods = ['GET'])
def home():
	if not session.get('logged_in'):
		return index()

	check_db_connection()

	try:
		cursor.execute("SELECT * FROM File as F ORDER BY (SELECT count(*) FROM VirusDetected WHERE file_id = F.id) DESC;")
		rows = cursor.fetchall()

		#Taking info about each file: num av that detected it vs num av that processed it
		data = []
		for row in rows:
			id = row[0]
			cursor.execute("SELECT count(*) FROM VirusDetected WHERE file_id = %s", (id,))
			num_detected = cursor.fetchone()
			cursor.execute("SELECT count(*) FROM AvProcessedFile WHERE file_id = %s", (id,))
			num_processed = cursor.fetchone()

			#file_info is a tuple
			file_info = row + num_detected + num_processed
			data.append(file_info)

		return render_template("home.html", files = data)
	except Exception as e:
		write_error_log(str(e))
		return render_template("error.html")

@app.route('/av-general-stats', methods = ['GET'])
def antivirus_general():
	if not session.get('logged_in'):
		return index()

	return render_template("antivirus.html")

@app.route('/get-av-general-stats', methods= ['GET'])
def av_general_stats():
	try:
		data = json.loads(open('/var/www/FlaskApp/StatsFiles/general_stats.json').read())
		return data
	except Exception as e:
		write_error_log(str(e))
		return "error"

@app.route('/av-time-stats', methods = ['GET'])
def antivirus_time():
	if not session.get('logged_in'):
		return index()

	return render_template("antivirus-time.html")

@app.route('/get-av-time-stats', methods= ['GET'])
def av_time_stats():
	try:
		data = json.loads(open('/var/www/FlaskApp/StatsFiles/time_stats.json').read())
		return data
	except Exception as e:
		write_error_log(str(e))
		return "error"

@app.route('/av-copies-stats', methods = ['GET'])
def antivirus_copies():
	if not session.get('logged_in'):
		return index()

	return render_template("antivirus-copies.html")

@app.route('/get-av-copies-stats', methods= ['GET'])
def av_copies_stats():
	try:
		data = json.loads(open('/var/www/FlaskApp/StatsFiles/copies_stats.json').read())
		return data
	except Exception as e:
		write_error_log(str(e))
		return "error"

@app.route('/file', methods = ['GET'])
def file():
	if not session.get('logged_in'):
		return index()

	return render_template("file.html")

@app.route('/file-info', methods = ['GET'])
def file_info():
	check_db_connection()
	id = request.args['id']
	data = {}
	detailed_info = []

	try:
		# Prelevo le date in cui il file è stato detectato
		cursor.execute("SELECT distinct(detect_date) FROM VirusDetected WHERE file_id = " + id + " ORDER BY detect_date")
		dates = cursor.fetchall()

		count = 0
		if len(dates) == 0:
			return home()

		for date_ in dates:
			cursor.execute("SELECT av_name FROM VirusDetected WHERE file_id = %s AND detect_date = %s", (id, date_[0]))
			count += cursor.rowcount

			detailed_info.append((date_[0], cursor.rowcount, cursor.fetchall(), count))
		data['file_info'] = detailed_info

		# Prelevo il nome del file
		cursor.execute("SELECT name FROM File WHERE id = " + id)
		file_name_t = cursor.fetchone()
		if file_name_t is None:
			return home()

		data['name'] = file_name_t[0]
		data['length'] = len(dates)
		return data
	except Exception as e:
		write_error_log(str(e))
		return render_template("error.html")

@app.route('/add', methods = ['POST'])
def add_file():
	if not session.get('logged_in'):
		return index()

	check_db_connection()

	try:
		if 'file' not in request.files:
			return "nofile"

		f = request.files['file']
		return manage_new_file(f)
	except Exception as e:
		write_error_log(str(e))
		return "error"

@app.route('/rmv', methods = ['POST'])
def rmv_file():
	if not session.get('logged_in'):
		return index()

	check_db_connection()
	try:
		id = request.data
		cursor.execute("DELETE FROM File WHERE id = " + id)
		db_connection.commit()
		return "success"
	except Exception as e:
		write_error_log(str(e))
		return "error"

@app.route('/logout')
def logout():
	if session.get('logged_in'):
		session['logged_in'] = False

	return index()

#MAIN
if __name__ == '__main__':
	app.run()
