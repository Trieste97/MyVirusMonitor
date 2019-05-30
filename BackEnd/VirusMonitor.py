import json
import time
import requests
import sys
import mysql.connector
from datetime import datetime, timedelta
from threading import Thread

class VirusMonitor(Thread):
	def __init__(self, db_connection, queue, where_print):
		super().__init__()
		self.db_connection = db_connection
		self.cursor = db_connection.cursor(buffered=True)
		self.queue = queue
		self.console = where_print

		conf_file = open('BackEnd/ServerConfig.json')
		conf_info = json.loads(conf_file.read())
		self.api_key = conf_info['vm_api']
		self.post_rescan_url = conf_info['post_rescan_url']
		self.get_report_url = conf_info['get_report_url']
		conf_file.close()
	

	def check_av(self, av_name):
		tmp_query = ("SELECT name FROM AntiVirus WHERE name = %s")
		self.cursor.execute(tmp_query, (av_name,))

		if self.cursor.rowcount <= 0:
			tmp_query = ("INSERT INTO AntiVirus(name) VALUES(%s)")
			self.cursor.execute(tmp_query, (av_name,))
			self.db_connection.commit()


	def run(self):

		self.console.print("[VM] VirusMonitor started")
		was_empty = True

		while True:

			self.console.print("[VM] Querying files to control")
			query = ("SELECT id FROM File WHERE next_scan < NOW() ORDER BY next_scan LIMIT 10")
			self.cursor.execute(query)

			self.console.print("[VM] Got {}/10 files to scan".format(self.cursor.rowcount))
			for x in range(self.cursor.rowcount):
				self.queue.put((0, str(self.cursor.fetchone()[0])))

			while not self.queue.isEmpty():

				was_empty = False
				tmp = self.queue.get()

				#action = 0 OR 1 OR 2 OR 3
				#action = 0 => id_ = file id to rescan
				#action = 1 => id_ = file id to get report and update
				#action = 2 => id_ = file id to remove
				#action = 3 => id_ = resource_id|file_name of file to wait report and insert
				action_ = tmp[0]
				id_ = tmp[1]

				self.console.print("[VM] Checking file with id = {}, action = {}".format(id_, action_))

				try:
					if action_ == 0:
						self.rescan(id_)

					elif action_ == 1:
						self.update(id_)

					elif action_ == 2:
						self.remove(id_)
						continue

					elif action_ == 3:
						self.insert(id_)
						continue

				except Exception as e:
					self.console.print('[VM] Some error happened')
					self.console.print(str(e))

				self.console.print("[VM] Going to sleep for 15 seconds")
				time.sleep(16)

			if was_empty:
				self.console.print("[VM] Going to sleep for 5 minutes")
				self.db_connection.commit()
				time.sleep(300)
			
			was_empty = True


#END run() function


	def rescan(self, id_):
		self.console.print("[VM] Re-scanning file")
		query = ("SELECT resource_id FROM File WHERE id = %s")
		self.cursor.execute(query, (id_,))
		resource_ = self.cursor.fetchone()[0]

		self.console.print("[VM] Submitting resource to VirusTotal")
		params = {'apikey': self.api_key, 'resource': resource_}
		response = requests.post(self.post_rescan_url, params=params)
		self.console.print("[VM] Received response")		

		response_json = response.json()
		if response_json['response_code'] == 1:
			self.console.print("[VM] Resource submitted successfully")
			nextscan_ = datetime.now() + timedelta(hours=8)
			query = ("UPDATE File SET next_scan = %s WHERE id = %s")
			self.cursor.execute(query, (nextscan_,id_,))
			self.db_connection.commit()

			self.queue.put((1,id_))
		else:
			self.console.print("[VM] Couldn't submit resource")
			nextscan_ = datetime.now() + timedelta(hours=1)
			query = ("UPDATE File SET next_scan = %s WHERE id = %s")
			self.cursor.execute(query, (nextscan_,id_,))
			self.db_connection.commit()


	def update(self, id_):
		self.console.print("[VM] Updating file")
		query = ("SELECT resource_id FROM File WHERE id = %s")
		self.cursor.execute(query, (id_,))
		resource_ = self.cursor.fetchone()[0]

		self.console.print("[VM] Requesting data from VirusTotal")
		params = {'apikey': self.api_key, 'resource': resource_}
		response = requests.post(self.get_report_url, params=params)
		self.console.print("[VM] Data received")

		report_data = response.json()
		if report_data['response_code'] == 1:
			self.console.print("[VM] Report is ready")
			detected_av_query = ("SELECT av_name FROM VirusDetected WHERE file_id = %s")
			self.cursor.execute(detected_av_query, (id_,))
			detected_av_list = []
			for x in range(self.cursor.rowcount):
				detected_av_list.append(self.cursor.fetchone()[0])

			processed_av_query = ("SELECT av_name FROM AvProcessedFile WHERE file_id = %s")
			self.cursor.execute(processed_av_query, (id_,))
			processed_av_list = []
			for x in range(self.cursor.rowcount):
				processed_av_list.append(self.cursor.fetchone()[0])
			

			scan_date = report_data['scan_date']
			scans_data = report_data['scans']
			
			for av, info_scan in scans_data.items():
				self.check_av(av)

				if av in detected_av_list:
					#1 caso: file individuato da av che lo aveva già individuato
					if info_scan['detected']:
						#per ora non fare niente
						pass

					#2 caso: file non individuato da av che prima lo aveva individuato => FALSO POSITIVO
					else:
						rmv_query = ("DELETE FROM VirusDetected WHERE file_id = %s and av_name = %s")
						self.cursor.execute(rmv_query, (id_,av,))
						self.db_connection.commit()

						try:
							ins_query = ("INSERT INTO FalsePositive(file_id,av_name) VALUES(%s,%s)")
							self.cursor.execute(ins_query, (id_,av,))
							self.db_connection.commit()

						except mysql.connector.IntegrityError:
							self.console.print("[VM] False positive already registered")

				#3 caso: file individuato da av che non lo aveva individuato
				elif info_scan['detected']:
					ins_query = ("INSERT INTO VirusDetected(file_id,av_name,detect_date) VALUES(%s,%s,%s)")
					self.cursor.execute(ins_query, (id_,av,scan_date,))
					self.db_connection.commit()

				#checks for antivirus che hanno processato il file
				if av not in processed_av_list:
					try:
						ins_query = ("INSERT INTO AvProcessedFile(file_id,av_name) VALUES(%s,%s)")
						self.cursor.execute(ins_query, (id_,av,))
						self.db_connection.commit()

					except mysql.connector.IntegrityError:
						self.console.print("[VM] AntiVirus-File already registered as processed")

		else:
			self.console.print("[VM] Report is NOT ready")
			self.queue.put((1, id_))

	def remove(self, id_):
		self.console.print("[VM] Deleting file from DB")
		remove_query = ("DELETE FROM File WHERE id = %s")
		self.cursor.execute(remove_query, (id_,))
		self.db_connection.commit()

		self.console.print("[VM] File successfully deleted")

	#API, for inserting multiple files with scripts
	def insert(self, resource_and_filename):
		comma_indx = resource_and_filename.find(',')
		stang_indx = resource_and_filename.find('|')

		resource_id_ = resource_and_filename[comma_indx+1 : stang_indx]
		file_name_ = resource_and_filename[stang_indx+1 :]

		self.console.print("[VM] Inserting file")
		query = ("INSERT INTO File(name,resource_id,next_scan) VALUES(%s,%s,%s)")
		nextscan_ = datetime.now() + timedelta(hours=8)
		try:
			self.cursor.execute(query, (file_name_,resource_id_,nextscan_,))
			self.db_connection.commit()
			self.console.print("[VM] File successfully inserted")
			newfile_id = self.cursor.lastrowid
			self.queue.put((1, str(newfile_id)))
			self.console.print("[VM] File successfully queued for update")

		except mysql.connector.IntegrityError:
			self.console.print("[VM] File already registered")
