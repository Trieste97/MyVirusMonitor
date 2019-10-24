import json
import time
import requests
import sys
import mysql.connector
import os
import BlockingQueue
from datetime import datetime, timedelta
from threading import Thread

class VirusMonitor(Thread):
	def __init__(self, queue):
		super().__init__()

		conf_file = open("VMConfig.json")
		conf = json.loads(conf_file.read())
		self.db_connection = mysql.connector.connect(
        		user=conf['db_user'],
        		password=conf['db_psw'],
        		host=conf['db_host'],
        		database=conf['db_name'])
		self.cursor = self.db_connection.cursor(buffered=True)
		self.queue = queue

		self.api_key = conf['vm_api']
		self.post_scan_url = conf['post_scan_url']
		self.post_rescan_url = conf['post_rescan_url']
		self.get_report_url = conf['get_report_url']
		conf_file.close()


	def check_av(self, av_name):
		tmp_query = ("SELECT name FROM AntiVirus WHERE name = %s")
		self.cursor.execute(tmp_query, (av_name,))

		if self.cursor.rowcount <= 0:
			tmp_query = ("INSERT INTO AntiVirus(name) VALUES(%s)")
			self.cursor.execute(tmp_query, (av_name,))
			self.db_connection.commit()


	def run(self):

		print("[VM] VirusMonitor started")
		was_empty = True

		while True:

			print("[VM] Checking if there are files in directory to scan")
			path, dirs, files = next(os.walk("../FlaskApp/tmp_files"))
			for file_ in files:
				try:
					self.scan(file_)
					os.remove("tmp_files/" + file_)
					print("[VM] File " + file_ + " successfully scanned and deleted")
				except Exception as e:
					print("[VM] Some problem happened scanning file\n" + str(e))


			print("[VM] Querying files to control")
			query = ("SELECT id FROM File WHERE next_scan < NOW() ORDER BY next_scan LIMIT 10")
			self.cursor.execute(query)

			print("[VM] Got {}/10 files to scan".format(self.cursor.rowcount))
			for x in range(self.cursor.rowcount):
				self.queue.put((0, str(self.cursor.fetchone()[0])))

			while not self.queue.isEmpty():

				was_empty = False
				tmp = self.queue.get()

				#action = 0 OR 1 OR 2
				#action = 0 => id_ = file id to rescan
				#action = 1 => id_ = file id to get report and update
				action_ = tmp[0]
				id_ = tmp[1]

				print("[VM] Checking file with id = {}, action = {}".format(id_, action_))

				try:
					if action_ == 0:
						self.rescan(id_)

					elif action_ == 1:
						self.update(id_)

				except Exception as e:
					print('[VM] Some error happened')
					print(str(e))

				print("[VM] Going to sleep for 15 seconds")
				time.sleep(16)

			if was_empty:
				print("[VM] Going to sleep for 5 minutes")
				self.db_connection.commit()
				time.sleep(300)
			
			was_empty = True


#END run() function


	def rescan(self, id_):
		print("[VM] Re-scanning file")
		query = ("SELECT resource_id FROM File WHERE id = %s")
		self.cursor.execute(query, (id_,))
		resource_ = self.cursor.fetchone()[0]

		print("[VM] Submitting resource to VirusTotal")
		params = {'apikey': self.api_key, 'resource': resource_}
		response = requests.post(self.post_rescan_url, params=params)
		print("[VM] Received response")		

		response_json = response.json()
		if response_json['response_code'] == 1:
			print("[VM] Resource submitted successfully")
			nextscan_ = datetime.now() + timedelta(hours=12)
			query = ("UPDATE File SET next_scan = %s WHERE id = %s")
			self.cursor.execute(query, (nextscan_,id_,))
			self.db_connection.commit()
			self.queue.put((1,id_))
			
		else:
			print("[VM] Couldn't submit resource")
			nextscan_ = datetime.now() + timedelta(hours=1)
			query = ("UPDATE File SET next_scan = %s WHERE id = %s")
			self.cursor.execute(query, (nextscan_,id_,))
			self.db_connection.commit()


	def update(self, id_):
		print("[VM] Updating file")
		query = ("SELECT resource_id FROM File WHERE id = %s")
		self.cursor.execute(query, (id_,))
		resource_ = self.cursor.fetchone()[0]

		print("[VM] Requesting data from VirusTotal")
		params = {'apikey': self.api_key, 'resource': resource_}
		response = requests.post(self.get_report_url, params=params)
		print("[VM] Data received")

		report_data = response.json()
		if report_data['response_code'] == 1:
			print("[VM] Report is ready")
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
							print("[VM] False positive already registered")

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
						print("[VM] AntiVirus-File already registered as processed")

		else:
			print("[VM] Report is NOT ready")
			self.queue.put((1, id_))


	def scan(self, filename):
		print("[VM] Scanning file " + filename)
		params = {'apikey': self.api_key}
		files = {'file': (filename, open("tmp_files/" + filename, "rb"))}
		response = requests.post(self.post_scan_url, files=files, params=params)
		response_data = response.json()

		if response_data['response_code'] == 1:
			self.insert(response_data['resource'], filename)
			print("[VM] Scan succesfull")
		else:
			print("[VM] Some problem happened\n" + response_data['verbose_msg'])

		print("[VM] Going to sleep for 15 seconds")
		time.sleep(16)


	def insert(self, resource_id_, file_name_):
		print("[VM] Inserting file")
		query = ("INSERT INTO File(name,resource_id,next_scan) VALUES(%s,%s,%s)")
		nextscan_ = datetime.now() + timedelta(hours=12)
		try:
			self.cursor.execute(query, (file_name_,resource_id_,nextscan_,))
			self.db_connection.commit()
			print("[VM] File successfully inserted")
			newfile_id = self.cursor.lastrowid
			self.queue.put((1, str(newfile_id)))
			print("[VM] File successfully queued for update")

		except mysql.connector.IntegrityError:
			print("[VM] File already registered")


if __name__ == '__main__':
	queue = BlockingQueue.BlockingQueue()

	vm = VirusMonitor(queue)
	vm.start()
