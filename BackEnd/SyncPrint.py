from threading import Lock
import datetime

class SyncPrint:
	def __init__(self):
		self.lock = Lock()

	def print(self, stri):
		self.lock.acquire()
		now = datetime.datetime.now()
		clock = "[" + str(now.hour) + ":" + str(now.minute) + "]"
		print(clock + stri)
		self.lock.release()
