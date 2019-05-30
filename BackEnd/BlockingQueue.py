from threading import Lock, Condition

#BLOCKING QUEUE FOR TASKS
#2 tipi di task: 
#id > 0 ==> semplice get report da virustotal e memorizazzione db in caso di nuovi av
#id = -1 ==> get report finchè non è pronto, stato da poco submittato, memorizzazione db nuovo file quando pronto

class BlockingQueue:

	def __init__(self):
		self.lock = Lock()
		self.full_condition = Condition(self.lock)
		self.empty_condition = Condition(self.lock)
		self.ins = 0
		self.out = 0
		self.slotPieni = 0
		self.dim = 1000
		self.thebuffer = [None] * self.dim
        
	def put(self,c):
		self.lock.acquire()

		while self.slotPieni == len(self.thebuffer):
			self.full_condition.wait()
        
		self.thebuffer[self.ins] = c
		self.ins = (self.ins + 1) % len(self.thebuffer)

		#
		# Notifico se passo da 0 slot liberi a 1. Inutile fare notifiche altrimenti.
		#
		if self.slotPieni == 0:
			self.empty_condition.notifyAll()

		self.slotPieni += 1
		self.lock.release()


	def get(self): 

		self.lock.acquire()
		try:
			while self.slotPieni == 0:
				self.empty_condition.wait()
    
			returnValue = self.thebuffer[self.out]
			self.out = (self.out + 1) % len(self.thebuffer)
			#
			# Se sto per liberare un posto, notifico. Altrimenti non c'è bisogno
			#
			if self.slotPieni == len(self.thebuffer):
				self.full_condition.notifyAll()

			self.slotPieni -= 1
			return returnValue
		finally:
			self.lock.release()

	
	def isEmpty(self):
		return self.ins == self.out