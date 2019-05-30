import json
import time
import requests
import sys
import mysql.connector
from threading import Thread, Lock, RLock, Condition
from socket import *

from ClientListener import ClientListener
from VirusMonitor import VirusMonitor
from BlockingQueue import BlockingQueue
from SyncPrint import SyncPrint

#ogni cella della blocking queue ha 2 valori: il primo ne identifica l'azione
tasks_queue = BlockingQueue()

#classe per eseguire print sincronizzati
sync_print = SyncPrint()

conf_file = open('ServerConfig.json')
conf_info = json.loads(conf_file.read())
db_connection = mysql.connector.connect(
	user=conf_info['db_user'], password=conf_info['db_password'],
	host=conf_info['db_host'], database=conf_info['db_name'])

listener_port = conf_info['host_port']
conf_file.close()

virus_monitor = VirusMonitor(db_connection,tasks_queue,sync_print)
client_listener = ClientListener(db_connection,tasks_queue,sync_print, listener_port)

try:
	virus_monitor.start()
	client_listener.start()
except:
	db_connection.close()







	
