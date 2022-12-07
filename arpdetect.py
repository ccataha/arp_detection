from scapy.all import Ether, ARP, srp, sniff, conf
import time, logging

mes = "%(asctime)s %(message)s"
logging.basicConfig(format = mes, level=logging.INFO, filename="arp_log.log", filemode="w")

from collections import Counter
packet_counts = Counter() #каунтер для пакетов
def arp_check2(packet):
    if packet.haslayer(ARP):
        logging.info("ARP conversation started")
        if packet[ARP].op == 1:    #SCAPY ARP STATES ОР1 - "who-has"
            logging.info("ARP 'WHO-HAS' SNIFFED")  
        if packet[ARP].op == 2: #SCAPY ARP STATES OP2 - "is-at" Если получен АРП реплай
            logging.info("ARP 'IS-AT' SNIFFED")
            timing = time.time() #Старт таймера. Берем текущее время
            logging.info("TIMER STARTED") 
            key = tuple(sorted([packet[0][1].hwsrc, packet[ARP].hwsrc]))  #key - диалог hwsrc - mac адрес который нам отправлен
            packet_counts.update([key])  
            if sum(packet_counts.values()) > 3: logging.info("ARP Spoofing Detected");
            #Обнуление таймера. Если текущее время отличаетсяS на 2 секунды (в задании - N)
            if time.time() - timing > 2: 
                timing = time.time()
                key = 0
                #logging.info("#debug 2s#")

sniff(prn=arp_check2)


