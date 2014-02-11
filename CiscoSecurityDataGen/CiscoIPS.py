import time,sys,os,traceback,random

## Define the events per second
EPS = 1

## Get common app vars, IPS's, sigs, etc. 


# Initialze vars
int_ips = open(os.path.join('data','internal')).readlines()
ext_ips = open(os.path.join('data','external')).readlines()
hostId = ["sensor1.acme","sensor.dmz","sensor.honeypot"]
mars_category = ["Info/Misc/Routing","Info/Misc","DoS/Host","DoS/Network/UDP","Penetrate/ArpPoisoning","Info/AllSession"]
sigs = open(os.path.join('data','ips_sigs') ).readlines()

## Define output log
log_out = open(os.path.join('logs','ips_sdee.log.ips.secure.acme'),'w')


def getRandomEvent():
	print "getRandomEvent()"
def getTransaction():
	print "getTransaction()"

def writeTransaction(ip):
	user = users[random.randint(0,len(users)-1)].replace("\n","")
	t = time.time() - 12500
	for line in bad_wsa:
		ts =  t + 60
		l = line.replace('###C_IP###',dest_ip).replace('###USER###',user)
		l = str(ts) + l[l.find(' '):]
		wsa_log.writelines(l)
		wsa_log.flush()


def getCurrentEvent():
	int_ips = open(os.path.join('data','internal')).readlines()
	ext_ips = open(os.path.join('data','external')).readlines()
	hostId = ["sensor1.acme","sensor.dmz","sensor.honeypot"]
	mars_category = ["Info/Misc/Routing","Info/Misc","DoS/Host","DoS/Network/UDP","Penetrate/ArpPoisoning","Info/AllSession"]
	sigs = open(os.path.join('data','ips_sigs') ).readlines()
	severity=["informational","severe","warn","severe","severe","severe","severe","severe"]

	int_ip = int_ips[random.randint(0,len(int_ips)-1)].replace("\n","")
	ext_ip = ext_ips[random.randint(0,len(ext_ips)-1)].replace("\n","")
	hostId = hostId[random.randint(0,len(hostId)-1)].replace("\n","")
	mars_category = mars_category[random.randint(0,len(mars_category)-1)].replace("\n","")
	sigs = sigs[random.randint(0,len(sigs)-1)].replace("\n","")
	fieldDict = {}
	ts = time.strftime('%b %d %Y %X')
	fieldDict["ts"] = ts
	full_sig = sigs.replace("\n","").split("#")
 	fieldDict["sig_id"] = full_sig[0]
 	fieldDict["sig_desc"] = full_sig[1]
	fieldDict["mars_category"] = mars_category.replace("\n","")
	fieldDict["severity"] = severity[random.randint(0,len(severity)-1)]
	fieldDict["hostId"] = hostId[random.randint(0,len(hostId)-1)]
	fieldDict["gc_score"] = str(random.randint(-5,5) )
	fieldDict["gc_riskdelta"] = str(random.randint(1,4) )
	dest_count	 = random.randint(1,4)

	targets = ""
	x = 0
	while x < dest_count:
		targets = targets + 'target='+int_ips[random.randint(0,len(int_ips)-1)].replace("\n","")+" "
		x = x + 1 
	fieldDict["target"] = targets
	evt = fieldDict["ts"] + " eventid='1278457197410173971' severity="+fieldDict["severity"] + ' mars_category="'+fieldDict["mars_category"]+"\" hostId="+fieldDict["hostId"]+" signature="+fieldDict["sig_id"] + " description=\"" + fieldDict["sig_desc"]  + "\" attacker=" + ext_ip +" " + fieldDict["target"] + 	' gc_score="'+fieldDict["gc_score"]+'" gc_riskdelta="'+fieldDict["gc_riskdelta"]+'" gc_riskrating="false" gc_deny_packet="true" gc_deny_attacker="false"\n'
	return evt
	

while True:
	e = 0
	while True:
		if e < EPS:
			evt = getCurrentEvent()
			log_out.writelines(evt)
			log_out.flush()	
			e = e + 1
		else:
			e = 0 
			evt = getCurrentEvent()

			log_out.writelines(evt)
			log_out.flush()	
			time.sleep(2)