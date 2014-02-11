import time,sys,os,traceback,random

## Define the events per second
EPS = 1

## Get common app vars, IPS's, sigs, etc. 


# Initialze vars
int_ips = open(os.path.join('data','internal')).readlines()
ext_ips = open(os.path.join('data','external')).readlines()
users = open(os.path.join('data','users')).readlines()

## Get required log samples 
log_sample  = open(os.path.join('data','cisco_asa.log'),'r').readlines()
bad_wsa  = open(os.path.join('data','bad_wsa_traffic'),'r').readlines()

## Define output log
log_out = open(os.path.join('logs','cisco_firewall.log'),'w')
wsa_log = open(os.path.join('logs','wsa_web_proxy.log'),'w')



### Add Data for Last X hours



def getRandomEvent():
	print "getRandomEvent()"
def getTransaction():
	print "getTransaction()"

def genTime(offset=0):
	ts = datetime.utcnow() + timedelta(hours=offset)
	ts = ts + timedelta(seconds=random.randint(17,250))
	ts = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
	return ts


def writeTransaction(ip):
	user = users[random.randint(0,len(users)-1)].replace("\n","")
	t = time.time() - 12500
	for line in bad_wsa:
		ts =  t + 60
		l = line.replace('###C_IP###',dest_ip).replace('###USER###',user)
		l = str(ts) + l[l.find(' '):]
		wsa_log.writelines(l)
		wsa_log.flush()


def getCurrentEvent(evt):
	int_ip = int_ips[random.randint(0,len(int_ips)-1)].replace("\n","")
	ext_ip = ext_ips[random.randint(0,len(ext_ips)-1)].replace("\n","")
	ts = time.strftime('%b %d %Y %X')
	x = evt.find('%ASA')
	line = ts + evt[x-2:]
	line = line.replace('###IP###',ext_ip).replace('###DESTIP###',int_ip)
	return line,ext_ip,int_ip
	

while True:
	e = 0
	
	for line in log_sample:
		if e < EPS:
			l,ip,dest_ip = getCurrentEvent(line)
			if line.find('Dynamic Filter')>0:
				writeTransaction(dest_ip)
			print l
			log_out.writelines(l)
			log_out.flush()	
			e = e + 1
		else:
			e = 0 
			l,ip,dest_ip = getCurrentEvent(line)
			log_out.writelines(l)
			print l
			log_out.flush()	
			time.sleep(1)