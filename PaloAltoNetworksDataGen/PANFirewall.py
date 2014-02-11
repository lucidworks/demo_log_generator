import time,sys,os,traceback,random


## Define the events per second
EPS = 2

## Get common app vars, IPS's, sigs, etc. 


# Initialze vars
int_ips = open(os.path.join('data','internal')).readlines()
ext_ips = open(os.path.join('data','external')).readlines()
users = open(os.path.join('data','users')).readlines()

## Get required log samples 
log_sample  = open(os.path.join('data','pan_log.log'),'r').readlines()
bad_wsa  = open(os.path.join('data','bad_wsa_traffic'),'r').readlines()

## Define output log
log_out = open(os.path.join('logs','pan.log'),'w')
wsa_log = open(os.path.join('logs','wsa_web_proxy.log'),'w')



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
	user = users[random.randint(0,len(users)-1)].replace("\n","")
	current_time = time.localtime()
	ts = time.strftime('%x %X')
	new_line =  '1,'+ts+','+evt.replace('###USER###', user)
	new_line = new_line.replace('###IP###',int_ip)
	return new_line,ext_ip,int_ip
	

while True:
	e = 0
	
	for line in log_sample:
		if e < EPS:
			l,ip,dest_ip = getCurrentEvent(line)

### Bad Web Activity? Remove Cisco replace with squid logs pointing to EXE download OR pan traffic to EXE file
			if line.find('THREAT,spyware')>0:
				writeTransaction(dest_ip)
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