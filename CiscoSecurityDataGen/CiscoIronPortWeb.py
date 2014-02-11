import time,sys,os,traceback,random

## Define the events per second
EPS = 1

## Get common app vars, IPS's, sigs, etc. 


# Initialze vars
int_ips = open(os.path.join('data','internal')).readlines()

## Get required log samples 
log_sample  = open(os.path.join('data','cisco_wsa.log'),'r').readlines()


## Define output log
log_out = open(os.path.join('logs','ironport_web.log'),'w')

def getCurrentEvent(evt):
	int_ip = int_ips[random.randint(0,len(int_ips)-1)].replace("\n","")
	ts = time.time()
	line  =  str(ts) + evt[evt.find(' '):].replace('###C_IP###',int_ip)
	return line
	

while True:
	e = 0
	for line in log_sample:
		if e < EPS:
			l = getCurrentEvent(line)
			log_out.writelines(l)
			log_out.flush()	
			e = e + 1
		else:
			e = 0 
			l = getCurrentEvent(line)
			log_out.writelines(l)
			log_out.flush()	
			time.sleep(1)


