(Note: This README file added by interested 3rd party, so your mileage may vary!)

Python code to generate mock log data, reading template logs,
and substituting in random values from lists.

Usage:
    * Edit python script, set EPS (events per second) to the volume you want
    * python CiscoXyz.py
    * control-C when yuo have enough data
    * output will be in logs

CiscoIPS.py
    * Correpsonds to Silk parsing config
    Reads from data/:
        Lists: internal, external, ips_sigs
    Hard-coded lists:
        hostId(s), mars_category(ies), severity(in getCurrentEvent)
    Writes to logs/:
        ips_sdee.log.ips.secure.acme
    Parse with:
        logstash_configs/silk_ciscoips

CiscoFirewall.py
    Reads from data/:
        Templates: cisco_asa.log, bad_wsa_traffic
        Lists: internal, external, users
    Writes to logs/:
        cisco_firewall.log, wsa_web_proxy.log

CiscoIronPortWeb.py
    Reads from data/:
        Template: cisco_wsa.log
        Lists: internal
    Writes to logs/:
        ironport_web.log


Data directory contains Template Logs and Lists of values
Value lists are one per line

data/
    # Sample/Template Logs
    bad_wsa_traffic
    cisco_asa.log
    cisco_csa.log
    cisco_esa.log
    cisco_wsa.log
    cs_mars.sample
    # Lists of Values
    external   # eg: 109.120.128.18, 110.152.0.14
    internal   # eg: 10.2.1.44, 12.130.60.4
    ips_sigs   # eg: 3146-0#Bropia Worm Activity, 3150-0#FTP SITE
    urls       # eg: "www.rpmfind.com", "www.gonemovies.com"
    users      # List of usernames, eg: bashful grumpy sneezy...

Sample Output

logs/
    cisco_firewall.log
    wsa_web_proxy.log

README.txt
