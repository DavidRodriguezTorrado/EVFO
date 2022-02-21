import time
from datetime import datetime
import calendar

def dateorder(file):
    original_log = 'Feb 25 12:21:33 bastion snort: [1:483:5] ICMP PING CyberKit 2.2 Windows [Classification: Misc activity] [Priority: 3]: {ICMP} 70.81.243.88 -> 11.11.79.100'

    second_log = '210.116.59.164 - - [13/Mar/2005:04:09:00 -0500] "POST /_vti_bin/_vti_aut/fp30reg.dll HTTP/1.1" 404 1063 "-" "-"'

    third_log = 'Mar 13 04:16:16 combo sendmail[26065]: j2D9FD3X026065: from=root, size=39455, class=0, nrcpts=1, msgid=<200503130915.j2D9FD3X026065@combo.honeypotbox.com>, relay=root@localhost'

    ### First log
    if file == 1:
        f = open('./snortsyslog')
        original_log = f.read()
        date_string = '2005 ' + original_log[:original_log.find('bastion')-1]
        #print(date_string)

        #print("date_string =", date_string)

        date_object = datetime.strptime(date_string, "%Y %b %d %X")

        #print("date_object =", date_object)
        #print("type of date_object =", type(date_object))

        fmt = ("%Y-%m-%d %H:%M:%S")

        epochDate = int(calendar.timegm(time.strptime(str(date_object), fmt)))
        print('date: ', epochDate)
        #print('tipo: ', type(epochDate))


    ### Second log
    if file == 2:
        f = open('./access_log')
        second_log = f.read()
        date_string = second_log[second_log.find('[')+1:second_log.find('-0500')-1]
        print(date_string)

        fmt = ("%d/%b/%Y:%H:%M:%S")
        epochDate = int(calendar.timegm(time.strptime(str(date_string), fmt)))
        print(epochDate)

    ### Third log
    if file == 3:
        f = open('./maillog')
        third_log = f.read()
        date_string = '2005 ' + third_log[:third_log.find('combo')-1]
        date_object = datetime.strptime(date_string, "%Y %b %d %X")

        fmt = ("%Y-%m-%d %H:%M:%S")

        epochDate = int(calendar.timegm(time.strptime(str(date_object), fmt)))
        print(epochDate)

dateorder(1)
dateorder(2)
dateorder(3)
