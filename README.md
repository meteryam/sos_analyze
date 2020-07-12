Script used to analyze the sosreport file (focus on Satellite info)

To use it.

1. Extract the sosreport
```
# ll
-rw-------. 1 root root 21735576 Mar  7 15:57 sosreport-sat64test-123456-2019-03-07-obvjctv.tar.xz
#

# tar xf sosreport-sat64test-123456-2019-03-07-obvjctv.tar.xz 
# ll
drwx------. 14 root root     4096 Mar  7 15:56 sosreport-sat64test-123456-2019-03-07-obvjctv
-rw-------.  1 root root 21735576 Mar  7 15:57 sosreport-sat64test-123456-2019-03-07-obvjctv.tar.xz
# 
```
2. Execute the command as below 
```
<file path or $PATH>/sos_analyze.sh <sosreport_dir>
```
The output will be similar to below
```
$ ./sos_analyze.sh sosreport-sat67test-02644260-2020-07-12-aaohkfx/
The sosreport is: sosreport-sat67test-02644260-2020-07-12-aaohkfx/

creating soft links for compatibility...

### Welcome to Report ###
### CEE/SysMGMT ###

## Date
## Identity
## Platform
## Memory
## Storage
## Proxies
## Network Information
## Environment
## SELinux
## cron
## /var/log/messages

## Satellite Services

## Repos and Packages
## Upgrade
## Subscriptions
## /var/log/rhsm/rhsm.log

## virt-who
## httpd (Apache)
## Tomcat
## qpidd
## qdrouterd
## goferd
## Passenger
## Foreman
## Subscription Watch
## Dynflow
## Katello
## Pulp
/home/remote/jrichards2/sos_analyze.sh: line 2176: grep pulp.agent sosreport-moya67-02644260-2020-07-12-aaohkfx//sos_commands/katello/qpid-stat_-q_--ssl-certificate_.etc.pki.katello.qpid_client_striped.crt_-b_amqps_..localhost_5671 | grep " 1.*1$": No such file or directory
## Candlepin
## Puppet Server
## PostgreSQL
## MongoDB

Calling insights ...
done.


## The output has been saved in these locations:
    report_sosreport-sat67test-02644260-2020-07-12-aaohkfx.log
    /tmp/report_sosreport-sat67test-02644260-2020-07-12-aaohkfx.log

```
3. Check the generated report file
```
$ less /tmp/report-sosreport-sat64test-123456-2019-03-07-obvjctv.log
```


Note. You will see the file as below. The content is all the commands executed by this script.
```
internals_help/executed_commands.txt
```

Hope you enjoy it.
