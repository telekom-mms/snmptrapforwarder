# snmpTrapForwarder

### What is this?
This it for forwarding snmpTrap and optionally change the protocoll and secure them

#requirements
java-11

### How to build this (from source):
Build with maven "package"
In the "build" folder are all needed files
 * config/*
 * libs/*
 * snmpTrapForwarder.jar
 * snmpTrapForwarder.sh

#snmpTrapForwarder.sh
place correct java-11 path here


### Install
* install Java openJdk-11 "yum install java-11-openjdk-devel"
* copy the files in the build folder to your server
* edit the config.properties file if needed
* edit the log4j.properties file if needed
* chmod u+x /opt/snmpTrapForwader/snmpTrapForwarder.sh
* chmod u+x /opt/snmpTrapForwader/config/snmpTrapForwarder.sh
* execute snmpTrapForwarder.sh

### Usage

send a snmpTrap to the receiver_ip on the receiber_port
It will forward the trapt to the sender_ip on the sender port with the given snmp version and creds


### New Features:

### Configuration

receiver_ip=127.0.0.1
receiver_port=1621

keystore_path=config/keystore.jks
keystore_pass=changeit

sender_ip=127.0.0.1
sender_port=163

#valid is 1 2c 3 3Command
snmp_version=3
snmp_oid=1.3.6.1
snmp_extra_oid=1.3.6.1.4.1
snmp_engineid=
snmp_username=testtest
snmp_securityname=testtest
snmp_authpassphrase=testtest
snmp_privpassphrase=testtest
snmp_authcypher=MD5
snmp_privcypher=AES192


### Start snmpTrapForwarder
use the snmpTrapForwarder.sh start

### Stop snmpTrapForwarder
use the snmpTrapForwarder.sh stop

### Logging
StandardLog: There is a Standard Logfile in the log folder
EventLog: additionanlly we log all events in a special file

### License: 
Copyright 2023 Deutsche Telekom MMS GmbH (https://www.t-systems-mms.com/) 

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

### Author: 
Kay Koedel, kay.koedel@t-systems.com
