#!/bin/bash

JAVA_EXECUTABLE=/usr/lib/jvm/jre/bin/java
snmpTrapForwarder_HOME=/opt/snmpTrapForwarder/

start() {


cd ${snmpTrapForwarder_HOME}


nohup ${JAVA_EXECUTABLE} -jar snmpTrapForwarder.jar >/dev/null 2>&1 &
echo $! > snmpTrapForwarder.pid

}

stop() {
cd {snmpTrapForwarder_HOME}
kill -9 `cat snmpTrapForwarder.pid`
rm snmpTrapForwarder.pid

}

case "$1" in 
    start)
       start
       ;;
    stop)
       stop
       ;;
    *)
       echo "Usage: $0 {start|stop}"
esac

exit 0 
