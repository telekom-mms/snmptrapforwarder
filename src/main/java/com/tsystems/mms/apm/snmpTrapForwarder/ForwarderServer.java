/*Copyright 2019 T-Systems Multimedia Solutions GmbH (https://www.t-systems-mms.com/) 

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Author: Kay Koedel
*/

package com.tsystems.mms.apm.snmpTrapForwarder;


import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;



public class ForwarderServer  {


	private static final Logger log = LogManager.getLogger("standard");
	private  Properties properties = new Properties();
	
	  
	  public void start() {
	    readConfig();
	    
	    try {
	      SNMPTrapReceiver.start();
	      log.info("Starting SNMPForwarderServer complete ");
	      log.info("*************************************************************************");
	      SNMPTrapSender sender = new SNMPTrapSender();
	      // just for internal test
	      // sender.send("test");

	    } catch (Exception e) {
	      log.error(e);
	    } 
	  }
	public void readConfig() {

		InputStream input = null;

		try {

			input = this.getClass()
					.getResourceAsStream("/META-INF/maven/com.tsystems.mms.apm.snmpTrapForwarder/SNMPTrapForwarder/pom.properties");
			properties.load(input);
			if (properties.containsKey("version")) {
				log.info("Version: " + properties.getProperty("version"));
			}
		} catch (Exception e) {
			log.error(e);
		} finally {
			if (input != null) {
				try {
					input.close();
				} catch (IOException e) {
					log.error(e);
				}
			}
		}

		try {

			input = new FileInputStream("config/config.properties");
			
			// load a properties file
			properties.load(input);

			Config.getInstance().setConfig(properties);
			
			// get the property value and print it out
			log.info("receiver_host: " + properties.getProperty("receiver_host"));
			log.info("receiver_port: " + properties.getProperty("receiver_port"));
			log.info("sender_host: " + properties.getProperty("sender_host"));
			log.info("sender_port: " + properties.getProperty("sender_port"));

			
			log.info("keystore_path: " + properties.getProperty("keystore_path"));
			log.debug("keystore_pass: " + properties.getProperty("keystore_pass"));

			log.info("snmp_securityname: " + properties.getProperty("snmp_securityname"));
			log.info("snmp_authpassphrase: " + properties.getProperty("snmp_authpassphrase"));
			log.info("snmp_privpassphrase: " + properties.getProperty("snmp_privpassphrase"));
			log.info("snmp_engineid: " + properties.getProperty("snmp_engineid"));
			log.info("snmp_securitycypher: " + properties.getProperty("snmp_securitycypher"));
			log.info("snmp_authcypher: " + properties.getProperty("snmp_authcypher"));
			log.info("snmp_oid: " + properties.getProperty("snmp_oid"));
			log.info("snmp_extra_oid: " + properties.getProperty("snmp_extra_oid"));
			
		} catch (IOException e) {
			log.error(e.getClass().toString(), e);
		} finally {
			if (input != null) {
				try {
					input.close();
				} catch (Exception e) {
					log.error(e);
				}
			}
		}

	}

	
	
		
	
	
}