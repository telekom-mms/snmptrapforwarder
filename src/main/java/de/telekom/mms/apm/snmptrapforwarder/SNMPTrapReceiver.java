/*Copyright 2023 Deutsche Telekom MMS GmbH (https://www.t-systems-mms.com/) 

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
package de.telekom.mms.apm.snmptrapforwarder;

import java.io.IOException;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.util.Iterator;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.snmp4j.CommandResponder;
import org.snmp4j.CommandResponderEvent;
import org.snmp4j.MessageDispatcherImpl;
import org.snmp4j.PDU;
import org.snmp4j.PDUv1;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.AuthHMAC128SHA224;
import org.snmp4j.security.AuthHMAC192SHA256;
import org.snmp4j.security.AuthHMAC256SHA384;
import org.snmp4j.security.AuthHMAC384SHA512;
import org.snmp4j.security.AuthMD5;
import org.snmp4j.security.AuthSHA;
import org.snmp4j.security.Priv3DES;
import org.snmp4j.security.PrivAES128;
import org.snmp4j.security.PrivAES192;
import org.snmp4j.security.PrivAES256;
import org.snmp4j.security.PrivDES;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.security.UsmUser;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.TcpAddress;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultTcpTransportMapping;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.MultiThreadedMessageDispatcher;
import org.snmp4j.util.ThreadPool;

/**
 * @author
 * 
 */
public class SNMPTrapReceiver implements CommandResponder {

	private static final Logger log = LogManager.getLogger("standard");
	private static final Logger logevent = LogManager.getLogger("event");
	private MultiThreadedMessageDispatcher dispatcher;
	private Snmp snmp = null;
	private Address listenAddress;
	private ThreadPool threadPool;

	public SNMPTrapReceiver() {
	}

	public static void start() {
		new SNMPTrapReceiver().run();
	}

	private void run() {
		try {
			init();
			snmp.addCommandResponder(this);
		} catch (Exception ex) {
			log.error(ex.getMessage());
		}
	}

	private void init() throws UnknownHostException, IOException {
		log.info("now init snmp receiver");
		threadPool = ThreadPool.create("Trap", 10);
		dispatcher = new MultiThreadedMessageDispatcher(threadPool, new MessageDispatcherImpl());

		// TRANSPORT
		listenAddress = GenericAddress.parse(
				System.getProperty("snmp4j.listenAddress", "udp:" + Config.getInstance().getValue("receiver_ip") + "/"
						+ Config.getInstance().getValue("receiver_port")));
		TransportMapping<?> transport;

		if (listenAddress instanceof UdpAddress) {
			transport = new DefaultUdpTransportMapping((UdpAddress) listenAddress);
		} else {
			transport = new DefaultTcpTransportMapping((TcpAddress) listenAddress);
		}

		SecurityProtocols.getInstance().addDefaultProtocols();
		SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthSHA());
		SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthMD5());
		SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthHMAC128SHA224());
		SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthHMAC192SHA256());
		SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthHMAC256SHA384());
		SecurityProtocols.getInstance().addAuthenticationProtocol(new AuthHMAC384SHA512());
		SecurityProtocols.getInstance().addPrivacyProtocol(new Priv3DES());
		SecurityProtocols.getInstance().addPrivacyProtocol(new PrivAES128());
		SecurityProtocols.getInstance().addPrivacyProtocol(new PrivAES192());
		SecurityProtocols.getInstance().addPrivacyProtocol(new PrivAES256());

		// V3 SECURITY
		USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(
				MPv3.createLocalEngineID(new OctetString(Config.getInstance().getValue("snmp_engineid")))), 0);
		log.info("Endinge ID used: " + usm.getLocalEngineID());
		usm.setEngineDiscoveryEnabled(true);

		SecurityModels.getInstance().addSecurityModel(usm);

		snmp = new Snmp(dispatcher, transport);
		snmp.getMessageDispatcher().addMessageProcessingModel(new MPv1());
		snmp.getMessageDispatcher().addMessageProcessingModel(new MPv2c());
		snmp.getMessageDispatcher().addMessageProcessingModel(new MPv3(usm));

		String username = Config.getInstance().getValue("snmp_username");
		String authpassphrase = Config.getInstance().getValue("snmp_authpassphrase");
		
		String privacypassphrase = Config.getInstance().getValue("snmp_privpassphrase");
		
		OID authProtocol = getAuth(Config.getInstance().getValue("snmp_authcypher"));
		OID privProtocol = getPriv(Config.getInstance().getValue("snmp_privcypher"));

		snmp.getUSM().addUser( // SET THE SECURITY PROTOCOLS HERE
				new OctetString(username), new UsmUser(new OctetString(username), authProtocol,
						new OctetString(authpassphrase),  privProtocol, new OctetString(privacypassphrase)));

		snmp.listen();
		log.info("now init snmp receiver done");

	}

	public void processPdu(CommandResponderEvent crEvent) {
		log.info("Now processing new PDU");

		PDU pdu = crEvent.getPDU();
		if (pdu.getType() == PDU.V1TRAP) {

			PDUv1 pduV1 = (PDUv1) pdu;
			log.info("");
			log.info("===== NEW SNMP 1 TRAP RECEIVED ====");
			log.info("agentAddr " + pduV1.getAgentAddress().toString());
			log.info("enterprise " + pduV1.getEnterprise().toString());
			log.info("timeStam" + String.valueOf(pduV1.getTimestamp()));
			log.info("genericTrap" + String.valueOf(pduV1.getGenericTrap()));
			log.info("specificTrap " + String.valueOf(pduV1.getSpecificTrap()));
			log.info("snmpVersion " + String.valueOf(PDU.V1TRAP));
			log.info("communityString " + new String(crEvent.getSecurityName(),Charset.forName("UTF-8")));

		} else if (pdu.getType() == PDU.TRAP) {
			log.info("");
			log.info("===== NEW SNMP 2/3 TRAP RECEIVED ====");

			log.info("errorStatus " + String.valueOf(pdu.getErrorStatus()));
			log.info("errorIndex " + String.valueOf(pdu.getErrorIndex()));
			log.info("requestID " + String.valueOf(pdu.getRequestID()));
			log.info("snmpVersion " + String.valueOf(PDU.TRAP));
			log.info("communityString " + new String(crEvent.getSecurityName(),Charset.forName("UTF-8")));

		}

		List<? extends VariableBinding> varBinds =   pdu.getVariableBindings();
		if (varBinds != null && !varBinds.isEmpty()) {
			Iterator<? extends VariableBinding> varIter = varBinds.iterator();

			
			String trap = "";
			StringBuilder resultset = new StringBuilder();
			resultset.append("-----");
			while (varIter.hasNext()) {
				VariableBinding vb = varIter.next();
				
				String syntaxstr = vb.getVariable().getSyntaxString();
				
				int syntax = vb.getVariable().getSyntax();
				
				if (syntaxstr.equals("OCTET STRING")) {
					trap = trap.concat(vb.getVariable().toString());
				}
				log.info("OID: " + vb.getOid());
				log.info("Value: " + vb.getVariable());
				log.info("syntaxstring: " + syntaxstr);
				log.info("syntax: " + syntax);
				log.info("------");
			}

			log.info("now forwarding the trap");
			SNMPTrapSender sender = new SNMPTrapSender();
			sender.send(trap);
			logevent.info(trap);
			log.info(trap);
			log.info("forwarding the trap done");
			
			
		}
		log.info("==== TRAP END ===");
		log.info("");

	}

	
	/**
	 * Method to return the private protocol given the property
	 * @param privProtocol property
	 * @return protocol
	 */
	public static OID getPriv(String privProtocol) {
	    switch (privProtocol) {
	    case "DES":
	        return PrivDES.ID;
	    case "3DES":
	        return Priv3DES.ID;
	    case "AES128":
	        return PrivAES128.ID;
	    case "AES192":
	        return PrivAES192.ID;
	    case "AES256":
	        return PrivAES256.ID;
	    default:
	        return null;
	    }
	}
	
	/**
	 * Method to return the auth protocol given the property
	 * @param authProtocol property
	 * @return protocol
	 */
	public static OID getAuth(String authProtocol) {
		switch (authProtocol) {
	    case "SHA":
	        return AuthSHA.ID;
	    case "MD5":
	        return AuthMD5.ID;
	    default:
	        return null;
	    }
	}
	
}