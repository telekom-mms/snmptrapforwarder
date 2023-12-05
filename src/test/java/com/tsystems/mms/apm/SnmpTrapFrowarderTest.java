package com.tsystems.mms.apm;

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
import static org.junit.Assert.assertEquals;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import de.telekom.mms.apm.snmptrapforwarder.Config;
import de.telekom.mms.apm.snmptrapforwarder.ForwarderServer;
import de.telekom.mms.apm.snmptrapforwarder.SNMPTrapSender;


/**
 * @author kao
 *
 */
public class SnmpTrapFrowarderTest {

	private ForwarderServer forwarderServer;
	private SNMPTrapSender snmpTrapSender;
	
	
	@Before
	public void setUp() throws Exception {

			
		
	}

	@After
	public void tearDown() throws Exception {
		
	}
	

		
	@Test
	public void testSendEvent() {

		try {

			forwarderServer = new ForwarderServer();
			forwarderServer.start();
			Config.getInstance().setValue("sender_port", Config.getInstance().getValue("receiver_port")); 
			snmpTrapSender = new SNMPTrapSender();
			snmpTrapSender.sendSnmpV3Trap("TestTrapV3");
			snmpTrapSender.sendSnmpV2Trap("TestTrapV2");
			
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			assertEquals(0,1);
		}

		assertEquals(1, 1);

	}



	
		
}
