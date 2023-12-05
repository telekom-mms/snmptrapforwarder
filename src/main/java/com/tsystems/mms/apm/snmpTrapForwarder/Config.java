/*Copyright 2022 T-Systems MMS GmbH (https://www.t-systems-mms.com/) 

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

import java.util.Properties;

public class Config {

	 private static final Config config = new Config(); 
	 private Properties properties;
	 
	  private Config() {

      }
          
      public static Config getInstance() {
        return config;
      } 
      
      public String getValue(String key) {
    	  return properties.getProperty(key);
      }

	public void setConfig(Properties properties) {
		this.properties = properties; 

	}
}
