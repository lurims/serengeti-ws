/******************************************************************************
 *   Copyright (c) 2012 VMware, Inc. All Rights Reserved.
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 ******************************************************************************/
package com.vmware.bdd.cli.command.tests;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.codehaus.jackson.JsonParseException;
import org.codehaus.jackson.map.JsonMappingException;
import org.springframework.shell.support.util.Assert;
import org.testng.annotations.Test;
import static org.testng.AssertJUnit.assertEquals;

import com.vmware.bdd.apitypes.ClusterCreate;
import com.vmware.bdd.apitypes.DistroRead;
import com.vmware.bdd.apitypes.NodeGroupCreate;
import com.vmware.bdd.cli.commands.CommandsUtils;

public class CommandsUtilsTest {

   @Test
   public void testCommandsUtils() {

      String name01 = " , ,";
      List<String> test01 = CommandsUtils.inputsConvert(name01);
      List<String> testDef01 = new ArrayList<String>(0);
      System.out.println(test01.toString());
      assertEquals(test01, testDef01);

      String name02 = " , ,.";
      List<String> test02 = CommandsUtils.inputsConvert(name02);
      List<String> testDef02 = new ArrayList<String>(0);
      testDef02.add(".");
      System.out.println(test02.toString());
      assertEquals(test02, testDef02);

      String name03 = " a, b,c";
      List<String> test03 = CommandsUtils.inputsConvert(name03);
      List<String> testDef03 = new ArrayList<String>(0);
      testDef03.add("a");
      testDef03.add("b");
      testDef03.add("c");
      System.out.println(test03.toString());
      assertEquals(test03, testDef03);
   }

   @Test(enabled = false)
   public void testDataFromFile() throws Exception {
      String path01 = "C:/Users/weiw/aurora_bigdata/spec.txt";
      String path02 = "spec.txt";
      String path03 = "C:/Users/weiw/aurora_bigdata/spectt.txt";

      String test01 = CommandsUtils.dataFromFile(path01);
      System.out.println(test01);
      try {
         NodeGroupCreate[] NodeGroupsCreate01 =
               CommandsUtils.getObjectByJsonString(NodeGroupCreate[].class,
                     test01);

         System.out.println("Test: "
               + NodeGroupsCreate01[0].getStorage().getSizeGB());
         assertEquals(NodeGroupsCreate01.length, 3);
         assertEquals(NodeGroupsCreate01[0].getName(), "master");
         assertEquals(NodeGroupsCreate01[0].getStorage().getDsNames().size(), 2);
         assertEquals(NodeGroupsCreate01[1].getName(), "worker");
         assertEquals(NodeGroupsCreate01[1].getStorage().getDsNames(), null);
         assertEquals(NodeGroupsCreate01[2].getName(), "client");
      } catch (Exception ex) {
         System.out.println(ex.getMessage());
         assert (true);
      }

      try {
         CommandsUtils.dataFromFile(path02);
      } catch (Exception e) {
         assert (true);
      }
      String test03 = CommandsUtils.dataFromFile(path03);
      System.out.println(test03);

      NodeGroupCreate[] NodeGroupsCreate03 =
            CommandsUtils
                  .getObjectByJsonString(NodeGroupCreate[].class, test03);

      assertEquals(NodeGroupsCreate03.length, 3);
      assertEquals(NodeGroupsCreate03[0].getName(), "master");
      assertEquals(NodeGroupsCreate03[1].getName(), "worker");
      assertEquals(NodeGroupsCreate03[2].getName(), "client");

   }


   @Test
   public void testIsBank() {
      assertEquals(CommandsUtils.isBlank(null), true);
      assertEquals(CommandsUtils.isBlank(""), true);
      assertEquals(CommandsUtils.isBlank(" "), true);
      assertEquals(CommandsUtils.isBlank("12345"), false);
      assertEquals(CommandsUtils.isBlank(" 12345 "), false);
   }

   @Test
   public void testCheckDistro() {
      DistroRead[] distros = new DistroRead[2];

      DistroRead distro1 = new DistroRead();
      distro1.setName("Apache");
      List<String> roles1 = new ArrayList<String>();
      roles1.add("NameNode");
      roles1.add("JobTracker");
      roles1.add("DataNode");
      roles1.add("HadoopClient");
      distro1.setRoles(roles1);

      DistroRead distro2 = new DistroRead();
      distro2.setName("GP");
      List<String> roles2 = new ArrayList<String>();
      roles2.add("NameNode");
      roles2.add("JobTracker");
      roles2.add("DataNode");
      roles2.add("HadoopClient");
      roles2.add("PIG");
      roles2.add("HIVE");

      distro2.setRoles(roles2);

      distros[0] = distro1;
      distros[1] = distro2;

      String distroNames = "";
      //String distro01 = "Apache";
      String distro02 = "CDH3";
      for (DistroRead name : distros)
         if (distro02.equals(name.getName())) {
            distroNames = "";
            break;
         } else {
            distroNames = distroNames + name.getName() + " ";
         }
      distroNames = distroNames.trim().replaceAll(" ", ",");

      assertEquals(distroNames, "Apache,GP");
   }

   @Test
   @SuppressWarnings("unchecked")
   public void testGetObjectByJsonString() throws JsonParseException,
         JsonMappingException, IOException {
      StringBuilder jsonBuff = new StringBuilder();
      jsonBuff
            .append("{  ")
            .append(" \"nodeGroups\": [ ")
            .append("      {            ")
            .append("        \"name\": \"master\"  ,  ")
            .append("        \"roles\": [             ")
            .append("        \"hadoop_namenode\"   ,  ")
            .append("        \"hadoop_jobtracker\"   ")
            .append("         ],                      ")
            .append("        \"instanceNum\": 1,             ")
            .append("        \"cpuNum\": 2,                  ")
            .append("        \"memCapacityMB\":2048,         ")
            .append("        \"storage\": {                  ")
            .append("        \"type\": \"SHARED\",           ")
            .append("        \"sizeGB\": 10                  ")
            .append("         },                               ")
            .append("    \"configuration\": {            ")
            .append("       \"hadoop\": {                ")
            .append("           \"core-site.xml\" : {           ")
            .append(
                  "           \"fs.default.name\": \"hdfs://localhost:8020\" ")
            .append("        },                            ")
            .append("       \"hdfs-site.xml\" : {           ")
            .append("          \"dfs.replication\": 4          ")
            .append("       },                               ")
            .append("       \"mapred-site.xml\" : {         ")
            .append("          \"mapred.map.tasks\": 5          ")
            .append("      },                             ")
            .append("      \"hadoop-env.sh\" : {           ")
            .append(
                  "         \"JAVA_HOME\": \"/path/to/javahome\"              ")
            .append("      },                              ")
            .append("     \"log4j.properties\" : {        ")
            .append("       \"hadoop.root.logger\": \"DEBUG,console\" ")
            .append("      }                                          ")
            .append("    }                                          ")
            .append("  }                                          ")
            .append("}, ").append("{").append("      \"name\": \"worker\",  ")
            .append("      \"roles\": [           ")
            .append("          \"hadoop_datanode\",   ")
            .append("          \"hadoop_tasktracker\" ").append("       ], ")
            .append("      \"instanceNum\": 3, ")
            .append("      \"cpuNum\": 2, ")
            .append("      \"memCapacityMB\":2048, ")
            .append("      \"storage\": {          ")
            .append("      \"type\": \"SHARED\",   ")
            .append("      \"sizeGB\": 10          ")
            .append("     }                        ")
            .append("   }                          ").append("], ")
            .append(" \"configuration\": {   ")
            .append(" \"hadoop\": {          ")
            .append(" \"core-site.xml\" : {  ")
            .append(" \"fs.default.name\": \"hdfs://fqdn_or_ip:8020\",")
            .append(" \"dfs.data.dir\":\"/data/\", ")
            .append(" \"dfs.http.address\":\"localhost\" ").append("}, ")
            .append(" \"hdfs-site.xml\" : {  ")
            .append(" \"dfs.repliation\": 2   ").append("}, ")
            .append(" \"mapred-site.xml\" : { ")
            .append(" \"mapred.map.tasks\": 3 ").append(" }, ")
            .append(" \"hadoop-env.sh\" : {   ")
            .append(" \"JAVA_HOME\": \"/path/to/javahome\" ").append(" }, ")
            .append("\"log4j.properties\" : {              ")
            .append("\"hadoop.root.logger\": \"DEBUG,console\" ")
            .append("  } ").append("}  ").append("} ").append("}");
      ClusterCreate clusterCreate =
            CommandsUtils.getObjectByJsonString(ClusterCreate.class,
                  jsonBuff.toString());
      Assert.notNull(clusterCreate);
      Map<String, Object> hadoopConfig =
            (Map<String, Object>) clusterCreate.getConfiguration()
                  .get("hadoop");
      Map<String, Object> coreSiteConfig =
            (Map<String, Object>) hadoopConfig.get("core-site.xml");
      assertEquals(coreSiteConfig.get("fs.default.name"),
            "hdfs://fqdn_or_ip:8020");
   }

}
