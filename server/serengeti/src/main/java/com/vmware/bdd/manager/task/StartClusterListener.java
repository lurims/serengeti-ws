/***************************************************************************
 * Copyright (c) 2012-2013 VMware, Inc. All Rights Reserved. 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ***************************************************************************/
package com.vmware.bdd.manager.task;

import java.util.Map;

import org.apache.log4j.Logger;

import com.google.gson.Gson;
import com.vmware.bdd.apitypes.ClusterRead.ClusterStatus;
import com.vmware.bdd.dal.DAL;
import com.vmware.bdd.entity.ClusterEntity;
import com.vmware.bdd.utils.AuAssert;
import com.vmware.bdd.utils.BddMessageUtil;
import com.vmware.bdd.utils.ClusterCmdUtil;

public class StartClusterListener implements TaskListener {
   private static final long serialVersionUID = 7606936739226271788L;

   private static final Logger logger = Logger.getLogger(StartClusterListener.class);

   private String clusterName;
   private String nodeGroupName;
   private String nodeName;

   public StartClusterListener(String clusterName, String nodeGroupName, String nodeName) {
      super();
      AuAssert.check(clusterName != null && !clusterName.isEmpty());
      AuAssert.check(nodeGroupName == null || !nodeGroupName.isEmpty());
      AuAssert.check(nodeGroupName == null || !nodeGroupName.isEmpty());
      AuAssert.check(!(nodeName != null && nodeGroupName == null));

      this.clusterName = clusterName;
      this.nodeGroupName = nodeGroupName;
      this.nodeName = nodeName;
   }

   public StartClusterListener(String clusterName) {
      this(clusterName, null, null);
   }

   @Override
   public void onSuccess() {
      logger.debug("start cluster " + clusterName
            + " task listener called onSuccess");

      // only update status when the command is issued on the whole cluster
      if (nodeGroupName == null) {
         ClusterEntity.updateStatus(clusterName, ClusterStatus.RUNNING);
      }
   }

   @Override
   public void onFailure() {
      logger.debug("start cluster listener called onFailure");

      // only update status when the command is issued on the whole cluster
      if (nodeGroupName == null) {
         ClusterEntity.updateStatus(clusterName, ClusterStatus.ERROR);
      }
      logger.error("failed to start cluster nodes "
            + ClusterCmdUtil.getFullNodeName(clusterName, nodeGroupName, nodeName)
            + " set its status as ERROR");
   }

   @Override
   public void onMessage(Map<String, Object> mMap) {
      logger.debug("start cluster nodes "
            + ClusterCmdUtil.getFullNodeName(clusterName, nodeGroupName, nodeName)
            + " task listner received message " + mMap);

      BddMessageUtil.validate(mMap, clusterName);

      ClusterEntity cluster =
            ClusterEntity.findClusterEntityByName(clusterName);
      AuAssert.check(cluster != null);

      // parse cluster data from message and store them in db
      String description =
            (new Gson()).toJson(mMap.get(BddMessageUtil.CLUSTER_DATA_FIELD));
      BddMessageUtil.processClusterData(clusterName, description);
   }

   public String[] getTaskCommand(String clusterNodesName, String fileName) {
      String nodeFullName = 
         ClusterCmdUtil.getFullNodeName(clusterName, nodeGroupName, nodeName);
      return ClusterCmdUtil.getStartClusterNodesCmdArray(nodeFullName, fileName);
   }
}
