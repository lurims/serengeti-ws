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
package com.vmware.bdd.manager;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import org.apache.log4j.Logger;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.vmware.bdd.apitypes.ClusterCreate;
import com.vmware.bdd.apitypes.Datastore.DatastoreType;
import com.vmware.bdd.apitypes.DistroRead;
import com.vmware.bdd.apitypes.IpBlock;
import com.vmware.bdd.apitypes.NetworkAdd;
import com.vmware.bdd.apitypes.NodeGroup.PlacementPolicy;
import com.vmware.bdd.apitypes.NodeGroup.PlacementPolicy.GroupAssociation;
import com.vmware.bdd.apitypes.NodeGroup.PlacementPolicy.GroupRacks;
import com.vmware.bdd.apitypes.NodeGroup.PlacementPolicy.GroupRacks.GroupRacksType;
import com.vmware.bdd.apitypes.NodeGroupCreate;
import com.vmware.bdd.apitypes.RackInfo;
import com.vmware.bdd.apitypes.StorageRead;
import com.vmware.bdd.apitypes.TopologyType;
import com.vmware.bdd.dal.DAL;
import com.vmware.bdd.entity.ClusterEntity;
import com.vmware.bdd.entity.IpBlockEntity;
import com.vmware.bdd.entity.NetworkEntity;
import com.vmware.bdd.entity.NodeGroupAssociation;
import com.vmware.bdd.entity.NodeGroupEntity;
import com.vmware.bdd.entity.Saveable;
import com.vmware.bdd.exception.BddException;
import com.vmware.bdd.exception.ClusterConfigException;
import com.vmware.bdd.exception.UniqueConstraintViolationException;
import com.vmware.bdd.specpolicy.CommonClusterExpandPolicy;
import com.vmware.bdd.spectypes.GroupType;
import com.vmware.bdd.spectypes.HadoopRole;
import com.vmware.bdd.spectypes.HadoopRole.RoleComparactor;
import com.vmware.bdd.spectypes.VcCluster;
import com.vmware.bdd.utils.AuAssert;
import com.vmware.bdd.utils.Configuration;
import com.vmware.bdd.utils.Constants;

public class ClusterConfigManager {
   private static final long serialVersionUID = 1L;
   private static final Logger logger = Logger
         .getLogger(ClusterConfigManager.class);
   private static final String TEMPLATE_ID = "template_id";
   private static final String HTTP_PROXY = "serengeti.http_proxy";
   private static final String NO_PROXY = "serengeti.no_proxy";
   private static final String ELASTIC_RUNTIME_AUTOMATION_ENABLE = "elastic_runtime.automation.enable";
   private VcResourcePoolManager rpMgr;
   private NetworkManager networkMgr;
   private DistroManager distroMgr;
   private RackInfoManager rackInfoMgr;
   private VcDataStoreManager datastoreMgr;
   private String templateId = Configuration.getString(TEMPLATE_ID.toString(),
         "centos57-x64");
   private String httpProxy = Configuration.getString(HTTP_PROXY.toString(), "");
   private String noProxy = Configuration.getStrings(NO_PROXY.toString(), "");
   private boolean automationEnable = Configuration.getBoolean(ELASTIC_RUNTIME_AUTOMATION_ENABLE, false); 

   public VcDataStoreManager getDatastoreMgr() {
      return datastoreMgr;
   }

   public void setDatastoreMgr(VcDataStoreManager datastoreMgr) {
      this.datastoreMgr = datastoreMgr;
   }

   public DistroManager getDistroMgr() {
      return distroMgr;
   }

   public void setDistroMgr(DistroManager distroMgr) {
      this.distroMgr = distroMgr;
   }

   public RackInfoManager getRackInfoMgr() {
      return rackInfoMgr;
   }

   public void setRackInfoMgr(RackInfoManager rackInfoMgr) {
      this.rackInfoMgr = rackInfoMgr;
   }

   public VcResourcePoolManager getRpMgr() {
      return rpMgr;
   }

   public void setRpMgr(VcResourcePoolManager rpMgr) {
      this.rpMgr = rpMgr;
   }

   public NetworkManager getNetworkMgr() {
      return networkMgr;
   }

   public void setNetworkMgr(NetworkManager networkMgr) {
      this.networkMgr = networkMgr;
   }

   public ClusterEntity createClusterConfig(final ClusterCreate cluster) {
      final String name = cluster.getName();
      if (name == null || name.isEmpty()) {
         throw ClusterConfigException.CLUSTER_NAME_MISSING();
      }

      List<String> failedMsgList = new ArrayList<String>();
      List<String> warningMsgList = new ArrayList<String>();

      if (cluster.getDistro() == null ||
            distroMgr.getDistroByName(cluster.getDistro()) == null) {
           throw BddException.INVALID_PARAMETER("distro", cluster.getDistro());
      }
      if (!cluster.getDistroVendor().equalsIgnoreCase(Constants.MAPR_VENDOR)) {
         cluster.validateClusterCreate(failedMsgList, warningMsgList, distroMgr
               .getDistroByName(cluster.getDistro()).getRoles());
      }
      if (!failedMsgList.isEmpty()) {
         throw ClusterConfigException.INVALID_SPEC(failedMsgList);
      }

      if (!validateRacksInfo(cluster, failedMsgList)) {
         throw ClusterConfigException.INVALID_PLACEMENT_POLICIES(failedMsgList);
      }

      transformHDFSUrl(cluster);

      try {
         return DAL.inTransactionDo(new Saveable<ClusterEntity>() {
            public ClusterEntity body() {
               ClusterEntity entity =
                     ClusterEntity.findClusterEntityByName(name);
               if (entity != null) {
                  logger.info("can not create cluster " + name
                        + ", which is already existed.");
                  throw BddException.ALREADY_EXISTS("cluster", name);
               }

               // persist cluster config
               logger.debug("begin to add cluster config for " + name);
               Gson gson = new Gson();
               ClusterEntity clusterEntity = new ClusterEntity(name);
               clusterEntity.setDistro(cluster.getDistro());
               clusterEntity.setDistroVendor(cluster.getDistroVendor());
               clusterEntity.setDistroVersion(cluster.getDistroVersion());
               clusterEntity.setStartAfterDeploy(true);

               Boolean autoFlag = cluster.getAutomationEnable();
               if (cluster.containsComputeOnlyNodeGroups()) {
                  if (autoFlag == null) {
                     clusterEntity.setAutomationEnable(automationEnable);
                  } else {
                     clusterEntity.setAutomationEnable(autoFlag);
                  }
               } else if (autoFlag != null) {
                  throw BddException.INVALID_PARAMETER("automation enable", autoFlag);
               }
               clusterEntity.setVhmMinNum(cluster.getVhmMinNum());

               if (cluster.getRpNames() != null
                     && cluster.getRpNames().size() > 0) {
                  logger.debug("resource pool " + cluster.getRpNames()
                        + " specified for cluster " + name);
                  clusterEntity.setVcRpNameList(cluster.getRpNames());
               } else {
                  logger.debug("no resource pool name specified, use global configuration.");
               }
               if (cluster.getDsNames() != null
                     && !cluster.getDsNames().isEmpty()) {
                  logger.debug("datastore " + cluster.getDsNames()
                        + " specified for cluster " + name);
                  clusterEntity.setVcDatastoreNameList(cluster.getDsNames());
               } else {
                  logger.debug("no datastore name specified, use global configuration.");
               }
               String networkName = cluster.getNetworkName();
               NetworkEntity networkEntity = null;
               if (networkName == null || networkName.isEmpty()) {
                  List<NetworkEntity> nets = networkMgr.getAllNetworkEntities();
                  if (nets.isEmpty() || nets.size() > 1) {
                     throw ClusterConfigException.NETWORK_IS_NOT_SPECIFIED(
                           nets.size(), name);
                  } else {
                     networkEntity = nets.get(0);
                  }
               } else {
                  networkEntity = networkMgr.getNetworkEntityByName(networkName);
               }

               if (networkEntity == null) {
                  throw ClusterConfigException.NETWORK_IS_NOT_FOUND(
                        networkName, name);
               }
               clusterEntity.setNetwork(networkEntity);
               if (cluster.getConfiguration() != null
                     && cluster.getConfiguration().size() > 0) {
                  // validate hadoop config
                  CommonClusterExpandPolicy.validateAppConfig(
                        cluster.getConfiguration(), cluster.isValidateConfig());
                  clusterEntity.setHadoopConfig((new Gson()).toJson(cluster
                        .getConfiguration()));
               }

               NodeGroupCreate[] groups = cluster.getNodeGroups();
               if (groups != null && groups.length > 0) {
                  clusterEntity.setNodeGroups(convertNodeGroupsToEntities(gson,
                        clusterEntity, cluster.getDistro(), groups,
                        EnumSet.noneOf(HadoopRole.class), cluster.isValidateConfig()));
               }

               if (cluster.getTopologyPolicy() == null) {
                  clusterEntity.setTopologyPolicy(TopologyType.NONE);
               } else {
                  clusterEntity.setTopologyPolicy(cluster.getTopologyPolicy());
               }

               if (clusterEntity.getTopologyPolicy() == TopologyType.HVE) {
                  boolean hveSupported = false;
                  if (clusterEntity.getDistro() != null) {
                     DistroRead dr = distroMgr.getDistroByName(clusterEntity.getDistro());
                     if (dr != null) {
                        hveSupported = dr.isHveSupported();
                     }
                  }
                  if (!hveSupported) {
                     throw ClusterConfigException.INVALID_TOPOLOGY_POLICY(
                           clusterEntity.getTopologyPolicy(),
                           "current distro does not support HVE");
                  }
               }

               clusterEntity.insert();
               logger.debug("finished to add cluster config for " + name);
               return clusterEntity;
            }
         });
      } catch (UniqueConstraintViolationException ex) {
         logger.info("can not create cluster " + name
               + ", which is already existed.");
         throw BddException.ALREADY_EXISTS(ex, "cluster", name);
      }
   }

   private boolean validateRacksInfo(ClusterCreate cluster, List<String> failedMsgList) {
      boolean valid = true;
      Map<String, NodeGroupCreate> allGroups = new TreeMap<String, NodeGroupCreate>();
      if (cluster.getNodeGroups() == null) {
         return valid;
      }

      List<RackInfo> racksInfo = rackInfoMgr.exportRackInfo();

      if ((cluster.getTopologyPolicy() == TopologyType.HVE || cluster
            .getTopologyPolicy() == TopologyType.RACK_AS_RACK) && racksInfo.isEmpty()) {
         valid = false;
         throw ClusterConfigException.TOPOLOGY_WITH_NO_MAPPING_INFO_EXIST(cluster
               .getTopologyPolicy().toString());
      }

      for (NodeGroupCreate nodeGroupCreate : cluster.getNodeGroups()) {
         allGroups.put(nodeGroupCreate.getName(), nodeGroupCreate);
      }

      for (NodeGroupCreate ngc : cluster.getNodeGroups()) {
         PlacementPolicy policies = ngc.getPlacementPolicies();
         if (policies != null && policies.getGroupAssociations() != null) {
            continue;
         }

         if (ngc.getStorage() != null && ngc.getStorage().getType() != null
               && ngc.getStorage().getType().equals(DatastoreType.SHARED.toString())) {
            continue;
         }

         if (policies != null && policies.getGroupRacks() != null) {
            if (racksInfo.isEmpty()) {
               valid = false;
               throw ClusterConfigException.RACKPOLICY_WITH_NO_MAPPING_INFO_EXIST(ngc
                     .getName());
            }

            GroupRacks r = policies.getGroupRacks();
            GroupRacksType rackType = r.getType();
            Set<String> specifiedRacks = new HashSet<String>(Arrays.asList(r.getRacks()));
            List<String> intersecRacks = new ArrayList<String>();
            int intersecHostNum = 0;
            int maxIntersecHostNum = 0;

            for (RackInfo rackInfo : racksInfo) {
               if (specifiedRacks.isEmpty() || specifiedRacks.size() == 0 || specifiedRacks.contains(rackInfo.getName())) {
                  intersecHostNum += rackInfo.getHosts().size();
                  intersecRacks.add(rackInfo.getName());
                  if (rackInfo.getHosts().size() > maxIntersecHostNum) {
                     maxIntersecHostNum = rackInfo.getHosts().size();
                  }
               }
            }

            if (intersecRacks.size() == 0) {
               valid = false;
               throw ClusterConfigException.NO_VALID_RACK(ngc.getName());
            }

            if (ngc.calculateHostNum() != null) {
               if (rackType.equals(GroupRacksType.ROUNDROBIN)
                     && ngc.calculateHostNum() > intersecHostNum) {
                  valid = false;
                  throw ClusterConfigException.LACK_PHYSICAL_HOSTS(ngc.getName(),
                        ngc.calculateHostNum(), intersecHostNum);
               } else if (rackType.equals(GroupRacksType.SAMERACK) && ngc.calculateHostNum() > maxIntersecHostNum) {
                  valid = false;
                  throw ClusterConfigException.LACK_PHYSICAL_HOSTS(ngc.getName(),
                        ngc.calculateHostNum(), maxIntersecHostNum);
               }
            }

            if (specifiedRacks.isEmpty()) {
               r.setRacks(new String[0]);
            } else {
               r.setRacks(intersecRacks.toArray(new String[intersecRacks.size()]));
            }
         }
      }
      return valid;
   }

   private void transformHDFSUrl(ClusterCreate cluster) {
      if (cluster.hasHDFSUrlConfigured()) {
         if (cluster.validateHDFSUrl()) {
            changeNodeGroupHDFSUrl(cluster.getNodeGroups(),
                  cluster.getExternalHDFS());
            changeClusterHDFSUrl(cluster);
         } else {
            throw BddException.INVALID_PARAMETER("externalHDFS",
                  cluster.getExternalHDFS());
         }
      }
   }

   @SuppressWarnings("unchecked")
   private void changeNodeGroupHDFSUrl(NodeGroupCreate[] nodeGroups,
         final String externalHDFS) {
      if (nodeGroups == null || nodeGroups.length == 0) {
         return;
      }
      String[] configKeyNames =
            new String[] { "hadoop", "core-site.xml", "fs.default.name" };
      for (NodeGroupCreate nodeGroup : nodeGroups) {
         Map<String, Object> conf = nodeGroup.getConfiguration();
         if (conf != null) {
            for (String configKeyName : configKeyNames) {
               if (configKeyName.equals(configKeyNames[configKeyNames.length - 1])) {
                  if (conf.get(configKeyName) != null) {
                     conf.put(configKeyName, externalHDFS);
                  }
               } else {
                  conf = (Map<String, Object>) conf.get(configKeyName);
                  if (conf == null) {
                     break;
                  }
               }
            }
         }
      }
   }

   private void changeClusterHDFSUrl(ClusterCreate cluster) {
      Map<String, Object> conf = cluster.getConfiguration();
      if (conf == null) {
         conf = new HashMap<String, Object>();
         cluster.setConfiguration(conf);
      }
      @SuppressWarnings("unchecked")
      Map<String, Object> hadoopConf = (Map<String, Object>) conf.get("hadoop");
      if (hadoopConf == null) {
         hadoopConf = new HashMap<String, Object>();
         conf.put("hadoop", hadoopConf);
      }
      @SuppressWarnings("unchecked")
      Map<String, Object> coreSiteConf =
            (Map<String, Object>) hadoopConf.get("core-site.xml");
      if (coreSiteConf == null) {
         coreSiteConf = new HashMap<String, Object>();
         hadoopConf.put("core-site.xml", coreSiteConf);
      }
      coreSiteConf.put("fs.default.name", cluster.getExternalHDFS());
   }

   private Set<NodeGroupEntity> convertNodeGroupsToEntities(Gson gson,
         ClusterEntity clusterEntity, String distro, NodeGroupCreate[] groups,
         EnumSet<HadoopRole> allRoles, boolean validateWhiteList) {
      Set<NodeGroupEntity> nodeGroups;
      nodeGroups = new HashSet<NodeGroupEntity>();
      Set<String> referencedNodeGroups = new HashSet<String>();
      for (NodeGroupCreate group : groups) {
         NodeGroupEntity groupEntity =
               convertGroup(gson, clusterEntity, allRoles, group, distro,
                     validateWhiteList);
         if (groupEntity != null) {
            nodeGroups.add(groupEntity);
            if (groupEntity.getStorageType() == DatastoreType.TEMPFS) {
               for (NodeGroupAssociation associate : groupEntity.getGroupAssociations()) {
                  referencedNodeGroups.add(associate.getReferencedGroup());
               }
            }
         }
      }

      //insert tempfs_server role into the referenced data node groups
      for (String nodeGroupName : referencedNodeGroups) {
         for (NodeGroupEntity groupEntity : nodeGroups) {
            if (groupEntity.getName().equals(nodeGroupName)) {
               List<String> sortedRoles = gson.fromJson(groupEntity.getRoles(), List.class);
               sortedRoles.add(0, HadoopRole.TEMPFS_SERVER_ROLE.toString());
               groupEntity.setRoles(gson.toJson(sortedRoles));
            }
         }
      }

      return nodeGroups;
   }

   private NodeGroupEntity convertGroup(Gson gson, ClusterEntity clusterEntity,
         EnumSet<HadoopRole> allRoles, NodeGroupCreate group, String distro,
         boolean validateWhiteList) {
      NodeGroupEntity groupEntity = new NodeGroupEntity();
      if (group.getRoles() == null || group.getRoles().isEmpty()) {
         throw ClusterConfigException.NO_HADOOP_ROLE_SPECIFIED(group.getName());
      }
      Set<String> roles = new HashSet<String>();

      groupEntity.setCluster(clusterEntity);
      groupEntity.setCpuNum(group.getCpuNum());
      groupEntity.setDefineInstanceNum(group.getInstanceNum());
      groupEntity.setMemorySize(group.getMemCapacityMB());
      groupEntity.setName(group.getName());
      groupEntity.setNodeType(group.getInstanceType());

      PlacementPolicy policies = group.getPlacementPolicies();
      if (policies != null) {
         List<GroupAssociation> associons = policies.getGroupAssociations();
         if (associons != null) {
            Set<NodeGroupAssociation> associonEntities = new TreeSet<NodeGroupAssociation>();
            for (GroupAssociation a : associons) {
               NodeGroupAssociation ae = new NodeGroupAssociation();
               ae.setAssociationType(a.getType());
               ae.setNodeGroup(groupEntity);
               ae.setReferencedGroup(a.getReference());
               associonEntities.add(ae);
            }
            groupEntity.setGroupAssociations(associonEntities);
         }
         if (policies.getInstancePerHost() != null) {
            groupEntity.setInstancePerHost(policies.getInstancePerHost());
         }

         if (policies.getGroupRacks() != null) {
            groupEntity.setGroupRacks((new Gson()).toJson(policies.getGroupRacks()));
         }
      }

      if (group.getRpNames() != null && group.getRpNames().size() > 0) {
         groupEntity.setVcRpNameList(group.getRpNames());
      }
      if (group.getStorage() != null) {
         groupEntity.setStorageSize(group.getStorage().getSizeGB());
         List<String> groupRoles = group.getRoles();
         //currently, ignore input from CLI and hard code here
         if ((groupRoles.contains(HadoopRole.ZOOKEEPER_ROLE.toString()) || groupRoles.contains(HadoopRole.MAPR_ZOOKEEPER_ROLE.toString())) && groupRoles.size() == 1) {
            groupEntity.setDiskBisect(true);
         } else {
            groupEntity.setDiskBisect(false);
         }
         String storageType = group.getStorage().getType();
         if (storageType != null) {
            if (storageType.equalsIgnoreCase(DatastoreType.TEMPFS.name())) {
               groupEntity.setStorageType(DatastoreType.TEMPFS);
               roles.add(HadoopRole.TEMPFS_CLIENT_ROLE.toString());
            } else if (storageType.equalsIgnoreCase(DatastoreType.LOCAL.name())) {
               groupEntity.setStorageType(DatastoreType.LOCAL);
            } else {
               groupEntity.setStorageType(DatastoreType.SHARED);
            }
         }
         groupEntity.setVcDatastoreNameList(group.getStorage().getDsNames());
      }

      roles.addAll(group.getRoles());
      List<String> sortedRolesByDependency = new ArrayList<String>();
      sortedRolesByDependency.addAll(roles);
      Collections.sort(sortedRolesByDependency, new RoleComparactor());
      EnumSet<HadoopRole> enumRoles = getEnumRoles(group.getRoles(), distro);
      if (enumRoles.isEmpty()) {
         throw ClusterConfigException.NO_HADOOP_ROLE_SPECIFIED(group.getName());
      }
      groupEntity.setRoles(gson.toJson(sortedRolesByDependency));
      GroupType groupType = GroupType.fromHadoopRole(enumRoles);

      if (groupType == GroupType.CLIENT_GROUP && group.getInstanceNum() <= 0) {
         logger.warn("Zero or negative instance number for group "
               + group.getName()
               + ", remove the client group from cluster spec.");
         return null;
      }

      allRoles.addAll(enumRoles);

      List<String> dsNames = groupEntity.getVcDatastoreNameList();
      if (dsNames == null) {
         dsNames = clusterEntity.getVcDatastoreNameList();
      }
      Set<String> sharedPattern;
      Set<String> localPattern;
      if (dsNames != null) {
         sharedPattern = datastoreMgr.getSharedDatastoresByNames(dsNames);
         localPattern = datastoreMgr.getLocalDatastoresByNames(dsNames);
      } else {
         sharedPattern = datastoreMgr.getAllSharedDatastores();
         localPattern = datastoreMgr.getAllLocalDatastores();
      }

      CommonClusterExpandPolicy.expandGroupInstanceType(groupEntity, groupType,
            sharedPattern, localPattern);
      groupEntity.setHaFlag(group.getHaFlag());
      if (group.getConfiguration() != null
            && group.getConfiguration().size() > 0) {
         // validate hadoop config
         CommonClusterExpandPolicy.validateAppConfig(group.getConfiguration(),
               validateWhiteList);
         groupEntity.setHadoopConfig(gson.toJson(group.getConfiguration()));
      }
      // set vm folder path
      groupEntity.setVmFolderPath(clusterEntity);
      logger.debug("finished to convert node group config for "
            + group.getName());
      return groupEntity;
   }

   public ClusterCreate getClusterConfig(final String clusterName) {
      return DAL.autoTransactionDo(new Saveable<ClusterCreate>() {
         public ClusterCreate body() {

            ClusterEntity clusterEntity =
                  ClusterEntity.findClusterEntityByName(clusterName);
            if (clusterEntity == null) {
               throw ClusterConfigException
                     .CLUSTER_CONFIG_NOT_FOUND(clusterName);
            }
            ClusterCreate clusterConfig = new ClusterCreate();
            clusterConfig.setName(clusterEntity.getName());

            convertClusterConfig(clusterEntity, clusterConfig);

            Gson gson =
                  new GsonBuilder().excludeFieldsWithoutExposeAnnotation()
                        .create();
            String manifest = gson.toJson(clusterConfig);
            logger.debug("final cluster manifest " + manifest);
            return clusterConfig;
         }
      });
   }

   @SuppressWarnings("unchecked")
   private void convertClusterConfig(ClusterEntity clusterEntity,
         ClusterCreate clusterConfig) {
      logger.debug("begin to expand config for cluster "
            + clusterEntity.getName());

      CommonClusterExpandPolicy.expandDistro(clusterEntity, clusterConfig,
            distroMgr);
      clusterConfig.setDistroVendor(clusterEntity.getDistroVendor());
      clusterConfig.setDistroVersion(clusterEntity.getDistroVersion());
      clusterConfig.setHttpProxy(httpProxy);
      clusterConfig.setNoProxy(noProxy);
      clusterConfig.setTopologyPolicy(clusterEntity.getTopologyPolicy());
      clusterConfig.setAutomationEnable(clusterEntity.isAutomationEnable());
      clusterConfig.setVhmMinNum(clusterEntity.getVhmMinNum());

      Map<String, String> hostToRackMap = rackInfoMgr.exportHostRackMap();
      if ((clusterConfig.getTopologyPolicy() == TopologyType.RACK_AS_RACK ||
           clusterConfig.getTopologyPolicy() == TopologyType.HVE) &&
           hostToRackMap.isEmpty()) {
         logger.error("trying to use host-rack topology which is absent");
         throw ClusterConfigException.INVALID_TOPOLOGY_POLICY(
               clusterConfig.getTopologyPolicy(), "no rack information");
      }
      clusterConfig.setHostToRackMap(hostToRackMap);

      clusterConfig.setTemplateId(templateId);
      if (clusterEntity.getVcRpNames() != null) {
         logger.debug("resource pool specified at cluster level.");
         String[] rpNames =
               clusterEntity.getVcRpNameList().toArray(new String[clusterEntity.getVcRpNameList().size()]);
         List<VcCluster> vcClusters =
               rpMgr.getVcResourcePoolByNameList(rpNames);
         clusterConfig.setVcClusters(vcClusters);
         clusterConfig.setRpNames(clusterEntity.getVcRpNameList());
      } else {
         logger.debug("no resource pool config at cluster level.");
      }

      if (clusterEntity.getVcDatastoreNameList() != null) {
         logger.debug("datastore specified at cluster level.");
         Set<String> sharedPattern =
               datastoreMgr.getSharedDatastoresByNames(clusterEntity
                     .getVcDatastoreNameList());
         clusterConfig.setSharedPattern(sharedPattern);
         Set<String> localPattern =
               datastoreMgr.getLocalDatastoresByNames(clusterEntity
                     .getVcDatastoreNameList());
         clusterConfig.setLocalPattern(localPattern);
         clusterConfig.setDsNames(clusterEntity.getVcDatastoreNameList());
      } else {
         logger.debug("no datastore config at cluster level.");
      }
      List<NodeGroupCreate> nodeGroups = new ArrayList<NodeGroupCreate>();

      // TODO need more role checks

      Set<NodeGroupEntity> nodeGroupEntities = clusterEntity.getNodeGroups();
      long instanceNum = 0;

      for (NodeGroupEntity ngEntity : nodeGroupEntities) {
         NodeGroupCreate group =
               convertNodeGroups(clusterEntity.getDistro(), ngEntity,
                     clusterEntity.getName());
         nodeGroups.add(group);
         instanceNum += group.getInstanceNum();
      }
      sortGroups(nodeGroups);
      clusterConfig.setNodeGroups(nodeGroups.toArray(new NodeGroupCreate[nodeGroups.size()]));
      NetworkEntity networkEntity = clusterEntity.getNetwork();
      List<NetworkAdd> networking = new ArrayList<NetworkAdd>();
      NetworkAdd network = new NetworkAdd();
      network.setPortGroup(networkEntity.getPortGroup());
      network
            .setDhcp(networkEntity.getAllocType() == NetworkEntity.AllocType.DHCP);
      if (!network.isDhcp()) {
         logger.debug("using static ip.");
         List<IpBlockEntity> ipBlockEntities =
               networkMgr.getAllocatedIpBlocks(networkEntity,
                     clusterEntity.getId());
         long allocatedIpNum = IpBlockEntity.count(ipBlockEntities);
         if (allocatedIpNum < instanceNum) {
            long newNum = instanceNum - allocatedIpNum;
            List<IpBlockEntity> newIpBlockEntities =
                  networkMgr
                        .alloc(networkEntity, clusterEntity.getId(), newNum);
            ipBlockEntities.addAll(newIpBlockEntities);
         }
         network.setDns1(networkEntity.getDns1());
         network.setDns2(networkEntity.getDns2());
         network.setGateway(networkEntity.getGateway());
         network.setNetmask(networkEntity.getNetmask());
         List<IpBlock> ips = new ArrayList<IpBlock>();
         for (IpBlockEntity ipBlockEntity : ipBlockEntities) {
            IpBlock ip = new IpBlock();
            ip.setBeginIp(ipBlockEntity.getBeginAddress());
            ip.setEndIp(ipBlockEntity.getEndAddress());
            ips.add(ip);
         }
         network.setIp(ips);
      }
      networking.add(network);
      clusterConfig.setNetworking(networking);
      clusterConfig.setNetworkName(networkEntity.getName());
      if (clusterEntity.getHadoopConfig() != null) {
         Map hadoopConfig =
               (new Gson())
                     .fromJson(clusterEntity.getHadoopConfig(), Map.class);
         clusterConfig.setConfiguration((Map<String, Object>) hadoopConfig);
      }
   }

   private void sortGroups(List<NodeGroupCreate> nodeGroups) {
      logger.debug("begin to sort node groups.");
      Collections.sort(nodeGroups, new Comparator<NodeGroupCreate>() {
         public int compare(NodeGroupCreate arg0, NodeGroupCreate arg1) {
            if (arg0.getGroupType().equals(arg1.getGroupType())) {
               return arg0.getName().compareTo(arg1.getName());
            } else {
               return arg0.getGroupType().compareTo(arg1.getGroupType());
            }
         }
      });
   }

   @SuppressWarnings("unchecked")
   private NodeGroupCreate convertNodeGroups(String distro,
         NodeGroupEntity ngEntity, String clusterName) {
      Gson gson = new Gson();
      List<String> groupRoles = gson.fromJson(ngEntity.getRoles(), List.class);
      Collections.sort(groupRoles, new Comparator<String>(){
         public int compare(String str1, String str2) {
            if (HadoopRole.fromString(str1).shouldRunAfterHDFS()) {
               return 1;
            } else if (HadoopRole.fromString(str2).shouldRunAfterHDFS()) {
               return -1;
            } else {
               return 0;
            }  
         }
      });   
      EnumSet<HadoopRole> enumRoles = getEnumRoles(groupRoles, distro);
      if (enumRoles.isEmpty()) {
         throw ClusterConfigException.NO_HADOOP_ROLE_SPECIFIED(ngEntity
               .getName());
      }
      GroupType groupType = GroupType.fromHadoopRole(enumRoles);
      AuAssert.check(groupType != null);
      NodeGroupCreate group = new NodeGroupCreate();
      group.setName(ngEntity.getName());
      group.setGroupType(groupType);
      group.setRoles(groupRoles);
      int cpu = ngEntity.getCpuNum();
      if (cpu > 0) {
         group.setCpuNum(cpu);
      }

      int memory = ngEntity.getMemorySize();
      if (memory > 0) {
         group.setMemCapacityMB(memory);
      }
      if (ngEntity.getNodeType() != null) {
         group.setInstanceType(ngEntity.getNodeType());
      }

      group.setInstanceNum(ngEntity.getDefineInstanceNum());

      Integer instancePerHost = ngEntity.getInstancePerHost();
      Set<NodeGroupAssociation> associonEntities =
            ngEntity.getGroupAssociations();
      String ngRacks = ngEntity.getGroupRacks();
      if (instancePerHost == null
            && (associonEntities == null || associonEntities.isEmpty()) && ngRacks == null) {
         group.setPlacementPolicies(null);
      } else {
         PlacementPolicy policies = new PlacementPolicy();
         policies.setInstancePerHost(instancePerHost);
         if (ngRacks != null) {
            policies.setGroupRacks((GroupRacks) new Gson().fromJson(ngRacks, GroupRacks.class));
         }
         if (associonEntities != null) {
            List<GroupAssociation> associons =
                  new ArrayList<GroupAssociation>(associonEntities.size());
            for (NodeGroupAssociation ae : associonEntities) {
               GroupAssociation a = new GroupAssociation();
               a.setReference(ae.getReferencedGroup());
               a.setType(ae.getAssociationType());
               associons.add(a);
            }
            policies.setGroupAssociations(associons);
         }

         group.setPlacementPolicies(policies);
      }

      String rps = ngEntity.getVcRpNames();
      if (rps != null && rps.length() > 0) {
         logger.debug("resource pool specified at node group "
               + ngEntity.getName());
         String[] rpNames = gson.fromJson(rps, String[].class);
         List<VcCluster> vcClusters =
               rpMgr.getVcResourcePoolByNameList(rpNames);
         group.setVcClusters(vcClusters);
         group.setRpNames(Arrays.asList(rpNames));
      }

      expandGroupStorage(ngEntity, group);
      group.setHaFlag(ngEntity.getHaFlag());
      if (ngEntity.getHadoopConfig() != null) {
         Map hadoopConfig = (new Gson()).fromJson(ngEntity.getHadoopConfig(), Map.class);
         group.setConfiguration((Map<String, Object>)hadoopConfig);
      }

      group.setVmFolderPath(ngEntity.getVmFolderPath());
      return group;
   }

   private void expandGroupStorage(NodeGroupEntity ngEntity,
         NodeGroupCreate group) {
      int storageSize = ngEntity.getStorageSize();
      DatastoreType storageType = ngEntity.getStorageType();
      boolean storageBisect = ngEntity.getDiskBisect();
      List<String> storeNames = ngEntity.getVcDatastoreNameList();
      if (storageSize <= 0 && storageType == null
            && (storeNames == null || storeNames.isEmpty())) {
         logger.debug("no storage specified for node group "
               + ngEntity.getName());
      }

      logger.debug("storage size is " + storageSize + " for node group "
            + ngEntity.getName());
      logger.debug("storage diskBisect is " + storageBisect + "for node group "
            + ngEntity.getName());
      logger.debug("storage type is " + storageType + " for node group "
            + ngEntity.getName());
      logger.debug("storage name pattern is " + storeNames + " for node group "
            + ngEntity.getName());
      StorageRead storage = new StorageRead();
      group.setStorage(storage);
      storage.setSizeGB(storageSize);
      storage.setDiskBisect(storageBisect);
      if (storageType != null) {
         storage.setType(storageType.toString().toLowerCase());
      }
      storage.setNamePattern(getStoreNamePattern(storageType, storeNames));
      storage.setDsNames(storeNames);
   }

   private List<String> getStoreNamePattern(DatastoreType storageType,
         List<String> storeNames) {
      if (storageType == null && (storeNames == null || storeNames.isEmpty())) {
         return null;
      }
      Set<String> storePattern = null;
      if (storageType == null) {
         logger.debug("storage type is not specified.");
         storePattern = datastoreMgr.getDatastoresByNameList(storeNames);
      }
      if (storageType == DatastoreType.LOCAL) {
         storePattern = datastoreMgr.getLocalDatastoresByNames(storeNames);
      } else {
         storePattern = datastoreMgr.getSharedDatastoresByNames(storeNames);
      }

      if (storePattern == null || storePattern.isEmpty()) {
         logger.warn("No any datastore found for datastore name: " + storeNames
               + ", type: " + storageType
               + ". Will use cluster storage definition.");
         return null;
      }

      List<String> result = new ArrayList<String>();
      result.addAll(storePattern);
      return result;
   }

   private EnumSet<HadoopRole> getEnumRoles(List<String> roles, String distro) {
      logger.debug("convert string roles to enum roles");
      EnumSet<HadoopRole> enumRoles = EnumSet.noneOf(HadoopRole.class);
      for (String role : roles) {
         HadoopRole configuredRole = HadoopRole.fromString(role);
         if (configuredRole == null) {
            throw ClusterConfigException.UNSUPPORTED_HADOOP_ROLE(role, distro);
         }
         enumRoles.add(configuredRole);
      }
      return enumRoles;
   }

   public void updateAppConfig(final String clusterName, final ClusterCreate clusterCreate) {
      logger.debug("Update configuration for cluster " + clusterName);

      DAL.inTransactionDo(new Saveable<Void>() {
         public Void body() {
            ClusterEntity cluster = ClusterEntity.findClusterEntityByName(clusterCreate.getName());

            if (cluster == null) {
               logger.error("cluster " + clusterName + " does not exist");
               throw BddException.NOT_FOUND("cluster", clusterName);
            }
            transformHDFSUrl(clusterCreate);
            Map<String, Object> clusterLevelConfig = clusterCreate.getConfiguration();

            if (clusterLevelConfig != null && clusterLevelConfig.size() > 0) {
               logger.debug("Cluster level app config is updated.");
               CommonClusterExpandPolicy.validateAppConfig(
                     clusterCreate.getConfiguration(), clusterCreate.isValidateConfig());
               cluster.setHadoopConfig((new Gson()).toJson(clusterLevelConfig));
            } else {
               logger.debug("cluster configuration is not set in cluster spec, so treat it as an empty configuration.");
               cluster.setHadoopConfig(null);
            }

            updateNodegroupAppConfig(clusterCreate, cluster, clusterCreate.isValidateConfig());
            return null;
         }
      });
   }

   private void updateNodegroupAppConfig(ClusterCreate clusterCreate, ClusterEntity cluster, boolean validateWhiteList) {
      Gson gson = new Gson();
      Set<NodeGroupEntity> groupEntities = cluster.getNodeGroups();
      Map<String, NodeGroupEntity> groupMap = new HashMap<String, NodeGroupEntity>();
      for (NodeGroupEntity entity : groupEntities) {
         groupMap.put(entity.getName(), entity);
      }

      Set<String> updatedGroups = new HashSet<String>();
      NodeGroupCreate[] groupCreates = clusterCreate.getNodeGroups();
      if (groupCreates == null) {
         return;
      }
      for (NodeGroupCreate groupCreate : groupCreates) {
         Map<String, Object> groupConfig = groupCreate.getConfiguration();
         if (groupConfig != null && groupConfig.size() > 0) {
            NodeGroupEntity groupEntity = groupMap.get(groupCreate.getName());
            // validate hadoop config
            CommonClusterExpandPolicy.validateAppConfig(groupConfig,
                  validateWhiteList);
            groupEntity.setHadoopConfig(gson.toJson(groupConfig));
            updatedGroups.add(groupCreate.getName());
         }
      }
      for (NodeGroupEntity entity : groupEntities) {
         if (updatedGroups.contains(entity.getName())) {
            continue;
         }
         entity.setHadoopConfig(null);
      }
   }
}
