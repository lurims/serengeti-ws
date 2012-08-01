{
  "nodeGroups":[
    {
      "name": "master",
      "roles": [
        "hadoop_namenode",
        "hadoop_jobtracker"
      ],
      "instanceNum": 1,
      "cpuNum": 2,
      "memCapacityMB": 7500,
      "storage": {
        "type": "SHARED",
        "sizeGB": 50
      },
      "haFlag": "on",
      "configuration": {
        "hadoop": {
        }
      }
    },
    {
      "name": "worker",
      "roles": [
        "hadoop_tasktracker",
        "hadoop_datanode"
      ],
      "instanceNum": 3,
      "cpuNum": 1,
      "memCapacityMB": 3748,	
      "storage": {
        "type": "LOCAL",
        "sizeGB": 50
      },
      "haFlag": "off",
      "configuration": {
        "hadoop": {
        }
      }
    },
    {
      "name": "client",
      "roles": [
        "hadoop_client",
        "hive",
        "hive_server",
        "pig"
      ],
      "instanceNum": 1,
      "cpuNum": 1,
      "memCapacityMB": 3748,
      "storage": {
        "type": "LOCAL",
        "sizeGB": 50
      },
      "haFlag": "off",
      "configuration": {
        "hadoop": {
        }
      }
    }
  ],
  "configuration": {
    "hadoop": {
      "core-site.xml": {
        // check for all settings at http://hadoop.apache.org/common/docs/r1.0.0/core-default.html
        // note: any value (int, float, boolean, string) must be enclosed in double quotes and here is a sample: 
        // "io.file.buffer.size": "4096"
      },
      "hdfs-site.xml": {
        // check for all settings at http://hadoop.apache.org/common/docs/r1.0.0/hdfs-default.html
      },
      "mapred-site.xml": {
        // check for all settings at http://hadoop.apache.org/common/docs/r1.0.0/mapred-default.html
      },
      "hadoop-env.sh": {
        // "HADOOP_HEAPSIZE": "",
        // "HADOOP_NAMENODE_OPTS": "",
        // "HADOOP_DATANODE_OPTS": "",
        // "HADOOP_SECONDARYNAMENODE_OPTS": "",
        // "HADOOP_JOBTRACKER_OPTS": "",
        // "HADOOP_TASKTRACKER_OPTS": "",
        // "JAVA_HOME": "",
        // "PATH": "",
      },
      "log4j.properties": {
        // "hadoop.root.logger": "DEBUG,console",
        // "hadoop.security.logger": "DEBUG,console",
      }
    }
  }
}
