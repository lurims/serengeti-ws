/***************************************************************************
 * Copyright (c) 2012 VMware, Inc. All Rights Reserved.
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
package com.vmware.bdd.utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;

import org.apache.commons.configuration.ConfigurationUtils;
import org.apache.log4j.Logger;

public class FileUtil {

   private static final Logger logger = Logger.getLogger(FileUtil.class);

   public static File getConfigFile(final String filename,final String typeName) {
      // try to locate file directly
      File specFile = new File(filename);
      if (specFile.exists()) {
         return specFile;
      }

      // search ${serengeti.home.dir}/conf directory
      String homeDir = System.getProperties().getProperty("serengeti.home.dir");
      if (homeDir != null && !homeDir.trim().isEmpty()) {
         StringBuilder builder = new StringBuilder();
         builder.append(homeDir).append(File.separator).append("conf")
               .append(File.separator).append(filename);
         specFile = new File(builder.toString());

         if (!specFile.exists()) {
            logger.warn(typeName + " file does not exist: " + builder);
         } else {
            return specFile;
         }
      }

      // search in class paths
      URL filePath = ConfigurationUtils.locate(filename);
      if (filePath != null) {
         specFile = ConfigurationUtils.fileFromURL(filePath);
      }

      if (!specFile.exists()) {
         String errorMsg = "Can not find file" + filename;
         logger.fatal(errorMsg);
         new RuntimeException(errorMsg);
      }

      return specFile;
   }

   public static String obtainStringFromFile(File file) throws IOException {
      InputStream inputStream = new FileInputStream(file);
      BufferedReader rufferedReader =
            new BufferedReader(new InputStreamReader(inputStream));
      StringBuilder buff = new StringBuilder();
      String temp = "";
      while ((temp = rufferedReader.readLine()) != null) {
         buff.append(temp);
      }
      return buff.toString();
   }

}