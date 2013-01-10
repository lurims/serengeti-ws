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

import static org.testng.AssertJUnit.assertEquals;

import java.io.File;
import java.io.IOException;

import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class TestFileUtil {

   private static File file;
   private static final String TestFile = "test.txt";

   @BeforeClass
   public static void createFile() {
      file = new File(TestFileUtil.TestFile);
      try {
         if (!file.exists()) {
            file.createNewFile();
         }
      } catch (IOException e) {
      }
   }

   @AfterClass
   public static void deleteFile() {
      if (file.exists()) {
         file.delete();
      }
   }

   @Test
   public void testGetConfigFile() {
      File testFile =
            FileUtil.getConfigFile(TestFileUtil.TestFile, "Test file");
      Assert.assertNotNull(testFile);
      assertEquals(testFile.getName(), TestFileUtil.TestFile);
   }

}
