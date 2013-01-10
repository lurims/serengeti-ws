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
package com.vmware.bdd.security;

import static org.testng.AssertJUnit.assertNotNull;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.testng.Assert;
import org.testng.annotations.Test;

import com.vmware.bdd.security.UserService;

public class TestAccountService {

   @Test
   public void testLoadUserByUsername() {
      UserDetailsService accountService = new UserService();
      UserDetails user1 = null;
      try {
         user1 = accountService.loadUserByUsername("root");
      } catch (UsernameNotFoundException e) {
      }
      Assert.assertNull(user1);
      UserDetails user2 = accountService.loadUserByUsername("serengeti");
      assertNotNull(user2);
   }
}
