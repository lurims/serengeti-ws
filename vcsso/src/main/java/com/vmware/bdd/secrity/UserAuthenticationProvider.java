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
package com.vmware.bdd.secrity;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;


public class UserAuthenticationProvider implements AuthenticationProvider {

   private UserService userService;

   @Override
   public Authentication authenticate(Authentication authentication)
         throws AuthenticationException {
      UserDetails user =
         userService.loadUserByUsername(authentication.getName());
      UserAuthenticationToken accountAuthenticationToken =
            new UserAuthenticationToken(user.getAuthorities());

      return accountAuthenticationToken;
   }

   @Override
   public boolean supports(Class<?> authentication) {
      return true;
   }

   public UserService getUserService() {
      return userService;
   }

   public void setUserService(UserService userService) {
      this.userService = userService;
   }

}
