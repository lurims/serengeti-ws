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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.vmware.vim.sso.client.DefaultSecurityTokenServiceFactory;
import com.vmware.vim.sso.client.SecurityTokenService;
import com.vmware.vim.sso.client.SecurityTokenServiceConfig;
import com.vmware.vim.sso.client.SecurityTokenServiceConfig.ConnectionConfig;
import com.vmware.vim.sso.client.TokenSpec;

public class UserAuthenticationProvider implements AuthenticationProvider {
   private static final Logger logger = Logger.getLogger(UserAuthenticationProvider.class);
   private static final String STS_PROP_KEY = "sts";
   private static final int TOKEN_LIFE_TIME = 60;
   private UserService userService;

   @Override
   public Authentication authenticate(Authentication authentication)
         throws AuthenticationException {
      String userName = (String) authentication.getPrincipal();
      String passwd = (String) authentication.getCredentials();

      String stsLocation = Configuration.getString(STS_PROP_KEY);
      if (stsLocation == null) { //vc login logic
         //TODO add vc login authentication here
         return null;
      } else { //sso authentication
         SecurityTokenService stsClient = SecurityUtils.getSTSClient(stsLocation);
         try {
            // Describe the requested token properties using a TokenSpec
            TokenSpec tokenSpec = new TokenSpec.Builder(TOKEN_LIFE_TIME).createTokenSpec();

            // Acquire the requested token
            stsClient.acquireToken(userName, passwd, tokenSpec);

            UserDetails user =
                  userService.loadUserByUsername(authentication.getName());
            UserAuthenticationToken accountAuthenticationToken =
                  new UserAuthenticationToken(user.getAuthorities());

            return accountAuthenticationToken;
         } catch (AuthenticationServiceException serviceException) {
            throw serviceException;
         } catch (UsernameNotFoundException userNotfoundException) {
            throw userNotfoundException;
         } catch (Exception e) {
            logger.error("Authentication error :" + e.getMessage());
            throw new BadCredentialsException(e.getMessage());
         } 
      }
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
