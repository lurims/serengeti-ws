/***************************************************************************
 *    Copyright (c) 2012 VMware, Inc. All Rights Reserved.
 *    Licensed under the Apache License, Version 2.0 (the "License");
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

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public class RedirectSuccessHandler implements AuthenticationSuccessHandler {
   private static final Logger logger = Logger.getLogger(RedirectSuccessHandler.class);

   @Override
   public void onAuthenticationSuccess(HttpServletRequest request,
         HttpServletResponse response, Authentication authentication)
         throws ServletException, IOException {
      logger.debug("Redirect request.");
      response.setStatus(HttpServletResponse.SC_OK);
      String url = "https://" + getServerIp(request) + "/datadirector";
      response.sendRedirect(url);
   }

   private String getServerIp(HttpServletRequest request) {
      String ip = request.getHeader("x-forwarded-for");
      if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
         ip = request.getRemoteAddr();
      }
      return ip;
   }
}
