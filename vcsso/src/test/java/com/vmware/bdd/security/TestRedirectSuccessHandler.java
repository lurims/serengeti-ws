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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.easymock.EasyMock;
import org.easymock.EasyMockSupport;
import org.easymock.IMocksControl;
import org.testng.annotations.Test;

public class TestRedirectSuccessHandler extends EasyMockSupport {

   @Test
   public void testOnAuthenticationSuccess () throws Exception {
      IMocksControl control = EasyMock.createControl();
      HttpServletRequest request = control.createMock(HttpServletRequest.class);
      HttpServletResponse response = control.createMock(HttpServletResponse.class);
      EasyMock.expect(request.getRemoteAddr()).andReturn("192.168.0.2");
      response.setStatus(EasyMock.eq(HttpServletResponse.SC_OK));
      EasyMock.expect(request.getHeader("x-forwarded-for")).andReturn(null);
      response.sendRedirect(EasyMock.eq("https://192.168.0.2/datadirector"));
      control.replay();
      RedirectSuccessHandler redirectSuccessHandler = new RedirectSuccessHandler();
      redirectSuccessHandler.onAuthenticationSuccess(request, response, null);
      control.verify();
   }
}
