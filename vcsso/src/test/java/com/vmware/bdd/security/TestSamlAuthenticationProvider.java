package com.vmware.bdd.security;

import java.io.File;
import java.io.IOException;

import javax.servlet.http.HttpServletRequest;

import org.easymock.EasyMock;
import org.easymock.EasyMockSupport;
import org.easymock.IMocksControl;
import org.opensaml.saml2.core.Response;
import org.springframework.security.core.Authentication;
import org.testng.annotations.Test;

import com.vmware.bdd.utils.FileUtil;

public class TestSamlAuthenticationProvider  extends EasyMockSupport {

   private static final String SPRING_SECURITY_FROM_SAML_TOKEN_KEY = "SAMLResponse";
   private static final String SSO_XML_FILE = "sso.xml";

   @Test
   public void testAuthenticate() throws Exception {
      IMocksControl control = EasyMock.createControl();
      HttpServletRequest request = control.createMock(HttpServletRequest.class);
      File ssoFile = FileUtil.getConfigFile(SSO_XML_FILE, "SSO");
      String samlToken = FileUtil.obtainStringFromFile(ssoFile);
      EasyMock
            .expect(request.getParameter(SPRING_SECURITY_FROM_SAML_TOKEN_KEY))
            .andReturn(samlToken);
      control.replay();
      SamlAuthenticationFilter samlAuthenticationFilter = new SamlAuthenticationFilter();
      Response response = samlAuthenticationFilter.obtainSamlToken(request);
      control.reset();
      Authentication authentication = control.createMock(Authentication.class);
      EasyMock
            .expect(authentication.getCredentials())
            .andReturn(response);
      control.replay();
      SamlAuthenticationProvider provider = new SamlAuthenticationProvider();
      provider.authenticate(authentication);
      control.verify();
   }
}
