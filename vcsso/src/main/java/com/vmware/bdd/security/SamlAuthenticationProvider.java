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

import org.apache.log4j.Logger;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import java.io.ByteArrayInputStream;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.SecretKey;

import org.apache.log4j.Logger;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.CredentialContextSet;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.validation.ValidationException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

public class SamlAuthenticationProvider implements AuthenticationProvider {
   private static final Logger logger = Logger.getLogger(SamlAuthenticationProvider.class);

   private UserService userService;

   @Override
   public Authentication authenticate(Authentication authentication)
         throws AuthenticationException {
      String errorMsg = "";
      Response samlResponse = (Response) authentication.getCredentials();
      Assertion assertion = samlResponse.getAssertions().get(0);
      if(assertion == null) {
         errorMsg = "SAML authenticate failed. Assertion cannot be null.";
         logger.error(errorMsg);
         throw new BadCredentialsException(errorMsg);
      }
//      token valid time period
      Conditions conditions = assertion.getConditions();
//      SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
      long beforeTime = conditions.getNotBefore().getMillis();
//      Calendar a = Calendar.getInstance();
//      a.setTime(new Date(beforeTime));
//      System.out.println("a=====================>" + format.format(a.getTime()));
      long afterTime = conditions.getNotOnOrAfter().getMillis();
//      Calendar b = Calendar.getInstance();
//      b.setTime(new Date(afterTime));
//      System.out.println("b=====================>" + format.format(b.getTime()));
      long currentTime = System.currentTimeMillis();
//      Calendar c = Calendar.getInstance();
//      c.setTime(new Date(currentTime));
//      System.out.println("c=====================>" + format.format(c.getTime()));

//      System.out.println("beforeTime=====>"+beforeTime);
//      System.out.println("afterTime=====>"+afterTime);
//      System.out.println("currentTime=====>"+currentTime);
//      System.out.println("currentTime < beforeTime=====>"+(currentTime < beforeTime));
//      System.out.println("currentTime > afterTime=====>"+(currentTime > afterTime));
      if (currentTime < beforeTime || currentTime > afterTime) {
         errorMsg= "SAML token has an invalid time period.";
         logger.error(errorMsg);
         throw new BadCredentialsException(errorMsg);
      }
//      token audience
      String loginUrl = getSamlLoginURI();
      List<AudienceRestriction> audienceRestrictions = conditions.getAudienceRestrictions();
      Audience audience = audienceRestrictions.get(0).getAudiences().get(0);
      if (!loginUrl.equals(audience.getAudienceURI())) {
         errorMsg= "SAML token has an invalid audience URI.";
         logger.error(errorMsg);
         throw new BadCredentialsException(errorMsg);
      }
//      HOK signature check
      Signature responseSignature = samlResponse.getSignature();
//      SubjectConfirmationData subjectConfirmationData= 
//         assertion.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData();
//      subjectConfirmationData
   // Get the <ds:X509Data/> elements
     /* List<X509Data> x509Data = subjectConfirmationData.getKeyInfo().getX509Datas();
      if (x509Data != null && x509Data.size() > 0) {
         // Pick the first <ds:X509Data/> element
         X509Data x509Cred = (X509Data) x509Data.get(0);
         // Get the <ds:X509Certificate/> elements
         List<org.opensaml.xml.signature.X509Certificate> x509Certs =
               x509Cred.getX509Certificates();
         if (x509Certs != null && x509Certs.size() > 0) {
            // Pick the first <ds:X509Certificate/> element
            org.opensaml.xml.signature.X509Certificate cert = x509Certs.get(0);
            // Instantiate a java.security.cert.X509Certificate object out of the
            // base64 decoded byte[] of the certificate
            java.security.cert.X509Certificate x509Certificate = null;
            try {
               CertificateFactory cf = CertificateFactory.getInstance("X.509");
               x509Certificate =
                     (X509Certificate) cf
                           .generateCertificate(new ByteArrayInputStream(
                                 org.opensaml.xml.util.Base64.decode(cert
                                       .getValue())));
            } catch (CertificateException e) {
               errorMsg =
                     "SAML token cannot validate the response signatrue: "
                           + e.getMessage();
               logger.error(errorMsg);
               throw new BadCredentialsException(errorMsg);
            }
            Credential credential = new X509CredentialImpl(x509Certificate);
            System.out.println("credential==========>" + credential);
            System.out.println("credential.getPublicKey()==========>"
                  + credential.getPublicKey());
            PublicKey key = credential.getPublicKey();
            if (key != null) {
               System.out.println("getAlgorithm====>" + key.getAlgorithm());
               System.out.println("getFormat====>" + key.getFormat());
            }
            SignatureValidator validator = new SignatureValidator(credential);
            try {
               validator.validate(responseSignature);
            } catch (ValidationException e) {
               e.printStackTrace();
               errorMsg =
                     "SAML token cannot validate the response signatrue: "
                           + e.getMessage();
               logger.error(errorMsg);
               throw new BadCredentialsException(errorMsg);
            }
         }
      } */
//      saml assertion verification by SSO

      UserDetails user =
            userService.loadUserByUsername(assertion.getSubject().getNameID().getValue());
      SamlAuthenticationToken samlAuthenticationToken =
            new SamlAuthenticationToken(samlResponse, user.getAuthorities());
      return samlAuthenticationToken;
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

   private String getSamlLoginURI() throws BadCredentialsException{
         String ipAddress = "";
         try {
            Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
            NetworkInterface networkInterface = null;
            while (networkInterfaces.hasMoreElements()) {
               networkInterface = networkInterfaces.nextElement();
               Enumeration<InetAddress> inetAddresses =
                     networkInterface.getInetAddresses();
               InetAddress inetAddress = null;
               while (inetAddresses.hasMoreElements()) {
                  inetAddress = inetAddresses.nextElement();
                  if (!inetAddress.isLinkLocalAddress()
                        && !inetAddress.isLoopbackAddress()) {
                     ipAddress = inetAddress.getHostAddress();
                  }
               }
            }
         } catch (SocketException e) {
            logger.error("Cannot obtain a network interface: " + e.getMessage());
         }
         if(ipAddress.isEmpty()) {
            String errorMsg = "Unknown host: Cannot obtain a valid ip address .";
            logger.error(errorMsg);
            throw new BadCredentialsException(errorMsg);
         }
         return "http://" + ipAddress + ":8080/serengeti/sp/sso";
   }

   class X509CredentialImpl implements X509Credential {
      private PublicKey publicKey = null;

      public X509CredentialImpl(X509Certificate cert) {
         publicKey = cert.getPublicKey();
      }

      public X509Certificate getEntityCertificate() {
         return null;
      }

      public Collection<X509Certificate> getEntityCertificateChain() {
         return null;
      }

      public Collection<X509CRL> getCRLs() {
         return null;
      }

      public String getEntityId() {
         return null;
      }

      public UsageType getUsageType() {
         return null;
      }

      public Collection<String> getKeyNames() {
         return null;
      }

      public PublicKey getPublicKey() {
         return publicKey;
      }

      public PrivateKey getPrivateKey() {
         return null;
      }

      public SecretKey getSecretKey() {
         return null;
      }

      public CredentialContextSet getCredentalContextSet() {
         return null;
      }

      public Class<? extends Credential> getCredentialType() {
         return null;
      }
   }

}
