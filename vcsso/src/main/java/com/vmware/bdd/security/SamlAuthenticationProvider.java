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

import java.io.ByteArrayInputStream;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Enumeration;
import java.util.List;

import org.apache.log4j.Logger;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.KeyInfoConfirmationDataType;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.X509Data;
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
      Response response = (Response) authentication.getCredentials();
      
      Assertion assertion = response.getAssertions().get(0);
      if(assertion == null) {
         errorMsg = "SAML authenticate failed. Assertion cannot be null.";
         logger.error(errorMsg);
         throw new BadCredentialsException(errorMsg);
      }
      Conditions conditions = assertion.getConditions();
//      token valid time period
      validateTimePeriod(conditions);
//      token audience
      validateAudienceURI(conditions);
//    HOK signature check
      validateSignature(response, assertion);
//      saml assertion verification by SSO

      UserDetails user =
            userService.loadUserByUsername(assertion.getSubject().getNameID().getValue());
      SamlAuthenticationToken samlAuthenticationToken =
            new SamlAuthenticationToken(response, user.getAuthorities());
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

   private void validateTimePeriod(Conditions conditions) {
      long beforeTime = conditions.getNotBefore().getMillis();
      long afterTime = conditions.getNotOnOrAfter().getMillis();
      long currentTime = System.currentTimeMillis();
      if (currentTime < beforeTime || currentTime > afterTime) {
         String errorMsg = "SAML token has an invalid time period.";
         logger.error(errorMsg);
         throw new BadCredentialsException(errorMsg);
      }
   }

   private void validateAudienceURI(Conditions conditions) {
      String loginUrl = getSamlLoginURI();
      List<AudienceRestriction> audienceRestrictions = conditions.getAudienceRestrictions();
      Audience audience = audienceRestrictions.get(0).getAudiences().get(0);
      if (!loginUrl.equals(audience.getAudienceURI())) {
         String errorMsg= "SAML token has an invalid audience URI.";
         logger.error(errorMsg);
         throw new BadCredentialsException(errorMsg);
      }
   }

   private void validateSignature(Response response, Assertion assertion) {
      Signature responseSignature = response.getSignature();
      Subject subject = assertion.getSubject();
      SubjectConfirmationData subjectConfirmationData = 
         subject.getSubjectConfirmations().get(0)
                  .getSubjectConfirmationData();
      KeyInfoConfirmationDataType keyInfoConfirmationData =
            (KeyInfoConfirmationDataType) subjectConfirmationData;
      //Get the <ds:X509Data/> elements
      KeyInfo keyInfo = (KeyInfo) keyInfoConfirmationData.getKeyInfos().get(0);
      List<X509Data> x509Data = keyInfo.getX509Datas();
      if (x509Data != null && !x509Data.isEmpty()) {
         // Pick the first <ds:X509Data/> element
         X509Data x509Cred = (X509Data) x509Data.get(0);
         // Get the <ds:X509Certificate/> elements
         List<org.opensaml.xml.signature.X509Certificate> x509Certs =
               x509Cred.getX509Certificates();
         if (x509Certs != null && !x509Certs.isEmpty()) {
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
               X509EncodedKeySpec publicKeySpec =
                     new X509EncodedKeySpec(x509Certificate.getPublicKey()
                           .getEncoded());
               //get KeyFactory object that creates key objects, specifying RSA
               KeyFactory keyFactory = KeyFactory.getInstance("RSA");
               PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
               //generate public key to validate signatures
               BasicX509Credential publicCredential = new BasicX509Credential();
               publicCredential.setPublicKey(publicKey);
               SignatureValidator validator =
                     new SignatureValidator(publicCredential);
               validator.validate(responseSignature);
            } catch (Exception e) {
               String errorMsg =
                     "SAML token cannot validate the response signatrue: "
                           + e.getMessage();
               logger.error(errorMsg);
               throw new BadCredentialsException(errorMsg);
            }
         }
      }
   }

}
