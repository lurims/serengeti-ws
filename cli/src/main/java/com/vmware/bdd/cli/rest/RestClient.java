/******************************************************************************
 *   Copyright (c) 2012 VMware, Inc. All Rights Reserved.
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *****************************************************************************/
package com.vmware.bdd.cli.rest;

import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.fusesource.jansi.AnsiConsole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import com.vmware.bdd.apitypes.Connect;
import com.vmware.bdd.apitypes.TaskRead;
import com.vmware.bdd.apitypes.TaskRead.Status;
import com.vmware.bdd.cli.commands.CommandsUtils;
import com.vmware.bdd.cli.commands.Constants;
import com.vmware.bdd.cli.commands.CookieCache;

/**
 * RestClient provides common rest apis required by resource operations.
 * 
 */
@Component
public class RestClient {

   private String hostUri;

   @Autowired
   private RestTemplate client;

   private RestClient() {
      hostUri = getHostUriProperty();
   }

   /*
    *  Get Serengeti host from cli property file
    */
   private String getHostUriProperty() {
      String hostUri = null;
      FileReader hostFileReader = null;

      try {
         hostFileReader = new FileReader(Constants.PROPERTY_FILE);
         Properties hostProperties = new Properties();
         hostProperties.load(hostFileReader);

         if (hostProperties != null
               && hostProperties.get(Constants.PROPERTY_HOST) != null) {
            hostUri =
                  Constants.HTTP_CONNECTION_PREFIX
                        + (String) hostProperties
                              .get(Constants.PROPERTY_HOST)
                        + Constants.HTTP_CONNECTION_LOGIN_SUFFIX;
         }
      } catch (Exception e) {//not set yet; or read io error
      } finally {
         if (hostFileReader != null) {
            try {
               hostFileReader.close();
            } catch (IOException e) {
               //nothing to do
            }
         }
      }

      return hostUri;
   }

   /**
    * connect to a Serengeti server
    * 
    * @param host
    *           host url with optional port
    * @param userName 
    *           serengeti login name
    * @param password
    *           serengeti password                     
    */
   public Connect.ConnectType connect(final String host, final String userName, final String password) {
      String oldHostUri = hostUri;

      hostUri =
            Constants.HTTP_CONNECTION_PREFIX + host
                  + Constants.HTTP_CONNECTION_LOGIN_SUFFIX;

      try {
         ResponseEntity<String> response =
            login(Constants.REST_PATH_LOGIN, String.class, userName,password);

         if (response.getStatusCode() == HttpStatus.OK) {//normal response        
            updateHostproperty(host);
            String cookieValue=response.getHeaders().getFirst("Set-Cookie");
            if(cookieValue.contains(";")){
               cookieValue=cookieValue.split(";")[0];
            }
            writeCookieInfo(cookieValue);
            System.out.println(Constants.CONNECT_SUCCESS);
         } else { //error
            System.out.println(Constants.CONNECT_FAILURE);
            //recover old hostUri
            hostUri = oldHostUri;
            return Connect.ConnectType.ERROR;
         }
      }catch (Exception e) {
         if (e instanceof CliRestException) {
            CliRestException cliRestException = (CliRestException) e;
            if (cliRestException.getStatus() == HttpStatus.UNAUTHORIZED) {
               System.out.println(Constants.CONNECT_UNAUTHORIZATION);
               //recover old hostUri
               hostUri = oldHostUri;
               return Connect.ConnectType.UNAUTHORIZATION;
            }
         } else{
            System.out.println(Constants.CONNECT_FAILURE + ":" + e.getCause().getMessage().toLowerCase());
            return Connect.ConnectType.ERROR;
         }
      }
      return Connect.ConnectType.SUCCESS;
   }

   
   public void disconnect () {
      try {
         if(!checkConnection()){
            return ;
         }
         logout(Constants.REST_PATH_LOGOUT, String.class);
      } catch (Exception e) {
         System.out.println(Constants.DISCONNECT_FAILURE + ":" + e.getCause().getMessage().toLowerCase());
      }
   }

   private void writeCookieInfo(String cookie) {
      CookieCache.put("Cookie",cookie);
      String propertiseFile = "cookie.propertise";
      Properties propertise = new Properties();
      propertise.put("Cookie", cookie);
      CommandsUtils.writePropertise(propertise, propertiseFile);
   }

   private String readCookieInfo() { 
      String cookieValue = "";
      cookieValue = CookieCache.get("Cookie");
      if (CommandsUtils.isBlank(cookieValue)){
         String propertiseFile = "cookie.propertise";
         Properties propertise = null;
         propertise = CommandsUtils.readPropertise(propertiseFile);
         if (propertise != null) {
            return propertise.getProperty("Cookie");
         } else {
            return null;
         }         
      }
      return cookieValue;
   }

   private <T> ResponseEntity<T> restGetById(final String path, final String id,
         final Class<T> respEntityType, final boolean hasDetailQueryString) {
      String targetUri = hostUri + Constants.HTTP_CONNECTION_API + path + "/" + id;
      if (hasDetailQueryString) {
         targetUri += Constants.QUERY_DETAIL;
      }
      return restGetByUri(targetUri, respEntityType);
   }

   private <T> ResponseEntity<T> restGet(final String path, final Class<T> respEntityType, final boolean hasDetailQueryString) {
      String targetUri = hostUri + Constants.HTTP_CONNECTION_API + path;
      if (hasDetailQueryString) {
         targetUri += Constants.QUERY_DETAIL;
      }
      return restGetByUri(targetUri, respEntityType);
   }

   private <T> ResponseEntity<T> login(final String path, final Class<T> respEntityType, final String userName, final String password) {
      StringBuilder uriBuff = new StringBuilder();
      uriBuff.append(hostUri).append(path);
      if (!CommandsUtils.isBlank(userName) && !CommandsUtils.isBlank(password)) {
         uriBuff.append("?").append("j_username=").append(userName).append("&j_password=").append(password);
      }
      return restPostByUri(uriBuff.toString(), respEntityType);
   }

   private <T> ResponseEntity<T> logout(final String path, final Class<T> respEntityType) {
      StringBuilder uriBuff = new StringBuilder();
      uriBuff.append(hostUri).append(path);
      return restPostByUri(uriBuff.toString(), respEntityType);
   }

   private <T> ResponseEntity<T> restGetByUri(String uri,
         Class<T> respEntityType) {
      HttpHeaders headers = buildHeaders();
      HttpEntity<String> entity = new HttpEntity<String>(headers);

      return client.exchange(uri, HttpMethod.GET, entity, respEntityType);
   }

   private <T> ResponseEntity<T> restPostByUri(String uri,
         Class<T> respEntityType) {
      HttpHeaders headers = buildHeaders();
      HttpEntity<String> entity = new HttpEntity<String>(headers);

      return client.exchange(uri, HttpMethod.POST, entity, respEntityType);
   }

   private HttpHeaders buildHeaders() {
      HttpHeaders headers = new HttpHeaders();
      headers.setContentType(MediaType.APPLICATION_JSON);
      List<MediaType> acceptedTypes = new ArrayList<MediaType>();
      acceptedTypes.add(MediaType.APPLICATION_JSON);
      acceptedTypes.add(MediaType.TEXT_HTML);
      headers.setAccept(acceptedTypes);

      String cookieInfo = readCookieInfo();
      headers.add("Cookie", cookieInfo == null ? "" : cookieInfo);

      return headers;
   }

   /*
    * Update host property file
    */
   private void updateHostproperty(final String host) throws IOException {
      FileOutputStream hostFile = null;
      try {
         Properties hostProperty = new Properties();
         hostProperty.setProperty(Constants.PROPERTY_HOST, host);
         hostFile = new FileOutputStream(Constants.PROPERTY_FILE);
         hostProperty.store(hostFile,
               Constants.PROPERTY_FILE_HOST_COMMENT);
      } catch (IOException e) {
         throw new IOException(Constants.PROPERTY_FILE_HOST_FAILURE);
      } finally {
         if (hostFile != null) {
            try {
               hostFile.close();
            } catch (IOException e) {
               //nothing to do
            }
         }
      }
   }

   /**
    * Create an object through rest apis
    * @param entity the creation content
    * @param path the rest url
    * @param verb the http method
    * @param prettyOutput output callback
    */
   public void createObject(Object entity, final String path,
         final HttpMethod verb, PrettyOutput... prettyOutput) {
      if(!checkConnection()){
         return ;
      }
      try {
         if (verb == HttpMethod.POST) {
            ResponseEntity<String> response = restPost(path, entity);
            if (!validateAuthorization(response)) {
               return;
            }
            processResponse(response, HttpMethod.POST, prettyOutput);
         } else {
            throw new Exception(Constants.HTTP_VERB_ERROR);
         }

      } catch (Exception e) {
         throw new CliRestException(e.getMessage());
      }
   }

   private ResponseEntity<String> restPost(String path, Object entity) {
      String targetUri = hostUri + Constants.HTTP_CONNECTION_API + path;

      HttpHeaders headers = buildHeaders();
      HttpEntity<Object> postEntity = new HttpEntity<Object>(entity, headers);

      return client.exchange(targetUri, HttpMethod.POST, postEntity,
            String.class);
   }

   /*
    * Will process normal response with/without a task location header
    */
   private void processResponse(ResponseEntity<String> response,
         HttpMethod verb, PrettyOutput... prettyOutput) throws Exception {

      HttpStatus responseStatus = response.getStatusCode();
      if (responseStatus == HttpStatus.ACCEPTED) {//Accepted with task in the location header
         //get task uri from response to trace progress
         HttpHeaders headers = response.getHeaders();
         URI taskURI = headers.getLocation();
         String[] taskURIs = taskURI.toString().split("/");
         String taskId = taskURIs[taskURIs.length - 1];

         TaskRead taskRead;
         int oldProgress = 0;
         Status oldTaskStatus = null;
         do {
            ResponseEntity<TaskRead> taskResponse =
                  restGetById(Constants.REST_PATH_TASK, taskId, TaskRead.class, false);

            //task will not return exception as it has status

            taskRead = taskResponse.getBody();

            int progress = (int) (taskRead.getProgress() * 100);
            Status taskStatus = taskRead.getStatus();

            if ((prettyOutput != null && prettyOutput.length > 0 && prettyOutput[0]
                  .isRefresh())
                  || oldTaskStatus != taskStatus
                  || oldProgress != progress) { //need refresh
               oldTaskStatus = taskStatus;
               oldProgress = progress;

               //clear screen and show progress every few seconds 
               AnsiConsole.systemInstall();
               String separator = "[";
               char ESC = 27;
               String clearScreen = "2J";
               System.out.print(ESC + separator + clearScreen);
               AnsiConsole.systemUninstall();

               System.out.println(taskStatus + " " + progress + "%\n");

               // print call back customize the detailed output case by case
               if (prettyOutput != null && prettyOutput.length > 0) {
                  prettyOutput[0].prettyOutput();
               }
            }

            try {
               Thread.sleep(3 * 1000);
            } catch (InterruptedException ex) {
               //ignore
            }
         } while (taskRead.getStatus() != TaskRead.Status.SUCCESS
               && taskRead.getStatus() != TaskRead.Status.FAILED);

         if (taskRead.getStatus().equals(TaskRead.Status.FAILED)) {
            String logdir = taskRead.getWorkDir();
            String errorMsg = taskRead.getErrorMessage();
            if (logdir != null && !logdir.isEmpty()) {
               String outputErrorInfo = Constants.OUTPUT_LOG_INFO + logdir;
               if (errorMsg != null) {
                  outputErrorInfo = errorMsg + " " + outputErrorInfo;
               }
               throw new CliRestException(outputErrorInfo);
            } else if (errorMsg != null && !errorMsg.isEmpty()){
               throw new CliRestException(errorMsg);
            } else {
               throw new CliRestException("task failed");
            }
         }

      } else if (responseStatus == HttpStatus.OK
            || responseStatus == HttpStatus.NO_CONTENT) {
         //TODO
      } else if (responseStatus == HttpStatus.CREATED) {
         //TODO
      }
   }

   /**
    * Generic method to get an object by id
    * @param id
    * @param entityType the object type
    * @param path the rest url
    * @param verb the http method
    * @param detail flag to retrieve detailed information or not
    * @return the object
    */
   public <T> T getObject(final String id, Class<T> entityType,
         final String path, final HttpMethod verb, final boolean detail) {
      if(!checkConnection()){
         return null;
      }
      try {
         if (verb == HttpMethod.GET) {
            ResponseEntity<T> response = restGetById(path, id, entityType, detail);
            if (!validateAuthorization(response)) {
               return null;
            }
            T objectRead = response.getBody();

            return objectRead;
         } else {
            throw new Exception(Constants.HTTP_VERB_ERROR);
         }
      } catch (Exception e) {
         throw new CliRestException(e.getMessage());
      }
   }

   /**
    * Method to get by path
    * @param entityType
    * @param path
    * @param verb
    * @param detail
    * @return
    */
   public <T> T getObjectByPath(Class<T> entityType,
         final String path, final HttpMethod verb, final boolean detail) {
      checkConnection();

      try {
         if (verb == HttpMethod.GET) {
            ResponseEntity<T> response = restGet(path, entityType, detail);

            T objectRead = response.getBody();

            return objectRead;
         } else {
            throw new Exception(Constants.HTTP_VERB_ERROR);
         }
      } catch (Exception e) {
         throw new CliRestException(e.getMessage());
      }
   }

   /**
    * Generic method to get all objects of a type
    * @param entityType object type
    * @param path the rest url
    * @param verb the http method
    * @param detail flag to retrieve detailed information or not
    * @return the objects
    */
   public <T> T getAllObjects(final Class<T> entityType, final String path,
         final HttpMethod verb, final boolean detail) {
      if(!checkConnection()){
         return null;
      }
      try {
         if (verb == HttpMethod.GET) {
            ResponseEntity<T> response = restGet(path, entityType, detail);
            if (!validateAuthorization(response)) {
               return null;
            }
            T objectsRead = response.getBody();

            return objectsRead;
         } else {
            throw new Exception(Constants.HTTP_VERB_ERROR);
         }
      } catch (Exception e) {
         throw new CliRestException(e.getMessage());
      }
   }

   /**
    * Delete an object by id
    * @param id 
    * @param path the rest url
    * @param verb the http method
    * @param prettyOutput utput callback
    */
   public void deleteObject(final String id, final String path,
         final HttpMethod verb, PrettyOutput... prettyOutput) {
      if(!checkConnection()){
         return ;
      }
      try {
         if (verb == HttpMethod.DELETE) {
            ResponseEntity<String> response = restDelete(path, id);
            if (!validateAuthorization(response)) {
               return;
            }
            processResponse(response, HttpMethod.DELETE, prettyOutput);
         } else {
            throw new Exception(Constants.HTTP_VERB_ERROR);
         }

      } catch (Exception e) {
         throw new CliRestException(e.getMessage());
      }
   }

   private ResponseEntity<String> restDelete(String path, String id) {
      String targetUri = hostUri + Constants.HTTP_CONNECTION_API + path + "/" + id;

      HttpHeaders headers = buildHeaders();
      HttpEntity<String> entity = new HttpEntity<String>(headers);

      return client
            .exchange(targetUri, HttpMethod.DELETE, entity, String.class);
   }

   private boolean checkConnection() {
      if (hostUri == null) {
         System.out.println(Constants.NEED_CONNECTION);
         return false;
      } else if (CommandsUtils.isBlank(readCookieInfo())) {
         System.out.println(Constants.CONNECT_CHECK_LOGIN);
         return false;
      }
      return true;
   }

   /**
    * process requests with query parameters
    * @param id
    * @param path the rest url
    * @param verb the http method
    * @param queryStrings required query strings
    * @param prettyOutput output callback
    */
   public void actionOps(final String id, final String path,
         final HttpMethod verb, final Map<String, ?> queryStrings,
         PrettyOutput... prettyOutput) {
      if(!checkConnection()){
         return ;
      }
      try {
         if (verb == HttpMethod.PUT) {
            ResponseEntity<String> response = restActionOps(path, id, queryStrings);
            if (!validateAuthorization(response)) {
               return;
            }
            processResponse(response, HttpMethod.PUT, prettyOutput);
         } else {
            throw new Exception(Constants.HTTP_VERB_ERROR);
         }

      } catch (Exception e) {
         throw new CliRestException(e.getMessage());
      }
   }

   private ResponseEntity<String> restActionOps(String path, String id,
         Map<String, ?> queryStrings) {
      String targetUri = hostUri + Constants.HTTP_CONNECTION_API + path + "/" + id;
      if (queryStrings != null) {
         targetUri = targetUri + buildQueryStrings(queryStrings);
      }
      HttpHeaders headers = buildHeaders();
      HttpEntity<String> entity = new HttpEntity<String>(headers);

      return client.exchange(targetUri, HttpMethod.PUT, entity, String.class);
   }

   private String buildQueryStrings(Map<String, ?> queryStrings) {
      StringBuilder stringBuilder = new StringBuilder("?");

      Set<String> keys = queryStrings.keySet();
      for (String key : keys) {
         stringBuilder.append(key + "=" + queryStrings.get(key));
      }
      return stringBuilder.toString();
   }

   /**
    * Update an object 
    * @param entity the updated content
    * @param path the rest url
    * @param verb the http method
    * @param prettyOutput output callback
    */
   public void update(Object entity, final String path, final HttpMethod verb,
         PrettyOutput... prettyOutput) {
      if(!checkConnection()){
         return ;
      }
      try {
         if (verb == HttpMethod.PUT) {
            ResponseEntity<String> response = restUpdate(path, entity);
            if (!validateAuthorization(response)) {
               return;
            }
            processResponse(response, HttpMethod.PUT, prettyOutput);
         } else {
            throw new Exception(Constants.HTTP_VERB_ERROR);
         }

      } catch (Exception e) {
         throw new CliRestException(e.getMessage());
      }
   }

   private ResponseEntity<String> restUpdate(String path, Object entityName) {
      String targetUri = hostUri + Constants.HTTP_CONNECTION_API + path;

      HttpHeaders headers = buildHeaders();
      HttpEntity<Object> entity = new HttpEntity<Object>(entityName, headers);

      return client.exchange(targetUri, HttpMethod.PUT, entity, String.class);
   }

   @SuppressWarnings("rawtypes")
   private boolean validateAuthorization(ResponseEntity response) {
      if (response.getStatusCode() == HttpStatus.UNAUTHORIZED) {
         System.out.println(Constants.CONNECT_UNAUTHORIZATION);
         return false;
      }
      return true;
   }

}
