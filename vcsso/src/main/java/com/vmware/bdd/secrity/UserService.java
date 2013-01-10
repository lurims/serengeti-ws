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

import java.util.ArrayList;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;

import org.apache.log4j.Logger;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.vmware.bdd.entity.User;
import com.vmware.bdd.entity.Users;
import com.vmware.bdd.utils.FileUtil;

public class UserService implements UserDetailsService {

   private static final Logger logger = Logger.getLogger(UserService.class);
   private static final String UsersFile = "Users.xml";

   @Override
   public UserDetails loadUserByUsername(String username)
         throws UsernameNotFoundException {
      JAXBContext jaxbContext;
      try {
         jaxbContext = JAXBContext.newInstance(Users.class);
         Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
         Users users =
               (Users) jaxbUnmarshaller.unmarshal(FileUtil.getConfigFile(
                     UserService.UsersFile, "Users"));
         User userDTO = null;
         boolean exsiting = false;
         if (users != null) {
            for (User user : users.getUsers()) {
               if (user.getName().equals(username)) {
                  exsiting = true;
                  userDTO = user;
               }
            }
         }
         if (!exsiting) {
            throw new UsernameNotFoundException(null);
         }

         ArrayList<GrantedAuthority> list = new ArrayList<GrantedAuthority>();
         list.add(new SimpleGrantedAuthority(userDTO.getRole()));
         return new org.springframework.security.core.userdetails.User(
               userDTO.getName(), "", list);
      } catch (Exception e) {
         logger.error("Authorized error :" + e.getMessage());
         throw new UsernameNotFoundException("Unauthorized");
      }
   }

}
