package com.opentext.ecommerce.services;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

public class CustomUserDetailsService implements UserDetailsService {
	/*
	@Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
System.out.println(username);
PasswordEncoder encoder =new BCryptPasswordEncoder();
        if(username.equals("user1")) {

        	 return User.withUsername("user1")
	                   .password(encoder.encode("123"))
	                   .roles("USER").build();
        } else {
            throw new UsernameNotFoundException("Not Found");
        }
	}
	*/
	 private static List<UserObject> users = new ArrayList();

	    public CustomUserDetailsService() {
	        //in a real application, instead of using local data,
	        // we will find user details by some other means e.g. from an external system
	        users.add(new UserObject("user1", "123", "ADMIN"));
	        users.add(new UserObject("user2", "234", "ADMIN"));
	    }

	    @Override
	    //UserName Authentication filter
	    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
	        Optional<UserObject> user = users.stream()
	                                         .filter(u -> u.name.equals(username))
	                                         .findAny();
	        if (!user.isPresent()) {
	            throw new UsernameNotFoundException("User not found by name: " + username);
	        }
	        return toUserDetails(user.get());
	    }

	    private UserDetails toUserDetails(UserObject userObject) {
	    	PasswordEncoder encoder =new BCryptPasswordEncoder();
	        return User.withUsername(userObject.name)
	                   .password(encoder.encode(userObject.password))
	                   .roles(userObject.role).build();
	    }

	    private static class UserObject {
	        private String name;
	        private String password;
	        private String role;

	        public UserObject(String name, String password, String role) {
	            this.name = name;
	            this.password = password;
	            this.role = role;
	        }
	    }
}
