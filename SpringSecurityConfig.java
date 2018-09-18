package com.opentext.ecommerce.configurations;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.expression.WebExpressionVoter;

import com.opentext.ecommerce.services.CustomUserDetailsService;
import com.opentext.ecommerce.services.WeekOffVoter;
@Configuration
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
/*
	@Bean
	  public UserDetailsService userDetailsService() {
	    return new CustomUserDetailsService();
	  };
	  
	  @Bean
	  public BCryptPasswordEncoder passwordEncoder() {
	    return new BCryptPasswordEncoder();
	  };
	*/  
	  
	  
	 @Override
	    protected void configure(AuthenticationManagerBuilder auth) 
	      throws Exception {
	       PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
	        auth.inMemoryAuthentication()
	          .withUser("spring")
	          .password(encoder.encode("secret"))
	          .roles("USER");
		//auth.userDetailsService(userDetailsService()).passwordEnco//der(passwordEncoder());
	    }
 
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
        
          .authorizeRequests()          
          .anyRequest()
          .authenticated()
          .and()
          .httpBasic();
        http.authorizeRequests()
       // .accessDecisionManager(accessDecisionManager());        // passed custom access decision manager
    }
/*
    @Bean
    public AccessDecisionManager accessDecisionManager() {
    	 List<AccessDecisionVoter<? extends Object>> decisionVoters = new ArrayList<AccessDecisionVoter<? extends Object>>();
    	 decisionVoters.add(new WebExpressionVoter());
    	 decisionVoters.add( new AuthenticatedVoter());
    	 decisionVoters.add(new WebExpressionVoter());
    	 decisionVoters.add( new WeekOffVoter() );
    	
        return new UnanimousBased(decisionVoters);
    }
*/
}
