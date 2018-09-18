package com.opentext.ecommerce.services;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import java.time.LocalDateTime;
import java.util.Collection;

public class WeekOffVoter implements AccessDecisionVoter {
    @Override
    public int vote(Authentication authentication, Object object, Collection collection) {
    	System.out.println("Entering.....");
    	authentication.getAuthorities().stream().forEach(e->System.out.println(e.getAuthority()));
        boolean isRoleUser = authentication.getAuthorities().stream()
                                           .filter(e -> e.getAuthority().equals("ROLE_ADMIN"))
                                           .findAny().isPresent();                      // check is staff role
        if (isRoleUser) {
        	System.out.println(LocalDateTime.now().getDayOfWeek().getValue());
            if (LocalDateTime.now().getDayOfWeek().getValue() == 7)        // check for sunday
                return ACCESS_DENIED;                                   // deny if sunday
            else {
                return ACCESS_ABSTAIN;                  // not granted or not deny, Decision based on other voter
            }
        } else {
            return ACCESS_ABSTAIN;              // not granted or not deny, Decision based on other voter
        }
    }
    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;            
    }
    @Override
    public boolean supports(Class clazz) {
        return true;                    
    }
}