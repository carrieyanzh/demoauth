package com.demoauth.demoauth;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

@SpringBootApplication
public class DemoauthApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoauthApplication.class, args);
	}

  /*public CommandLineRunner initData(UserDetailsService userDetailsService){
    return args ->{
      JdbcUserDetailsManager manager = (JdbcUserDetailsManager) userDetailsService;
      UserDetails user = User.withUsername("user1")
        .password(passwordEncoder().encode("password1"))
        .roles("USER")
        .build();
      UserDetails admin = User.withUsername("admin1")
        .password(passwordEncoder().encode("adminpassword1"))
        .roles("ADMIN")
        .build();

      JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager();
      userDetailsManager.createUser(user);
      userDetailsManager.createUser(admin);
    };
  }
  public PasswordEncoder passwordEncoder(){
    return new BCryptPasswordEncoder();
  }*/
}
