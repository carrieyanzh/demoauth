package com.demoauth.demoauth.config;

import com.demoauth.demoauth.jwt.AuthEntryPointJwt;
import com.demoauth.demoauth.jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class WebSecurityConfig {
  @Autowired
  DataSource dataSource;

  @Autowired
  private AuthEntryPointJwt unauthorizedHandler;

  @Bean
  public AuthTokenFilter authenticationJwtTokerFilter(){
    return new AuthTokenFilter();
  }

  @Bean
  SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests((requests) ->
      requests.requestMatchers("/h2-console/**").permitAll()
        .requestMatchers("/signin").permitAll()
      .anyRequest().authenticated());

    http.sessionManagement(session
        -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
    http.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler));
    //http.formLogin(withDefaults());
   //http.httpBasic(withDefaults());

    http.headers(headers ->
      headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));

    http.csrf(AbstractHttpConfigurer::disable);
    http.addFilterBefore(authenticationJwtTokerFilter(), UsernamePasswordAuthenticationFilter.class);
    return http.build();
  }

  @Bean
  public   AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception{
    return builder.getAuthenticationManager();
  }

 /* //@Bean
  public UserDetailsService userDetailsService() {
    UserDetails user =
        User.withUsername("user1")
//        .password("{noop}password1")
        .password(passwordEncoder().encode("password1"))
        .roles("USER")
        .build();

    UserDetails admin =
      User//.withDefaultPasswordEncoder()
        //.username("admin1")
        .withUsername("admin1")
        //.password("{noop}adminpassword1")
        .password(passwordEncoder().encode("adminpassword1"))
        .roles("ADMIN")
        .build();
    JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
    userDetailsManager.createUser(user);
    userDetailsManager.createUser(admin);
    return userDetailsManager;
    //return new InMemoryUserDetailsManager(user, admin);
  }*/

  @Bean
  public UserDetailsService userDetailsService(DataSource dataSource) {
    return new JdbcUserDetailsManager(dataSource);
  }

@Bean
  public CommandLineRunner initData(UserDetailsService userDetailsService){
    return args ->{
      JdbcUserDetailsManager userDetailsManager = (JdbcUserDetailsManager) userDetailsService;
      UserDetails user =
        User.withUsername("user1")
          .password(passwordEncoder().encode("password1"))
          .roles("USER")
          .build();

      UserDetails admin = User.withUsername("admin1")
        .password(passwordEncoder().encode("adminpassword1"))
        .roles("ADMIN")
        .build();

     // JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager();
      userDetailsManager.createUser(user);
      userDetailsManager.createUser(admin);
    };
  }

  @Bean
  public PasswordEncoder passwordEncoder(){
    return new BCryptPasswordEncoder();
  }
}
