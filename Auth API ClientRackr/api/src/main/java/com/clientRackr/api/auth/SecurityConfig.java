package com.clientRackr.api.auth;

import com.clientRackr.api.servicesImpl.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomUserDetailsService userDetailsService;
    private final JwtAuthorizationFilter jwtAuthorizationFilter;

    public SecurityConfig(CustomUserDetailsService customUserDetailsService, JwtAuthorizationFilter jwtAuthorizationFilter) {
        this.userDetailsService = customUserDetailsService;
        this.jwtAuthorizationFilter = jwtAuthorizationFilter;
    }

    @SuppressWarnings("deprecation")
    @Bean
    public NoOpPasswordEncoder passwordEncoder() {
        return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http, NoOpPasswordEncoder passwordEncoder)
            throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
        return authenticationManagerBuilder.build();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
//        httpSecurity.csrf(AbstractHttpConfigurer::disable)
//                .cors(cors -> cors.disable())
//                .authorizeHttpRequests(auth -> auth
//                                .requestMatchers("/rest/token").permitAll()
//                                .requestMatchers("/rest/auth/SignUp").permitAll()
//                                .requestMatchers("/rest/auth/login").permitAll()
                        /*      .authorizeHttpRequests(auth -> auth.requestMatchers("/user/**")
                        .authenticated().requestMatchers("/userAuth/**").permitAll())*/

//                                .requestMatchers("/rest/createSuperAdmin")/*.hasAnyAuthority("SUPERADMIN")*/.permitAll()
        /*SA: Partial access with Tl and not able to View status of the deals, create/cancel/assign/approve tasks,
         * not able to arrange views and close the deals
         * */

        /*.requestMatchers("/rest/auth/**").hasAnyAuthority("TEAMLEAD")*/
        // TL has all the access

        /*.requestMatchers("/rest/auth/**").hasAnyAuthority("BROKER", "AGENT")*/
        /* only limited access
         *
         * AGENT: the agent has the capability to add the sub-agents so do we need to promote the agent as the TL
         * because after the adding the sub-agents he has the team now.
         * */

        /*.requestMatchers("/rest/home/**").authenticated()*/

//                                .anyRequest().authenticated()
                       /* .and().cors().and()
                        .logout(logout -> logout // Configure logout
                                .logoutUrl("/logout") // Specify logout URL
                                .permitAll() // Allow all users to logout
                                .logoutSuccessUrl("/login") // Redirect to login page after logout
                        )
                        .exceptionHandling(exceptionHandling -> exceptionHandling // Configure exception handling
                                .accessDeniedPage("/403") // Handle access denied with custom page
                        ))*/
//                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//                .addFilterBefore(jwtAuthorizationFilter, UsernamePasswordAuthenticationFilter.class).oauth2Login(Customizer.withDefaults());
        httpSecurity
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/rest/token").permitAll()
                        .requestMatchers("/rest/auth/signUp").permitAll()
                        .requestMatchers("/rest/auth/login").permitAll()
                        .requestMatchers("/rest/auth/save-otp/**").permitAll()
                        .requestMatchers("/rest/auth/resendOTP").permitAll()
                        .requestMatchers("/rest/createSuperAdmin").permitAll() // Permit access without authentication
                        .anyRequest().authenticated() // All other requests require authentication
                )
                .addFilterBefore(jwtAuthorizationFilter, UsernamePasswordAuthenticationFilter.class)
                .formLogin(Customizer.withDefaults()) // Enable form login
                .oauth2Login(Customizer.withDefaults()); // Enable OAuth2 login

        return httpSecurity.build();
    }

}
