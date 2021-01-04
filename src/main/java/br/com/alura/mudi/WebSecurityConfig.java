package br.com.alura.mudi;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private javax.sql.DataSource dataSource;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests().anyRequest().authenticated().and()
				.formLogin(form -> form.loginPage("/login").defaultSuccessUrl("/home", true).permitAll())
				//.logout(logout -> logout.logoutUrl("/logout"));
				.logout(logout -> logout.logoutUrl("/logout"));
				//.logout(logout -> logout.logoutUrl("/logout"));
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		BCryptPasswordEncoder enconder = new BCryptPasswordEncoder();

		auth.jdbcAuthentication()
			.dataSource(dataSource)
			.passwordEncoder(enconder);

	}
}
