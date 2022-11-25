package com.bezkoder.springjwt;

import com.bezkoder.springjwt.repository.RoleRepository;
import com.bezkoder.springjwt.repository.UserRepository;
import com.bezkoder.springjwt.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class SpringBootSecurityJwtApplication implements CommandLineRunner{

	@Autowired
	private RoleRepository roleRepository;

	@Autowired
	private UserRepository userRepository;


	@Autowired
	private PasswordEncoder encoder;

	public static void main(String[] args) {
    SpringApplication.run(SpringBootSecurityJwtApplication.class, args);
	}


	public void run(String... args) throws Exception {
		if (roleRepository.findAll().size()==0){
			roleRepository.creationRole();
		}
		if(userRepository.findAll().size()==0){
			userRepository.creationUsers();

		}
		if(userRepository.Verifier() == null){
			userRepository.AddRoleUser();
		}
	}
}
