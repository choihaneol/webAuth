package com.example.pkiDemo.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import com.example.pkiDemo.controller.RestCertController;

//서버 시작과동시에 구동되는 CommandLineRunner
@Component
public class CommandLineRunnerForRootCheck implements CommandLineRunner {

	@Autowired
	private RestCertController restCertController;

	@Override
	public void run(String... args) throws Exception {
		restCertController.checkRootCA();
	}
	
}
