package com.example.pkiDemo.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.pkiDemo.entity.CRL_;
import com.example.pkiDemo.entity.RevokedCertificate;


@Repository
public interface RVKRepository extends JpaRepository <RevokedCertificate, Integer>{

	void save(CRL_ newCrl);



	
}