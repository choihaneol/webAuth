package com.example.pkiDemo.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.pkiDemo.entity.CRL_;

@Repository
public interface CRLRepository extends JpaRepository <CRL_, Integer> {
	
	CRL_ findOneByCrlId(int crlId);
	
	

}