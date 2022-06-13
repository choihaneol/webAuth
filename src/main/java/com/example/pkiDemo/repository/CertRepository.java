package com.example.pkiDemo.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.example.pkiDemo.entity.Certificate_;

@Repository
public interface CertRepository extends JpaRepository <Certificate_, Integer> {

	Certificate_ findOneByCertId(int certId);

}