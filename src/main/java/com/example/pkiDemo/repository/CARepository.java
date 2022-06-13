package com.example.pkiDemo.repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.example.pkiDemo.entity.CA;
import com.example.pkiDemo.entity.CAType;
import com.example.pkiDemo.entity.Certificate_;
@Repository
public interface CARepository extends JpaRepository<CA, Integer>{

	//List<CAType> findByCAType(CAType type);
	CA findOneByCaType(CAType rootca); //주임님 수정 	
	Optional<Certificate_> findBycaType(int caId);
	CA findOneByCaId(int caId);

}
