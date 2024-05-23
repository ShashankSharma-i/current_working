package com.clientRackr.api.repository;

import com.clientRackr.api.entity.OTP;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;


@Repository
public interface OtpRepository extends JpaRepository<OTP, Long> {
    OTP findByEmail(String email);

    @Transactional
    @Modifying
    @Query(value = "DELETE FROM User u WHERE u.email = :email", nativeQuery = true)
    void deleteByEmail(String email);
}

