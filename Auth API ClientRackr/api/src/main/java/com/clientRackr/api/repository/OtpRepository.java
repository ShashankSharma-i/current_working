package com.clientRackr.api.repository;

import com.clientRackr.api.entity.OTP;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


@Repository
public interface OtpRepository extends JpaRepository<OTP, Long> {
    OTP findByEmail(String email);
}

