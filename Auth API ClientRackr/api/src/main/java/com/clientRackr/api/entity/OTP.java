package com.clientRackr.api.entity;

import com.clientRackr.api.validators.ValidEmail;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "OTP")
public class OTP {

    @Id
    @Basic
    @Column(name = "OTP_Id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "Email", unique = true)
    @Basic
    @ValidEmail
    private String email;

    @Basic
    @Column(name = "otp")
    private Integer oneTimePassword;

    @Basic
    private LocalDateTime otpTimestamp;

}
