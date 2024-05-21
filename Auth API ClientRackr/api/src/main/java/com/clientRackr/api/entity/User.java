package com.clientRackr.api.entity;

import com.clientRackr.api.validators.ValidEmail;
import com.clientRackr.api.validators.ValidFirstName;
import com.clientRackr.api.validators.ValidPassword;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "User")
public class User {
    @Id
    @Basic
    @Column(name = "User_Id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "Email", unique = true)
    @Basic
    @ValidEmail
    private String email;

    @Column(name = "Password")
    @Basic
    @ValidPassword
    private String password;

    @Column(name = "First_Name")
    @Basic
    @ValidFirstName
    private String firstName;

    @Column(name = "Last_Name")
    @Basic
    private String lastName;

    /*@OneToOne
    @JoinColumn(name = "role_id")
    private Role role;*/

}
