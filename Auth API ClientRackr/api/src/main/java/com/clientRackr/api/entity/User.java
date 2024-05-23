package com.clientRackr.api.entity;

import com.clientRackr.api.IValidation.MailValidator;
import com.clientRackr.api.IValidation.ValidFirstName;
import com.clientRackr.api.IValidation.ValidLastName;
import com.clientRackr.api.IValidation.ValidPassword;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

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
//    @Basic
//    @Email
    @MailValidator
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
    @ValidLastName
    private String lastName;

    @Column(name = "Is_Verified")
    private Boolean isVerified;

    /*@OneToOne
    @JoinColumn(name = "role_id")
    private Role role;*/

}
