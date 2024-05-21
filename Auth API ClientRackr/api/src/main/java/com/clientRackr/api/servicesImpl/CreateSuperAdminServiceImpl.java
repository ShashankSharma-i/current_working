package com.clientRackr.api.servicesImpl;

import com.clientRackr.api.entity.Role;
import com.clientRackr.api.repository.RoleRepository;
import com.clientRackr.api.IServices.CreateSuperAdminService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CreateSuperAdminServiceImpl implements CreateSuperAdminService {

    @Autowired
    RoleRepository roleRepository;

    public Role DummySuperAdminData() {
        Role role = new Role();
        role.setRole("superAdmin");
        roleRepository.save(role);
        return role;
    }
}
