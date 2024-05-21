package com.clientRackr.api.controllerImpl;

import com.clientRackr.api.entity.Role;
import com.clientRackr.api.IServices.CreateSuperAdminService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/rest")
public class HomeController {

    @Autowired
    CreateSuperAdminService createSuperAdminService;

    @ResponseBody
    @RequestMapping(value = "/home",method = RequestMethod.GET)
    public String hello(){
        return "hello world";
    }

    @ResponseBody
    @RequestMapping(value = "/createSuperAdmin",method = RequestMethod.POST)
    public ResponseEntity<Role> createSuperAdmin(){
        Role role = createSuperAdminService.DummySuperAdminData();
        return ResponseEntity.status(HttpStatus.CREATED).body(role);
    }


}
