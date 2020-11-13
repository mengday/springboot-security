package com.example.security.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/user")
public class UserController {

    @RequestMapping("/add")
    @PreAuthorize("hasAnyRole('user:add')")
    public String add() {
        return "user:add";
    }

    @RequestMapping("/update")
    @PreAuthorize("hasAnyRole('user:update')")
    public String update() {
        return "user:update";
    }

    @RequestMapping("/view")
    @PreAuthorize("hasAnyRole('user:view')")
    public String view() {
        return "user:view";
    }

    @RequestMapping("/delete")
    @PreAuthorize("hasAnyRole('user:delete')")
    public String delete() {
        return "user:delete";
    }
}
