package com.service.hi.servicehi.dto;

import javax.validation.constraints.NotBlank;
import java.io.Serializable;


public class UserPhoneLoginParamDto implements Serializable {

    @NotBlank(message = "用户名不能为空")
    private String phone;

    @NotBlank(message = "密码不能为空")
    private String code;

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }
}
