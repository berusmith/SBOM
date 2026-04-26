package com.example;

/** Plain POJO with public setters — Spring will bind request params
 *  into instances of this via reflective property access, which is the
 *  CVE-2022-22965 attack surface. */
public class UserDto {
    private String name;
    private String email;

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
}
