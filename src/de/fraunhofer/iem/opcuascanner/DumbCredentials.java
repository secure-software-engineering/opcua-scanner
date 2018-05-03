package de.fraunhofer.iem.opcuascanner;

import java.util.ArrayList;
import java.util.List;

public class DumbCredentials {
    static final List<Login> logins = new ArrayList<>();
    public DumbCredentials(){
        logins.add(new Login("username", "password"));
        logins.add(new Login("user", "password"));
        logins.add(new Login("username", "123456"));
        logins.add(new Login("user", "123456"));
        logins.add(new Login("username", "123456789"));
        logins.add(new Login("user", "123456789"));
        logins.add(new Login("username", "qwerty"));
        logins.add(new Login("user", "qwerty"));
        logins.add(new Login("admin", "admin"));
        logins.add(new Login("admin", "server"));
    }

}
