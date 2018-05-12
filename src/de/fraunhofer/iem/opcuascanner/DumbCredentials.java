package de.fraunhofer.iem.opcuascanner;

import java.util.ArrayList;
import java.util.List;

/**
 * Class providing logins that can be regarded as insecure since
 * they may be easy to guess.
 * Loosely based on most recent data from https://en.wikipedia.org/wiki/List_of_the_most_common_passwords.
 * Also includes passwords from eclipse milo examples.
 */
class DumbCredentials {

    private DumbCredentials() {
        //Do not instantiate this, this a util class.
        //Private constructor hides implicit public one
    }

    static final List<Login> logins = new ArrayList<>();
    static{
        logins.add(new Login("username", "password"));
        logins.add(new Login("user", "password"));
        logins.add(new Login("username", "password1"));
        logins.add(new Login("user", "password1"));
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
