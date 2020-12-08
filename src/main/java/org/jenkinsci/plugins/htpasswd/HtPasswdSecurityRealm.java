/**
 * The MIT License
 *
 * Copyright (c) 2014, Kestutis Kupciunas (aka kesha)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jenkinsci.plugins.htpasswd;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.kohsuke.stapler.DataBoundConstructor;

import com.identity4j.connector.ConnectorBuilder;
import com.identity4j.connector.flatfile.AbstractFlatFileConfiguration;
import com.identity4j.connector.htpasswd.HTPasswdConnector;
import com.identity4j.util.MultiMap;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;

/**
 *
 * @author kesha
 */
public class HtPasswdSecurityRealm extends AbstractPasswordBasedSecurityRealm implements Serializable {

    private static final long serialVersionUID = 2L;

    private static final Logger logger = Logger.getLogger("htpasswd-security-realm");

    private final String htpasswdLocation;
    private final String htgroupsLocation;

    // Transient to avoid XStream2 serialization (JEP-200 compatibility)
    private transient HTPasswdConnector htPasswdConnector;

    @DataBoundConstructor
    public HtPasswdSecurityRealm(String htpasswdLocation, String htgroupsLocation) throws IOException {
        this.htpasswdLocation = htpasswdLocation;
        this.htgroupsLocation = htgroupsLocation;
        getHTPasswdConnector();
    }

    public String getHtpasswdLocation() {
        return this.htpasswdLocation;
    }

    public String getHtgroupsLocation() {
        return this.htgroupsLocation;
    }

    private HTPasswdConnector getHTPasswdConnector() throws IOException {
        if (htPasswdConnector == null) {
            htPasswdConnector = new HTPasswdConnector();
            try (InputStream inputStream = getClass().getResourceAsStream("/htpasswd-connector.properties")) {
                Properties properties = new Properties();
                properties.load(inputStream);
                properties.put(AbstractFlatFileConfiguration.KEY_FILENAME, htpasswdLocation);
                htPasswdConnector.open(new ConnectorBuilder().buildConfiguration(MultiMap.toMultiMap(properties)));
            }
        }
        return htPasswdConnector;
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
        @Override
        public String getDisplayName() {
            return "htpasswd";
        }
    }

    private transient CachedHtFile<HtGroupFile> cachedHtGroupsFile;
    private HtGroupFile getHtGroupFile() throws IOException, ReflectiveOperationException {
        if (cachedHtGroupsFile == null) {
            cachedHtGroupsFile = new CachedHtFile<>(this.htgroupsLocation, HtGroupFile.class);
        }
        return cachedHtGroupsFile.get();
    }

    private static final GrantedAuthority[] DEFAULT_AUTHORITY = new GrantedAuthority[] { AUTHENTICATED_AUTHORITY };
    private static final GrantedAuthority[] GRANTED_AUTHORITY_TYPE = new GrantedAuthority[0];

    /**
     * Retrieves the array of granted authorities for the given user.
     * It will always contain at least one entry - "authenticated"
     *
     * @param username
     * @return the array of granted authorities, with at least
     */
    private GrantedAuthority[] getAuthenticatedUserGroups(final String username) {
        try {
            HtGroupFile htgroups = getHtGroupFile();
            List<String> groups = htgroups.getGroups(username);
            ArrayList<GrantedAuthority> authorities = new ArrayList<>(groups.size() + 1);
            authorities.add(AUTHENTICATED_AUTHORITY);
            for (String group : groups) {
                authorities.add(new GrantedAuthorityImpl(group));
            }
            return authorities.toArray(GRANTED_AUTHORITY_TYPE);
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            return DEFAULT_AUTHORITY;
        }
    }

    private GrantedAuthority[] getUserGroups(final String username) {
        try {
            List<GrantedAuthority> authorities = getHtGroupFile().getGroups(username).stream()
                    .map(GrantedAuthorityImpl::new).collect(Collectors.toList());
            return authorities.toArray(GRANTED_AUTHORITY_TYPE);
        } catch (Exception ex) {
            logger.log(Level.SEVERE, ex.getMessage(), ex);
            return GRANTED_AUTHORITY_TYPE;
        }
    }

    @Override
    protected UserDetails authenticate(final String username, final String password) {
        logger.finest(() -> "authenticate(" + username + ")");
        try {
            if (getHTPasswdConnector().checkCredentials(username, password.toCharArray())) {
                return new User(username, password, true, true, true, true, getAuthenticatedUserGroups(username));
            }
        } catch (Exception ex) {
            throw new BadCredentialsException(ex.getMessage(), ex);
        }
        throw new BadCredentialsException(String.format("Invalid user '%s' credentials", username));
    }

    @Override
    public UserDetails loadUserByUsername(final String username) {
        logger.finest(() -> "loadUserByUsername(" + username + ")");
        try {
            if (getHTPasswdConnector().getIdentityByName(username) != null) {
                return new User(username, "", true, true, true, true, getUserGroups(username));
            }
            throw new IllegalStateException(String.format("User '%s' does not exist", username));
        } catch (Exception ex) {
            throw new UsernameNotFoundException(String.format("Failed to load user '%s'", username), ex);
        }
    }

    @Override
    public GroupDetails loadGroupByGroupname(final String groupname) {
        logger.finest(() -> "loadGroupByGroupname(" + groupname + ")");
        try {
            HtGroupFile htgroups = getHtGroupFile();

            List<String> users = htgroups.getUsers(groupname);
            if (users != null && !users.isEmpty()) {
                return new SimpleGroup(groupname);
            }
        } catch (Exception ex) {
            throw new UsernameNotFoundException(String.format("Failed to load group '%s'", groupname), ex);
        }
        throw new UsernameNotFoundException(String.format("Group '%s' not found", groupname));
    }
}
