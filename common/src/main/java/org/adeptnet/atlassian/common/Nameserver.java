/*
 * Copyright 2015 Francois Steyn - Adept Internet (PTY) LTD (francois.s@adept.co.za).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.adeptnet.atlassian.common;

import java.util.ArrayList;
import java.util.List;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

public class Nameserver {

    public Nameserver() {
    }

    public String[] lookup(final String fqdn, final String type) throws NamingException {

        final Attributes atrs = getInitialContext().getAttributes(fqdn, new String[]{type});
        final NamingEnumeration<? extends Attribute> naming_enum = atrs.getAll();
        final List<String> res = new ArrayList<>();
        while (naming_enum.hasMoreElements()) {
            Attribute atr = naming_enum.nextElement();
            for (int j = 0; j < atr.size(); ++j) {
                res.add((String) atr.get(j));
            }
        }
        return res.toArray(new String[]{});
    }

    private DirContext makeDirContext() throws NamingException {
        final java.util.Hashtable<String, Object> env = new java.util.Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
        return new InitialDirContext(env);
    }

    private DirContext getInitialContext() throws NamingException {
        if (ictx != null) {
            return ictx;
        } else {
            return ictx = makeDirContext();
        }
    }

    private transient DirContext ictx;
}
