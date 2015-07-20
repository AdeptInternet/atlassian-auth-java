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
package org.adeptnet.atlassian.kerberos;

import java.io.File;
import java.util.function.Function;

/**
 *
 * @author Francois Steyn - Adept Internet (PTY) LTD (francois.s@adept.co.za)
 */
public class Krb5ConfigImpl implements Krb5Config {

    private String realm;
    private String contextName;
    private String keytabName;
    private File keytab;

    @Override
    public String getRealm() {
        return realm;
    }

    @Override
    public String getContextName() {
        return contextName;
    }

    @Override
    public File getKeytab() {
        return keytab;
    }

    public void setRealm(final String realm) {
        if (realm == null) {
            throw new NullPointerException("Realm should never be null");
        }

        this.realm = realm;

        if (contextName == null) {
            setContextName(String.format("dynamic-%s", realm));
        }
        if (keytabName == null) {
            setKeytabName(String.format("%s.keytab", realm));
        }
    }

    public void setContextName(final String contextName) {
        if (contextName == null) {
            throw new NullPointerException("ContextName should never be null");
        }
        this.contextName = contextName;
    }

    public String getKeytabName() {
        return keytabName;
    }

    public void setKeytabName(final String keytabName) {
        if (keytabName == null) {
            throw new NullPointerException("KeytabName should never be null");
        }
        keytab = null;
        this.keytabName = keytabName;
    }

    public void init(final Function<String, String> function) {
        if (keytab != null) {
            return;
        }
        keytab = new File(function.apply(getKeytabName()));
    }

}
