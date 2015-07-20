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
package org.adeptnet.atlassian.saml;

public class SAMLException extends Exception {

    private static final long serialVersionUID = -4190176773559991188L;

    public SAMLException(final String reason) {
        super(reason);
    }

    public SAMLException(final String reason, final Throwable cause) {
        super(reason, cause);
    }

    public SAMLException(final Throwable cause) {
        super(cause);
    }
}
