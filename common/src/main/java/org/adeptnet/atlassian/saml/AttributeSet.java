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

import java.util.Map;
import java.util.List;

/**
 * AttributeSet contains the NameID from the subject as well as any attributes
 * contained in the assertion, as a map of Attribute Name to list of String
 * values.
 */
public class AttributeSet {

    private final String nameId;
    private final Map<String, List<String>> attributes;

    public AttributeSet(final String nameId, final Map<String, List<String>> attributes) {
        this.nameId = nameId;
        this.attributes = attributes;
    }

    public String getNameId() {
        return nameId;
    }

    public Map<String, List<String>> getAttributes() {
        return this.attributes;
    }
}
