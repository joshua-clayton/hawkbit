/*
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 */

package org.eclipse.hawkbit.repository.jpa.jdbc;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.sql.SQLException;
import java.util.Properties;

import org.junit.jupiter.api.Test;
import org.mariadb.jdbc.HostAddress;

class AwsAssumeRoleCredentialGeneratorTest {

    @Test
    void constructorRequiresAssumeRoleArn() {
        assertThatExceptionOfType(SQLException.class)
                .isThrownBy(() -> new AwsAssumeRoleCredentialGenerator(new Properties(), "hawkbit_app",
                        HostAddress.from("hawkbit.database.int.aws.lvt.cloud", 3306)))
                .withMessageContaining("assumeRoleArn");
    }
}
