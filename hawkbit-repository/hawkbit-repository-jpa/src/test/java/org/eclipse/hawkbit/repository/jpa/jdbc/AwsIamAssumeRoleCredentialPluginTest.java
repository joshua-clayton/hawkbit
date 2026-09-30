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

import static org.assertj.core.api.Assertions.assertThat;

import java.sql.SQLException;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.mariadb.jdbc.Configuration;
import org.mariadb.jdbc.HostAddress;
import org.mariadb.jdbc.plugin.Credential;

class AwsIamAssumeRoleCredentialPluginTest {

    @Test
    void exposesExpectedPluginTypeAndSslRequirement() {
        final AwsIamAssumeRoleCredentialPlugin plugin = new AwsIamAssumeRoleCredentialPlugin();

        assertThat(plugin.type()).isEqualTo("AWS-IAM-ASSUME-ROLE");
        assertThat(plugin.mustUseSsl()).isTrue();
    }

    @Test
    void cachesGeneratedCredentialsForTheSameConfiguration() throws SQLException {
        final AtomicInteger calls = new AtomicInteger();
        final AwsIamAssumeRoleCredentialPlugin plugin = new AwsIamAssumeRoleCredentialPlugin(
                (conf, userName, hostAddress) -> {
                    calls.incrementAndGet();
                    return () -> new Credential(userName, "token-" + calls.get());
                });

        final Configuration configuration = Configuration.parse(
                "jdbc:mariadb://hawkbit.database.int.aws.lvt.cloud:3306/hawkbit?user=hawkbit_app"
                        + "&credentialType=AWS-IAM-ASSUME-ROLE"
                        + "&assumeRoleArn=arn:aws:iam::310656228086:role/hawkbit-app-operator");
        plugin.initialize(configuration, configuration.user(), configuration.addresses().get(0));

        final Credential first = plugin.get();
        final Credential second = plugin.get();

        assertThat(first.getUser()).isEqualTo("hawkbit_app");
        assertThat(first.getPassword()).isEqualTo("token-1");
        assertThat(second.getPassword()).isEqualTo("token-1");
        assertThat(calls).hasValue(1);
    }

    @Test
    void initializePassesTheConfiguredUserAndHostToTheGenerator() throws SQLException {
        final HostAddress expectedHost = HostAddress.from("hawkbit.database.int.aws.lvt.cloud", 3306);
        final StringBuilder observed = new StringBuilder();
        final AwsIamAssumeRoleCredentialPlugin plugin = new AwsIamAssumeRoleCredentialPlugin(
                (conf, userName, hostAddress) -> {
                    observed.append(userName).append('@').append(hostAddress.host).append(':').append(hostAddress.port);
                    return () -> new Credential(userName, "token");
                });

        final Configuration configuration = Configuration.parse(
                "jdbc:mariadb://hawkbit.database.int.aws.lvt.cloud:3306/hawkbit?user=hawkbit_app"
                        + "&credentialType=AWS-IAM-ASSUME-ROLE"
                        + "&assumeRoleArn=arn:aws:iam::310656228086:role/hawkbit-app-operator");

        plugin.initialize(configuration, "hawkbit_app", expectedHost);

        assertThat(observed.toString()).isEqualTo("hawkbit_app@hawkbit.database.int.aws.lvt.cloud:3306");
    }
}
