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

import java.sql.SQLException;
import java.util.Properties;

import org.mariadb.jdbc.HostAddress;
import org.mariadb.jdbc.plugin.Credential;

import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.regions.providers.DefaultAwsRegionProviderChain;
import software.amazon.awssdk.services.rds.RdsUtilities;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;
import software.amazon.awssdk.services.sts.StsClient;

final class AwsAssumeRoleCredentialGenerator implements AwsIamAssumeRoleCredentialPlugin.CredentialGenerator {

    static final String ASSUME_ROLE_ARN_PROPERTY = "assumeRoleArn";
    static final String REGION_PROPERTY = "region";
    static final String ROLE_SESSION_NAME = "hawkbit-db";

    private final String userName;
    private final String authenticationToken;

    AwsAssumeRoleCredentialGenerator(final Properties options, final String userName, final HostAddress hostAddress)
            throws SQLException {
        this(options, userName, hostAddress, createBaseCredentialsProvider(), requireAssumeRoleArn(options),
                resolveRegion(options));
    }

    AwsAssumeRoleCredentialGenerator(final Properties options, final String userName, final HostAddress hostAddress,
            final AwsCredentialsProvider baseCredentialsProvider, final Region region) throws SQLException {
        this(options, userName, hostAddress, baseCredentialsProvider, requireAssumeRoleArn(options),
                region);
    }

    AwsAssumeRoleCredentialGenerator(final Properties options, final String userName, final HostAddress hostAddress,
            final AwsCredentialsProvider baseCredentialsProvider, final String assumeRoleArn, final Region region)
            throws SQLException {
        this.userName = userName;

        if (assumeRoleArn == null || assumeRoleArn.isBlank()) {
            throw new SQLException("Identity plugin 'AWS-IAM-ASSUME-ROLE' requires the 'assumeRoleArn' connection property");
        }

        final StsClient stsClient = StsClient.builder()
                .credentialsProvider(baseCredentialsProvider)
                .region(region)
                .build();
        final AwsCredentialsProvider assumedRoleCredentialsProvider = StsAssumeRoleCredentialsProvider.builder()
                .stsClient(stsClient)
                .refreshRequest(request -> request.roleArn(assumeRoleArn).roleSessionName(ROLE_SESSION_NAME))
                .build();
        final RdsUtilities utilities = RdsUtilities.builder()
                .credentialsProvider(assumedRoleCredentialsProvider)
                .region(region)
                .build();
        authenticationToken = utilities.generateAuthenticationToken(request -> request
                .hostname(hostAddress.host)
                .port(hostAddress.port)
                .username(userName)
                .credentialsProvider(assumedRoleCredentialsProvider));
    }

    public Credential getToken() {
        return new Credential(userName, authenticationToken);
    }

    static AwsCredentialsProvider createBaseCredentialsProvider() {
        return DefaultCredentialsProvider.builder().build();
    }

    static String requireAssumeRoleArn(final Properties options) throws SQLException {
        final String assumeRoleArn = options.getProperty(ASSUME_ROLE_ARN_PROPERTY);
        if (assumeRoleArn == null || assumeRoleArn.isBlank()) {
            throw new SQLException("Identity plugin 'AWS-IAM-ASSUME-ROLE' requires the 'assumeRoleArn' connection property");
        }
        return assumeRoleArn;
    }

    static Region resolveRegion(final Properties options) {
        final String region = options.getProperty(REGION_PROPERTY);
        return region != null ? Region.of(region) : new DefaultAwsRegionProviderChain().getRegion();
    }
}
