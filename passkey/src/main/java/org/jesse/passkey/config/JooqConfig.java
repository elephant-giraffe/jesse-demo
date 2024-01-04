package org.jesse.passkey.config;

import javax.sql.DataSource;
import org.jooq.ConnectionProvider;
import org.jooq.DSLContext;
import org.jooq.SQLDialect;
import org.jooq.impl.DSL;
import org.jooq.impl.DataSourceConnectionProvider;
import org.jooq.impl.DefaultConfiguration;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

@Configuration
public class JooqConfig {

    @Bean
    @Primary
    @ConfigurationProperties("hikari")
    public DataSourceProperties dataSourceProperties() {
        return new DataSourceProperties();
    }

    @Bean
    @Primary
    public DataSource dataSource() {
        return dataSourceProperties().initializeDataSourceBuilder().build();
    }

    @Bean
    public DSLContext dslContext() {
        ConnectionProvider provider = new DataSourceConnectionProvider(dataSource());
        org.jooq.Configuration configuration = new DefaultConfiguration().set(provider).set(SQLDialect.MYSQL);
        return DSL.using(configuration);
    }

}
