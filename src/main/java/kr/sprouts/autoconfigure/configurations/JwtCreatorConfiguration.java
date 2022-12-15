package kr.sprouts.autoconfigure.configurations;

import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtCreatorConfiguration {
    public JwtCreatorConfiguration() {
        LoggerFactory.getLogger(JwtCreatorConfiguration.class)
                .info(String.format("Initialized %s", JwtCreatorConfiguration.class.getName()));
    }
}
