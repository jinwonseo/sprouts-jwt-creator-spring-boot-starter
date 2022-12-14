package kr.sprouts.autoconfigure.configurations;

import kr.sprouts.autoconfigure.components.JwtCreator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtCreatorConfiguration {
    private final Logger logger = LoggerFactory.getLogger(JwtCreatorConfiguration.class);

    public JwtCreatorConfiguration() {
        this.logger.info(String.format("Initialized %s", JwtCreatorConfiguration.class.getName()));
    }

    @Bean
    public JwtCreator jwtCreator() {
        return new JwtCreator();
    }
}
