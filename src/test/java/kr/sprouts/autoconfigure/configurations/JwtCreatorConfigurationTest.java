package kr.sprouts.autoconfigure.configurations;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

class JwtCreatorConfigurationTest {
    private final ApplicationContextRunner applicationContextRunner = new ApplicationContextRunner().withConfiguration(
            AutoConfigurations.of(JwtCreatorConfiguration.class)
    );

    @Test
    public void bean_test() {
        this.applicationContextRunner.run(
                context -> assertThat(context).hasSingleBean(JwtCreatorConfiguration.class)
        );
    }
}