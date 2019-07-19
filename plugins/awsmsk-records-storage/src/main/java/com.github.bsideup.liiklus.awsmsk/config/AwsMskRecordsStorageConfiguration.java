package com.github.bsideup.liiklus.awsmsk.config;

import com.github.bsideup.liiklus.awsmsk.AwsMskRecordsStorage;
import com.github.bsideup.liiklus.records.RecordsStorage;
import com.google.auto.service.AutoService;
import lombok.Data;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.core.env.Profiles;
import org.springframework.validation.annotation.Validated;
import software.amazon.awssdk.services.kafka.KafkaAsyncClient;

import javax.validation.constraints.NotEmpty;
import java.net.URI;
import java.util.Optional;

@AutoService(ApplicationContextInitializer.class)
public class AwsMskRecordsStorageConfiguration implements ApplicationContextInitializer<GenericApplicationContext> {

    @Override
    public void initialize(GenericApplicationContext applicationContext) {
        var environment = applicationContext.getEnvironment();

        if (!environment.acceptsProfiles(Profiles.of("gateway"))) {
            return;
        }

        if (!"AWSMSK".equals(environment.getProperty("storage.records.type"))) {
            return;
        }

        var binder = Binder.get(environment);

        var awsMskProperties = binder.bind("awsmsk", AwsMskProperties.class).get();

        applicationContext.registerBean(
                RecordsStorage.class,
                () -> {
                    var builder = KafkaAsyncClient.builder();

                    awsMskProperties.getEndpoint()
                            .map(URI::create)
                            .ifPresent(builder::endpointOverride);

                    var awsMsk = builder
                            .build();


                    return new AwsMskRecordsStorage(
                            awsMsk,
                            awsMskProperties.getArn(),
                            awsMskProperties.getAuthentication().map(it -> new AwsMskRecordsStorage.Authentication(
                                    it.getCertificateChain(),
                                    it.getPrivateKey()
                            ))
                    );
                }
        );
    }

    @Data
    @Validated
    public static class AwsMskProperties {

        Optional<String> endpoint = Optional.empty();

        @NotEmpty
        String arn;

        Optional<AwsMskAuthenticationProperties> authentication = Optional.empty();

    }

    @Data
    @Validated
    public static class AwsMskAuthenticationProperties {

        @NotEmpty
        String certificateChain;

        @NotEmpty
        String privateKey;

    }

}
