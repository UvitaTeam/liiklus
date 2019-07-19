package com.github.bsideup.liiklus.awsmsk;

import com.github.bsideup.liiklus.kafka.KafkaRecordsStorage;
import com.github.bsideup.liiklus.records.RecordsStorage;
import lombok.AccessLevel;
import lombok.SneakyThrows;
import lombok.Value;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import software.amazon.awssdk.services.kafka.KafkaAsyncClient;
import software.amazon.awssdk.services.kafka.model.GetBootstrapBrokersRequest;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletionStage;

@Slf4j
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
public class AwsMskRecordsStorage implements RecordsStorage {

    private static final String DEFAULT_TRUSTSTORE = Path.of(
            System.getProperty("java.home"), "lib", "security", "cacerts"
    ).toString();

    KafkaRecordsStorage kafkaRecordsStorage;

    public AwsMskRecordsStorage(KafkaAsyncClient kafkaClient, String arn, Optional<Authentication> authOpt) {
        final Map<String, String> props = new HashMap<>();

        BrokerBootstrapInformation brokerBootstrapInfo = getBroker(arn, kafkaClient);
        if (brokerBootstrapInfo.getType() == BrokerBootstrapInformation.Type.TLS) {
            // defaults to TLS if available
            props.put("security.protocol", "SSL");
            props.put("ssl.truststore.location", DEFAULT_TRUSTSTORE);
        }

        authOpt.map(this::setupStores).ifPresent(kafkaStore -> {
            props.put("ssl.keystore.location", kafkaStore.getKeystoreLocation());
            props.put("ssl.keystore.password", kafkaStore.getKeystorePassword());
            props.put("ssl.key.password", kafkaStore.getKeyPassword());
        });

        this.kafkaRecordsStorage = new KafkaRecordsStorage(
                brokerBootstrapInfo.getBootstrapServer(),
                props
        );
    }

    @Override
    public CompletionStage<OffsetInfo> publish(Envelope envelope) {
        return kafkaRecordsStorage.publish(envelope);
    }

    @Override
    public Subscription subscribe(String topic, String groupName, Optional<String> autoOffsetReset) {
        return kafkaRecordsStorage.subscribe(topic, groupName, autoOffsetReset);
    }

    @SneakyThrows
    private BrokerBootstrapInformation getBroker(String arn, KafkaAsyncClient kafkaClient) {
        var request = GetBootstrapBrokersRequest.builder()
                .clusterArn(arn)
                .build();

        var response = kafkaClient.getBootstrapBrokers(request).get(); // does not make sense to wait unfortunately

        return Optional.ofNullable(response.bootstrapBrokerStringTls())
                .map(it -> new BrokerBootstrapInformation(BrokerBootstrapInformation.Type.TLS, it))
                .orElseGet(() -> new BrokerBootstrapInformation(BrokerBootstrapInformation.Type.PLAINTEXT, response.bootstrapBrokerString()));
    }

    @SneakyThrows
    private KafkaKeyStoreInformation setupStores(Authentication authentication) {
        PrivateKey key = toRSAPrivateKey(authentication.getPrivateKey());
        List<X509Certificate> chain = toX509Certificates(authentication.getCertificateChain());

        String keystoreLocation = UUID.randomUUID().toString() + "-" + UUID.randomUUID().toString() + ".jks";
        String keystorePassword = generatePassword();
        String keyPassword = generatePassword();
        String keyAlias = UUID.randomUUID().toString();

        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(null);
        keyStore.setKeyEntry(keyAlias, key, keyPassword.toCharArray(), chain.toArray(new Certificate[0]));
        keyStore.store(new FileOutputStream(keystoreLocation), keystorePassword.toCharArray());

        return new KafkaKeyStoreInformation(
                keystoreLocation,
                keystorePassword,
                keyPassword
        );
    }

    @SneakyThrows
    private String generatePassword() {
        byte[] password = new byte[512]; // 4096 bit
        SecureRandom.getInstanceStrong().nextBytes(password);
        return new String(password);
    }

    @SneakyThrows
    private PrivateKey toRSAPrivateKey(String privateKeyString) {
        StringReader stringReader = new StringReader(privateKeyString);
        PemObject pemObject = new PemReader(stringReader).readPemObject();
        byte[] pemContent = pemObject.getContent();
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(pemContent);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(privateKeySpec);
    }

    @SneakyThrows({IOException.class, CertificateException.class})
    private List<X509Certificate> toX509Certificates(String pemStringCertificates) {
        PEMParser pemParser = new PEMParser(new StringReader(pemStringCertificates));

        List<X509Certificate> certificates = new ArrayList<>();

        Object currentObject = pemParser.readObject();
        while (currentObject != null) {
            if (currentObject instanceof X509CertificateHolder) {
                X509Certificate x509Cert = new JcaX509CertificateConverter().getCertificate((X509CertificateHolder) currentObject);
                certificates.add(x509Cert);
            } else {
                // be careful in logging pem, sometimes a pem can also contain private key, we should not just log it out
                throw new IllegalStateException("There are other non certificate objects inside the certificate chain");
            }

            currentObject = pemParser.readObject();
        }

        if (certificates.isEmpty()) {
            // be careful in logging pem, sometimes a pem can also contain private key, we should not just log it out
            throw new IllegalStateException("Certificate string does not contain any certificate");
        }

        return certificates;
    }

    @Value
    public static class Authentication {

        String certificateChain;

        String privateKey;

    }

    @Value
    private static class BrokerBootstrapInformation {

        Type type;

        String bootstrapServer;

        public enum Type {
            TLS, PLAINTEXT
        }

    }

    @Value
    private static class KafkaKeyStoreInformation {

        String keystoreLocation;

        String keystorePassword;

        String keyPassword;

    }

}
