package com.example.demo;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

@Service
public class MetricsService {

    private final MeterRegistry meterRegistry;

    public MetricsService(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    @PostConstruct
    public void registerCertificateMetrics() {
        var keyStores = List.of(
                "JKS",
                "Windows-MY",
                "Windows-ROOT"
        );
        var javaHome = System.getProperty("java.home");
        var certsPath = javaHome + "/lib/security/cacerts";
        var currentTime = Instant.now();

        for (var keyStoreType : keyStores) {
            try {
                var keyStore = KeyStore.getInstance(keyStoreType);
                if (keyStoreType.equals("JKS")) {
                    keyStore.load(new FileInputStream(certsPath), "changeit".toCharArray());
                } else {
                    keyStore.load(null, null);
                }
                var aliases = keyStore.aliases();
                while (aliases.hasMoreElements()) {
                    var alias = aliases.nextElement();
                    var cert = keyStore.getCertificate(alias);
                    if (cert instanceof X509Certificate x509Certificate && x509Certificate.getNotAfter() != null) {
                        var certExpirationTime = x509Certificate.getNotAfter().toInstant();
                        long remainingDays = Duration.between(currentTime, certExpirationTime).toDays();
                        int roundedRemainingDays = (int) Math.ceil(remainingDays);

                        Gauge.builder("certificate.days", () -> roundedRemainingDays)
                                .description("Количество дней до окончания срока действия сертификата " + alias)
                                .tag("certificate_alias", alias)
                                .register(meterRegistry);
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}