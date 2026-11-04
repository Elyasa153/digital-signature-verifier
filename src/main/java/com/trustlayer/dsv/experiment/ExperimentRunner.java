package com.trustlayer.dsv.experiment;

import java.nio.file.Path;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * Yalnız "deney" profiliyle çalışır, sunucu açılmaz; ölçümler bitince uygulama kapanır.
 * <pre>mvnw spring-boot:run -Dspring-boot.run.profiles=deney</pre>
 */
@Component
@Profile("deney")
class ExperimentRunner implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(ExperimentRunner.class);

    /** 100 KB, 1 MB, 10 MB. */
    private static final List<Integer> SIZES = List.of(100 * 1024, 1024 * 1024, 10 * 1024 * 1024);

    private final PerformanceExperiment experiment;
    private final Path outDir;

    ExperimentRunner(PerformanceExperiment experiment, @Value("${dsv.experiment-dir}") Path outDir) {
        this.experiment = experiment;
        this.outDir = outDir;
    }

    @Override
    public void run(ApplicationArguments args) {
        int n = experiment.run(SIZES, outDir).size();
        log.info("Deney bitti: {} ölçüm, sonuçlar {}", n, outDir.toAbsolutePath());
    }
}
