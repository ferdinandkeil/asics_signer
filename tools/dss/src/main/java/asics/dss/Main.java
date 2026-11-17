// SPDX-FileCopyrightText: 2026 Ferdinand Keil
// SPDX-License-Identifier: MIT
package asics.dss;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Offline-Validator fuer ASiC-S/CAdES-Container auf Basis von EU-DSS.
 * Exitcode: 0 = TOTAL_PASSED, 1 = nicht bestanden, 2 = Aufruf-/Verarbeitungsfehler.
 */
public final class Main {

    private static void usage() {
        System.err.println("Aufruf: asics-dss --trust <ca.pem> [--trust <weitere.pem>] [--policy <policy.xml>]"
                + " [--report-dir <dir>] <datei.asics>");
    }

    public static void main(String[] args) {
        System.exit(run(args));
    }

    static int run(String[] args) {
        List<Path> trust = new ArrayList<>();
        Path policy = null, reportDir = null, input = null;
        try {
            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "--trust" -> trust.add(Path.of(args[++i]));
                    case "--policy" -> policy = Path.of(args[++i]);
                    case "--report-dir" -> reportDir = Path.of(args[++i]);
                    case "-h", "--help" -> { usage(); return 2; }
                    default -> {
                        if (args[i].startsWith("--") || input != null) { usage(); return 2; }
                        input = Path.of(args[i]);
                    }
                }
            }
        } catch (ArrayIndexOutOfBoundsException e) {
            usage();
            return 2;
        }
        if (input == null || trust.isEmpty()) { usage(); return 2; }

        try {
            // Strikt offline: nur lokal uebergebene Trust Anchors, keine Datenlader
            // (kein OCSP/CRL/AIA, kein LOTL/TSL).
            CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
            for (Path t : trust) {
                try (InputStream in = Files.newInputStream(t)) {
                    for (java.security.cert.Certificate c : java.security.cert.CertificateFactory
                            .getInstance("X.509").generateCertificates(in)) {
                        trusted.addCertificate(new CertificateToken((java.security.cert.X509Certificate) c));
                    }
                }
            }
            CertificateVerifier verifier = new CommonCertificateVerifier();
            verifier.setTrustedCertSources(trusted);
            verifier.setOcspSource(null);
            verifier.setCrlSource(null);
            verifier.setAIASource(null);
            verifier.setRevocationFallback(false);

            DSSDocument doc = new FileDocument(input.toFile());
            SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
            validator.setCertificateVerifier(verifier);

            Reports reports;
            if (policy != null) {
                try (InputStream p = Files.newInputStream(policy)) {
                    reports = validator.validateDocument(p);
                }
            } else {
                reports = validator.validateDocument();
            }

            SimpleReport sr = reports.getSimpleReport();
            DiagnosticData dd = reports.getDiagnosticData();

            System.out.println("Datei:          " + input.getFileName());
            System.out.println("Policy:         " + (policy != null ? policy : "DSS-Default (constraint.xml)"));
            System.out.println("Containertyp:   " + (dd.getContainerType() != null ? dd.getContainerType() : "(kein ASiC-Container)"));
            System.out.println("MIME-Type:      " + dd.getMimetypeFileContent());
            System.out.println("Signaturen:     " + sr.getSignaturesCount() + " (gueltig: " + sr.getValidSignaturesCount() + ")");

            boolean allPassed = sr.getSignaturesCount() > 0;
            for (String id : sr.getSignatureIdList()) {
                Indication ind = sr.getIndication(id);
                SignatureWrapper sw = dd.getSignatureById(id);
                System.out.println("--- Signatur " + id);
                System.out.println("Indication:     " + ind);
                System.out.println("SubIndication:  " + sr.getSubIndication(id));
                System.out.println("Format:         " + sr.getSignatureFormat(id));
                if (sw != null) {
                    System.out.println("Signer:         " + sw.getSigningCertificate().getCertificateDN());
                    System.out.println("Signierte Dateien:");
                    for (XmlSignatureScope s : sw.getSignatureScopes()) {
                        System.out.println("  - " + s.getName() + " (" + s.getScope() + ")");
                    }
                }
                for (var e : sr.getAdESValidationErrors(id)) System.out.println("  Fehler:  " + e.getValue());
                for (var e : sr.getAdESValidationWarnings(id)) System.out.println("  Warnung: " + e.getValue());
                for (var e : sr.getAdESValidationInfo(id)) System.out.println("  Info:    " + e.getValue());
                for (var e : sr.getQualificationErrors(id)) System.out.println("  QErr:    " + e.getValue());
                if (ind != Indication.TOTAL_PASSED) allPassed = false;
            }

            if (reportDir != null) {
                Files.createDirectories(reportDir);
                Files.writeString(reportDir.resolve("simple-report.xml"), reports.getXmlSimpleReport(), StandardCharsets.UTF_8);
                Files.writeString(reportDir.resolve("detailed-report.xml"), reports.getXmlDetailedReport(), StandardCharsets.UTF_8);
                Files.writeString(reportDir.resolve("diagnostic-data.xml"), reports.getXmlDiagnosticData(), StandardCharsets.UTF_8);
                Files.writeString(reportDir.resolve("etsi-validation-report.xml"),
                        reports.getXmlValidationReport(), StandardCharsets.UTF_8);
                System.out.println("Reports:        " + reportDir);
            }
            System.out.println("Ergebnis:       " + (allPassed ? "TOTAL_PASSED" : "NICHT BESTANDEN"));
            return allPassed ? 0 : 1;
        } catch (Exception e) {
            System.err.println("Fehler: " + e);
            Throwable c = e.getCause();
            while (c != null) { System.err.println("  Ursache: " + c); c = c.getCause(); }
            return 2;
        }
    }
}
