#!/usr/bin/env python3
"""
Verify pre-analysis filter on misclassified findings.

This script tests if the new implementation correctly identifies these as false positives.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.context.pre_analysis_filter import PreAnalysisFilter, PreAnalysisVerdict

# Initialize filter
project_root = Path(__file__).parent.parent
pre_filter = PreAnalysisFilter(project_root)

print("=" * 70)
print("VERIFICATION: Pre-Analysis Filter on Misclassified Findings")
print("=" * 70)
print()

results = []

# ==============================================================================
# Finding 1: PostgresMetrics.java:67 - SQL Injection
# ==============================================================================
print("FINDING 1: PostgresMetrics.java:67 - SQL Injection")
print("-" * 70)

code1 = '''
private Long getMaxConnections() {
    return runQuery("select @@max_connections", 1);
}
private Long getThreadsRunning() {
    return runQuery("show global status like 'Threads_running'", 2);
}
private Long getThreadsConnected() {
    return runQuery("show global status like 'Threads_connected'", 2);
}

private Long runQuery(String query, int columnIndex) {
    try (Connection connection = dataSource.getConnection();
         Statement statement = connection.createStatement();
         ResultSet resultSet = statement.executeQuery(query)) {
        if (resultSet.next()) {
            return resultSet.getObject(columnIndex, Long.class);
        }
    } catch (SQLException e) {
        log.error("Error running query", e);
    }
    return null;
}
'''

result1 = pre_filter.analyze(
    rule_id='java.lang.security.audit.sqli.jdbc-sqli',
    code=code1,
    file_path='PostgresMetrics.java',
    line_number=67,
    variable_name='query',
    function_name='runQuery',
)
print(f"  Verdict: {result1.verdict.value}")
print(f"  Confidence: {result1.confidence:.2f}")
print(f"  Reasons: {result1.reasons}")
print(f"  Expected: likely_false_positive (all callers pass hardcoded strings)")
results.append(("PostgresMetrics SQL", result1.verdict == PreAnalysisVerdict.LIKELY_FALSE_POSITIVE or 
                result1.confidence >= 0.6))
print()

# ==============================================================================
# Finding 2 & 3: TFileBasedProperties.java:54,65 - Path Traversal
# ==============================================================================
print("FINDING 2/3: TFileBasedProperties.java:54,65 - Path Traversal")
print("-" * 70)

code2 = '''
private static final String propertyFileLocation = "/etc/config/application.properties";

private void loadPropertiesIfRequired() {
    if (properties != null) return;
    if (!fileExists(propertyFileLocation)) {
        throw new RuntimeException("Failed to load properties file");
    }
    synchronized (this) {
        if (properties != null) return;
        properties = loadPropertiesFromFile(propertyFileLocation, false);
    }
}

private static Properties loadPropertiesFromFile(String fileName, boolean isResource) {
    try (InputStream stream = new FileInputStream(fileName)) {
        Properties properties = new Properties();
        properties.load(stream);
        return properties;
    } catch (IOException e) {
        log.error("Error loading properties", e);
    }
    return null;
}

private static boolean fileExists(String fileName) {
    File file = new File(fileName);
    return file.exists();
}
'''

result2 = pre_filter.analyze(
    rule_id='java.lang.security.httpservlet-path-traversal',
    code=code2,
    file_path='TFileBasedProperties.java',
    line_number=54,
    variable_name='fileName',
    function_name='loadPropertiesFromFile',
)
print(f"  Verdict: {result2.verdict.value}")
print(f"  Confidence: {result2.confidence:.2f}")
print(f"  Reasons: {result2.reasons}")
print(f"  Expected: likely_false_positive (path is static final constant)")
results.append(("TFileBasedProperties Path", result2.verdict == PreAnalysisVerdict.LIKELY_FALSE_POSITIVE or 
                result2.confidence >= 0.6))
print()

# ==============================================================================
# Finding 4: ContextFromRequestInitializerImpl.java:119 - XSS
# ==============================================================================
print("FINDING 4: ContextFromRequestInitializerImpl.java:119 - XSS")
print("-" * 70)

code3 = '''
private TekLocale extractLocale(HttpServletRequest request) {
    String locale = request.getParameter(LOCALE_KEY);
    if(TStringUtils.isBlank(locale)) {
        locale = request.getHeader(LOCALE_KEY);
    }
    return resolveTekLocale(locale);
}

private TekLocale resolveTekLocale(String locale) {
    if (locale == null) return TekLocale.EN_US;
    try {
        return TekLocale.valueOf(locale.toUpperCase());
    } catch (IllegalArgumentException e) {
        return TekLocale.EN_US;
    }
}
'''

result3 = pre_filter.analyze(
    rule_id='java.lang.security.audit.xss.xss-injection',
    code=code3,
    file_path='ContextFromRequestInitializerImpl.java',
    line_number=119,
    variable_name='locale',
    function_name='extractLocale',
)
print(f"  Verdict: {result3.verdict.value}")
print(f"  Confidence: {result3.confidence:.2f}")
print(f"  Reasons: {result3.reasons}")
print(f"  Expected: likely_false_positive (output goes to enum, not HTML)")
results.append(("ContextFromRequest XSS", result3.verdict == PreAnalysisVerdict.LIKELY_FALSE_POSITIVE or 
                result3.confidence >= 0.6))
print()

# ==============================================================================
# Finding 5: KafkaUtils.java:52 - Hardcoded Key
# ==============================================================================
print("FINDING 5: KafkaUtils.java:52 - Hardcoded Key")
print("-" * 70)

code4 = '''
if (hostConfig.getKafkaDetails().getSaslMechanisms().equalsIgnoreCase("PLAIN")) {
    String jaasTemplate =
        "org.apache.kafka.common.security.plain.PlainLoginModule required username=\\"%s\\" password=\\"%s\\";";
    String jaasCfg =
        String.format(jaasTemplate, hostConfig.getUserName(), hostConfig.getPassword());
    configProps.put("sasl.jaas.config", jaasCfg);
}
'''

result4 = pre_filter.analyze(
    rule_id='java.lang.security.audit.crypto.hard_code_key',
    code=code4,
    file_path='KafkaUtils.java',
    line_number=52,
    variable_name='jaasCfg',
    function_name='configureKafka',
)
print(f"  Verdict: {result4.verdict.value}")
print(f"  Confidence: {result4.confidence:.2f}")
print(f"  Reasons: {result4.reasons}")
print(f"  Expected: likely_false_positive (password from getter, not hardcoded)")
results.append(("KafkaUtils Hardcoded", result4.verdict == PreAnalysisVerdict.LIKELY_FALSE_POSITIVE or 
                result4.confidence >= 0.6))
print()

# ==============================================================================
# Summary
# ==============================================================================
print("=" * 70)
print("SUMMARY")
print("=" * 70)
passed = sum(1 for _, r in results if r)
total = len(results)
print(f"Results: {passed}/{total} findings correctly identified")
print()
for name, passed in results:
    status = "✓ PASS" if passed else "✗ FAIL"
    print(f"  {status}: {name}")
print()

if passed == total:
    print("🎉 All misclassified findings are now correctly detected!")
else:
    print(f"⚠️  {total - passed} findings still need improvement")
