#!/usr/bin/env python3
"""Test the pre-analysis filter with examples matching our misclassified findings."""

from pathlib import Path
from src.context.pre_analysis_filter import PreAnalysisFilter, PreAnalysisVerdict

# Initialize filter
pre_filter = PreAnalysisFilter(Path('.'))

print("=" * 60)
print("TEST 1: Static Final Constant Path")
print("=" * 60)
code1 = '''
private static final String propertyFileLocation = "/etc/config/application.properties";

private void loadPropertiesIfRequired() {
    if (!fileExists(propertyFileLocation)) {
        throw new RuntimeException("Failed to load properties file");
    }
    properties = loadPropertiesFromFile(propertyFileLocation, false);
}
'''
result1 = pre_filter.analyze(
    rule_id='java.lang.security.httpservlet-path-traversal',
    code=code1,
    file_path='TFileBasedProperties.java',
    line_number=5,
    variable_name='propertyFileLocation',
)
print(f"Verdict: {result1.verdict.value}")
print(f"Confidence: {result1.confidence:.2f}")
print(f"Reasons: {result1.reasons}")
print(f"Skip LLM: {result1.skip_llm}")
print()

print("=" * 60)
print("TEST 2: Password from Getter (NOT Hardcoded)")
print("=" * 60)
code2 = '''
String jaasTemplate = "org.apache.kafka.common.security.plain.PlainLoginModule required username=\\"%s\\" password=\\"%s\\";";
String jaasCfg = String.format(jaasTemplate, hostConfig.getUserName(), hostConfig.getPassword());
configProps.put("sasl.jaas.config", jaasCfg);
'''
result2 = pre_filter.analyze(
    rule_id='java.lang.security.audit.crypto.hard_code_key',
    code=code2,
    file_path='KafkaUtils.java',
    line_number=2,
    variable_name='jaasCfg',
)
print(f"Verdict: {result2.verdict.value}")
print(f"Confidence: {result2.confidence:.2f}")
print(f"Reasons: {result2.reasons}")
print()

print("=" * 60)
print("TEST 3: XSS to Non-HTML Context")
print("=" * 60)
code3 = '''
private TekLocale extractLocale(HttpServletRequest request) {
    String locale = request.getParameter(LOCALE_KEY);
    if(TStringUtils.isBlank(locale)) {
        locale = request.getHeader(LOCALE_KEY);
    }
    return resolveTekLocale(locale);
}
'''
result3 = pre_filter.analyze(
    rule_id='java.lang.security.audit.xss.xss-injection',
    code=code3,
    file_path='ContextFromRequestInitializerImpl.java',
    line_number=2,
    variable_name='locale',
)
print(f"Verdict: {result3.verdict.value}")
print(f"Confidence: {result3.confidence:.2f}")
print(f"Reasons: {result3.reasons}")
print()

print("=" * 60)
print("SUMMARY")
print("=" * 60)
print(f"Test 1 (Path constant): {result1.verdict.value} (expected: likely_false_positive)")
print(f"Test 2 (Template secret): {result2.verdict.value} (expected: likely_false_positive)")
print(f"Test 3 (Non-HTML XSS): {result3.verdict.value} (expected: likely_false_positive)")
