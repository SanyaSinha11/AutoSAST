#!/usr/bin/env python3
"""
Test Source Classifier on sample findings.

Verifies that parameters are correctly classified (e.g., CONFIG_LOADED, USER_CONTROLLED).
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.context.source_classifier import SourceClassifier, SourceType

# Test with sample file from test_samples
TARGET_FILE = Path(__file__).parent.parent / "test_samples" / "java" / "src" / "AccountHandler.java"

def test_line_40():
    """Test tableExists method - tableName parameter."""
    print("=" * 70)
    print("TEST 1: Line 40 - tableExists(String tableName, ...)")
    print("=" * 70)
    
    # Read the full file
    code = TARGET_FILE.read_text()
    
    classifier = SourceClassifier(TARGET_FILE.parent.parent.parent.parent)
    
    # Classify the 'tableName' parameter of tableExists method
    result = classifier.classify_parameter(
        method_name="tableExists",
        param_name="tableName",
        param_index=0,
        code=code,
        file_path=str(TARGET_FILE)
    )
    
    print(f"\nVariable: tableName")
    print(f"Source Type: {result.source_type.value}")
    print(f"Confidence: {result.confidence:.0%}")
    print(f"Is Trusted: {result.is_trusted()}")
    print(f"\nReasons:")
    for reason in result.reasons:
        print(f"  - {reason}")
    
    if result.trace:
        print(f"\nTrace Path:")
        for i, step in enumerate(result.trace, 1):
            print(f"  {i}. {step.description}")
            print(f"     Type: {step.source_type.value}")
    
    # Expected: CONFIG_LOADED or SYSTEM_INTERNAL (trusted)
    expected_trusted = True
    actual_trusted = result.is_trusted()
    
    print(f"\n{'✓ PASS' if actual_trusted == expected_trusted else '✗ FAIL'}: "
          f"Expected trusted={expected_trusted}, got trusted={actual_trusted}")
    
    return actual_trusted == expected_trusted


def test_line_190():
    """Test doClearTable method - tableCopyMetadata.getTable()."""
    print("\n" + "=" * 70)
    print("TEST 2: Line 190 - doClearTable uses tableCopyMetadata.getTable()")
    print("=" * 70)
    
    code = TARGET_FILE.read_text()
    
    classifier = SourceClassifier(TARGET_FILE.parent.parent.parent.parent)
    
    # For line 190, the table name comes from tableCopyMetadata.getTable()
    # Let's test classification of a variable that uses entity getter
    
    # Create a focused code snippet for testing the getter pattern
    test_code = '''
    String tableName = tableCopyMetadata.getTable();
    String query = String.format("select count(*) from %s", tableName);
    '''
    
    result = classifier.classify_variable(
        variable_name="tableName",
        code=test_code,
        file_path=str(TARGET_FILE),
        line_number=190
    )
    
    print(f"\nVariable: tableName (from tableCopyMetadata.getTable())")
    print(f"Source Type: {result.source_type.value}")
    print(f"Confidence: {result.confidence:.0%}")
    print(f"Is Trusted: {result.is_trusted()}")
    print(f"\nReasons:")
    for reason in result.reasons:
        print(f"  - {reason}")
    
    # Expected: CONFIG_LOADED (TableCopyMetadata is a @Document entity)
    expected_trusted = True
    actual_trusted = result.is_trusted()
    
    print(f"\n{'✓ PASS' if actual_trusted == expected_trusted else '✗ FAIL'}: "
          f"Expected trusted={expected_trusted}, got trusted={actual_trusted}")
    
    return actual_trusted == expected_trusted


def test_entity_detection():
    """Test that TableCopyMetadata is recognized as a config entity."""
    print("\n" + "=" * 70)
    print("TEST 3: Entity Detection - DataCopyMetaData.TableCopyMetadata")
    print("=" * 70)
    
    classifier = SourceClassifier(TARGET_FILE.parent.parent.parent.parent)
    
    # Read the DataCopyMetaData file to check annotations
    metadata_file = TARGET_FILE.parent.parent / "beans" / "DataCopyMetaData.java"
    if metadata_file.exists():
        metadata_code = metadata_file.read_text()
        print(f"\nFound: {metadata_file}")
        
        # Check for @Document annotation
        has_document = "@Document" in metadata_code
        print(f"Has @Document annotation: {has_document}")
        
        # Test _is_config_entity
        is_config = classifier._is_config_entity("TableCopyMetadata", metadata_code, str(metadata_file))
        print(f"Detected as config entity: {is_config}")
        
        return has_document and is_config
    else:
        print(f"File not found: {metadata_file}")
        return False


def test_user_input_detection():
    """Test that user input patterns are correctly detected."""
    print("\n" + "=" * 70)
    print("TEST 4: User Input Detection")
    print("=" * 70)
    
    classifier = SourceClassifier(Path("."))
    
    test_code = '''
    String userInput = request.getParameter("name");
    String header = request.getHeader("X-Custom");
    '''
    
    result = classifier.classify_variable(
        variable_name="userInput",
        code=test_code,
        file_path="test.java",
        line_number=1
    )
    
    print(f"\nVariable: userInput")
    print(f"Source Type: {result.source_type.value}")
    print(f"Is Trusted: {result.is_trusted()}")
    
    # Expected: USER_INPUT (untrusted)
    expected = SourceType.USER_INPUT
    actual = result.source_type
    
    print(f"\n{'✓ PASS' if actual == expected else '✗ FAIL'}: "
          f"Expected {expected.value}, got {actual.value}")
    
    return actual == expected


def main():
    print("\n" + "=" * 70)
    print("SOURCE CLASSIFIER VERIFICATION")
    print("=" * 70)
    
    results = [
        ("Line 40 tableExists", test_line_40()),
        ("Line 190 doClearTable", test_line_190()),
        ("Entity Detection", test_entity_detection()),
        ("User Input Detection", test_user_input_detection()),
    ]
    
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    
    for name, result in results:
        print(f"  {'✓' if result else '✗'} {name}")
    
    print(f"\nResults: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n✅ All tests passed!")
        return 0
    else:
        print(f"\n⚠️ {total - passed} tests failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
