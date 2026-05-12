#[test]
fn debug_markdown() {
    let mut result = hostveil::domain::ScanResult::default();
    result.findings.push(hostveil::domain::Finding {
        id: "test.id".to_string(),
        axis: hostveil::domain::Axis::HostHardening,
        severity: hostveil::domain::Severity::High,
        scope: hostveil::domain::Scope::Host,
        source: hostveil::domain::Source::NativeHost,
        subject: "host".to_string(),
        related_service: None,
        title: "Test Finding".to_string(),
        description: "Description text".to_string(),
        why_risky: "It is risky".to_string(),
        how_to_fix: "Fix it".to_string(),
        evidence: std::collections::BTreeMap::new(),
        remediation: hostveil::domain::RemediationKind::Review,
    });
    let md = hostveil::export::scan_result_markdown(&result);
    print!("MARKDOWN:\n---\n{}\n---\n", md);
    assert!(md.contains("high"), "md: {:?}", md);
}
