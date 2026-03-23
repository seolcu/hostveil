use serde_json::to_string_pretty;

use crate::domain::ScanResult;
use crate::i18n;

pub fn scan_result_json(scan_result: &ScanResult) -> String {
    to_string_pretty(scan_result).unwrap_or_else(|_| {
        format!(
            concat!(
                "{{\n",
                "  \"status\": \"error\",\n",
                "  \"message\": \"{}\"\n",
                "}}\n"
            ),
            escape_json(&i18n::tr("app.error.json_export_failed"))
        )
    }) + "\n"
}

fn escape_json(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[cfg(test)]
mod tests {
    use super::scan_result_json;
    use crate::domain::ScanResult;

    #[test]
    fn emits_valid_scan_result_shape() {
        let json = scan_result_json(&ScanResult::default());

        assert!(json.contains("\"findings\": []"));
        assert!(json.contains("\"score_report\":"));
        assert!(json.contains("\"metadata\":"));
    }
}
