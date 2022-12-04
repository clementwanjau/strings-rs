/// Return sanitized string for printing to cli.
pub fn sanitize(mut s: String) -> String {
    s = s.replace("\n", "\\n");
    s = s.replace("\r", "\\r");
    s = s.replace("\t", "\\t");
    s = s.replace("\\\\", "\\");
    s = s
        .chars()
        .filter(|c| c.is_ascii())
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("");
    s
}
