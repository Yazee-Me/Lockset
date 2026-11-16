/// Minimal dotenv handling: values only, no quoting rules beyond "everything
/// after the first `=` is the value". That matches what sops writes.
pub fn parse(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        if !crate::meta::is_name(name) {
            continue;
        }
        out.push((name.to_owned(), value.to_owned()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pairs_and_skips_noise() {
        let text = "# comment\nA=1\nB=\n\nC=base64:xx==\nnot a pair\n";
        assert_eq!(
            parse(text),
            vec![
                ("A".into(), "1".into()),
                ("B".into(), "".into()),
                ("C".into(), "base64:xx==".into())
            ]
        );
    }
}
