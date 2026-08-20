use clap::Parser;
use regex::Regex;
use serde::Serialize;

#[derive(Parser)]
struct Args {
    #[arg(default_value = "answer=42")]
    value: String,
}

#[derive(Serialize)]
struct Parsed<'a> {
    key: &'a str,
    value: u32,
}

fn parse(value: &str) -> Parsed<'_> {
    let regex = Regex::new(r"^(?<key>[a-z]+)=(?<value>\d+)$").unwrap();
    let captures = regex.captures(value).unwrap();
    Parsed {
        key: captures.name("key").unwrap().as_str(),
        value: captures.name("value").unwrap().as_str().parse().unwrap(),
    }
}

fn main() {
    let args = Args::parse();
    let parsed = parse(&args.value);
    println!("{}", serde_json::to_string(&parsed).unwrap());
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_regex_and_serializes_json() {
        let parsed = super::parse("answer=42");
        assert_eq!(parsed.key, "answer");
        assert_eq!(parsed.value, 42);
    }
}
