use clap::{Arg, ArgAction, ArgGroup, Command, value_parser};

fn output() -> Arg {
    Arg::new("output")
        .long("output")
        .short('o')
        .value_parser(value_parser!(std::path::PathBuf))
        .help("Write body or profile JSON to this file (otherwise stdout)")
}

pub(super) fn command() -> Command {
    Command::new("phantom")
        .version(env!("CARGO_PKG_VERSION"))
        .about("HTTP requests with explicit profiles and protocols")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("request")
                .about("Send one logical HTTP request")
                .arg(Arg::new("url").required(true))
                .arg(
                    Arg::new("profile")
                        .long("profile")
                        .help("Fixed catalog selector or full profile identifier"),
                )
                .arg(
                    Arg::new("profile-file")
                        .long("profile-file")
                        .value_parser(value_parser!(std::path::PathBuf))
                        .help("Complete custom-profile JSON file"),
                )
                .arg(
                    Arg::new("bundle")
                        .long("bundle")
                        .requires_all(["bundle-store", "bundle-profile"])
                        .help("Exact installed bundle SHA-256"),
                )
                .arg(
                    Arg::new("bundle-store")
                        .long("bundle-store")
                        .requires("bundle")
                        .value_parser(value_parser!(std::path::PathBuf)),
                )
                .arg(
                    Arg::new("bundle-profile")
                        .long("bundle-profile")
                        .requires("bundle")
                        .help("Exact profile name in the pinned bundle"),
                )
                .group(
                    ArgGroup::new("identity")
                        .args(["profile", "profile-file", "bundle"])
                        .required(true),
                )
                .arg(
                    Arg::new("protocol")
                        .long("protocol")
                        .required(true)
                        .value_parser(["h1", "h2", "h3", "negotiated"]),
                )
                .arg(
                    Arg::new("context")
                        .long("context")
                        .requires("profile")
                        .conflicts_with_all(["profile-file", "bundle"])
                        .value_parser(["navigation", "fetch"])
                        .help("Select this catalog request template; omitted means no template"),
                )
                .arg(
                    Arg::new("method")
                        .long("method")
                        .short('X')
                        .default_value("GET"),
                )
                .arg(
                    Arg::new("header")
                        .long("header")
                        .short('H')
                        .action(ArgAction::Append)
                        .help("Ordered Name: value field; repeat to preserve duplicates"),
                )
                .arg(
                    Arg::new("proxy")
                        .long("proxy")
                        .help("Explicit http(s), socks4(a), or socks5(h) proxy URI"),
                )
                .arg(
                    Arg::new("upload")
                        .long("upload")
                        .value_parser(value_parser!(std::path::PathBuf))
                        .help("Stream a file once; does not change the method"),
                )
                .arg(output())
                .arg(
                    Arg::new("timeout-ms")
                        .long("timeout-ms")
                        .value_parser(value_parser!(std::num::NonZeroU64))
                        .help("Limit send and download, including output waits"),
                )
                .arg(
                    Arg::new("attempts")
                        .long("attempts")
                        .value_parser(value_parser!(usize))
                        .help("Cap admitted origin attempts, including the initial attempt"),
                )
                .arg(
                    Arg::new("diagnostics")
                        .long("diagnostics")
                        .value_parser(value_parser!(std::path::PathBuf))
                        .help("Write measured request diagnostics as JSON"),
                )
                .arg(
                    Arg::new("fail")
                        .long("fail")
                        .action(ArgAction::SetTrue)
                        .help("Exit 22 for HTTP 4xx/5xx after consuming the body"),
                ),
        )
        .subcommand(
            Command::new("profiles")
                .about("Inspect compiled or local custom profiles")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("bundle")
                        .about("Inspect or install offline profile bundles")
                        .subcommand_required(true)
                        .subcommand(
                            Command::new("inspect").arg(
                                Arg::new("file")
                                    .required(true)
                                    .value_parser(value_parser!(std::path::PathBuf)),
                            ),
                        )
                        .subcommand(
                            Command::new("install")
                                .arg(
                                    Arg::new("file")
                                        .required(true)
                                        .value_parser(value_parser!(std::path::PathBuf)),
                                )
                                .arg(
                                    Arg::new("store")
                                        .long("store")
                                        .required(true)
                                        .value_parser(value_parser!(std::path::PathBuf)),
                                ),
                        ),
                )
                .subcommand(Command::new("list").about("List fixed compiled profile selectors"))
                .subcommand(
                    Command::new("describe")
                        .about("Describe catalog metadata and configured settings")
                        .arg(Arg::new("id").required(true)),
                )
                .subcommand(
                    Command::new("export")
                        .about("Export editable custom-profile JSON")
                        .arg(Arg::new("id").required(true))
                        .arg(output()),
                )
                .subcommand(
                    Command::new("import")
                        .about("Validate and export local custom-profile JSON")
                        .arg(
                            Arg::new("file")
                                .required(true)
                                .value_parser(value_parser!(std::path::PathBuf)),
                        )
                        .arg(output()),
                ),
        )
}
