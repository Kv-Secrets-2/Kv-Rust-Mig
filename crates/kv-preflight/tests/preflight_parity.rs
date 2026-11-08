//! Byte-exact Python manifest comparisons and deliberate fail-closed depth limits.
#![cfg(unix)]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

use kv_preflight::{PROVIDERS, PreflightError, manifest_json, preflight_command};
use serde_json::{Value, json};

struct Case {
    name: String,
    argv: Vec<String>,
    cwd: String,
    hardening: bool,
    syntax_since: Option<u64>,
}

fn rust_result(case: &Case) -> Value {
    match preflight_command(&case.argv, Some(&case.cwd)) {
        Ok(mut m) => {
            m.identity["run_id"] = json!("run_MASKED");
            json!({"json": manifest_json(&m)})
        }
        Err(e) => json!({"error": {"type": e.kind(), "message": e.to_string()}}),
    }
}

#[test]
fn isolated_preflight_probe() {
    let Some(input) = std::env::var_os("KV_PREFLIGHT_INPUT") else {
        return;
    };
    let data: Value = serde_json::from_slice(&std::fs::read(input).unwrap()).unwrap();
    let results: Vec<Value> = data["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            rust_result(&Case {
                name: String::new(),
                argv: item["argv"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap().to_owned())
                    .collect(),
                cwd: item["cwd"].as_str().unwrap().into(),
                hardening: false,
                syntax_since: None,
            })
        })
        .collect();
    std::fs::write(
        std::env::var_os("KV_PREFLIGHT_OUTPUT").unwrap(),
        serde_json::to_vec(&results).unwrap(),
    )
    .unwrap();
}

#[test]
fn preflight_matches_python() {
    let Some(python) = kv_test_support::python_reference() else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let cwd = root.to_string_lossy().into_owned();
    let home = root.join("home");
    std::fs::create_dir(&home).unwrap();
    let mut projects = vec![cwd.clone()];
    let mut cases = Vec::new();
    let sources = [
        "",
        "pass",
        "import openai",
        "import anthropic as a",
        "import google.cloud",
        "from openai import OpenAI as O",
        "from .openai import x",
        "from ..anthropic.sub import X",
        "def f():\n import openai\n if x:\n  import anthropic",
        "try:\n import github\nexcept Exception:\n import google",
        "from kv.cap_client import api_call\napi_call('openai','/x')",
        "api_call(provider='anthropic')",
        "kv.cap_client.api_call('google')",
        "cap_client.api_call('github')",
        "a.b.api_call('google-cloud')",
        "api_call()",
        "api_call('unknown')",
        "api_call(x, provider='openai')",
        "api_call(provider=x)",
        "api_call('openai')\napi_call('anthropic')",
        "openai.OpenAI()",
        "anthropic.Anthropic()",
        "c=OpenAI()\nc.chat.completions.create()",
        "c=anthropic.Anthropic()\nc.messages.create()",
        "a=b=OpenAI()\na.chat()\nb.chat()",
        "a: X=OpenAI()\na.chat()",
        "a += OpenAI()",
        "x[0]=OpenAI()\nx.chat()",
        "for x in range(3):\n api_call('openai')",
        "for x in range(2,5):\n api_call('openai')",
        "for x in range(True):\n api_call('openai')",
        "for x in range(False,True):\n api_call('openai')",
        "for x in range(-2):\n api_call('openai')",
        "for x in range(8,2):\n api_call('openai')",
        "for x in range(1,4,2):\n api_call('openai')",
        "for x in [1,*xs,3]:\n api_call('openai')",
        "for x in (1,2):\n api_call('anthropic')",
        "for x in {1,1,2}:\n api_call('github')",
        "for x in things:\n api_call('google')",
        "while api_call('github'):\n api_call('openai')\nelse:\n api_call('anthropic')",
        "for x in range(2):\n for y in range(3):\n  api_call('openai')\nelse:\n api_call('openai')",
        "async def f():\n async for x in api_call('github'):\n  api_call('openai')",
        "for x in api_call('github'):\n pass",
        "subprocess.run(['ssh','host'])",
        "subprocess.Popen(['/usr/bin/scp','-P','22','x','y'])",
        "run(('rsync','user@host:x'))",
        "Popen(['sftp',None,'host'])",
        "subprocess.run('ssh host',shell=True)",
        "os.system('ssh host')",
        "import paramiko, fabric, asyncssh",
        "requests.get('x')\nhttpx.post('x')\nurllib.request.urlopen('x')\nsocket.socket()",
        "open('a','w')\nopen('b',mode='w')\nopen('c','r+')\nPath.open('d','a')",
        "Path('a').write_text('x')\npathlib.Path('b').write_bytes(b'x')\nPath('c').touch()\n'd'.mkdir()",
        "Path(x).write_text('x')\nwrite_text('x')",
        "os.environ['OPENAI_API_KEY']",
        "os.getenv('ANTHROPIC_API_KEY')",
        "process.env.OPENAI_API_KEY",
        "foo(api_key='OPENAI_API_KEY')",
        "secret='OPENAI_API_KEY'",
        "@c.chat()\ndef f():\n c=OpenAI()",
        "@c.chat()\nclass C(c.base()):\n c=OpenAI()",
        "async def f(x=api_call('google'),*,y=api_call('github')) -> api_call('anthropic'):\n api_call('openai')",
        "{api_call('github'): api_call('openai')}",
        "ｃ=ＯｐｅｎＡＩ()\nｃ.chat()",
        "import ｏｐｅｎａｉ\nｏｐｅｎａｉ.chat()",
        "from ａｎｔｈｒｏｐｉｃ import Anthropic",
        "api_call(ｐｒｏｖｉｄｅｒ='openai')",
        "kv.cap_client.api_call('open' 'ai')",
        "api_call(f'openai')",
        "api_call(b'openai')",
        "api_call('open' f'ai')",
        "factory().api_call('openai')",
        "factory().openai.chat()",
        "for x in range(9007199254740993):\n api_call('openai')",
        "for x in range(10000000000000000000000000000000000000000):\n api_call('openai')",
        "for",
        "x =",
        "def f(: pass",
        "x = (1",
        "if x:\npass",
        "x='unterminated",
        "a +* b",
        "x=1\n\u{feff}api_call('openai')",
        "\u{feff}api_call('openai')",
        "x='\u{feff}'",
        "x\0",
        "api_call('openai')\r\napi_call('github')\rpass",
        "match x:\n case 1:\n  api_call('openai')",
        "with (open('x') as x, open('y') as y):\n api_call('openai')",
        "if x:\n c=OpenAI()\nelif y:\n c.chat()\nelse:\n c.chat()",
        "try:\n c=OpenAI()\nexcept E:\n c.chat()\nelse:\n c.chat()\nfinally:\n c.chat()",
        "def f(a: c.chat(), /, b=api_call('github'), *xs: c.chat(), y: c.chat()=api_call('anthropic'), **kw: c.chat()) -> c.chat():\n c=OpenAI()",
        "class C(c.base(), kw=c.base()):\n c=OpenAI()",
        "async def f():\n async for x in things:\n  c=OpenAI()\n else:\n  c.chat()",
        "for c.chat() in api_call('github'):\n pass",
        "# \u{feff}\napi_call('openai')",
        "Path('世界/🦀').touch()",
    ];
    let nul_name = format!(
        "source-{:03}.py",
        sources.iter().position(|s| s.contains('\0')).unwrap()
    );
    for (i, source) in sources.iter().enumerate() {
        let name = format!("source-{i:03}.py");
        std::fs::write(root.join(&name), source).unwrap();
        cases.push(Case {
            name: name.clone(),
            argv: vec!["python3".into(), name],
            cwd: cwd.clone(),
            hardening: false,
            syntax_since: None,
        });
    }
    let mut add = |name: &str, bytes: Vec<u8>, hardening: bool, syntax_since: Option<u64>| {
        std::fs::write(root.join(name), bytes).unwrap();
        cases.push(Case {
            name: name.into(),
            argv: vec!["python3".into(), name.into()],
            cwd: cwd.clone(),
            hardening,
            syntax_since,
        });
    };
    add("type.py", b"type X = int".to_vec(), false, Some(12));
    add("generic.py", b"def f[T](): pass".to_vec(), false, Some(12));
    add("fstring.py", br#"f"{"a"}""#.to_vec(), false, Some(12));
    add(
        "exceptstar.py",
        b"try:\n pass\nexcept* E:\n pass".to_vec(),
        false,
        Some(11),
    );
    add(
        "nonutf.py",
        b"# \xff\xed\xa0\x80\napi_call('openai')".to_vec(),
        false,
        None,
    );
    let mut large = b"api_call('openai')\n#".to_vec();
    large.resize(1_000_010, b'x');
    add("large.py", large, false, None);
    let real = format!("x='{}'\n", "a".repeat(1995)).repeat(10_000);
    add("real20mb.py", real.into_bytes(), false, None);
    add(
        "overflow.py",
        format!(
            "for x in range({}):\n api_call('openai')",
            "1".to_owned() + &"0".repeat(400)
        )
        .into_bytes(),
        false,
        None,
    );
    for n in [50, 95, 99, 100, 101, 200, 201, 1000, 10000, 100000] {
        // Deep input must be refused before analysis; syntax-limit rejection takes precedence.
        for (kind, source) in [
            ("unary", format!("{}x", "-".repeat(n))),
            ("not", format!("{}x", "not ".repeat(n))),
            ("lambda", format!("{}x", "lambda: ".repeat(n))),
            ("ternary", format!("{}z", "x if y else ".repeat(n))),
            ("calls", format!("f{}", "()".repeat(n))),
            ("attr", format!("x{}", ".a".repeat(n))),
            ("binary", format!("{}x", "x+".repeat(n))),
            ("power", format!("{}x", "x**".repeat(n))),
        ] {
            add(
                &format!("depth-{kind}-{n}.py"),
                source.into_bytes(),
                n >= 95,
                None,
            );
        }
    }
    for n in [40, 95, 99, 100, 101, 200, 201] {
        for (kind, source) in [
            (
                "nested-calls",
                format!("{}x{}", "f(".repeat(n), ")".repeat(n)),
            ),
            ("subscripts", format!("x{}", "[0]".repeat(n))),
            (
                "comprehensions",
                format!("{}y{}", "[x for x in ".repeat(n), "]".repeat(n)),
            ),
            ("implicit-strings", "'x' ".repeat(n)),
            ("string-plus", format!("{}'x'", "'x'+".repeat(n))),
        ] {
            add(
                &format!("extra-{kind}-{n}.py"),
                source.into_bytes(),
                kind != "implicit-strings" && n >= 95,
                None,
            );
        }
    }
    for n in [99, 100, 200, 201] {
        add(
            &format!("brackets-{n}.py"),
            format!("{}x{}", "(".repeat(n), ")".repeat(n)).into_bytes(),
            false,
            None,
        );
        let mut source = (0..n)
            .map(|i| format!("{}if x:\n", " ".repeat(i)))
            .collect::<String>();
        source.push_str(&format!("{}pass", " ".repeat(n)));
        add(
            &format!("indent-{n}.py"),
            source.into_bytes(),
            (95..100).contains(&n),
            None,
        );
    }
    std::fs::write(root.join("tool.sh"), "# ssh host\n").unwrap();
    std::fs::write(root.join("module.py"), "api_call('openai')").unwrap();
    std::fs::create_dir(root.join("package")).unwrap();
    std::fs::write(root.join("package/__main__.py"), "api_call('anthropic')").unwrap();
    std::fs::create_dir(root.join(".secrets")).unwrap();
    std::fs::write(root.join(".secrets/config.json"), "{}").unwrap();
    std::fs::set_permissions(
        root.join(".secrets"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    std::fs::set_permissions(
        root.join(".secrets/config.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    std::fs::write(root.join(".secrets/hidden.py"), "api_call('openai')").unwrap();
    for argv in [
        vec![],
        vec!["--"],
        vec!["--", "python3", "module.py"],
        vec!["sh", "tool.sh"],
        vec!["./tool.sh"],
        vec!["echo", "hello ' 世界 🦀"],
        vec!["echo", "\0\x08\x0c\n\r\t\x1f\x7f\u{2028}\"\\"],
        vec!["curl", "https://example.com"],
        vec!["python3", "-m", "module"],
        vec!["python3", "-m", "package"],
        vec!["python3", "-m", "missing"],
        vec!["python3", "-c", "print(1)"],
        vec!["python3", "-u", "module.py"],
        vec!["python3", "missing.py"],
        vec!["python3", ".secrets/hidden.py"],
        vec!["kv", "get", "X"],
    ] {
        cases.push(Case {
            name: format!("argv {argv:?}"),
            argv: argv.into_iter().map(str::to_owned).collect(),
            cwd: cwd.clone(),
            hardening: false,
            syntax_since: None,
        });
    }
    for (name, config) in [
        (
            "allow",
            r#"{"security":{"kv_run_policy":"allowlist","allowed_commands":["python3"]}}"#,
        ),
        (
            "deny",
            r#"{"security":{"kv_run_policy":"allowlist","allowed_commands":["echo"]}}"#,
        ),
        ("block", r#"{"security":{"kv_run_policy":"blocklist"}}"#),
        ("corrupt", "{"),
        ("bad-root", "[]"),
        ("bad-security", r#"{"security":null}"#),
        (
            "bad-allowed-item",
            r#"{"security":{"kv_run_policy":"allowlist","allowed_commands":[42]}}"#,
        ),
        (
            "bad-allowed-after-match",
            r#"{"security":{"kv_run_policy":"allowlist","allowed_commands":["python3 script.py",42]}}"#,
        ),
        (
            "bad-allowed-before-match",
            r#"{"security":{"kv_run_policy":"allowlist","allowed_commands":[42,"python3 script.py"]}}"#,
        ),
        (
            "allowed-string",
            r#"{"security":{"kv_run_policy":"allowlist","allowed_commands":"python3"}}"#,
        ),
        (
            "allowed-dict",
            r#"{"security":{"kv_run_policy":"allowlist","allowed_commands":{"python3 script.py":true}}}"#,
        ),
        (
            "bad-allowed",
            r#"{"security":{"kv_run_policy":"allowlist","allowed_commands":null}}"#,
        ),
    ] {
        let project = root.join(name);
        std::fs::create_dir_all(project.join(".secrets")).unwrap();
        std::fs::write(project.join(".secrets/config.json"), config).unwrap();
        std::fs::set_permissions(
            project.join(".secrets"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::set_permissions(
            project.join(".secrets/config.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        std::fs::write(project.join("script.py"), "api_call('openai')").unwrap();
        projects.push(project.to_string_lossy().into_owned());
        cases.push(Case {
            name: name.into(),
            argv: vec!["python3".into(), "script.py".into()],
            cwd: project.to_string_lossy().into_owned(),
            hardening: false,
            syntax_since: None,
        });
    }
    for (name, registered) in [("missing-config", true), ("no-origin", false)] {
        let project = root.join(name);
        std::fs::create_dir_all(project.join(".secrets")).unwrap();
        std::fs::set_permissions(
            project.join(".secrets"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        if registered {
            projects.push(project.to_string_lossy().into_owned());
        }
        cases.push(Case {
            name: name.into(),
            argv: vec!["echo".into(), "hello".into()],
            cwd: project.to_string_lossy().into_owned(),
            hardening: false,
            syntax_since: None,
        });
    }
    let input=json!({"projects":projects,"cases":cases.iter().map(|c|json!({"argv":c.argv,"cwd":c.cwd})).collect::<Vec<_>>()}).to_string();
    let rust_input = root.join("input.json");
    let rust_output = root.join("output.json");
    std::fs::write(&rust_input, &input).unwrap();
    let mut child = Command::new(python)
        .arg("-I")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/py/preflight_probe.py"))
        .env("HOME", &home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()).unwrap());
    let output = child.wait_with_output().unwrap();
    writer.join().unwrap();
    assert!(output.status.success());
    let reference: Value = serde_json::from_slice(&output.stdout).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "isolated_preflight_probe"])
        .env("HOME", &home)
        .env("KV_PREFLIGHT_INPUT", &rust_input)
        .env("KV_PREFLIGHT_OUTPUT", &rust_output)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "isolated preflight failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let rust_results: Vec<Value> =
        serde_json::from_slice(&std::fs::read(rust_output).unwrap()).unwrap();
    assert_eq!(json!(PROVIDERS), reference["providers"]);
    let version = reference["version"][1].as_u64().unwrap();
    let mut hardened = 0;
    let mut syntax = 0;
    for ((case, want), got) in cases
        .iter()
        .zip(reference["results"].as_array().unwrap())
        .zip(rust_results)
    {
        if case.hardening && got["error"]["type"] == "TooDeep" {
            hardened += 1;
            continue;
        }
        if case.syntax_since.is_some_and(|minor| version >= minor) {
            let result: Value = serde_json::from_str(got["json"].as_str().unwrap()).unwrap();
            assert!(
                result["limits"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|s| s == "Python script could not be parsed; estimates are incomplete."),
                "{}",
                case.name
            );
            syntax += 1;
            continue;
        }
        if case.name == nul_name && reference["nul_error"] == "SyntaxError" {
            // NUL changed from ValueError to SyntaxError.
            assert_eq!(
                got["error"]["message"],
                "source code string cannot contain null bytes"
            );
            continue;
        }
        assert_eq!(&got, want, "case {}", case.name);
    }
    eprintln!(
        "preflight parity: {} cases, {} Python source samples, {hardened} depth refusals, {syntax} version-specific syntax checks",
        cases.len(),
        sources.len()
    );
}

#[test]
fn empty_command_is_an_error() {
    assert!(
        matches!(preflight_command(&[],None),Err(PreflightError::ValueError(message)) if message=="preflight requires a command")
    );
}
