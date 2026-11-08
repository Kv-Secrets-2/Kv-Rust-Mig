use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use num_bigint::BigInt;
use num_traits::Zero;
use ruff_python_ast::token::TokenKind;
use ruff_python_ast::visitor::source_order::{SourceOrderVisitor, TraversalSignal};
use ruff_python_ast::visitor::transformer::{self, Transformer};
use ruff_python_ast::{self as ast, AnyNodeRef, Expr, Number};
use ruff_python_parser::{Mode, ParseOptions};
use unicode_normalization::UnicodeNormalization;

use crate::manifest::{PROVIDERS, PreflightError, PreflightManifest, budget};

fn normalized(name: &str) -> String {
    name.nfkc().collect()
}

enum OwnedNode {
    Stmt(ast::Stmt),
    Expr(Expr),
    Pattern(ast::Pattern),
    Interpolation(ast::InterpolatedStringElement),
}

struct Drain(RefCell<Vec<OwnedNode>>);
impl Transformer for Drain {
    fn visit_stmt(&self, node: &mut ast::Stmt) {
        let placeholder = ast::Stmt::Pass(ast::StmtPass {
            node_index: Default::default(),
            range: Default::default(),
        });
        self.0
            .borrow_mut()
            .push(OwnedNode::Stmt(std::mem::replace(node, placeholder)));
    }
    fn visit_expr(&self, node: &mut Expr) {
        self.0.borrow_mut().push(OwnedNode::Expr(std::mem::replace(
            node,
            Expr::NoneLiteral(ast::ExprNoneLiteral::default()),
        )));
    }
    fn visit_pattern(&self, node: &mut ast::Pattern) {
        let placeholder = ast::Pattern::MatchSingleton(ast::PatternMatchSingleton {
            node_index: Default::default(),
            range: Default::default(),
            value: ast::Singleton::None,
        });
        self.0
            .borrow_mut()
            .push(OwnedNode::Pattern(std::mem::replace(node, placeholder)));
    }
    fn visit_interpolated_string_element(&self, node: &mut ast::InterpolatedStringElement) {
        let placeholder =
            ast::InterpolatedStringElement::Literal(ast::InterpolatedStringLiteralElement {
                node_index: Default::default(),
                range: Default::default(),
                value: "".into(),
            });
        self.0
            .borrow_mut()
            .push(OwnedNode::Interpolation(std::mem::replace(
                node,
                placeholder,
            )));
    }
}

struct SyntaxTree {
    root: ast::Mod,
    bounded: bool,
}
impl Drop for SyntaxTree {
    fn drop(&mut self) {
        if self.bounded {
            return;
        }
        // Ruff's default AST destructor recurses even when parsing used stacker.
        let drain = Drain(RefCell::new(Vec::new()));
        match &mut self.root {
            ast::Mod::Module(module) => drain.visit_body(&mut module.body),
            ast::Mod::Expression(expr) => drain.visit_expr(&mut expr.body),
        }
        loop {
            let node = drain.0.borrow_mut().pop();
            match node {
                Some(OwnedNode::Stmt(mut node)) => transformer::walk_stmt(&drain, &mut node),
                Some(OwnedNode::Expr(mut node)) => transformer::walk_expr(&drain, &mut node),
                Some(OwnedNode::Pattern(mut node)) => transformer::walk_pattern(&drain, &mut node),
                Some(OwnedNode::Interpolation(mut node)) => {
                    transformer::walk_interpolated_string_element(&drain, &mut node)
                }
                None => break,
            }
        }
    }
}

struct Children<'a>(Vec<AnyNodeRef<'a>>);
impl<'a> SourceOrderVisitor<'a> for Children<'a> {
    fn enter_node(&mut self, node: AnyNodeRef<'a>) -> TraversalSignal {
        self.0.push(node);
        TraversalSignal::Skip
    }
}

fn children(node: AnyNodeRef<'_>) -> Vec<AnyNodeRef<'_>> {
    let mut out = Vec::new();
    match node {
        AnyNodeRef::StmtFunctionDef(f) => {
            out.push(AnyNodeRef::Parameters(&f.parameters));
            out.extend(f.body.iter().map(AnyNodeRef::from));
            out.extend(
                f.decorator_list
                    .iter()
                    .map(|d| AnyNodeRef::from(&d.expression)),
            );
            out.extend(f.returns.iter().map(|e| AnyNodeRef::from(e.as_ref())));
        }
        AnyNodeRef::StmtClassDef(c) => {
            if let Some(args) = &c.arguments {
                out.extend(args.args.iter().map(AnyNodeRef::from));
                out.extend(args.keywords.iter().map(AnyNodeRef::from));
            }
            out.extend(c.body.iter().map(AnyNodeRef::from));
            out.extend(
                c.decorator_list
                    .iter()
                    .map(|d| AnyNodeRef::from(&d.expression)),
            );
        }
        AnyNodeRef::Parameters(p) => {
            out.extend(
                p.posonlyargs
                    .iter()
                    .chain(&p.args)
                    .map(|p| AnyNodeRef::Parameter(&p.parameter)),
            );
            out.extend(p.vararg.iter().map(|p| AnyNodeRef::Parameter(p)));
            out.extend(
                p.kwonlyargs
                    .iter()
                    .map(|p| AnyNodeRef::Parameter(&p.parameter)),
            );
            out.extend(
                p.kwonlyargs
                    .iter()
                    .filter_map(|p| p.default.as_deref())
                    .map(AnyNodeRef::from),
            );
            out.extend(p.kwarg.iter().map(|p| AnyNodeRef::Parameter(p)));
            out.extend(
                p.posonlyargs
                    .iter()
                    .chain(&p.args)
                    .filter_map(|p| p.default.as_deref())
                    .map(AnyNodeRef::from),
            );
        }
        AnyNodeRef::ExprCall(call) => {
            out.push(AnyNodeRef::from(call.func.as_ref()));
            out.extend(call.arguments.args.iter().map(AnyNodeRef::from));
            out.extend(call.arguments.keywords.iter().map(AnyNodeRef::from));
        }
        AnyNodeRef::ExprDict(dict) => {
            out.extend(
                dict.items
                    .iter()
                    .filter_map(|item| item.key.as_ref())
                    .map(AnyNodeRef::from),
            );
            out.extend(dict.items.iter().map(|item| AnyNodeRef::from(&item.value)));
        }
        _ => {
            let mut collector = Children(Vec::new());
            node.visit_source_order(&mut collector);
            out = collector.0;
        }
    }
    out
}

fn token_limits(source: &str) -> bool {
    let mut lexer = ruff_python_parser::lexer::lex(source, Mode::Module);
    let mut brackets: usize = 0;
    let mut indents: usize = 0;
    loop {
        match lexer.next_token() {
            TokenKind::EndOfFile => return true,
            TokenKind::Lpar | TokenKind::Lsqb | TokenKind::Lbrace => {
                brackets += 1;
                if brackets > 200 {
                    return false;
                }
            }
            TokenKind::Rpar | TokenKind::Rsqb | TokenKind::Rbrace => {
                brackets = brackets.saturating_sub(1)
            }
            TokenKind::Indent => {
                indents += 1;
                if indents >= 100 {
                    return false;
                }
            }
            TokenKind::Dedent => indents = indents.saturating_sub(1),
            _ => {}
        }
    }
}

/// Computes a conservative depth without invoking a recursive AST visitor.
fn check_depth(root: AnyNodeRef<'_>) -> Result<(), PreflightError> {
    let mut pending = vec![(root, 1usize)];
    while let Some((node, depth)) = pending.pop() {
        // Reserve a level for CPython's operator/context leaves.
        if depth >= 100 {
            return Err(PreflightError::TooDeep);
        }
        if let AnyNodeRef::StmtIf(stmt) = node {
            pending.push((AnyNodeRef::from(stmt.test.as_ref()), depth + 1));
            pending.extend(stmt.body.iter().map(|s| (AnyNodeRef::from(s), depth + 1)));
            for (i, clause) in stmt.elif_else_clauses.iter().enumerate() {
                pending.push((AnyNodeRef::ElifElseClause(clause), depth + i + 1));
            }
        } else {
            pending.extend(children(node).into_iter().map(|child| (child, depth + 1)));
        }
    }
    Ok(())
}

fn const_str(expr: &Expr) -> Option<&str> {
    if let Expr::StringLiteral(s) = expr {
        Some(s.value.to_str())
    } else {
        None
    }
}
fn const_int(expr: &Expr) -> Option<BigInt> {
    match expr {
        Expr::NumberLiteral(n) => {
            if let Number::Int(n) = &n.value {
                n.to_string().parse().ok()
            } else {
                None
            }
        }
        Expr::BooleanLiteral(n) => Some(BigInt::from(u8::from(n.value))),
        _ => None,
    }
}
fn call_name(expr: &Expr) -> String {
    let mut parts = Vec::new();
    let mut current = expr;
    while let Expr::Attribute(a) = current {
        parts.push(normalized(a.attr.as_str()));
        current = &a.value;
    }
    if let Expr::Name(n) = current {
        parts.push(normalized(n.id.as_str()));
    }
    parts.reverse();
    parts.join(".")
}
fn call_root(mut expr: &Expr) -> Option<String> {
    while let Expr::Attribute(a) = expr {
        expr = &a.value;
    }
    if let Expr::Name(n) = expr {
        Some(normalized(n.id.as_str()))
    } else {
        None
    }
}
fn constructor(expr: &Expr) -> Option<&'static str> {
    let Expr::Call(call) = expr else {
        return None;
    };
    match call_name(&call.func).as_str() {
        "anthropic.Anthropic" | "Anthropic" => Some("anthropic"),
        "openai.OpenAI" | "OpenAI" => Some("openai"),
        _ => None,
    }
}
fn broker(call: &ast::ExprCall) -> Option<&str> {
    let name = call_name(&call.func);
    if name != "api_call" && !name.ends_with(".api_call") {
        return None;
    }
    let provider = if let Some(arg) = call.arguments.args.first() {
        const_str(arg)
    } else {
        call.arguments
            .keywords
            .iter()
            .find(|k| {
                k.arg
                    .as_ref()
                    .is_some_and(|a| normalized(a.as_str()) == "provider")
            })
            .and_then(|k| const_str(&k.value))
    }?;
    PROVIDERS.contains(&provider).then_some(provider)
}
fn elements(expr: &Expr) -> Option<&[Expr]> {
    match expr {
        Expr::List(l) => Some(&l.elts),
        Expr::Tuple(t) => Some(&t.elts),
        Expr::Set(s) => Some(&s.elts),
        _ => None,
    }
}
fn loop_count(iterable: &Expr) -> Option<BigInt> {
    if let Expr::Call(call) = iterable
        && call_name(&call.func) == "range"
    {
        let args = &call.arguments.args;
        if args.len() == 1 {
            return Some(const_int(&args[0])?.max(BigInt::zero()));
        }
        if args.len() == 2 {
            return Some((const_int(&args[1])? - const_int(&args[0])?).max(BigInt::zero()));
        }
    }
    elements(iterable).map(|e| BigInt::from(e.len()))
}
const SSH: &[&str] = &["ssh", "scp", "sftp", "rsync"];
fn ssh_call(call: &ast::ExprCall) -> Option<Option<String>> {
    if !["subprocess.run", "subprocess.Popen", "run", "Popen"]
        .contains(&call_name(&call.func).as_str())
    {
        return None;
    }
    let first = call.arguments.args.first()?;
    if !matches!(first, Expr::List(_) | Expr::Tuple(_)) {
        return None;
    }
    let elts = elements(first)?;
    let program = const_str(elts.first()?)?;
    if !SSH.contains(&program.rsplit('/').next()?) {
        return None;
    }
    let strings: Vec<_> = elts
        .iter()
        .filter_map(const_str)
        .filter(|s| !s.is_empty())
        .collect();
    for (i, value) in strings.iter().enumerate() {
        if SSH.contains(&value.rsplit('/').next().unwrap_or(""))
            && let Some(next) = strings.get(i + 1)
            && !next.starts_with('-')
        {
            return Some(Some(next.to_string()));
        }
    }
    Some(None)
}
fn path_expr(expr: &Expr) -> Option<&str> {
    if let Expr::Call(call) = expr
        && ["Path", "pathlib.Path"].contains(&call_name(&call.func).as_str())
    {
        return call.arguments.args.first().and_then(const_str);
    }
    const_str(expr)
}
fn write_path(call: &ast::ExprCall) -> Option<&str> {
    let name = call_name(&call.func);
    if ["open", "Path.open"].contains(&name.as_str())
        && !call.arguments.args.is_empty()
        && let Some(mode) = call.arguments.args.get(1).and_then(const_str)
        && mode.contains(['w', 'a', 'x', '+'])
    {
        return const_str(&call.arguments.args[0]);
    }
    if ["write_text", "write_bytes", "touch", "mkdir"]
        .iter()
        .any(|method| name == *method || name.ends_with(&format!(".{method}")))
        && let Expr::Attribute(attr) = call.func.as_ref()
    {
        return path_expr(&attr.value).filter(|p| !p.is_empty());
    }
    None
}

#[derive(Default)]
struct Analysis {
    imported: BTreeSet<String>,
    direct: BTreeSet<String>,
    brokered: BTreeSet<String>,
    counts: BTreeMap<String, Vec<Option<BigInt>>>,
    broker_counts: BTreeMap<String, Vec<Option<BigInt>>>,
    clients: BTreeMap<String, String>,
    ssh: bool,
    hosts: BTreeSet<String>,
    writes: BTreeSet<String>,
}
impl Analysis {
    fn import(&mut self, name: &str) {
        let normalized = normalized(name);
        let root = normalized.split('.').next().unwrap_or("");
        if PROVIDERS.contains(&root) {
            self.imported.insert(root.into());
        }
        if ["paramiko", "fabric", "asyncssh"].contains(&root) {
            self.ssh = true;
        }
    }
    fn call(&mut self, call: &ast::ExprCall, multiplier: &Option<BigInt>) {
        if let Some(provider) = broker(call) {
            self.brokered.insert(provider.into());
            self.counts
                .entry(provider.into())
                .or_default()
                .push(multiplier.clone());
            self.broker_counts
                .entry(provider.into())
                .or_default()
                .push(multiplier.clone());
        } else {
            let sdk = match call_name(&call.func).as_str() {
                "anthropic.Anthropic" | "Anthropic" => Some("anthropic".to_owned()),
                "openai.OpenAI" | "OpenAI" => Some("openai".to_owned()),
                _ => None,
            };
            let provider = sdk.clone().or_else(|| {
                call_root(&call.func).and_then(|root| {
                    self.clients
                        .get(&root)
                        .cloned()
                        .or_else(|| PROVIDERS.contains(&root.as_str()).then_some(root))
                })
            });
            if let Some(provider) = provider {
                self.direct.insert(provider.clone());
                if sdk.is_none() {
                    self.counts
                        .entry(provider)
                        .or_default()
                        .push(multiplier.clone());
                }
            }
        }
        if let Some(host) = ssh_call(call) {
            self.ssh = true;
            if let Some(host) = host {
                self.hosts.insert(host);
            }
        }
        if let Some(path) = write_path(call).filter(|p| !p.is_empty()) {
            self.writes.insert(path.into());
        }
    }
    fn visit(&mut self, root: AnyNodeRef<'_>) {
        let mut pending = vec![(root, Some(BigInt::from(1)))];
        while let Some((node, multiplier)) = pending.pop() {
            match node {
                AnyNodeRef::StmtImport(i) => {
                    for alias in &i.names {
                        self.import(alias.name.as_str());
                    }
                }
                AnyNodeRef::StmtImportFrom(i) => {
                    if let Some(module) = &i.module {
                        self.import(module.as_str());
                    }
                }
                AnyNodeRef::StmtAssign(a) => {
                    if let Some(provider) = constructor(&a.value) {
                        self.direct.insert(provider.into());
                        for target in &a.targets {
                            if let Expr::Name(name) = target {
                                self.clients
                                    .insert(normalized(name.id.as_str()), provider.into());
                            }
                        }
                    }
                }
                AnyNodeRef::ExprCall(call) => self.call(call, &multiplier),
                AnyNodeRef::StmtFor(f) if !f.is_async => {
                    pending.extend(
                        f.orelse
                            .iter()
                            .rev()
                            .map(|s| (AnyNodeRef::from(s), multiplier.clone())),
                    );
                    let count = multiplier.and_then(|m| loop_count(&f.iter).map(|n| m * n));
                    pending.extend(
                        f.body
                            .iter()
                            .rev()
                            .map(|s| (AnyNodeRef::from(s), count.clone())),
                    );
                    continue;
                }
                AnyNodeRef::StmtWhile(w) => {
                    pending.extend(
                        w.orelse
                            .iter()
                            .rev()
                            .map(|s| (AnyNodeRef::from(s), multiplier.clone())),
                    );
                    pending.extend(w.body.iter().rev().map(|s| (AnyNodeRef::from(s), None)));
                    continue;
                }
                _ => {}
            }
            pending.extend(
                children(node)
                    .into_iter()
                    .rev()
                    .map(|child| (child, multiplier.clone())),
            );
        }
    }
    fn merge(self, manifest: &mut PreflightManifest) -> Result<(), PreflightError> {
        for (provider, need) in &mut manifest.api {
            need.imported = self.imported.contains(provider);
            need.direct_sdk = self.direct.contains(provider);
            need.brokered = self.brokered.contains(provider);
            let counts = self.counts.get(provider).map(Vec::as_slice).unwrap_or(&[]);
            need.call_sites = counts.len();
            if !counts.is_empty() {
                if counts.iter().any(Option::is_none) {
                    need.estimated_calls = None;
                    need.unknown_call_count = true;
                } else {
                    need.estimated_calls = Some(counts.iter().flatten().sum());
                    if let Some(counts) = self.broker_counts.get(provider)
                        && !counts.is_empty()
                        && counts.iter().all(Option::is_some)
                    {
                        need.recommended_max_calls = budget(&counts.iter().flatten().sum())?;
                    }
                }
            }
            if need.direct_sdk {
                need.rewrite_required = true;
                need.recommended_max_calls = BigInt::zero();
            }
        }
        manifest.ssh_detected = self.ssh;
        manifest.ssh_hosts = self.hosts.into_iter().collect();
        manifest.file_writes = self.writes.into_iter().collect();
        Ok(())
    }
}

pub(crate) fn analyze(
    source: &str,
    manifest: &mut PreflightManifest,
) -> Result<bool, PreflightError> {
    if source.contains('\0') {
        return Err(PreflightError::ValueError(
            "source code string cannot contain null bytes".into(),
        ));
    }
    if source.starts_with('\u{feff}') || !token_limits(source) {
        return Ok(false);
    }
    let parsed = ruff_python_parser::parse_unchecked(
        source,
        ParseOptions::from(Mode::Module).with_target_version(ast::PythonVersion::PY310),
    );
    let valid = parsed.has_no_syntax_errors();
    let mut tree = SyntaxTree {
        root: parsed.into_syntax(),
        bounded: false,
    };
    if !valid {
        return Ok(false);
    }
    let root = AnyNodeRef::from(&tree.root);
    check_depth(root)?;
    tree.bounded = true;
    let mut analysis = Analysis::default();
    analysis.visit(root);
    analysis.merge(manifest)?;
    Ok(true)
}
