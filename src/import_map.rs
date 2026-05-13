use oxc_ast::ast::{
    BindingPattern, Expression, ImportDeclarationSpecifier, ImportOrExportKind, ObjectPattern,
    Program, PropertyKey, Statement, VariableDeclaration,
};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ImportKind {
    Named,
    Namespace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImportEntry {
    pub original_name: String,
    pub source: String,
    pub kind: ImportKind,
}

#[derive(Debug, Default)]
pub(crate) struct ImportMap {
    entries: HashMap<String, ImportEntry>,
}

impl ImportMap {
    pub(crate) fn build(program: &Program<'_>) -> Self {
        let mut map = Self::default();
        for stmt in &program.body {
            match stmt {
                Statement::ImportDeclaration(decl)
                    if decl.import_kind == ImportOrExportKind::Value =>
                {
                    if let Some(specs) = decl.specifiers.as_ref() {
                        for spec in specs {
                            map.collect_es_specifier(&decl.source.value, spec);
                        }
                    }
                }
                Statement::VariableDeclaration(decl) => {
                    map.collect_cjs_require(decl);
                }
                _ => {}
            }
        }
        map
    }

    pub(crate) fn resolve(&self, local: &str) -> Option<&ImportEntry> {
        self.entries.get(local)
    }

    fn insert_named(&mut self, local: String, original_name: String, source: &str) {
        self.entries.insert(
            local,
            ImportEntry {
                original_name,
                source: source.to_owned(),
                kind: ImportKind::Named,
            },
        );
    }

    fn insert_namespace(&mut self, local: String, source: &str) {
        self.entries.insert(
            local.clone(),
            ImportEntry {
                original_name: local,
                source: source.to_owned(),
                kind: ImportKind::Namespace,
            },
        );
    }

    fn collect_es_specifier(&mut self, source: &str, spec: &ImportDeclarationSpecifier<'_>) {
        match spec {
            ImportDeclarationSpecifier::ImportSpecifier(s)
                if s.import_kind == ImportOrExportKind::Value =>
            {
                self.insert_named(
                    s.local.name.to_string(),
                    s.imported.name().to_string(),
                    source,
                );
            }
            ImportDeclarationSpecifier::ImportNamespaceSpecifier(s) => {
                self.insert_namespace(s.local.name.to_string(), source);
            }
            _ => {}
        }
    }

    fn collect_cjs_require(&mut self, decl: &VariableDeclaration<'_>) {
        for declarator in &decl.declarations {
            let Some(init) = &declarator.init else {
                continue;
            };
            let Some(source) = require_source(init) else {
                continue;
            };
            match &declarator.id {
                BindingPattern::BindingIdentifier(id) => {
                    self.insert_namespace(id.name.to_string(), source);
                }
                BindingPattern::ObjectPattern(obj) => {
                    self.collect_cjs_destructure(obj, source);
                }
                _ => {}
            }
        }
    }

    fn collect_cjs_destructure(&mut self, obj: &ObjectPattern<'_>, source: &str) {
        for prop in &obj.properties {
            let original = match &prop.key {
                PropertyKey::StaticIdentifier(id) => id.name.to_string(),
                PropertyKey::StringLiteral(s) => s.value.to_string(),
                _ => continue,
            };
            let local = match &prop.value {
                BindingPattern::BindingIdentifier(id) => id.name.to_string(),
                _ => continue,
            };
            self.insert_named(local, original, source);
        }
    }
}

fn require_source<'a>(expr: &'a Expression<'a>) -> Option<&'a str> {
    let Expression::CallExpression(call) = expr else {
        return None;
    };
    let Expression::Identifier(id) = &call.callee else {
        return None;
    };
    if id.name != "require" {
        return None;
    }
    let arg = call.arguments.first()?.as_expression()?;
    let Expression::StringLiteral(s) = arg else {
        return None;
    };
    Some(s.value.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast;

    fn build(content: &str) -> ImportMap {
        ast::with_parsed_program(content, "/src/app.ts", |program, _| {
            ImportMap::build(program)
        })
        .unwrap_or_default()
    }

    fn assert_entry(map: &ImportMap, local: &str, original: &str, source: &str, kind: ImportKind) {
        let entry = map
            .resolve(local)
            .unwrap_or_else(|| panic!("expected entry for {local}"));
        assert_eq!(entry.original_name, original, "local={local}");
        assert_eq!(entry.source, source, "local={local}");
        assert_eq!(entry.kind, kind, "local={local}");
    }

    #[test]
    fn es_named_with_alias_resolves_to_original() {
        let map = build("import { exec as run } from 'child_process';");
        assert_entry(&map, "run", "exec", "child_process", ImportKind::Named);
    }

    #[test]
    fn es_named_without_alias_uses_same_name() {
        let map = build("import { exec } from 'child_process';");
        assert_entry(&map, "exec", "exec", "child_process", ImportKind::Named);
    }

    #[test]
    fn es_namespace_resolves_to_namespace_kind() {
        let map = build("import * as fs from 'fs';");
        assert_entry(&map, "fs", "fs", "fs", ImportKind::Namespace);
    }

    #[test]
    fn cjs_destructure_with_alias_resolves_to_original() {
        let map = build("const { exec: run } = require('child_process');");
        assert_entry(&map, "run", "exec", "child_process", ImportKind::Named);
    }

    #[test]
    fn cjs_destructure_without_alias_uses_same_name() {
        let map = build("const { exec } = require('child_process');");
        assert_entry(&map, "exec", "exec", "child_process", ImportKind::Named);
    }

    #[test]
    fn cjs_namespace_resolves_to_namespace_kind() {
        let map = build("const cp = require('child_process');");
        assert_entry(&map, "cp", "cp", "child_process", ImportKind::Namespace);
    }

    #[test]
    fn unrelated_local_name_resolves_none() {
        let map = build("import { exec as run } from 'child_process';");
        assert!(map.resolve("nope").is_none());
    }

    #[test]
    fn empty_file_resolves_none() {
        let map = build("");
        assert!(map.resolve("anything").is_none());
    }

    #[test]
    fn invalid_syntax_returns_empty() {
        let map = build("function { invalid !!!");
        assert!(map.resolve("anything").is_none());
    }

    #[test]
    fn multiple_imports_all_registered() {
        let map = build(concat!(
            "import { exec } from 'child_process';\n",
            "import * as fs from 'fs';\n",
            "const { readFile } = require('fs');\n",
            "const cp = require('child_process');\n",
        ));
        assert_entry(&map, "exec", "exec", "child_process", ImportKind::Named);
        assert_entry(&map, "fs", "fs", "fs", ImportKind::Namespace);
        assert_entry(&map, "readFile", "readFile", "fs", ImportKind::Named);
        assert_entry(&map, "cp", "cp", "child_process", ImportKind::Namespace);
    }

    #[test]
    fn side_effect_import_ignored() {
        let map = build("import 'polyfill';");
        assert!(map.resolve("polyfill").is_none());
    }

    #[test]
    fn require_non_literal_source_ignored() {
        let map = build("const cp = require(mod);");
        assert!(map.resolve("cp").is_none());
    }

    #[test]
    fn require_with_template_literal_ignored() {
        let map = build("const cp = require(`./mod-${env}`);");
        assert!(map.resolve("cp").is_none());
    }

    #[test]
    fn nested_destructure_ignored() {
        let map = build("const { a: { b } } = require('foo');");
        assert!(map.resolve("b").is_none());
    }

    #[test]
    fn nested_function_scope_not_collected() {
        let map = build("function f() { const cp = require('child_process'); }");
        assert!(map.resolve("cp").is_none());
    }

    #[test]
    fn duplicate_local_name_last_write_wins() {
        let map = build(concat!(
            "import { exec } from 'child_process';\n",
            "const { exec } = require('shelljs');\n",
        ));
        let entry = map.resolve("exec").expect("exec should resolve");
        assert_eq!(entry.original_name, "exec");
        assert_eq!(entry.source, "shelljs");
    }

    #[test]
    fn css_file_returns_empty_map() {
        let map =
            ast::with_parsed_program("body { color: red; }", "/src/styles.css", |program, _| {
                ImportMap::build(program)
            })
            .unwrap_or_default();
        assert!(map.resolve("anything").is_none());
    }

    #[test]
    fn default_import_ignored() {
        let map = build("import fs from 'fs';");
        assert!(map.resolve("fs").is_none());
    }

    #[test]
    fn mixed_default_and_named_only_named_registered() {
        let map = build("import fs, { readFile } from 'fs';");
        assert!(map.resolve("fs").is_none());
        assert_entry(&map, "readFile", "readFile", "fs", ImportKind::Named);
    }

    #[test]
    fn type_only_import_declaration_ignored() {
        let map = build("import type { exec } from 'child_process';");
        assert!(map.resolve("exec").is_none());
    }

    #[test]
    fn type_only_specifier_ignored() {
        let map = build("import { type exec } from 'child_process';");
        assert!(map.resolve("exec").is_none());
    }

    #[test]
    fn mixed_value_and_type_specifier_only_value_registered() {
        let map = build("import { exec, type Foo } from 'child_process';");
        assert_entry(&map, "exec", "exec", "child_process", ImportKind::Named);
        assert!(map.resolve("Foo").is_none());
    }
}
