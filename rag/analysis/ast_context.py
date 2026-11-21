"""Conservative, syntax-only extraction of security-relevant Python context.

This module never imports or executes the source being analyzed. Its relationships
are syntactic candidates and do not establish runtime taint or exploitability.
"""

from __future__ import annotations

import ast
import inspect
from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class SourceSpan:
    line_start: int
    column_start: int
    line_end: int
    column_end: int


@dataclass(frozen=True)
class ImportContext:
    module: str
    imported_names: Tuple[str, ...]
    aliases: Tuple[Tuple[str, str], ...]
    scope: str
    span: SourceSpan
    is_from_import: bool


@dataclass(frozen=True)
class FunctionContext:
    name: str
    qualified_name: str
    parameters: Tuple[str, ...]
    potential_sources: Tuple[str, ...]
    line_start: int
    line_end: int
    scope: str
    span: SourceSpan


@dataclass(frozen=True)
class AssignmentContext:
    targets: Tuple[str, ...]
    expression: str
    identifiers: Tuple[str, ...]
    cwe_categories: Tuple[str, ...]
    indicator: Optional[str]
    scope: str
    span: SourceSpan


@dataclass(frozen=True)
class CallContext:
    call_name: str
    arguments: Tuple[str, ...]
    keyword_arguments: Tuple[Tuple[str, str], ...]
    scope: str
    cwe_categories: Tuple[str, ...]
    is_source: bool
    is_sink: bool
    safeguards: Tuple[str, ...]
    span: SourceSpan


@dataclass(frozen=True)
class FlowEvidence:
    source: str
    sink: str
    variables: Tuple[str, ...]
    cwe_categories: Tuple[str, ...]
    scope: str
    span: SourceSpan
    relationship: str
    complete: bool
    uncertainty: str


@dataclass(frozen=True)
class ParseDiagnostic:
    message: str
    line: Optional[int]
    column: Optional[int]


@dataclass(frozen=True)
class CodeContext:
    functions: Tuple[FunctionContext, ...]
    imports: Tuple[ImportContext, ...]
    assignments: Tuple[AssignmentContext, ...]
    calls: Tuple[CallContext, ...]
    sources: Tuple[CallContext, ...]
    sinks: Tuple[CallContext, ...]
    safeguards: Tuple[CallContext, ...]
    flows: Tuple[FlowEvidence, ...]
    parse_error: Optional[ParseDiagnostic] = None
    source: str = ""


_SOURCES = {
    "input": (),
    "request.args.get": (),
    "request.args": (),
    "request.form.get": (),
    "request.form": (),
    "request.json": (),
    "request.get_json": (),
    "request.data": (),
    "request.values.get": (),
    "request.values": (),
    "sys.argv": (),
    "os.environ.get": (),
    "getenv": (),
}

_SINKS = {
    "execute": ("CWE-89",),
    "executemany": ("CWE-89",),
    "cursor.execute": ("CWE-89",),
    "cursor.executemany": ("CWE-89",),
    "os.system": ("CWE-78",),
    "os.popen": ("CWE-78",),
    "subprocess.run": ("CWE-78",),
    "subprocess.call": ("CWE-78",),
    "subprocess.popen": ("CWE-78",),
    "subprocess.check_output": ("CWE-78",),
    "subprocess.check_call": ("CWE-78",),
    "eval": ("CWE-78",),
    "exec": ("CWE-78",),
    "open": ("CWE-22",),
    "pathlib.Path": ("CWE-22",),
    "Path": ("CWE-22",),
    "send_file": ("CWE-22",),
    "render_template_string": ("CWE-79",),
    "Markup": ("CWE-79",),
    "Response": ("CWE-79",),
}

_SAFE_CALLS = {
    "html.escape": "html escaping",
    "escape": "escaping",
    "sanitize": "sanitization",
    "os.path.realpath": "path canonicalization",
    "os.path.commonpath": "path containment check",
    "Path.resolve": "path resolution",
    "resolve": "path resolution",
}

_CWE_ORDER = ("CWE-22", "CWE-78", "CWE-79", "CWE-798", "CWE-89")


def _span(node: ast.AST) -> SourceSpan:
    return SourceSpan(
        getattr(node, "lineno", 1),
        getattr(node, "col_offset", 0),
        getattr(node, "end_lineno", getattr(node, "lineno", 1)),
        getattr(node, "end_col_offset", getattr(node, "col_offset", 0)),
    )


def _expr(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except (AttributeError, ValueError):
        return type(node).__name__


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id

    if isinstance(node, ast.Attribute):
        left = _dotted(node.value)
        return f"{left}.{node.attr}" if left else node.attr

    if isinstance(node, ast.Call):
        return _dotted(node.func)

    return ""


def _names(node: ast.AST) -> Tuple[str, ...]:
    return tuple(
        sorted({
            n.id for n in ast.walk(node)
            if isinstance(n, ast.Name)
        })
    )


def _targets(node: ast.AST) -> Tuple[str, ...]:
    if isinstance(node, (ast.Tuple, ast.List)):
        return tuple(
            name
            for elt in node.elts
            for name in _targets(elt)
        )

    return _names(node)


def _source_kind(name: str) -> bool:
    return (
        name in _SOURCES
        or name.endswith((
            ".args.get",
            ".form.get",
            ".values.get",
            ".get_json",
        ))
    )


class _Extractor(ast.NodeVisitor):

    def __init__(self, source: str):
        self.source = source
        self.lines = source.splitlines()
        self.functions = []
        self.imports = []
        self.assignments = []
        self.calls = []
        self.flows = []
        self.scope_stack = ["<module>"]
        self.function_assignments = {}
        self.function_sources = {}
        self.function_calls = {}

    @property
    def scope(self):
        return ".".join(self.scope_stack)

    def visit_FunctionDef(self, node):
        self._visit_function(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def _visit_function(self, node):
        parent = self.scope

        qualified = ".".join(
            self.scope_stack[1:] + [node.name]
        )

        args = node.args

        params = tuple(
            a.arg for a in (
                *args.posonlyargs,
                *args.args,
                *args.kwonlyargs,
            )
        )

        if args.vararg:
            params += (args.vararg.arg,)

        if args.kwarg:
            params += (args.kwarg.arg,)

        self.functions.append(
            FunctionContext(
                node.name,
                qualified,
                params,
                params,
                node.lineno,
                getattr(node, "end_lineno", node.lineno),
                parent,
                _span(node),
            )
        )

        self.scope_stack.append(node.name)

        self.function_assignments[self.scope] = {}

        self.function_sources[self.scope] = {
            parameter: {
                f"parameter:{parameter}@{node.lineno}"
            }
            for parameter in params
        }

        self.function_calls[self.scope] = []

        for stmt in node.body:
            self.visit(stmt)

        self._derive_flows(self.scope)

        self.scope_stack.pop()

    def visit_Import(self, node):
        aliases = tuple(
            (a.name, a.asname or a.name.split(".")[0])
            for a in node.names
        )

        self.imports.append(
            ImportContext(
                "",
                tuple(a.name for a in node.names),
                aliases,
                self.scope,
                _span(node),
                False,
            )
        )

    def visit_ImportFrom(self, node):
        module = ("." * node.level) + (node.module or "")

        aliases = tuple(
            (a.name, a.asname or a.name)
            for a in node.names
        )

        self.imports.append(
            ImportContext(
                module,
                tuple(a.name for a in node.names),
                aliases,
                self.scope,
                _span(node),
                True,
            )
        )

    def visit_Assign(self, node):
        self._record_assignment(
            node.targets,
            node.value,
            node,
        )
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self._record_assignment(
                [node.target],
                node.value,
                node,
            )

        self.generic_visit(node)

    def visit_NamedExpr(self, node):
        self._record_assignment(
            [node.target],
            node.value,
            node,
        )

        self.generic_visit(node)

    def _record_assignment(self, targets, value, node):
        names = tuple(
            dict.fromkeys(
                n
                for target in targets
                for n in _targets(target)
            )
        )

        rhs_names = _names(value)

        credential_name = any(
            any(
                token in name.lower()
                for token in (
                    "password",
                    "passwd",
                    "api_key",
                    "apikey",
                    "secret",
                    "token",
                    "credential",
                    "private_key",
                )
            )
            for name in names
        )

        literal_credential = (
            credential_name
            and isinstance(value, (ast.Constant, ast.JoinedStr))
        )

        self.assignments.append(
            AssignmentContext(
                names,
                _expr(value),
                rhs_names,
                ("CWE-798",) if literal_credential else (),
                (
                    "credential-like literal assignment"
                    if literal_credential
                    else None
                ),
                self.scope,
                _span(node),
            )
        )

        if self.scope != "<module>":
            mapping = self.function_assignments.setdefault(
                self.scope,
                {},
            )

            origins = set()

            for name in rhs_names:
                origins.update(
                    mapping.get(
                        name,
                        self.function_sources[self.scope].get(
                            name,
                            set(),
                        ),
                    )
                )

            for call in (
                n for n in ast.walk(value)
                if isinstance(n, ast.Call)
            ):
                call_name = _dotted(call.func)

                if _source_kind(call_name):
                    origins.add(
                        f"{call_name}@{call.lineno}"
                    )

            for name in names:
                mapping[name] = set(origins)

                if origins:
                    self.function_sources[self.scope][name] = set(
                        origins
                    )

    def visit_Call(self, node):
        name = _dotted(node.func)

        categories = set(_SINKS.get(name, ()))

        if name.rsplit(".", 1)[-1] in {
            "execute",
            "executemany",
        }:
            categories.add("CWE-89")

        # Resolve common imported aliases syntactically.
        for imp in self.imports:
            if not (
                self.scope == imp.scope
                or self.scope.startswith(imp.scope + ".")
            ):
                continue

            for original, alias in imp.aliases:

                if (
                    original == "subprocess"
                    and name.startswith(alias + ".")
                ):
                    categories.update(
                        _SINKS.get(
                            "subprocess."
                            + name[len(alias) + 1:].lower(),
                            (),
                        )
                    )

                if name == alias and original in {
                    "system",
                    "popen",
                    "run",
                    "call",
                    "Popen",
                    "execute",
                    "executemany",
                }:
                    categories.update(
                        _SINKS.get(
                            f"{imp.module}.{original}".lower(),
                            (),
                        )
                    )

                    categories.update(
                        _SINKS.get(
                            original.lower()
                            if original == "Popen"
                            else original,
                            (),
                        )
                    )

                    if (
                        imp.module == "os"
                        and original in {"system", "popen"}
                    ):
                        categories.add("CWE-78")

        is_source = _source_kind(name)
        is_sink = bool(categories)

        safeguards = []

        if name in _SAFE_CALLS:
            safeguards.append(_SAFE_CALLS[name])

        if (
            name.rsplit(".", 1)[-1] in {
                "execute",
                "executemany",
            }
            and len(node.args) >= 2
        ):
            safeguards.append(
                "parameterized SQL arguments present"
            )

        shell_value = next(
            (
                kw.value
                for kw in node.keywords
                if kw.arg == "shell"
            ),
            None,
        )

        subprocess_call = (
            name.startswith("subprocess.")
            or any(
                name.startswith(alias + ".")
                and original == "subprocess"
                for imp in self.imports
                if (
                    self.scope == imp.scope
                    or self.scope.startswith(imp.scope + ".")
                )
                for original, alias in imp.aliases
            )
        )

        if (
            subprocess_call
            and isinstance(shell_value, ast.Constant)
            and shell_value.value is False
        ):
            safeguards.append("subprocess shell=False")

        call = CallContext(
            name,
            tuple(_expr(a) for a in node.args),
            tuple(
                (kw.arg or "**", _expr(kw.value))
                for kw in node.keywords
            ),
            self.scope,
            tuple(
                c for c in _CWE_ORDER
                if c in categories
            ),
            is_source,
            is_sink,
            tuple(safeguards),
            _span(node),
        )

        self.calls.append(call)

        if self.scope != "<module>":
            self.function_calls.setdefault(
                self.scope,
                [],
            ).append((call, node))

        self.generic_visit(node)

    def _derive_flows(self, scope):
        assignments = self.function_assignments[scope]

        for call, node in self.function_calls[scope]:

            if not call.is_sink:
                continue

            sources = set()
            variables = set()

            for arg in node.args:
                for variable in _names(arg):

                    origins = assignments.get(
                        variable,
                        self.function_sources[scope].get(
                            variable,
                            set(),
                        ),
                    )

                    if origins:
                        variables.add(variable)
                        sources.update(origins)

            # Identify a source call passed directly into a sink.
            for child in ast.walk(node):

                if (
                    isinstance(child, ast.Call)
                    and _source_kind(_dotted(child.func))
                ):
                    sources.add(
                        f"{_dotted(child.func)}@{child.lineno}"
                    )

            for source in sorted(sources):
                self.flows.append(
                    FlowEvidence(
                        source,
                        call.call_name,
                        tuple(sorted(variables)),
                        call.cwe_categories,
                        scope,
                        call.span,
                        (
                            "direct"
                            if "@" in source and not variables
                            else "assignment_or_expression"
                        ),
                        False,
                        (
                            "Syntactic candidate only; runtime value "
                            "flow and exploitability are unverified."
                        ),
                    )
                )


def extract_code_context(source: str) -> CodeContext:
    """Extract syntax-level context without executing or importing source.

    Common leading indentation is removed before parsing so that indented
    methods and code fragments can be analyzed as standalone snippets.

    The original source is preserved in CodeContext.source.
    """

    # cleandoc removes indentation from standalone code snippets,
    # including indentation on the first line.
    normalized_source = inspect.cleandoc(source)

    try:
        tree = ast.parse(normalized_source)

    except SyntaxError as exc:
        return CodeContext(
            (),
            (),
            (),
            (),
            (),
            (),
            (),
            (),
            ParseDiagnostic(
                exc.msg,
                exc.lineno,
                exc.offset,
            ),
            source,
        )

    extractor = _Extractor(normalized_source)
    extractor.visit(tree)

    sources = tuple(
        call
        for call in extractor.calls
        if call.is_source
    )

    sinks = tuple(
        call
        for call in extractor.calls
        if call.is_sink
    )

    safeguards = tuple(
        call
        for call in extractor.calls
        if call.safeguards
    )

    return CodeContext(
        tuple(extractor.functions),
        tuple(extractor.imports),
        tuple(extractor.assignments),
        tuple(extractor.calls),
        sources,
        sinks,
        safeguards,
        tuple(extractor.flows),
        None,
        source,
    )