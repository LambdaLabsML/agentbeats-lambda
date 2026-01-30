"""
ConfigForge Runtime Simulator

Simulates what real application deserializers would do with configs.
This is the core of the "simulated vulnerable application environment".

Supports:
- LangChain loads() simulation
- PyYAML unsafe_load() simulation
- Pickle loads() simulation
- Code execution pattern detection
"""

import concurrent.futures
import re
from typing import Any

import yaml

from .models import (
    ExtractedConfig,
    Operation,
    OperationType,
    Severity,
    SimulationResult,
)


class LangChainSimulator:
    """
    Simulates langchain.load.loads() behavior.

    Based on LangChain source code analysis:
    - Checks for 'lc' key to identify serialized objects
    - 'type' field determines handling: 'constructor', 'secret', 'not_implemented'
    - 'id' array specifies module path for import
    - 'kwargs' passed to constructor

    Security Model:
    - 'type: secret' for common API keys is SAFE (legitimate env var reference)
    - 'type: secret' for sensitive system vars is DANGEROUS
    - 'type: constructor' with langchain.* modules is SAFE
    - 'type: constructor' with other modules is DANGEROUS
    """

    # Safe module prefixes - these are legitimate LangChain imports
    SAFE_MODULE_PREFIXES = [
        "langchain",
        "langchain_core",
        "langchain_community",
        "langchain_openai",
        "langchain_anthropic",
    ]

    # LangChain components that legitimately contain code/callable fields
    # These are safe because LangChain's loads() handles them specially
    SAFE_CODE_COMPONENTS = [
        "RunnableLambda",      # Stores lambda/function in 'func' field
        "RunnablePassthrough", # May have transform functions
        "TransformChain",      # Has transform_func
        "StructuredTool",      # Has func field
        "Tool",                # Has func field
        "BaseTool",            # Has func field
    ]

    # Safe secret names - common API keys that are expected in configs
    SAFE_SECRET_PATTERNS = [
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GOOGLE_API_KEY",
        "HUGGINGFACE_API_KEY",
        "COHERE_API_KEY",
        "PINECONE_API_KEY",
        "WEAVIATE_API_KEY",
        "REDIS_URL",
        "DATABASE_URL",  # Generic DB connection is acceptable
    ]

    # Dangerous secret patterns - system/cloud credentials that shouldn't be exposed
    DANGEROUS_SECRET_PATTERNS = [
        "AWS_SECRET",
        "AWS_ACCESS_KEY",
        "PRIVATE_KEY",
        "SSH_KEY",
        "GCP_CREDENTIALS",
        "AZURE_SECRET",
        "GITHUB_TOKEN",
        "SLACK_TOKEN",
        "DISCORD_TOKEN",
    ]

    def _is_safe_secret(self, secret_ids: list) -> bool:
        """Check if secret name is a safe/expected API key."""
        if not secret_ids:
            return False
        secret_name = str(secret_ids[0]) if secret_ids else ""
        # Check if it's a known safe pattern
        for safe_pattern in self.SAFE_SECRET_PATTERNS:
            if safe_pattern in secret_name.upper():
                return True
        return False

    def _is_dangerous_secret(self, secret_ids: list) -> bool:
        """Check if secret name is a dangerous system credential."""
        if not secret_ids:
            return False
        secret_name = str(secret_ids[0]) if secret_ids else ""
        for dangerous_pattern in self.DANGEROUS_SECRET_PATTERNS:
            if dangerous_pattern in secret_name.upper():
                return True
        return False

    def _is_safe_module(self, id_path: list) -> bool:
        """Check if the module path is in the safe allowlist."""
        if not id_path:
            return False
        first_module = str(id_path[0])
        return any(first_module.startswith(prefix) for prefix in self.SAFE_MODULE_PREFIXES)

    def simulate(self, data: Any, path: str = "") -> list[Operation]:
        """Simulate what langchain.load.loads() would do."""
        operations = []

        if not isinstance(data, dict):
            return operations

        # Check for LangChain serialization marker
        if "lc" in data and isinstance(data.get("lc"), (int, float)):
            lc_type = data.get("type", "")

            # 'type: secret' is ALWAYS dangerous - extracts env vars
            if lc_type == "secret":
                operations.extend(self._handle_secret(data, path))

            # 'type: constructor' - check if module is safe
            elif lc_type == "constructor":
                operations.extend(self._handle_constructor(data, path))

        # Check for alternative type markers
        if "_type" in data:
            type_value = data["_type"]
            operations.append(Operation(
                type=OperationType.OBJECT_INSTANTIATION,
                severity=Severity.HIGH,
                path=path or "root",
                detail=f"Type marker _type={type_value} would trigger instantiation"
            ))

        # Recurse into nested structures
        for key, value in data.items():
            if key in ("lc", "type", "id", "kwargs", "_type"):
                continue  # Already processed
            new_path = f"{path}.{key}" if path else key
            if isinstance(value, dict):
                operations.extend(self.simulate(value, new_path))
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        operations.extend(self.simulate(item, f"{new_path}[{i}]"))

        return operations

    def _handle_constructor(self, data: dict, path: str) -> list[Operation]:
        """Handle LangChain constructor type."""
        operations = []
        id_path = data.get("id", [])

        if id_path and isinstance(id_path, list):
            module_parts = [str(p) for p in id_path[:-1]]
            class_name = str(id_path[-1]) if id_path else "Unknown"
            module_path = ".".join(module_parts)

            # Check if this is a safe langchain module
            if self._is_safe_module(id_path):
                # Safe langchain import - no alert needed
                pass
            else:
                # DANGEROUS: Non-langchain module instantiation
                operations.append(Operation(
                    type=OperationType.LC_CONSTRUCTOR,
                    severity=Severity.CRITICAL,
                    path=path or "root",
                    detail=f"DANGEROUS: Would instantiate {class_name} from non-langchain module {module_path}"
                ))

                operations.append(Operation(
                    type=OperationType.MODULE_IMPORT,
                    severity=Severity.CRITICAL,
                    path=path or "root",
                    detail=f"DANGEROUS: Would import arbitrary module: {module_path}"
                ))

                operations.append(Operation(
                    type=OperationType.OBJECT_INSTANTIATION,
                    severity=Severity.CRITICAL,
                    path=path or "root",
                    detail=f"DANGEROUS: Arbitrary class instantiation: {class_name}"
                ))

        # Check kwargs for nested secrets
        kwargs = data.get("kwargs", {})
        if isinstance(kwargs, dict):
            operations.extend(self._check_kwargs(kwargs, f"{path}.kwargs" if path else "kwargs"))

        return operations

    def _handle_secret(self, data: dict, path: str) -> list[Operation]:
        """Handle LangChain secret type (env var extraction)."""
        operations = []
        secret_ids = data.get("id", [])

        # Check if this is a safe API key reference or dangerous credential
        if self._is_safe_secret(secret_ids):
            # Safe API key - this is expected and acceptable
            # No operation logged (reduce noise)
            pass
        elif self._is_dangerous_secret(secret_ids):
            # Dangerous system credential
            operations.append(Operation(
                type=OperationType.LC_SECRET,
                severity=Severity.CRITICAL,
                path=path or "root",
                detail=f"DANGEROUS: Would extract sensitive credential: {secret_ids}"
            ))
            operations.append(Operation(
                type=OperationType.ENV_ACCESS,
                severity=Severity.CRITICAL,
                path=path or "root",
                detail=f"DANGEROUS: Would read sensitive env var: {secret_ids}"
            ))
        else:
            # Unknown secret - log as medium severity (could be legitimate)
            operations.append(Operation(
                type=OperationType.LC_SECRET,
                severity=Severity.MEDIUM,
                path=path or "root",
                detail=f"LangChain secret would extract env var: {secret_ids}"
            ))

        return operations

    def _check_kwargs(self, kwargs: dict, path: str) -> list[Operation]:
        """Check kwargs for secrets_from_env and nested dangerous patterns."""
        operations = []

        for key, value in kwargs.items():
            if isinstance(value, dict):
                # Check for nested secret extraction
                if value.get("lc") and value.get("type") == "secret":
                    env_vars = value.get("id", [])
                    # Use same safe/dangerous logic as _handle_secret
                    if self._is_dangerous_secret(env_vars):
                        operations.append(Operation(
                            type=OperationType.ENV_ACCESS,
                            severity=Severity.CRITICAL,
                            path=f"{path}.{key}",
                            detail=f"DANGEROUS: secrets_from_env would read: {env_vars}"
                        ))
                    elif not self._is_safe_secret(env_vars):
                        # Unknown secret - medium severity
                        operations.append(Operation(
                            type=OperationType.ENV_ACCESS,
                            severity=Severity.MEDIUM,
                            path=f"{path}.{key}",
                            detail=f"secrets_from_env would read: {env_vars}"
                        ))
                    # Safe secrets (like OPENAI_API_KEY) are not flagged
                # Recurse into nested dicts
                operations.extend(self.simulate(value, f"{path}.{key}"))

            elif isinstance(value, str):
                # Check for secrets_from_env string pattern
                if "secrets_from_env" in value.lower():
                    operations.append(Operation(
                        type=OperationType.ENV_ACCESS,
                        severity=Severity.MEDIUM,  # Reduced from HIGH - could be legitimate
                        path=f"{path}.{key}",
                        detail=f"secrets_from_env reference in string"
                    ))

        return operations


class YAMLSimulator:
    """
    Simulates yaml.unsafe_load() / yaml.full_load() behavior.

    Dangerous YAML tags:
    - !!python/object:module.Class - instantiates arbitrary class
    - !!python/object/new:module.Class - calls __new__
    - !!python/object/apply:callable - calls arbitrary function
    - !!python/module:module - imports module
    - !!python/name:module.attr - accesses module attribute
    """

    # Tag patterns and their severity
    DANGEROUS_TAGS = [
        (r'!!python/object/apply:', OperationType.CODE_EXECUTION, Severity.CRITICAL,
         "!!python/object/apply would execute arbitrary callable"),
        (r'!!python/object/new:', OperationType.OBJECT_INSTANTIATION, Severity.CRITICAL,
         "!!python/object/new would instantiate class via __new__"),
        (r'!!python/object:', OperationType.OBJECT_INSTANTIATION, Severity.CRITICAL,
         "!!python/object would instantiate arbitrary class"),
        (r'!!python/module:', OperationType.MODULE_IMPORT, Severity.CRITICAL,
         "!!python/module would import arbitrary module"),
        (r'!!python/name:', OperationType.MODULE_IMPORT, Severity.HIGH,
         "!!python/name would access module attribute"),
        (r'!python/object/apply:', OperationType.CODE_EXECUTION, Severity.CRITICAL,
         "!python/object/apply would execute arbitrary callable"),
        (r'!python/object:', OperationType.OBJECT_INSTANTIATION, Severity.CRITICAL,
         "!python/object would instantiate arbitrary class"),
    ]

    def simulate(self, yaml_text: str) -> list[Operation]:
        """Simulate what yaml.unsafe_load() would do."""
        operations = []

        # Check for dangerous tags via string matching
        for pattern, op_type, severity, description in self.DANGEROUS_TAGS:
            matches = re.findall(pattern + r'([^\s\n]+)', yaml_text)
            for match in matches:
                operations.append(Operation(
                    type=op_type,
                    severity=severity,
                    path="yaml",
                    detail=f"{description}: {match}"
                ))

        # Also use yaml.scan() for tokenized detection
        try:
            for token in yaml.scan(yaml_text):
                if isinstance(token, yaml.TagToken):
                    tag_value = token.value[1] if token.value and len(token.value) > 1 else ""
                    if "python" in tag_value.lower():
                        operations.append(Operation(
                            type=OperationType.YAML_PYTHON_TAG,
                            severity=Severity.CRITICAL,
                            path="yaml",
                            detail=f"Python YAML tag detected: {tag_value}"
                        ))
        except yaml.YAMLError:
            pass  # Invalid YAML, but we already checked string patterns

        return operations


class PickleSimulator:
    """
    Simulates pickle.loads() vulnerability patterns.

    Pickle is inherently unsafe - any __reduce__ method can execute
    arbitrary code. We detect common patterns that indicate pickle
    exploitation attempts.
    """

    DANGEROUS_KEYS = {
        "__reduce__": (OperationType.CODE_EXECUTION, Severity.CRITICAL,
                       "__reduce__ allows arbitrary code execution on unpickle"),
        "__reduce_ex__": (OperationType.CODE_EXECUTION, Severity.CRITICAL,
                          "__reduce_ex__ allows arbitrary code execution on unpickle"),
        "__getstate__": (OperationType.PICKLE_PATTERN, Severity.HIGH,
                         "__getstate__ may enable state manipulation"),
        "__setstate__": (OperationType.PICKLE_PATTERN, Severity.HIGH,
                         "__setstate__ may enable arbitrary state injection"),
        "__class__": (OperationType.OBJECT_INSTANTIATION, Severity.HIGH,
                      "__class__ reference may enable type confusion"),
        "py/object": (OperationType.OBJECT_INSTANTIATION, Severity.CRITICAL,
                      "py/object pattern indicates pickle-like serialization"),
        "py/reduce": (OperationType.CODE_EXECUTION, Severity.CRITICAL,
                      "py/reduce would execute code on deserialization"),
    }

    def simulate(self, data: Any, path: str = "") -> list[Operation]:
        """Simulate what pickle.loads() patterns would enable."""
        operations = []

        if isinstance(data, dict):
            for key in data.keys():
                key_str = str(key)
                if key_str in self.DANGEROUS_KEYS:
                    op_type, severity, description = self.DANGEROUS_KEYS[key_str]
                    operations.append(Operation(
                        type=op_type,
                        severity=severity,
                        path=f"{path}.{key_str}" if path else key_str,
                        detail=description
                    ))

            # Recurse into nested structures
            for key, value in data.items():
                new_path = f"{path}.{key}" if path else str(key)
                if isinstance(value, dict):
                    operations.extend(self.simulate(value, new_path))
                elif isinstance(value, list):
                    for i, item in enumerate(value):
                        if isinstance(item, dict):
                            operations.extend(self.simulate(item, f"{new_path}[{i}]"))

        elif isinstance(data, list):
            for i, item in enumerate(data):
                if isinstance(item, dict):
                    operations.extend(self.simulate(item, f"{path}[{i}]"))

        return operations


class KubernetesSimulator:
    """
    Simulates kubectl apply behavior - detects dangerous K8s patterns.

    This demonstrates how the same "Insecure Output Handling" vulnerability
    applies to Kubernetes manifests (similar to K8s Kill scenario).

    Dangerous patterns (like K8s Kill):
    - privileged: true - container escapes to host
    - hostPath: { path: / } - mounts host filesystem
    - hostPID: true - sees host processes
    - hostNetwork: true - uses host network
    """

    def simulate(self, data: Any, path: str = "") -> list[Operation]:
        """Simulate what kubectl apply would do with this manifest."""
        operations = []

        if not isinstance(data, dict):
            return operations

        # Check for privileged container (K8s Kill pattern)
        if "securityContext" in data:
            sec_ctx = data["securityContext"]
            if isinstance(sec_ctx, dict) and sec_ctx.get("privileged") is True:
                operations.append(Operation(
                    type=OperationType.CODE_EXECUTION,
                    severity=Severity.CRITICAL,
                    path=f"{path}.securityContext.privileged" if path else "securityContext.privileged",
                    detail="K8s: privileged=true allows container escape to host"
                ))

        # Check for hostPath volume mounts
        if "volumes" in data:
            for i, vol in enumerate(data.get("volumes", [])):
                if isinstance(vol, dict) and "hostPath" in vol:
                    host_path = vol["hostPath"]
                    if isinstance(host_path, dict):
                        mount_path = host_path.get("path", "")
                        if mount_path == "/" or mount_path == "/etc" or mount_path == "/var":
                            operations.append(Operation(
                                type=OperationType.FILE_ACCESS,
                                severity=Severity.CRITICAL,
                                path=f"{path}.volumes[{i}].hostPath" if path else f"volumes[{i}].hostPath",
                                detail=f"K8s: hostPath={mount_path} mounts sensitive host filesystem"
                            ))

        # Check for hostPID
        if data.get("hostPID") is True:
            operations.append(Operation(
                type=OperationType.CODE_EXECUTION,
                severity=Severity.HIGH,
                path=f"{path}.hostPID" if path else "hostPID",
                detail="K8s: hostPID=true exposes host process namespace"
            ))

        # Check for hostNetwork
        if data.get("hostNetwork") is True:
            operations.append(Operation(
                type=OperationType.NETWORK_ACCESS,
                severity=Severity.HIGH,
                path=f"{path}.hostNetwork" if path else "hostNetwork",
                detail="K8s: hostNetwork=true uses host network stack"
            ))

        # Recurse into spec, containers, etc.
        for key in ["spec", "template", "containers", "initContainers"]:
            if key in data:
                value = data[key]
                new_path = f"{path}.{key}" if path else key
                if isinstance(value, dict):
                    operations.extend(self.simulate(value, new_path))
                elif isinstance(value, list):
                    for i, item in enumerate(value):
                        if isinstance(item, dict):
                            operations.extend(self.simulate(item, f"{new_path}[{i}]"))

        return operations


class CodeExecutionDetector:
    """
    Detects code execution patterns in configuration text.
    """

    PATTERNS = [
        (r'\beval\s*\(', OperationType.CODE_EXECUTION, Severity.CRITICAL,
         "eval() call would execute arbitrary code"),
        (r'\bexec\s*\(', OperationType.CODE_EXECUTION, Severity.CRITICAL,
         "exec() call would execute arbitrary code"),
        (r'\bcompile\s*\(', OperationType.CODE_EXECUTION, Severity.CRITICAL,
         "compile() call could enable code execution"),
        (r'__import__\s*\(', OperationType.MODULE_IMPORT, Severity.CRITICAL,
         "__import__() would import arbitrary modules"),
        (r'\bimportlib\.import_module\s*\(', OperationType.MODULE_IMPORT, Severity.CRITICAL,
         "importlib.import_module() would import arbitrary modules"),
        (r'\bos\.system\s*\(', OperationType.COMMAND_EXECUTION, Severity.CRITICAL,
         "os.system() would execute shell commands"),
        (r'\bos\.popen\s*\(', OperationType.COMMAND_EXECUTION, Severity.CRITICAL,
         "os.popen() would execute shell commands"),
        (r'\bsubprocess\.', OperationType.COMMAND_EXECUTION, Severity.CRITICAL,
         "subprocess module would execute external commands"),
        (r'\bPopen\s*\(', OperationType.COMMAND_EXECUTION, Severity.CRITICAL,
         "Popen() would execute external commands"),
        (r'\bos\.environ', OperationType.ENV_ACCESS, Severity.HIGH,
         "os.environ access would read environment variables"),
        (r'\bgetenv\s*\(', OperationType.ENV_ACCESS, Severity.HIGH,
         "getenv() would read environment variables"),
        # Base64 encoded command patterns
        (r'base64\.b64decode\s*\(', OperationType.CODE_EXECUTION, Severity.CRITICAL,
         "base64.b64decode() may decode malicious payload"),
        (r'base64\.decode', OperationType.CODE_EXECUTION, Severity.HIGH,
         "base64 decoding may contain obfuscated code"),
        # Socket/network patterns
        (r'\bsocket\.', OperationType.NETWORK_ACCESS, Severity.HIGH,
         "socket module may enable network exfiltration"),
        (r'\burllib\.', OperationType.NETWORK_ACCESS, Severity.MEDIUM,
         "urllib may enable network requests"),
        (r'\brequests\.', OperationType.NETWORK_ACCESS, Severity.MEDIUM,
         "requests library may enable network requests"),
        # File system patterns
        (r'\bopen\s*\([^)]*[\'"][wax]', OperationType.FILE_ACCESS, Severity.HIGH,
         "open() with write mode may modify files"),
        (r'\bshutil\.', OperationType.FILE_ACCESS, Severity.HIGH,
         "shutil may perform file system operations"),
    ]

    # Patterns that indicate embedded code in string fields
    # NOTE: These are detected in raw text without context, so use MEDIUM severity.
    # Safe LangChain components like RunnableLambda legitimately contain lambdas.
    # The LangChainSimulator handles context-aware detection at CRITICAL level.
    EMBEDDED_CODE_PATTERNS = [
        (r'import\s+\w+', OperationType.MODULE_IMPORT, Severity.MEDIUM,
         "Embedded import statement in string"),
        (r'from\s+\w+\s+import', OperationType.MODULE_IMPORT, Severity.MEDIUM,
         "Embedded from-import statement in string"),
        (r'def\s+\w+\s*\(', OperationType.CODE_EXECUTION, Severity.MEDIUM,
         "Embedded function definition in string"),
        (r'class\s+\w+\s*[\(:]', OperationType.CODE_EXECUTION, Severity.MEDIUM,
         "Embedded class definition in string"),
        (r'lambda\s+\w*:', OperationType.CODE_EXECUTION, Severity.MEDIUM,
         "Embedded lambda expression in string"),
    ]

    def detect(self, text: str) -> list[Operation]:
        """Detect code execution patterns in text."""
        operations = []

        for pattern, op_type, severity, description in self.PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                operations.append(Operation(
                    type=op_type,
                    severity=severity,
                    path="text",
                    detail=description
                ))

        # Check for embedded code patterns (in func fields, etc.)
        for pattern, op_type, severity, description in self.EMBEDDED_CODE_PATTERNS:
            if re.search(pattern, text):
                operations.append(Operation(
                    type=op_type,
                    severity=severity,
                    path="embedded_code",
                    detail=description
                ))

        return operations

    def detect_in_field(self, field_name: str, value: str) -> list[Operation]:
        """Detect code patterns in specific fields that commonly contain code."""
        operations = []

        # Fields that commonly contain embedded code
        CODE_FIELDS = ["func", "code", "script", "command", "callback", "handler"]

        if field_name.lower() in CODE_FIELDS and value:
            # Run full detection on the value
            field_ops = self.detect(value)
            for op in field_ops:
                op.path = f"field:{field_name}"
                op.severity = Severity.CRITICAL  # Escalate severity for code fields
            operations.extend(field_ops)

        return operations


class RuntimeSimulator:
    """
    Main simulator that combines all sub-simulators.

    Answers the question: "If a real application loaded this config
    using standard deserializers, what would happen?"

    Supports multiple config systems (generalized Insecure Output Handling):
    - LangChain: loads() deserialization
    - Kubernetes: kubectl apply manifests
    - PyYAML: unsafe_load() execution
    - Pickle: __reduce__ patterns
    """

    def __init__(self, timeout: int = 5):
        self.langchain_sim = LangChainSimulator()
        self.k8s_sim = KubernetesSimulator()
        self.yaml_sim = YAMLSimulator()
        self.pickle_sim = PickleSimulator()
        self.code_detector = CodeExecutionDetector()
        self.timeout = timeout

    def simulate(self, config: ExtractedConfig) -> SimulationResult:
        """
        Run simulation with timeout protection.

        Uses ThreadPoolExecutor to enforce timeout on simulation.
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(self._simulate_internal, config)
            try:
                return future.result(timeout=self.timeout)
            except concurrent.futures.TimeoutError:
                return SimulationResult(
                    operations=[Operation(
                        type=OperationType.TIMEOUT,
                        severity=Severity.HIGH,
                        path="simulation",
                        detail=f"Simulation timed out after {self.timeout}s - possible malicious input"
                    )],
                    compromised=True,
                    timeout=True
                )
            except Exception as e:
                return SimulationResult(
                    operations=[],
                    compromised=False,
                    timeout=False,
                    errors=[str(e)]
                )

    def _simulate_internal(self, config: ExtractedConfig) -> SimulationResult:
        """Core simulation logic."""
        result = SimulationResult()

        # Simulate based on parsed structure
        if config.parsed is not None:
            # LangChain serialization patterns
            try:
                lc_ops = self.langchain_sim.simulate(config.parsed)
                result.operations.extend(lc_ops)
            except Exception as e:
                result.errors.append(f"LangChain simulation error: {e}")

            # Kubernetes manifest patterns (K8s Kill style)
            try:
                k8s_ops = self.k8s_sim.simulate(config.parsed)
                result.operations.extend(k8s_ops)
            except Exception as e:
                result.errors.append(f"Kubernetes simulation error: {e}")

            # Pickle deserialization patterns
            try:
                pickle_ops = self.pickle_sim.simulate(config.parsed)
                result.operations.extend(pickle_ops)
            except Exception as e:
                result.errors.append(f"Pickle simulation error: {e}")

            # Check for code in specific fields (func, code, script, etc.)
            try:
                field_ops = self._scan_code_fields(config.parsed)
                result.operations.extend(field_ops)
            except Exception as e:
                result.errors.append(f"Field scanning error: {e}")

        # Always check raw text for YAML tags (even if parsed as JSON)
        try:
            yaml_ops = self.yaml_sim.simulate(config.text)
            result.operations.extend(yaml_ops)
        except Exception as e:
            result.errors.append(f"YAML simulation error: {e}")

        # Always check for code execution patterns
        try:
            code_ops = self.code_detector.detect(config.text)
            result.operations.extend(code_ops)
        except Exception as e:
            result.errors.append(f"Code detection error: {e}")

        # Determine if compromised (any CRITICAL severity operation)
        result.compromised = any(
            op.severity == Severity.CRITICAL
            for op in result.operations
        )

        return result

    def _is_safe_langchain_component(self, data: dict) -> bool:
        """Check if this dict represents a safe LangChain component that legitimately contains code."""
        if not isinstance(data, dict):
            return False
        # Check for LangChain serialization marker
        if data.get("lc") and data.get("type") == "constructor":
            id_path = data.get("id", [])
            if id_path and isinstance(id_path, list):
                # Get the class name (last element of id)
                class_name = str(id_path[-1]) if id_path else ""
                # Check if it's a known safe code-containing component
                if class_name in self.langchain_sim.SAFE_CODE_COMPONENTS:
                    return True
                # Also check if the module path starts with langchain
                first_module = str(id_path[0]) if id_path else ""
                if any(first_module.startswith(prefix) for prefix in self.langchain_sim.SAFE_MODULE_PREFIXES):
                    # It's a LangChain component - check if class suggests code handling
                    if any(safe in class_name for safe in ["Lambda", "Tool", "Transform", "Runnable"]):
                        return True
        return False

    def _scan_code_fields(self, data: Any, path: str = "", inside_safe_component: bool = False) -> list[Operation]:
        """Recursively scan for code in dangerous field names.

        Args:
            data: The data structure to scan
            path: Current path in the structure
            inside_safe_component: Whether we're inside a safe LangChain component that legitimately contains code
        """
        operations = []

        # Fields that commonly contain code
        CODE_FIELDS = {"func", "code", "script", "command", "callback", "handler", "exec", "run"}

        if isinstance(data, dict):
            # Check if this dict is a safe LangChain component
            is_safe = inside_safe_component or self._is_safe_langchain_component(data)

            for key, value in data.items():
                new_path = f"{path}.{key}" if path else key

                # Check if this field name suggests code content
                if key.lower() in CODE_FIELDS and isinstance(value, str):
                    # If we're inside a safe LangChain component, don't flag legitimate code fields
                    if is_safe and key.lower() in {"func", "callback", "handler"}:
                        # This is expected behavior for RunnableLambda, Tool, etc.
                        # Don't flag as dangerous
                        continue

                    field_ops = self.code_detector.detect(value)
                    for op in field_ops:
                        op.path = new_path
                        op.severity = Severity.CRITICAL  # Escalate
                    operations.extend(field_ops)

                    # Also flag the field itself as suspicious
                    if len(value) > 20:  # Non-trivial code
                        operations.append(Operation(
                            type=OperationType.CODE_EXECUTION,
                            severity=Severity.CRITICAL,
                            path=new_path,
                            detail=f"Code field '{key}' contains executable content ({len(value)} chars)"
                        ))

                # Recurse with updated context
                if isinstance(value, dict):
                    operations.extend(self._scan_code_fields(value, new_path, is_safe))
                elif isinstance(value, list):
                    for i, item in enumerate(value):
                        operations.extend(self._scan_code_fields(item, f"{new_path}[{i}]", is_safe))

        elif isinstance(data, list):
            for i, item in enumerate(data):
                operations.extend(self._scan_code_fields(item, f"{path}[{i}]", inside_safe_component))

        return operations

    def simulate_all(self, configs: list[ExtractedConfig]) -> SimulationResult:
        """Simulate all extracted configs and merge results."""
        combined = SimulationResult()

        for config in configs:
            result = self.simulate(config)
            combined.merge(result)

        return combined


def simulate_config(config: ExtractedConfig, timeout: int = 5) -> SimulationResult:
    """Convenience function to simulate a single config."""
    simulator = RuntimeSimulator(timeout=timeout)
    return simulator.simulate(config)


def simulate_configs(configs: list[ExtractedConfig], timeout: int = 5) -> SimulationResult:
    """Convenience function to simulate multiple configs."""
    simulator = RuntimeSimulator(timeout=timeout)
    return simulator.simulate_all(configs)
