from __future__ import annotations

import math
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from selectors import EVENT_READ, DefaultSelector
from typing import Mapping, Protocol

from .artifacts import ArtifactRecord


def _default_container_user() -> str:
    if not hasattr(os, "geteuid") or not hasattr(os, "getegid"):
        return "65532:65532"
    return f"{os.geteuid()}:{os.getegid()}"


@dataclass(frozen=True, slots=True)
class SandboxLimits:
    timeout_seconds: float = 120.0
    memory_limit: str = "512m"
    cpu_limit: float = 1.0
    pids_limit: int = 64
    tmpfs_limit: str = "64m"
    max_output_bytes: int = 256_000
    max_artifact_bytes: int = 50_000_000
    user: str = field(default_factory=_default_container_user)

    def __post_init__(self) -> None:
        if (
            not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
            or self.timeout_seconds > 3600
        ):
            raise ValueError("sandbox timeout must be finite and between 0 and 3600 seconds")
        if not re.fullmatch(r"[1-9][0-9]*[kKmMgG]", self.memory_limit):
            raise ValueError("memory_limit must use a positive k/m/g unit")
        if not math.isfinite(self.cpu_limit) or self.cpu_limit <= 0 or self.cpu_limit > 64:
            raise ValueError("cpu_limit must be finite and in the interval (0, 64]")
        if self.pids_limit < 1 or self.pids_limit > 4096:
            raise ValueError("pids_limit must be between 1 and 4096")
        if not re.fullmatch(r"[1-9][0-9]*[kKmMgG]", self.tmpfs_limit):
            raise ValueError("tmpfs_limit must use a positive k/m/g unit")
        if self.max_output_bytes < 1024 or self.max_output_bytes > 10_000_000:
            raise ValueError("max_output_bytes must be between 1024 and 10000000")
        if self.max_artifact_bytes < 1 or self.max_artifact_bytes > 500_000_000:
            raise ValueError("max_artifact_bytes must be between 1 and 500000000")
        if not re.fullmatch(r"[0-9]{1,10}:[0-9]{1,10}", self.user):
            raise ValueError("sandbox user must be an explicit numeric uid:gid")


@dataclass(frozen=True, slots=True)
class SandboxCheck:
    name: str
    command: tuple[str, ...]
    env: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,80}", self.name):
            raise ValueError("sandbox check name is invalid")
        if (
            not isinstance(self.command, tuple)
            or not self.command
            or len(self.command) > 32
            or any(
                not isinstance(part, str)
                or not part
                or "\x00" in part
                or len(part) > 2_048
                for part in self.command
            )
        ):
            raise ValueError("sandbox command must be a bounded non-empty argument vector")
        allowed_env = {"LANG", "LC_ALL", "TZ", "PYTHONHASHSEED"}
        if set(self.env) - allowed_env:
            raise ValueError("sandbox check contains a non-allowlisted environment variable")
        if any(
            not isinstance(value, str)
            or "\x00" in key
            or "\x00" in value
            or len(value) > 128
            for key, value in self.env.items()
        ):
            raise ValueError("sandbox environment contains an invalid or oversized value")


@dataclass(frozen=True, slots=True)
class SandboxExecution:
    check_name: str
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    duration_seconds: float
    output_truncated: bool = False

    @property
    def passed(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


class SandboxRunner(Protocol):
    def run(
        self, artifact: ArtifactRecord, check: SandboxCheck
    ) -> SandboxExecution: ...


class ContainerSandboxRunner:
    """Runs trusted validation commands inside a locked-down Docker/Podman container.

    Requires a rootless container engine where possible. The image must already exist
    locally and be pinned by digest. Candidate bytes are mounted read-only; the
    container has no network, no extra capabilities, a read-only root filesystem,
    bounded memory/CPU/PIDs/time/output, an unprivileged numeric user and a noexec tmpfs.
    The host container-engine daemon remains a trusted boundary.
    """

    def __init__(
        self,
        *,
        image: str,
        engine: str = "podman",
        limits: SandboxLimits | None = None,
        executable_path: str | None = None,
    ) -> None:
        if not (
            re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9./:_-]*@sha256:[0-9a-f]{64}", image
            )
            or re.fullmatch(r"sha256:[0-9a-f]{64}", image)
        ):
            raise ValueError("sandbox image must be pinned by immutable sha256 digest or local image ID")
        if engine not in {"podman", "docker"}:
            raise ValueError("container engine must be podman or docker")
        self.image = image
        self.engine = engine
        self.limits = limits or SandboxLimits()
        self.executable_path = executable_path

    def build_command(self, artifact_dir: Path, check: SandboxCheck) -> list[str]:
        executable = self.executable_path or shutil.which(self.engine)
        if not executable:
            raise FileNotFoundError(f"container engine not found: {self.engine}")
        args = [
            executable,
            "run",
            "--rm",
            "--pull=never",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--ulimit=core=0",
            "--pids-limit",
            str(self.limits.pids_limit),
            "--memory",
            self.limits.memory_limit,
            "--cpus",
            str(self.limits.cpu_limit),
            "--user",
            self.limits.user,
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,nodev,size={self.limits.tmpfs_limit}",
            "--workdir",
            "/tmp",
            "--mount",
            f"type=bind,src={artifact_dir},dst=/candidate,readonly",
        ]
        if self.engine == "podman":
            args.append("--userns=keep-id")
        for key, value in sorted(check.env.items()):
            args.extend(["--env", f"{key}={value}"])
        args.append(self.image)
        args.extend(check.command)
        args.append("/candidate/artifact.bin")
        return args

    @staticmethod
    def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def run(
        self, artifact: ArtifactRecord, check: SandboxCheck
    ) -> SandboxExecution:
        if os.name != "posix":
            raise RuntimeError("ContainerSandboxRunner currently requires a POSIX host")
        if os.geteuid() == 0:
            raise RuntimeError("run the sandbox orchestrator as an unprivileged host user")
        expected_user = f"{os.geteuid()}:{os.getegid()}"
        if self.limits.user != expected_user:
            raise RuntimeError(
                "sandbox user must match the unprivileged host uid:gid for the private read-only artifact mount"
            )
        if not artifact.verify():
            raise RuntimeError("refusing to sandbox an artifact with an invalid digest")
        if artifact.size_bytes > self.limits.max_artifact_bytes:
            raise ValueError("candidate artifact exceeds the configured size limit")

        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="psyche-sandbox-") as directory:
            artifact_dir = Path(directory)
            artifact_dir.chmod(0o700)
            candidate_path = artifact_dir / "artifact.bin"
            candidate_path.write_bytes(artifact.content)
            candidate_path.chmod(0o400)
            args = self.build_command(artifact_dir, check)
            process = subprocess.Popen(
                args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                start_new_session=True,
            )
            assert process.stdout is not None
            assert process.stderr is not None
            selector = DefaultSelector()
            selector.register(process.stdout, EVENT_READ, "stdout")
            selector.register(process.stderr, EVENT_READ, "stderr")
            output = {"stdout": bytearray(), "stderr": bytearray()}
            truncated = {"stdout": False, "stderr": False}
            deadline = started + self.limits.timeout_seconds
            timed_out = False

            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    self._kill_process_group(process)
                events = selector.select(timeout=max(0.0, min(0.1, remaining)))
                for key, _ in events:
                    chunk = os.read(key.fd, 65_536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    target = output[key.data]
                    available = self.limits.max_output_bytes - len(target)
                    if available > 0:
                        target.extend(chunk[:available])
                    if len(chunk) > max(0, available):
                        truncated[key.data] = True

            selector.close()
            try:
                return_code = process.wait(
                    timeout=max(0.0, deadline - time.monotonic())
                )
            except subprocess.TimeoutExpired:
                timed_out = True
                self._kill_process_group(process)
                return_code = process.wait()
            duration = time.monotonic() - started
            return SandboxExecution(
                check_name=check.name,
                exit_code=return_code,
                stdout=bytes(output["stdout"]).decode("utf-8", errors="replace"),
                stderr=bytes(output["stderr"]).decode("utf-8", errors="replace"),
                timed_out=timed_out,
                duration_seconds=duration,
                output_truncated=truncated["stdout"] or truncated["stderr"],
            )
