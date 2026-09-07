#!/usr/bin/env python3
"""Build exact allowlisted Content Hub Lambda artifacts for SAM."""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
from collections.abc import Sequence

REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE_ALLOWLIST = {
    "ServiceBindingRegistryV2MutationFunction": (
        "service_binding_registry_operator_lambda.py",
        "service_binding_registry_v2.py",
    ),
    "ThnContentHubV2AuthoringFunction": (
        "lambda_function.py",
        "content_hub_v2_authoring_handler.py",
        "content_hub_v2_authorization.py",
        "content_hub_v2_registry_fence.py",
        "service_binding_registry_consumer_v2.py",
        "service_binding_registry_operator_lambda.py",
        "service_binding_registry_v2.py",
    ),
    "ThnContentHubV2PrivateAssetCollectorFunction": (
        "content_hub_v2_private_asset_gc.py",
    ),
    "ThnContentHubV2PublisherFunction": ("publisher_lambda.py",),
    "ThnContentHubV2PublicMediaFunction": ("public_media_lambda.py",),
    "ThnContentHubV2InvalidationWorkerFunction": ("invalidation_worker_lambda.py",),
    "ThnContentHubV2EmergencyWithdrawFunction": (
        "emergency_withdraw_lambda.py",
        "content_hub_v2_projection_manifest.py",
        "service_binding_registry_consumer_v2.py",
        "service_binding_registry_operator_lambda.py",
        "service_binding_registry_v2.py",
    ),
    "ThnContentHubV2PreparedOrphanCollectorFunction": (
        "prepared_orphan_collector_lambda.py",
    ),
    "ContentHubFunction": ("lambda_function.py",),
}
RUNTIME_REQUIREMENTS = {
    "ServiceBindingRegistryV2MutationFunction": "requirements.txt",
    "ThnContentHubV2AuthoringFunction": "requirements.txt",
    "ThnContentHubV2PublicMediaFunction": "requirements.txt",
    "ThnContentHubV2EmergencyWithdrawFunction": "requirements.txt",
    "ContentHubFunction": "requirements.txt",
}


class ArtifactBuildError(RuntimeError):
    """The requested artifact cannot be assembled from its exact allowlist."""


def build_artifact(
    target: str,
    artifacts_dir: pathlib.Path | str,
    *,
    install_dependencies: bool = True,
) -> None:
    sources = SOURCE_ALLOWLIST.get(target)
    if sources is None:
        raise ArtifactBuildError("unknown Lambda artifact target")
    destination = pathlib.Path(artifacts_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise ArtifactBuildError("Lambda artifact destination must be empty")

    for relative_name in sources:
        source = REPOSITORY_ROOT / relative_name
        if not source.is_file():
            raise ArtifactBuildError("allowlisted Lambda source is missing")
        copied_target = destination / relative_name
        copied_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, copied_target)

    if not install_dependencies:
        return
    requirements_name = RUNTIME_REQUIREMENTS.get(target)
    if requirements_name is None:
        return
    requirements = REPOSITORY_ROOT / requirements_name
    if not requirements.is_file():
        raise ArtifactBuildError("runtime requirements are missing")
    try:
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-compile",
                "--requirement",
                str(requirements),
                "--target",
                str(destination),
            ],
            cwd=REPOSITORY_ROOT,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise ArtifactBuildError(
            "Lambda dependencies could not be installed"
        ) from error


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 2:
        print("usage: build_lambda_artifact.py TARGET ARTIFACTS_DIR", file=sys.stderr)
        return 2
    try:
        build_artifact(arguments[0], arguments[1])
        return 0
    except ArtifactBuildError as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
