"""
Collects Kubernetes resources created during a test run for debugging.

Enabled via pytest --collect-resources flag. Resources are matched by the
testrun label pattern (e.g. testrun-user--xyz) in their metadata name or labels,
and saved to debug-resources/ as YAML files stripped of cluster-managed noise.

## File Output:
- **Single-cluster tests**: Creates `{module_label}-{test_name}-resources.yaml`
- **Multicluster tests**: Creates separate files for each cluster:
  - `{module_label}-{test_name}-cluster1-resources.yaml`
  - `{module_label}-{test_name}-cluster2-resources.yaml`

Note: Collection runs per test function (not per module) because the collecting fixture
must tear down before module-scoped fixtures clean up the resources. To avoid duplicate
queries, each module is collected only once (on the first test) and subsequent tests skip.
For parametrized tests, the filename contains the first parameter's name, but the file
contains resources for all parameter combinations since they share module-scoped fixtures.
"""

import logging
import os

import yaml
from openshift_client import invoke

from testsuite.config import settings

logger = logging.getLogger(__name__)

# Resource types that inherit labels from parent resources and produce noise
EXCLUDED_TYPES = frozenset(
    {
        "events",
        "events.events.k8s.io",
        "endpoints",
        "endpointslices.discovery.k8s.io",
        "leases.coordination.k8s.io",
        "controllerrevisions.apps",
        "pods.metrics.k8s.io",
    }
)


_collected_modules: set[str] = set()


def _is_multicluster_test(item):
    """Detect if this is a multicluster test by checking if 'multicluster' appears in the test path."""
    if hasattr(item, "fspath") and "multicluster" in str(item.fspath):
        return True
    if hasattr(item, "nodeid") and "multicluster" in item.nodeid:
        return True
    return False


def collect_resources(item, module_label):
    """Collect test resources from one or more clusters based on test type and configuration."""
    if not item.config.getoption("--collect-resources"):
        return

    # Extract base pattern from module label for resource matching
    base_pattern = module_label
    if "--" in module_label:
        parts = module_label.split("--")
        if len(parts) >= 2:
            base_pattern = f"{parts[0]}--{parts[1].split('-')[0]}"

    if module_label in _collected_modules:
        return

    # Determine clusters to collect from
    clusters = [("cluster1", settings["control_plane"]["cluster"])]
    if _is_multicluster_test(item) and settings["control_plane"].get("cluster2"):
        clusters.append(("cluster2", settings["control_plane"]["cluster2"]))

    success = _save_resources_from_clusters(item, module_label, base_pattern, clusters)
    if success:
        _collected_modules.add(module_label)


def _discover_resource_types():
    """Discover all namespaced resource types available in the cluster."""
    result = invoke("api-resources", ["--namespaced=true", "--verbs=list", "-o", "name"])
    if result.status() != 0:
        return []
    return [t.strip() for t in result.out().strip().split("\n") if t.strip() and t.strip() not in EXCLUDED_TYPES]


def _save_resources_from_clusters(item, module_label, base_pattern, clusters):
    """Save resources from specified clusters. Returns True on success."""
    try:
        project = settings["service_protection"]["project"]
        os.makedirs("debug-resources", exist_ok=True)

        safe_name = (
            f"{module_label}-{item.name}".replace("[", "(").replace("]", ")").replace("/", "_").replace("\\", "_")
        )

        for cluster_name, cluster_client in clusters:
            try:
                with cluster_client.context:
                    resource_types = _discover_resource_types()
                    if not resource_types:
                        logger.warning("No resource types discovered for %s, skipping", cluster_name)
                        continue

                    # Choose filename: single cluster uses plain name, multicluster adds cluster suffix
                    if len(clusters) == 1:
                        output_file = f"debug-resources/{safe_name}-resources.yaml"
                    else:
                        output_file = f"debug-resources/{safe_name}-{cluster_name}-resources.yaml"

                    _save_matching_resources(
                        project=project,
                        base_pattern=base_pattern,
                        resource_types=resource_types,
                        output_file=output_file,
                    )
            except Exception:  # pylint: disable=broad-exception-caught
                logger.warning("Failed to collect resources from %s", cluster_name, exc_info=True)

        return True

    except Exception:  # pylint: disable=broad-exception-caught
        logger.warning("Resource collection failed", exc_info=True)
        return False


# Metadata fields managed by cluster that add noise to debugging output
METADATA_NOISE = {"resourceVersion", "uid", "creationTimestamp", "generation", "managedFields", "annotations"}


def _strip_resource(resource):
    """Keep only fields useful for debugging: apiVersion, kind, metadata (name+labels+namespace), spec, status."""
    stripped = {}
    for key in ("apiVersion", "kind"):
        if key in resource:
            stripped[key] = resource[key]

    metadata = resource.get("metadata", {})
    stripped["metadata"] = {k: v for k, v in metadata.items() if k not in METADATA_NOISE}

    for key in ("spec", "status"):
        if key in resource:
            stripped[key] = resource[key]

    return stripped


def _matches_metadata(resource, base_pattern):
    """Check if base_pattern appears in resource name or label values."""
    metadata = resource.get("metadata", {})
    name = metadata.get("name", "")
    if base_pattern in name:
        return True
    labels = metadata.get("labels", {})
    return any(base_pattern in str(v) for v in labels.values())


def _save_matching_resources(project, base_pattern, resource_types, output_file):
    """Fetch all resources and save those matching the base_pattern in metadata."""
    matching_resources = []

    result = invoke("get", [",".join(resource_types), "--ignore-not-found", "-n", project, "-o", "yaml"])

    if result.status() != 0:
        raise RuntimeError(f"Resource query failed: {result.err()}")

    if result.out().strip():
        try:
            data = yaml.safe_load(result.out())
        except yaml.YAMLError as e:
            raise RuntimeError(f"YAML parsing failed: {e}") from e
        items = data.get("items", [data]) if data else []
        for item in items:
            if _matches_metadata(item, base_pattern):
                matching_resources.append(_strip_resource(item))

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(f"# Resources from the testrun: {base_pattern}\n---\n")
        if matching_resources:
            f.write("\n---\n".join(yaml.dump(r, default_flow_style=False) for r in matching_resources))
        else:
            f.write("# No matching resources found\n")
