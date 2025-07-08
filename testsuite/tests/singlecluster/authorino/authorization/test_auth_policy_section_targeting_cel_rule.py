"""
Tests that the AuthPolicy is correctly applied only to requests matching a specific path and only
on a specific Gateway listener section using the 'sectionName' field.

Thus:
- The policy does not apply globally to all listeners
- CEL predicates further restrict the policy scope (e.g. only for '/get' path)
"""

import pytest
from testsuite.kuadrant.policy.authorization.auth_policy import AuthPolicy
from testsuite.kuadrant.policy import CelPredicate

pytestmark = [pytest.mark.kuadrant_only, pytest.mark.authorino]


@pytest.fixture(scope="module")
def route(route, backend):
    """Override default route to have two backends with different paths"""
    route.remove_all_rules()
    route.add_backend(backend, "/get")       # This backend path will be protected
    route.add_backend(backend, "/anything")  # This backend path will be public
    return route

@pytest.fixture(scope="module")
def authorization(cluster, blame, module_label, gateway, oidc_provider, route):
    """Create AuthPolicy that applies only to the 'api' section of the Gateway. Auth is required only for requests with path '/get' """
    policy = AuthPolicy.create_instance(
        cluster,
        blame("authz"),
        gateway,
        section_name="api",  # bind to specific listener section
        labels={"testRun": module_label}
    )
    # Require OIDC authentication for selected requests
    policy.identity.add_oidc("basic", oidc_provider.well_known["issuer"])

    # Apply the policy only when the request path matches '/get'
    policy.add_rule([CelPredicate("request.path == '/get'")])

    return policy


def test_auth_policy_applies_only_to_protected_path(client, auth):
    """Test that AuthPolicy protects only the /get path"""

    # /anything - unprotected path should be accessible without authentication
    response = client.get("/anything")
    assert response.status_code == 200

    # /get should require authentication, without token expect 401
    response = client.get("/get")
    assert response.status_code == 401

    # /get - protected path with valid token should allow requests
    response = client.get("/get", auth=auth)
    assert response.status_code == 200
