"""Tests that the AuthPolicy is correctly applied to the chosen Gateway Listener"""

import pytest
from testsuite.kuadrant.policy.authorization.auth_policy import AuthPolicy

pytestmark = [pytest.mark.kuadrant_only, pytest.mark.authorino]


@pytest.fixture(scope="module")
def auth_policy(cluster, blame, module_label, gateway, oidc_provider):
    """Creates an AuthPolicy tht targets a specific Gateway Listener, policy is applied only to 'api' listener"""
    policy = AuthPolicy.create_instance(
        cluster,
        blame("authz"),
        gateway,
        section_name="api",  # targeting specific listener
        labels={"testRun": module_label}
    )
    # add OIDC identity provider to the policy so that it enforces authentication
    policy.add_oidc("basic", issuer=oidc_provider.well_known["issuer"])
    return policy


def test_auth_policy_applied_to_gateway_listener(client, auth):
    """Test that AuthPolicy works only when client is authenticated"""
    # this should return 401 because no token is provided
    assert client.get("/get").status_code == 401

    # with valid token, request should pass
    response = client.get("/get", auth=auth)
    assert response.status_code == 200
