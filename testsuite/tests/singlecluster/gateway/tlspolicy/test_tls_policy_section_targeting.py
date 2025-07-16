"""TODO"""

import pytest
from testsuite.kuadrant.policy.tls import TLSPolicy
from testsuite.gateway.gateway_api.gateway import KuadrantGateway
from testsuite.gateway import TLSGatewayListener, CustomReference
from testsuite.gateway.exposers import StaticLocalHostname


pytestmark = [pytest.mark.kuadrant_only, pytest.mark.tlspolicy]


@pytest.fixture(scope="module")
def authorization():
    """Overridden unused policy fixtures – stops creating Auth/RateLimit/DNS policy"""
    return None


@pytest.fixture(scope="module")
def rate_limit():
    """Overridden unused policy fixtures – stops creating Auth/RateLimit/DNS policy"""
    return None


@pytest.fixture(scope="module")
def dns_policy():
    """Overridden unused policy fixtures – stops creating Auth/RateLimit/DNS policy"""
    return None


@pytest.fixture(scope="module")
def gateway(request, cluster, blame, base_domain, module_label):
    """Gateway with two TLS listeners: 'api' and 'extra' (fixed hostnames)"""
    gateway_name = blame("gw")
    gw = KuadrantGateway.create_instance(cluster, gateway_name, labels={"testRun": module_label})

    # Listener 'api' – targeted by TLSPolicy
    api_hostname = f"api-listener.{base_domain}"
    gw.add_listener(TLSGatewayListener(name="api", hostname=api_hostname, gateway_name=gateway_name))

    # Listener 'extra' – without TLS certificate
    extra_hostname = f"extra-listener.{base_domain}"
    gw.add_listener(TLSGatewayListener(name="extra", hostname=extra_hostname, gateway_name=gateway_name))

    request.addfinalizer(gw.delete)
    gw.commit()
    gw.wait_for_ready()
    return gw


@pytest.fixture(scope="module")
def api_hostname(base_domain):
    """Api Hostname"""
    return f"api-listener.{base_domain}"


@pytest.fixture(scope="module")
def extra_hostname(base_domain):
    """Extra Hostname"""
    return f"extra-listener.{base_domain}"


@pytest.fixture(scope="module")
def tls_policy(cluster, blame, module_label, gateway, cluster_issuer):
    """Create TLSPolicy, that targets only 'api' listener - sectionName"""
    parent_ref = CustomReference(
        group="gateway.networking.k8s.io",
        kind="Gateway",
        name=gateway.name(),
        sectionName="api",
    )

    return TLSPolicy.create_instance(
        cluster=cluster,
        name=blame("tls-section"),
        parent=parent_ref,
        issuer=cluster_issuer,
        labels={"testRun": module_label},
    )


@pytest.fixture(scope="module")
def custom_client():
    """
    Create TLS clients based on IP address
    """

    def _client(hostname: str, gateway: KuadrantGateway):
        return StaticLocalHostname(
            hostname=hostname, ip_getter=gateway.external_ip, verify=gateway.get_tls_cert(hostname)
        ).client()

    return _client


def test_tls_policy_section_applies_only_to_targeted_listener(
    tls_policy, gateway, api_hostname, extra_hostname, custom_client
):
    """
    TLSPolicy with sectionName should only be applied to listener 'api'.
    Listener 'extra' should not have a TLS certificate - connection should fail.
    """
    tls_policy.wait_for_ready()

    api_client = custom_client(api_hostname, gateway)
    response = api_client.get("/get")
    assert response.status_code == 200
    assert not response.has_cert_verify_error()

    extra_client = custom_client(extra_hostname, gateway)
    response = extra_client.get("/get")
    assert response.has_tls_error()
