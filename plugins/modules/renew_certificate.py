from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: renew_certificate
short_description: Renew a certificate from Infisical Certificate Manager
version_added: "1.2.0"
author:
  - Infisical Inc.
description:
  - Renew an existing X.509 certificate from Infisical Certificate Manager.
  - The renewed certificate inherits all attributes (subject, SANs, key usages, etc.)
    from the original certificate and its Certificate Profile.
  - If the original certificate was issued with a managed key, a new key pair is generated
    and the private key is returned. If the original used a CSR, no private key is returned.
  - The original certificate remains valid until it expires or is explicitly revoked.
  - Requires the certificate to have been issued via a Certificate Profile with API enrollment enabled.
extends_documentation_fragment:
  - infisical.vault.auth

options:
  certificate_id:
    description:
      - The UUID of the certificate to renew.
      - This is the C(certificate_id) returned by the C(infisical.vault.issue_certificate) module.
    type: str
    required: true
  remove_roots_from_chain:
    description: Whether to remove root CA certificates from the returned chain.
    type: bool

seealso:
  - module: infisical.vault.issue_certificate
    description: Use the issue_certificate module to issue a new certificate.
  - module: infisical.vault.login
    description: Use the login module to authenticate once and reuse the session.
"""

EXAMPLES = r"""
# Renew a certificate
- name: Login to Infisical
  infisical.vault.login:
    url: "https://app.infisical.com"
    auth_method: universal_auth
    universal_auth_client_id: "{{ client_id }}"
    universal_auth_client_secret: "{{ client_secret }}"
  register: infisical_login

- name: Renew the TLS certificate
  infisical.vault.renew_certificate:
    login_data: "{{ infisical_login.login_data }}"
    certificate_id: "{{ existing_cert_id }}"
  register: renewed_cert
  no_log: true

- name: Write renewed certificate to file
  ansible.builtin.copy:
    content: "{{ renewed_cert.certificate }}"
    dest: /etc/ssl/certs/api.pem
    mode: '0644'

- name: Write renewed private key to file
  ansible.builtin.copy:
    content: "{{ renewed_cert.private_key }}"
    dest: /etc/ssl/private/api.key
    mode: '0600'
  no_log: true
  when: renewed_cert.private_key is defined

- name: Reload Nginx
  ansible.builtin.service:
    name: nginx
    state: reloaded

# Renew with root CAs stripped from chain
- name: Renew certificate without root CAs in chain
  infisical.vault.renew_certificate:
    login_data: "{{ infisical_login.login_data }}"
    certificate_id: "{{ existing_cert_id }}"
    remove_roots_from_chain: true
  register: renewed_cert
  no_log: true
"""

RETURN = r"""
certificate:
  description: The PEM-encoded renewed certificate body.
  returned: always
  type: str
issuing_ca_certificate:
  description: The PEM-encoded issuing CA certificate.
  returned: always
  type: str
certificate_chain:
  description: The PEM-encoded full certificate chain.
  returned: always
  type: str
private_key:
  description:
    - The PEM-encoded private key (only returned if the original certificate used managed-key issuance).
    - This value is sensitive. Use C(no_log=true) on the task to prevent it from appearing in Ansible logs.
  returned: when the original certificate was issued with a managed key (not CSR)
  type: str
serial_number:
  description: The serial number of the renewed certificate.
  returned: always
  type: str
certificate_id:
  description: The unique identifier of the renewed certificate in Infisical.
  returned: always
  type: str
certificate_request_id:
  description: The ID of the certificate request for the renewal.
  returned: always
  type: str
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.infisical.vault.plugins.module_utils._authenticator import (
    InfisicalAuthenticator,
    create_client_from_login_data,
)


def get_sdk_client(module, login_data=None):
    """Get an authenticated Infisical SDK client."""
    if login_data is not None:
        try:
            return create_client_from_login_data(login_data)
        except (ImportError, ValueError) as e:
            module.fail_json(msg=str(e))

    try:
        authenticator = InfisicalAuthenticator(
            url=module.params['url'],
            auth_method=module.params['auth_method'],
            client_id=module.params['universal_auth_client_id'],
            client_secret=module.params['universal_auth_client_secret'],
            identity_id=module.params['identity_id'],
            jwt=module.params['jwt'],
            token=module.params['token'],
            ldap_username=module.params['ldap_username'],
            ldap_password=module.params['ldap_password'],
        )
        return authenticator.authenticate()
    except (ImportError, ValueError) as e:
        module.fail_json(msg=str(e))


def run_module():
    module_args = dict(
        # Auth options (same pattern as all other modules)
        login_data=dict(type='dict', no_log=True),
        url=dict(type='str', default='https://app.infisical.com'),
        auth_method=dict(
            type='str',
            default='universal_auth',
            choices=['universal_auth', 'oidc_auth', 'token_auth', 'ldap_auth']
        ),
        universal_auth_client_id=dict(type='str'),
        universal_auth_client_secret=dict(type='str', no_log=True),
        identity_id=dict(type='str'),
        jwt=dict(type='str', no_log=True),
        token=dict(type='str', no_log=True),
        ldap_username=dict(type='str'),
        ldap_password=dict(type='str', no_log=True),
        # Renew options
        certificate_id=dict(type='str', required=True),
        remove_roots_from_chain=dict(type='bool'),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
    )

    if module.check_mode:
        module.exit_json(
            changed=True,
            certificate='<check_mode>',
            certificate_request_id='<check_mode>',
        )

    try:
        login_data = module.params.get('login_data')
        client = get_sdk_client(module, login_data=login_data)

        certificate_id = module.params['certificate_id']

        request_body = {}
        if module.params.get("remove_roots_from_chain") is not None:
            request_body["removeRootsFromChain"] = module.params["remove_roots_from_chain"]

        response = client.api.post(
            "/api/v1/cert-manager/certificates/%s/renew" % certificate_id,
            dict,
            json=request_body if request_body else None
        )

        data = response.data

        result = dict(
            changed=True,
            certificate=data.get("certificate", ""),
            issuing_ca_certificate=data.get("issuingCaCertificate", ""),
            certificate_chain=data.get("certificateChain", ""),
            serial_number=data.get("serialNumber", ""),
            certificate_id=data.get("certificateId", ""),
            certificate_request_id=data.get("certificateRequestId", ""),
        )

        private_key = data.get("privateKey")
        if private_key:
            result["private_key"] = private_key

        module.exit_json(**result)
    except Exception as e:
        module.fail_json(msg="Error renewing certificate: %s: %s" % (type(e).__name__, e))


def main():
    run_module()


if __name__ == '__main__':
    main()
