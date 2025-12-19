from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase

from ansible_collections.infisical.vault.plugins.module_utils._authenticator import (
    InfisicalAuthenticator,
)


DOCUMENTATION = r"""
name: read_secrets
author:
  - Infisical Inc.

short_description: Look up secrets stored in Infisical
description:
  - Retrieve secrets from Infisical, granted the caller has the right permissions to access the secret.
  - Secrets can be located either by their name for individual secret loopups or by environment/folder path to return all secrets within the given scope.
  - You can either provide authentication credentials directly, or use C(client) from a previous C(infisical.vault.login) lookup to reuse an authenticated session.

seealso:
  - ref: infisical.vault.login lookup
    description: Use the login lookup to authenticate once and reuse the session.

options:

  client:
    description:
      - An authenticated Infisical SDK client from a previous C(infisical.vault.login) lookup.
      - When provided, this client will be reused, avoiding re-authentication.
      - This is mutually exclusive with direct authentication options (auth_method, universal_auth_client_id, etc.).
    required: False
    type: object
    version_added: 1.2.0
  auth_method:
    description: The method to use to authenticate with Infisical
    required: False
    type: string
    version_added: 1.1.3
    default: universal_auth
    choices:
      - universal_auth
      - oidc_auth
      - token_auth
    env:
      - name: INFISICAL_AUTH_METHOD
  universal_auth_client_id:
    description: The Machine Identity Client ID used to authenticate
    env:
      - name: UNIVERSAL_AUTH_MACHINE_IDENTITY_CLIENT_ID
      - name: INFISICAL_UNIVERSAL_AUTH_CLIENT_ID
    required: False
    type: string
    version_added: 1.0.0
  universal_auth_client_secret:
    description: The Machine Identity Client Secret used to authenticate
    env:
      - name: UNIVERSAL_AUTH_MACHINE_IDENTITY_CLIENT_SECRET
      - name: INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET
    required: False
    type: string
    version_added: 1.0.0
  url:
    description: Point to your self hosted instance of Infisical
    default: "https://app.infisical.com"
    env:
      - name: INFISICAL_URL
    required: False
    type: string
    version_added: 1.0.0
  path:
    description: "The folder path where the requested secret resides. For example: /services/backend"
    required: True
    type: string
    version_added: 1.0.0
  env_slug:
    description: "Used to select from which environment (environment slug) secrets should be fetched from. Environment slug is the short name of a given environment"
    required: True
    type: string
    version_added: 1.0.0
  project_id:
    description: "The ID of the project where the secrets are stored"
    required: True
    type: string
    version_added: 1.0.0
  secret_name:
    description: The name of the secret that should be fetched. The name should be exactly as it appears in Infisical.
    required: False
    type: string
    version_added: 1.0.0
  as_dict:
    description: "Return the listed secrets as a dictionary within a list instead of a list of key-value pairs (defaults to False). When True, returns [{'SECRET_KEY': 'secret_value', ...}] instead of [{'key': 'SECRET_KEY', 'value': 'secret_value'}, ...]. This only applies when reading all secrets within a scope, not when reading a single secret by name."
    required: False
    type: bool
    version_added: 1.0.0
  identity_id:
    description: The identity ID of the user that should be authenticated
    env:
      - name: INFISICAL_MACHINE_IDENTITY_ID
    required: False
    type: string
    version_added: 1.1.3
  jwt:
    description: The JWT of the user that should be authenticated
    required: False
    type: string
    version_added: 1.1.3
    env:
      - name: INFISICAL_JWT
      - name: INFISICAL_OIDC_AUTH_JWT
  token:
    description: >
      An access token used to authenticate with Infisical. This can be either a Machine Identity Token Auth token
      or a User JWT token. Both token types can be used interchangeably with this field.
    required: False
    type: string
    version_added: 1.1.4
    env:
      - name: INFISICAL_TOKEN
"""

EXAMPLES = r"""
# Direct authentication (authenticates on each call)
vars:
  read_all_secrets_within_scope: "{{ lookup('infisical.vault.read_secrets', universal_auth_client_id='<client-id>', universal_auth_client_secret='<client-secret>', project_id='<project-id>', path='/', env_slug='dev', url='https://app.infisical.com') }}"
  # [{ "key": "HOST", "value": "google.com" }, { "key": "SMTP", "value": "gmail.smtp.edu" }]

  read_all_secrets_as_dict: "{{ lookup('infisical.vault.read_secrets', universal_auth_client_id='<client-id>', universal_auth_client_secret='<client-secret>', project_id='<project-id>', path='/', env_slug='dev', as_dict=True, url='https://app.infisical.com') }}"
  # {"HOST": "google.com", "SMTP": "gmail.smtp.edu"}

  read_secret_by_name_within_scope: "{{ lookup('infisical.vault.read_secrets', universal_auth_client_id='<client-id>', universal_auth_client_secret='<client-secret>', project_id='<project-id>', path='/', env_slug='dev', secret_name='HOST', url='https://app.infisical.com') }}"
  # [{ "key": "HOST", "value": "google.com" }]

# Using client from infisical.vault.login (recommended for multiple lookups)
# This avoids re-authenticating on each call
- name: Login to Infisical once
  set_fact:
    infisical_client: "{{ lookup('infisical.vault.login', url='https://app.infisical.com', auth_method='universal_auth', universal_auth_client_id='<client-id>', universal_auth_client_secret='<client-secret>') }}"

- name: Read database secrets using cached client
  set_fact:
    db_secrets: "{{ lookup('infisical.vault.read_secrets', client=infisical_client, project_id='<project-id>', path='/database', env_slug='prod') }}"

- name: Read API secrets using the same client (no re-authentication)
  set_fact:
    api_secrets: "{{ lookup('infisical.vault.read_secrets', client=infisical_client, project_id='<project-id>', path='/api', env_slug='prod') }}"

- name: Read a specific secret using cached client
  set_fact:
    api_key: "{{ lookup('infisical.vault.read_secrets', client=infisical_client, project_id='<project-id>', path='/api', env_slug='prod', secret_name='API_KEY') }}"
"""


class LookupModule(LookupBase):

    def _get_sdk_client(self, client=None):
        """Get an authenticated Infisical SDK client.
        
        Args:
            client: Optional authenticated client from infisical.vault.login lookup.
        
        Returns:
            An authenticated InfisicalSDKClient instance
        """
        if client is not None:
            return client
        
        authenticator = InfisicalAuthenticator(
            url=self.get_option('url'),
            auth_method=self.get_option('auth_method'),
            client_id=self.get_option('universal_auth_client_id'),
            client_secret=self.get_option('universal_auth_client_secret'),
            identity_id=self.get_option('identity_id'),
            jwt=self.get_option('jwt'),
            token=self.get_option('token'),
        )
        
        try:
            return authenticator.authenticate()
        except (ImportError, ValueError) as e:
            raise AnsibleError(str(e))

    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)

        client = self._get_sdk_client(client=kwargs.get('client'))

        secret_name = kwargs.get('secret_name')
        as_dict = kwargs.get('as_dict')
        env_slug = kwargs.get('env_slug')
        path = kwargs.get('path')
        project_id = kwargs.get('project_id')

        if secret_name:
            return self._get_single_secret(client, project_id, secret_name, env_slug, path)
        else:
            return self._get_all_secrets(client, project_id, env_slug, path, as_dict)

    def _get_single_secret(self, client, project_id, secret_name, environment, path):
        """Fetch a single secret by name."""
        try:
            secret = client.secrets.get_secret_by_name(
                secret_name=secret_name,
                project_id=project_id,
                environment_slug=environment,
                secret_path=path
            )
            return [{"value": secret.secretValue, "key": secret.secretKey}]
        except Exception as e:
            raise AnsibleError(f"Error fetching secret '{secret_name}': {e}")

    def _get_all_secrets(self, client, project_id, environment="dev", path="/", as_dict=False):
        """Fetch all secrets within the specified scope."""
        try:
            secrets = client.secrets.list_secrets(
                project_id=project_id,
                environment_slug=environment,
                secret_path=path
            )

            if as_dict:
                return [{s.secretKey: s.secretValue for s in secrets.secrets}]
            else:
                return [{"value": s.secretValue, "key": s.secretKey} for s in secrets.secrets]
        except Exception as e:
            raise AnsibleError(f"Error fetching secrets: {e}")
