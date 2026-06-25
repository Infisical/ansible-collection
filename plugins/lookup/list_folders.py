from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase

from ansible_collections.infisical.vault.plugins.module_utils._authenticator import (
    InfisicalAuthenticator,
    create_client_from_login_data,
)


DOCUMENTATION = r"""
name: list_folders
author:
  - Infisical Inc.
version_added: "1.2.0"

short_description: List folders (directories) stored in Infisical
description:
  - Retrieve the list of folders at a given path within a project and environment.
  - Optionally walks the folder tree recursively.
  - You can either provide authentication credentials directly, or use C(login_data) from a previous C(infisical.vault.login) lookup to reuse an authenticated session.
extends_documentation_fragment:
  - infisical.vault.auth.lookup

seealso:
  - ref: infisical.vault.login lookup
    description: Use the login lookup to authenticate once and reuse the session.

options:
  path:
    description: "The folder path to list folders under. For example: /services"
    required: False
    type: string
    default: "/"
  env_slug:
    description: "The environment slug to list folders from. Environment slug is the short name of a given environment."
    required: True
    type: string
  project_id:
    description: "The ID of the project where folders are stored."
    required: True
    type: string
  recursive:
    description: Whether to list folders recursively under the given path.
    required: False
    type: bool
    default: False
"""

EXAMPLES = r"""
# List folders using a cached login
- name: Login to Infisical once
  set_fact:
    infisical_login: "{{ lookup('infisical.vault.login', url='https://app.infisical.com', auth_method='universal_auth', universal_auth_client_id='<client-id>', universal_auth_client_secret='<client-secret>') }}"

- name: List folders at /
  set_fact:
    folders: "{{ lookup('infisical.vault.list_folders', login_data=infisical_login, project_id='<project-id>', env_slug='dev', path='/') }}"

- name: List folders recursively under /services
  set_fact:
    nested: "{{ lookup('infisical.vault.list_folders', login_data=infisical_login, project_id='<project-id>', env_slug='prod', path='/services', recursive=true) }}"
"""

RETURN = r"""
_list:
  description: A list of folder objects at the requested path.
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier of the folder.
      type: str
    name:
      description: The name of the folder.
      type: str
    envId:
      description: The ID of the environment the folder belongs to.
      type: str
    parentId:
      description: The ID of the parent folder.
      type: str
    version:
      description: The version number of the folder.
      type: int
    description:
      description: The folder description.
      type: str
    isReserved:
      description: Whether the folder is reserved by Infisical.
      type: bool
    relativePath:
      description: The relative path to the folder (when recursive listing).
      type: str
    createdAt:
      description: The creation timestamp.
      type: str
    updatedAt:
      description: The last update timestamp.
      type: str
    lastSecretModified:
      description: Timestamp when a secret in this folder was last modified.
      type: str
"""


class LookupModule(LookupBase):

    def _get_sdk_client(self, login_data=None):
        if login_data is not None:
            try:
                return create_client_from_login_data(login_data)
            except (ImportError, ValueError) as e:
                raise AnsibleError(f"Configuration error creating client from login_data: {e}")
            except Exception as e:
                raise AnsibleError(f"Failed to create client from login_data: {type(e).__name__}: {e}")

        authenticator = InfisicalAuthenticator(
            url=self.get_option('url'),
            auth_method=self.get_option('auth_method'),
            client_id=self.get_option('universal_auth_client_id'),
            client_secret=self.get_option('universal_auth_client_secret'),
            identity_id=self.get_option('identity_id'),
            jwt=self.get_option('jwt'),
            token=self.get_option('token'),
            ldap_username=self.get_option('ldap_username'),
            ldap_password=self.get_option('ldap_password'),
        )

        try:
            return authenticator.authenticate()
        except (ImportError, ValueError) as e:
            raise AnsibleError(f"Configuration error during Infisical authentication: {e}")
        except Exception as e:
            raise AnsibleError(f"Failed to authenticate with Infisical: {type(e).__name__}: {e}")

    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)

        login_data = kwargs.get('login_data')
        client = self._get_sdk_client(login_data=login_data)

        project_id = kwargs.get('project_id')
        env_slug = kwargs.get('env_slug')
        path = kwargs.get('path', '/')
        recursive = kwargs.get('recursive', False)

        try:
            response = client.folders.list_folders(
                project_id=project_id,
                environment_slug=env_slug,
                path=path,
                recursive=recursive,
            )
            return [f.to_dict() for f in response.folders]
        except Exception as e:
            raise AnsibleError(f"Error listing folders: {type(e).__name__}: {e}")
