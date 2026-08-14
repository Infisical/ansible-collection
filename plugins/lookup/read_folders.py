from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase

from ansible_collections.infisical.vault.plugins.module_utils._authenticator import (
    InfisicalAuthenticator,
    create_client_from_login_data,
)


DOCUMENTATION = r"""
name: read_folders
author:
  - Infisical Inc.

short_description: Look up secret folders stored in Infisical
description:
  - Retrieve secret folders from Infisical, granted the caller has the right permissions to access them.
  - Folders can be located either by environment and parent path to list everything within that scope, or by their ID for a single folder.
  - You can either provide authentication credentials directly, or use C(login_data) from a previous C(infisical.vault.login) lookup to reuse an authenticated session.
extends_documentation_fragment:
  - infisical.vault.auth.lookup

seealso:
  - ref: infisical.vault.login lookup
    description: Use the login lookup to authenticate once and reuse the session.

options:
  path:
    description:
      - "The parent folder path to list folders from. For example: /services"
      - Required unless C(folder_id) is given.
    required: False
    type: string
    version_added: 1.2.0
  env_slug:
    description: "Used to select from which environment (environment slug) folders should be fetched from. Environment slug is the short name of a given environment. Required unless C(folder_id) is given."
    required: False
    type: string
    version_added: 1.2.0
  project_id:
    description: "The ID of the project where the folders are stored. Required unless C(folder_id) is given."
    required: False
    type: string
    version_added: 1.2.0
  folder_id:
    description: The ID of a single folder that should be fetched. When given, C(project_id), C(env_slug), and C(path) are not used.
    required: False
    type: string
    version_added: 1.2.0
  recursive:
    description: List folders recursively below C(path) instead of only its direct children. Only applies when listing by C(path).
    required: False
    type: bool
    default: False
    version_added: 1.2.0
"""

EXAMPLES = r"""
# Direct authentication (authenticates on each call)
vars:
  root_folders: "{{ lookup('infisical.vault.read_folders', universal_auth_client_id='<client-id>', universal_auth_client_secret='<client-secret>', project_id='<project-id>', path='/', env_slug='dev', url='https://app.infisical.com') }}"
  # [{ "id": "...", "name": "services", "relativePath": "/services", ... }]

# Using login_data from infisical.vault.login (recommended for multiple lookups)
# This avoids re-authenticating on each call
- name: Login to Infisical once
  set_fact:
    infisical_login: "{{ lookup('infisical.vault.login', url='https://app.infisical.com', auth_method='universal_auth', universal_auth_client_id='<client-id>', universal_auth_client_secret='<client-secret>') }}"

- name: List the folders under /services
  set_fact:
    service_folders: "{{ lookup('infisical.vault.read_folders', login_data=infisical_login, project_id='<project-id>', path='/services', env_slug='prod') }}"

- name: List every folder below the project root
  set_fact:
    all_folders: "{{ lookup('infisical.vault.read_folders', login_data=infisical_login, project_id='<project-id>', path='/', env_slug='prod', recursive=True) }}"

- name: Collect just the folder names
  set_fact:
    folder_names: "{{ lookup('infisical.vault.read_folders', login_data=infisical_login, project_id='<project-id>', path='/', env_slug='prod') | map(attribute='name') | list }}"

- name: Fetch a single folder by ID
  set_fact:
    one_folder: "{{ lookup('infisical.vault.read_folders', login_data=infisical_login, folder_id='a1b2c3d4-e5f6-7890-abcd-ef1234567890') }}"
"""

RETURN = r"""
_list:
  description:
    - A list of folder objects.
    - When C(folder_id) is given, the list contains exactly one folder.
  type: list
  elements: dict
  contains:
    id:
      description: The unique identifier of the folder.
      type: str
    name:
      description: The name of the folder.
      type: str
    relativePath:
      description: The path of the folder relative to the requested path (when listing by C(path)).
      type: str
    path:
      description: The full path of the folder (when fetching by C(folder_id)).
      type: str
    projectId:
      description: The ID of the project the folder belongs to (when fetching by C(folder_id)).
      type: str
    environment:
      description: The environment the folder belongs to (when fetching by C(folder_id)).
      type: dict
    description:
      description: The description of the folder.
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
    isReserved:
      description: Whether the folder is reserved by Infisical.
      type: bool
    lastSecretModified:
      description: Timestamp of the last secret modification within the folder.
      type: str
    createdAt:
      description: The creation timestamp.
      type: str
    updatedAt:
      description: The last update timestamp.
      type: str
"""


class LookupModule(LookupBase):

    def _get_sdk_client(self, login_data=None):
        """Get an authenticated Infisical SDK client.

        Args:
            login_data: Optional login data dict from infisical.vault.login lookup.
                       Contains url and access_token for authentication.

        Returns:
            An authenticated InfisicalSDKClient instance
        """
        # If login_data is provided, create a client using the saved token
        if login_data is not None:
            try:
                return create_client_from_login_data(login_data)
            except (ImportError, ValueError) as e:
                raise AnsibleError(f"Configuration error creating client from login_data: {e}")
            except Exception as e:
                raise AnsibleError(f"Failed to create client from login_data: {type(e).__name__}: {e}")

        # Otherwise, authenticate fresh
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

        # Get login_data if provided
        login_data = kwargs.get('login_data')

        folder_id = kwargs.get('folder_id')
        env_slug = kwargs.get('env_slug')
        path = kwargs.get('path')
        project_id = kwargs.get('project_id')
        recursive = kwargs.get('recursive', False)

        if not folder_id:
            missing = [
                name for name, value in (
                    ('project_id', project_id),
                    ('env_slug', env_slug),
                    ('path', path),
                ) if not value
            ]
            if missing:
                raise AnsibleError(
                    "Configuration error: read_folders requires either 'folder_id' or "
                    f"'project_id', 'env_slug' and 'path'. Missing: {', '.join(missing)}"
                )

        client = self._get_sdk_client(login_data=login_data)

        if folder_id:
            return self._get_single_folder(client, folder_id)
        return self._get_all_folders(client, project_id, env_slug, path, recursive)

    def _get_single_folder(self, client, folder_id):
        """Fetch a single folder by ID."""
        try:
            folder = client.folders.get_folder_by_id(id=folder_id)
            return [folder.to_dict()]
        except Exception as e:
            raise AnsibleError(f"Error fetching folder '{folder_id}': {e}")

    def _get_all_folders(self, client, project_id, environment, path, recursive=False):
        """Fetch all folders within the specified scope."""
        try:
            response = client.folders.list_folders(
                project_id=project_id,
                environment_slug=environment,
                path=path,
                recursive=recursive,
            )
            return [folder.to_dict() for folder in response.folders]
        except Exception as e:
            raise AnsibleError(f"Error fetching folders: {e}")
