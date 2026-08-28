from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: read_folders
short_description: Read secret folders from Infisical
version_added: "1.2.0"
author:
  - Infisical Inc.
description:
  - Read secret folders from Infisical.
  - Folders can be listed by environment and parent path, or fetched individually by their ID.
extends_documentation_fragment:
  - infisical.vault.auth

options:
  project_id:
    description:
      - The ID of the project where the folders are stored.
      - Required when C(path) is used. Ignored when C(folder_id) is used.
    type: str
  env_slug:
    description:
      - The environment slug to list folders from. Environment slug is the short name of a given environment.
      - Required when C(path) is used. Ignored when C(folder_id) is used.
    type: str
  path:
    description:
      - "The parent folder path to list folders from. For example: /services"
      - Mutually exclusive with C(folder_id). One of C(path) or C(folder_id) is required.
    type: str
  folder_id:
    description:
      - The ID of a single folder to fetch.
      - Mutually exclusive with C(path). One of C(path) or C(folder_id) is required.
    type: str
  recursive:
    description:
      - List folders recursively below C(path) instead of only its direct children.
      - Only applies when listing by C(path).
    type: bool
    default: false

notes:
  - Requires C(infisicalsdk) version 1.0.17 or newer.
  - This module is read-only, so it performs the real lookup in check mode rather than returning stub data.
  - Folders listed by C(path) carry a C(relativePath) field, while a folder fetched by C(folder_id) carries C(path), C(projectId), and a nested C(environment) object.

seealso:
  - module: infisical.vault.login
    description: Use the login module to authenticate once and reuse the session.
  - module: infisical.vault.create_folder
    description: Create a secret folder.
  - module: infisical.vault.update_folder
    description: Update an existing secret folder.
  - module: infisical.vault.delete_folder
    description: Delete a secret folder.
"""

EXAMPLES = r"""
# List folders with direct authentication
- name: List folders at the project root
  infisical.vault.read_folders:
    url: "https://app.infisical.com"
    auth_method: universal_auth
    universal_auth_client_id: "{{ client_id }}"
    universal_auth_client_secret: "{{ client_secret }}"
    project_id: "my-project-id"
    env_slug: "dev"
    path: "/"
  register: root_folders

# List folders using login_data
- name: Login to Infisical
  infisical.vault.login:
    url: "https://app.infisical.com"
    auth_method: universal_auth
    universal_auth_client_id: "{{ client_id }}"
    universal_auth_client_secret: "{{ client_secret }}"
  register: infisical_login

- name: List every folder below /services
  infisical.vault.read_folders:
    login_data: "{{ infisical_login.login_data }}"
    project_id: "my-project-id"
    env_slug: "prod"
    path: "/services"
    recursive: true
  register: service_folders

- name: Show the folder names
  ansible.builtin.debug:
    msg: "{{ service_folders.folders | map(attribute='name') | list }}"

- name: Fetch a single folder by ID
  infisical.vault.read_folders:
    login_data: "{{ infisical_login.login_data }}"
    folder_id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  register: one_folder

- name: Show the folder
  ansible.builtin.debug:
    var: one_folder.folders[0]
"""

RETURN = r"""
folders:
  description:
    - The folders that were read.
    - Always a list. When C(folder_id) is used, it contains exactly one folder.
  returned: success
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
      contains:
        envId:
          description: The ID of the environment.
          type: str
        envName:
          description: The name of the environment.
          type: str
        envSlug:
          description: The slug of the environment.
          type: str
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

import traceback

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.infisical.vault.plugins.module_utils._authenticator import (
    InfisicalAuthenticator,
    create_client_from_login_data,
)
from ansible_collections.infisical.vault.plugins.module_utils._folders import (
    ensure_folder_sdk_version,
)


def get_sdk_client(module, login_data=None):
    """Get an authenticated Infisical SDK client."""
    if login_data is not None:
        try:
            ensure_folder_sdk_version()
            client = create_client_from_login_data(login_data)
            return client
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
        ensure_folder_sdk_version()
        client = authenticator.authenticate()
        return client
    except (ImportError, ValueError) as e:
        module.fail_json(msg=str(e))


def run_module():
    module_args = dict(
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
        project_id=dict(type='str'),
        env_slug=dict(type='str'),
        path=dict(type='str'),
        folder_id=dict(type='str'),
        recursive=dict(type='bool', default=False),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        mutually_exclusive=[['folder_id', 'path']],
        required_one_of=[['folder_id', 'path']],
        required_by={'path': ['project_id', 'env_slug']},
    )

    try:
        login_data = module.params.get('login_data')
        client = get_sdk_client(module, login_data=login_data)

        if module.params.get('folder_id') is not None:
            folder = client.folders.get_folder_by_id(id=module.params['folder_id'])
            folders = [folder.to_dict()]
        else:
            response = client.folders.list_folders(
                project_id=module.params['project_id'],
                environment_slug=module.params['env_slug'],
                path=module.params['path'],
                recursive=module.params['recursive'],
            )
            folders = [folder.to_dict() for folder in response.folders]

        module.exit_json(
            changed=False,
            folders=folders,
        )
    except Exception as e:
        module.fail_json(
            msg=f"Error reading folders: {type(e).__name__}: {e}",
            exception=traceback.format_exc(),
        )


def main():
    run_module()


if __name__ == '__main__':
    main()
