from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: update_folder
short_description: Update a secret folder in Infisical
version_added: "1.2.0"
author:
  - Infisical Inc.
description:
  - Update an existing secret folder in Infisical.
  - The folder must already exist and is identified by its ID.
  - The folder is renamed to C(name), and its description is replaced when C(description) is given.
extends_documentation_fragment:
  - infisical.vault.auth

options:
  project_id:
    description: The ID of the project where the folder resides.
    type: str
    required: true
  env_slug:
    description: >
      The environment slug where the folder resides.
      Environment slug is the short name of a given environment.
    type: str
    required: true
  path:
    description: "The parent folder path the folder resides in. For example: /services"
    type: str
    required: true
  folder_id:
    description:
      - The ID of the folder to update.
      - The Infisical update endpoint accepts only an ID, so a folder cannot be targeted by name.
        Use M(infisical.vault.read_folders) to look up the ID first.
    type: str
    required: true
  name:
    description:
      - The new name of the folder.
      - Required by the Infisical API, so pass the folder's current name to keep it unchanged.
    type: str
    required: true
  description:
    description:
      - A new description for the folder.
      - Omitting this leaves the existing description unchanged. It cannot be used to clear a description.
    type: str

notes:
  - Requires a version of the C(infisicalsdk) Python package that supports folder updates.

seealso:
  - module: infisical.vault.login
    description: Use the login module to authenticate once and reuse the session.
  - module: infisical.vault.create_folder
    description: Create a secret folder.
  - module: infisical.vault.read_folders
    description: Read secret folders from Infisical.
  - module: infisical.vault.delete_folder
    description: Delete a secret folder.
"""

EXAMPLES = r"""
# Rename a folder with direct authentication
- name: Rename a folder
  infisical.vault.update_folder:
    url: "https://app.infisical.com"
    auth_method: universal_auth
    universal_auth_client_id: "{{ client_id }}"
    universal_auth_client_secret: "{{ client_secret }}"
    project_id: "my-project-id"
    env_slug: "dev"
    path: "/services"
    folder_id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    name: "backend-api"
  register: updated_folder

# Update a folder using login_data
- name: Login to Infisical
  infisical.vault.login:
    url: "https://app.infisical.com"
    auth_method: universal_auth
    universal_auth_client_id: "{{ client_id }}"
    universal_auth_client_secret: "{{ client_secret }}"
  register: infisical_login

- name: Update only the description, keeping the name
  infisical.vault.update_folder:
    login_data: "{{ infisical_login.login_data }}"
    project_id: "my-project-id"
    env_slug: "prod"
    path: "/services"
    folder_id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    name: "backend"
    description: "Secrets for the backend service"
  register: updated_folder

# Look the folder ID up by name first, since update accepts only an ID
- name: Find the folder
  infisical.vault.read_folders:
    login_data: "{{ infisical_login.login_data }}"
    project_id: "my-project-id"
    env_slug: "prod"
    path: "/services"
  register: service_folders

- name: Rename the folder that was found
  infisical.vault.update_folder:
    login_data: "{{ infisical_login.login_data }}"
    project_id: "my-project-id"
    env_slug: "prod"
    path: "/services"
    folder_id: "{{ (service_folders.folders | selectattr('name', 'eq', 'backend') | first).id }}"
    name: "backend-api"
  register: updated_folder
"""

RETURN = r"""
folder:
  description: The updated folder.
  returned: success
  type: dict
  contains:
    id:
      description: The unique identifier of the folder.
      type: str
    name:
      description: The name of the folder.
      type: str
    path:
      description: The full path of the folder.
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
        )
        return authenticator.authenticate()
    except (ImportError, ValueError) as e:
        module.fail_json(msg=str(e))


def run_module():
    module_args = dict(
        login_data=dict(type='dict', no_log=True),
        url=dict(type='str', default='https://app.infisical.com'),
        auth_method=dict(
            type='str',
            default='universal_auth',
            choices=['universal_auth', 'oidc_auth', 'token_auth']
        ),
        universal_auth_client_id=dict(type='str'),
        universal_auth_client_secret=dict(type='str', no_log=True),
        identity_id=dict(type='str'),
        jwt=dict(type='str', no_log=True),
        token=dict(type='str', no_log=True),
        project_id=dict(type='str', required=True),
        env_slug=dict(type='str', required=True),
        path=dict(type='str', required=True),
        folder_id=dict(type='str', required=True),
        name=dict(type='str', required=True),
        description=dict(type='str'),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
    )

    if module.check_mode:
        module.exit_json(
            changed=True,
            folder={'name': module.params['name'], 'path': module.params['path']},
        )

    try:
        login_data = module.params.get('login_data')
        client = get_sdk_client(module, login_data=login_data)

        update_kwargs = dict(
            folder_id=module.params['folder_id'],
            name=module.params['name'],
            project_id=module.params['project_id'],
            environment_slug=module.params['env_slug'],
            path=module.params['path'],
        )

        if module.params.get('description') is not None:
            update_kwargs['description'] = module.params['description']

        folder = client.folders.update_folder(**update_kwargs)

        module.exit_json(
            changed=True,
            folder=folder.to_dict(),
        )
    except Exception as e:
        module.fail_json(msg=f"Error updating folder: {type(e).__name__}: {e}")


def main():
    run_module()


if __name__ == '__main__':
    main()
