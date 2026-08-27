"""Folder utilities for Infisical Ansible Collection.

This module provides helper functions for working with folders.
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import uuid

from ansible_collections.infisical.vault.plugins.module_utils._authenticator import (
    INFISICAL_VERSION,
    check_minimum_version,
)

MINIMUM_FOLDER_SDK_VERSION = "1.0.17"


def ensure_folder_sdk_version():
    """Raise ValueError when the installed SDK is older than folder support.

    Folder operations require infisicalsdk 1.0.17 or newer.
    """
    if not check_minimum_version(INFISICAL_VERSION, MINIMUM_FOLDER_SDK_VERSION):
        raise ValueError(
            "Please upgrade infisicalsdk to at least {0} to use folder operations.".format(
                MINIMUM_FOLDER_SDK_VERSION
            )
        )


def full_folder_path(parent_path, name):
    """Build the full path of a folder from its parent path and its own name.

    The Infisical API always returns a folder's own full path, not the parent path
    that was passed in the request, so "/services" plus "backend" becomes
    "/services/backend" and "/" plus "backend" becomes "/backend".

    Args:
        parent_path: The path the folder lives under
        name: The name of the folder

    Returns:
        The full path of the folder
    """
    return '{0}/{1}'.format((parent_path or '').rstrip('/'), name)


def _looks_like_id(value):
    """Return True when a value is a UUID, which is how folder IDs are formatted."""
    try:
        uuid.UUID(str(value))
    except (AttributeError, TypeError, ValueError):
        return False
    return True


def check_mode_created_folder(parent_path, name, description=None):
    """Build the folder a create would produce, without calling the API.

    Every field the create response documents is present. Fields the server assigns
    are None because no folder is written in check mode.

    Args:
        parent_path: The path the folder would be created under
        name: The name of the folder
        description: The description of the folder, if one was given

    Returns:
        A dictionary shaped like a create response
    """
    return {
        'id': None,
        'name': name,
        'path': full_folder_path(parent_path, name),
        'description': description,
        'envId': None,
        'parentId': None,
        'version': None,
        'isReserved': False,
        'lastSecretModified': None,
        'createdAt': None,
        'updatedAt': None,
    }


def check_mode_updated_folder(folder_id, parent_path, name, description=None):
    """Build the folder an update would produce, without calling the API.

    The ID is known because update takes it as a parameter. The path reflects the
    requested name, matching the API, which re-reads the path after the rename.

    Args:
        folder_id: The ID of the folder being updated
        parent_path: The path the folder lives under
        name: The name the folder would be given
        description: The description of the folder, if one was given

    Returns:
        A dictionary shaped like an update response
    """
    return {
        'id': folder_id,
        'name': name,
        'path': full_folder_path(parent_path, name),
        'description': description,
        'envId': None,
        'parentId': None,
        'version': None,
        'isReserved': False,
        'lastSecretModified': None,
        'createdAt': None,
        'updatedAt': None,
    }


def check_mode_deleted_folder(folder_id_or_name):
    """Build the folder a delete would return, without calling the API.

    The delete response carries no path, so neither does this. The identifier is
    reported as the ID when it is a UUID and as the name otherwise.

    Args:
        folder_id_or_name: The ID or the name of the folder being deleted

    Returns:
        A dictionary shaped like a delete response
    """
    identifier_is_id = _looks_like_id(folder_id_or_name)

    return {
        'id': folder_id_or_name if identifier_is_id else None,
        'name': None if identifier_is_id else folder_id_or_name,
        'description': None,
        'envId': None,
        'parentId': None,
        'version': None,
        'isReserved': False,
        'lastSecretModified': None,
        'createdAt': None,
        'updatedAt': None,
    }
