// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

#include "rgw_auth_keystone_utils.h"
#include "rgw_log.h"

namespace rgw {
namespace auth {
namespace keystone {

void KeystoneDataExtractor::extract_keystone_data(
  const ::rgw::keystone::TokenEnvelope& token,
  rgw_log_entry& entry,
  bool include_keystone_scope
) noexcept {
  if (!include_keystone_scope) {
    return;
  }

  try {
    extract_project_fields(token, entry);
    extract_user_fields(token, entry);
    extract_roles_array(token, entry);
    extract_application_credential(token, entry);
  } catch (...) {
    // Clear fields on error to ensure consistent state
    entry.keystone_project_id.clear();
    entry.keystone_project_name.clear();
    entry.keystone_project_domain_id.clear();
    entry.keystone_project_domain_name.clear();
    entry.keystone_user_id.clear();
    entry.keystone_user_name.clear();
    entry.keystone_user_domain_id.clear();
    entry.keystone_user_domain_name.clear();
    entry.keystone_roles.clear();
    entry.keystone_app_credential_id.clear();
    entry.keystone_app_credential_name.clear();
    entry.keystone_app_credential_restricted = false;
  }
}

void KeystoneDataExtractor::populate_from_auth_info(
  const ::rgw::auth::RemoteApplier::AuthInfo& info,
  rgw_log_entry& entry
) {
  // Placeholder - AuthInfo doesn't currently contain TokenEnvelope data
}

void KeystoneDataExtractor::extract_project_fields(
  const ::rgw::keystone::TokenEnvelope& token,
  rgw_log_entry& entry
) noexcept {
  try {
    entry.keystone_project_id = token.project.id;
    entry.keystone_project_name = token.project.name;
    entry.keystone_project_domain_id = token.project.domain.id;
    entry.keystone_project_domain_name = token.project.domain.name;
  } catch (...) {
    // Clear fields on error
    entry.keystone_project_id.clear();
    entry.keystone_project_name.clear();
    entry.keystone_project_domain_id.clear();
    entry.keystone_project_domain_name.clear();
  }
}

void KeystoneDataExtractor::extract_user_fields(
  const ::rgw::keystone::TokenEnvelope& token,
  rgw_log_entry& entry
) noexcept {
  try {
    entry.keystone_user_id = token.user.id;
    entry.keystone_user_name = token.user.name;
    entry.keystone_user_domain_id = token.user.domain.id;
    entry.keystone_user_domain_name = token.user.domain.name;
  } catch (...) {
    // Clear fields on error
    entry.keystone_user_id.clear();
    entry.keystone_user_name.clear();
    entry.keystone_user_domain_id.clear();
    entry.keystone_user_domain_name.clear();
  }
}

void KeystoneDataExtractor::extract_roles_array(
  const ::rgw::keystone::TokenEnvelope& token,
  rgw_log_entry& entry
) noexcept {
  try {
    entry.keystone_roles.clear();

    if (!token.roles.empty()) {
      constexpr size_t MAX_ROLES = 1000;
      size_t roles_to_process = std::min(token.roles.size(), MAX_ROLES);

      entry.keystone_roles.reserve(roles_to_process);

      size_t role_count = 0;
      for (const auto& token_role : token.roles) {
        if (role_count >= roles_to_process) {
          break;
        }
        entry.keystone_roles.emplace_back(token_role.name);
        ++role_count;
      }
    }
  } catch (...) {
    entry.keystone_roles.clear();
  }
}

void KeystoneDataExtractor::extract_application_credential(
  const ::rgw::keystone::TokenEnvelope& token,
  rgw_log_entry& entry
) noexcept {
  // Extract application credential data if present in the token
  entry.keystone_app_credential_id = token.application_credential.id;
  entry.keystone_app_credential_name = token.application_credential.name;
  entry.keystone_app_credential_restricted = token.application_credential.restricted;
}

void KeystoneDataExtractor::safe_string_copy(
  const std::string& source,
  std::string& destination
) noexcept {
  try {
    constexpr size_t MAX_FIELD_SIZE = 4096;
    if (source.size() <= MAX_FIELD_SIZE) {
      destination = source;
    } else {
      destination = source.substr(0, MAX_FIELD_SIZE);
    }
  } catch (...) {
    destination.clear();
  }
}

} // namespace keystone
} // namespace auth
} // namespace rgw