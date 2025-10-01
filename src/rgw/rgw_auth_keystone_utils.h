// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

#pragma once

#include "rgw_keystone.h"
#include "rgw_auth.h"

struct rgw_log_entry;

namespace rgw {
namespace auth {
namespace keystone {

// Utility class for extracting Keystone identity data
class KeystoneDataExtractor {
public:
  // Extract Keystone identity data from TokenEnvelope into log entry
  static void extract_keystone_data(
    const ::rgw::keystone::TokenEnvelope& token,
    rgw_log_entry& entry,
    bool include_keystone_scope
  ) noexcept;

  // Populate Keystone fields from RemoteApplier::AuthInfo
  static void populate_from_auth_info(
    const ::rgw::auth::RemoteApplier::AuthInfo& info,
    rgw_log_entry& entry
  );

private:
  // Extract project-related fields from TokenEnvelope
  static void extract_project_fields(
    const ::rgw::keystone::TokenEnvelope& token,
    rgw_log_entry& entry
  ) noexcept;

  // Extract user-related fields from TokenEnvelope
  static void extract_user_fields(
    const ::rgw::keystone::TokenEnvelope& token,
    rgw_log_entry& entry
  ) noexcept;

  // Extract roles array from TokenEnvelope
  static void extract_roles_array(
    const ::rgw::keystone::TokenEnvelope& token,
    rgw_log_entry& entry
  ) noexcept;

  // Extract application credential information
  static void extract_application_credential(
    const ::rgw::keystone::TokenEnvelope& token,
    rgw_log_entry& entry
  ) noexcept;

  // Safely copy string field with error handling
  static void safe_string_copy(
    const std::string& source,
    std::string& destination
  ) noexcept;
};

} // namespace keystone
} // namespace auth  
} // namespace rgw